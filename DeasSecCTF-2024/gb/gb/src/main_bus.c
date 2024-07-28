#include "main_bus.h"
#include <stdint.h>

static main_bus_t* bus;

static uint8_t parse_ram(uint8_t header_val){
    switch(header_val){
        case 0:
            return 0;
        case 2:
            return 1;
        case 3:
            return 4;
        case 4:
            return 16;
        case 5:
            return 8;
        default:
            LOG(ERROR, "unused RAM value in header, returning 0");
            return 0;
    }
}

/*
 * num_ROM: the value containing the num of ROM sections in the cartridge
 * val_RAM: value to be parsed into WorkerRam and VRAM chunks
 */
main_bus_t* create_bus(uint8_t num_ROM, uint8_t val_RAM, bool is_CGB, char* filename){
    bus = malloc(sizeof(main_bus_t));
    uint8_t num_VRAM, num_EXRAM, num_WRAM;
    if(is_CGB){
        num_VRAM = 2;
        num_WRAM = 8;
    } else {
        num_VRAM = 1;
        num_WRAM = 2;
    }
    num_EXRAM = parse_ram(val_RAM);
    bus->mapper = create_mapper(num_ROM, num_VRAM, num_EXRAM, num_WRAM, filename); 
    //init values for the bus, later I may want to place these inside of the mapper, but not sure yet
    //mapper will control handling with banks for swapping, but I will allow the bus to read from here
    bus->ROM_B0 = bus->mapper->ROM_banks[0];
    bus->ROM_BN = bus->mapper->ROM_banks[1];
    bus->VRAM = bus->mapper->VRAM_banks[0];
    if(bus->mapper->EXRAM_banks)
        bus->EXRAM = bus->mapper->EXRAM_banks[0];
    else
        bus->EXRAM = NULL;
    bus->WRAM_B0 = bus->mapper->WRAM_banks[0];
    bus->WRAM_BN = bus->mapper->WRAM_banks[1];

    bus->OAM = Malloc(0xa0);
    return bus;
}

void release_bus(main_bus_t* bus){
    io_reg *tmp, *next;
    release_mapper(bus->mapper);
    free(bus->mapper);
    free(bus->OAM);

    for(tmp = bus->head_io_regs; tmp != NULL;){
        next = tmp->next;
        free(tmp);
        tmp = next;
    }

    memset(bus, 0, sizeof(main_bus_t));
    free(bus);
    LOG(INFO, "bus freed")
    return;
}

io_reg* check_io_reg(address addr){
    io_reg* ret = bus->head_io_regs;
    for(;ret != NULL; ret = ret->next){
        if(ret->addr == addr)
            return ret;
    }
    return NULL;
}

byte read_bus_generic(address addr){
    byte ret = 0;
    if(addr >= VRAM_START && addr < EXRAM_START){
#ifdef NATTACH_DB 
        if(bus->mem_perms == OAM_VRAM_BLOCKED)
            return 0xFF; //junk
#endif
        ret = bus->VRAM[addr-VRAM_START];
    } else if(addr >= WRAM0_START && addr < WRAMN_START){
        ret = bus->WRAM_B0[addr-WRAM0_START];
    } else if(addr >= WRAMN_START && addr < WRAMN_END){
        ret = bus->WRAM_BN[addr-WRAMN_START];
    } else if(addr >= WRAMN_END && addr < OAM_START){
        LOGF(ERROR, "{READ} undocumented memory access 0x%x\n", addr);
    } else if(addr >= OAM_START && addr < OAM_END){
#ifdef NATTACH_DB 
        if(bus->mem_perms != MEM_FREE)
            return 0xFF; //junk
#endif
        ret = bus->OAM[addr-OAM_START];
    } else if(addr >= OAM_END && addr < IO_START){
        LOGF(ERROR, "{READ} undocumented memory access 0x%x\n", addr);
    } else if((addr >= IO_START && addr < HRAM_START) || addr == IE){
        io_reg* reg = check_io_reg(addr);
        if(!reg){
            LOGF(ERROR, "{READ} register 0x%x not mapped\n", addr);
            return -1;
        }
        if(reg->read_callback == NULL){
            LOGF(ERROR, "register 0x%x not readable", addr);
            return -1;
        }
#ifdef DEBUG_BUS
        LOGF(DEBUG, "{READ} register 0x%x\n", addr);
#endif
        ret = reg->read_callback();
    } else if(addr >= HRAM_START && addr < IE_REG){
        ret = bus->mapper->HRAM[addr-HRAM_START];
    } else {
        LOGF(ERROR, "addr 0x%x is not mapped\n", addr);
    }
    return ret;
}

void write_bus_generic(address addr, byte data){
    if(addr >= VRAM_START && addr < EXRAM_START){
        if(bus->mem_perms == OAM_VRAM_BLOCKED)
            return;
        bus->VRAM[addr-VRAM_START] = data;
    } else if(addr >= WRAM0_START && addr < WRAMN_START){
        bus->WRAM_B0[addr-WRAM0_START] = data;
    } else if(addr >= WRAMN_START && addr < WRAMN_END){
        bus->WRAM_BN[addr-WRAMN_START] = data;
    } else if(addr >= WRAMN_END && addr < OAM_START){
        LOGF(ERROR, "{WRITE} undocumented memory access 0x%x\n", addr);
    } else if(addr >= OAM_START && addr < OAM_END){
        if(bus->mem_perms != MEM_FREE)
            return; //junk
        bus->OAM[addr-OAM_START] = data;
    } else if(addr >= OAM_END && addr < IO_START){
        LOGF(ERROR, "{WRITE} undocumented memory access 0x%x\n", addr);
    } else if((addr >= IO_START && addr < HRAM_START) || addr == IE){
        io_reg* reg = check_io_reg(addr);
        if(!reg){
            LOGF(ERROR, "{WRITE} register 0x%x not mapped", addr);
            return;
        }
        if(reg->write_callback == NULL){
            LOG(ERROR, "register not writable");
            return;
        }
#ifdef DEBUG_BUS
        LOGF(DEBUG, "{write} register 0x%x with data 0x%x\n", addr, data);
#endif
        reg->write_callback(data);
    } else if(addr >= HRAM_START && addr < IE_REG){
        bus->mapper->HRAM[addr-HRAM_START] = data;
    } else {
        LOGF(ERROR, "addr 0x%x is not mapped\n", addr);
    }
}

//trigger any special addresses and if there are none read from mapper
byte read_bus(address addr){
#ifdef DEBUG_BUS
    LOGF(DEBUG, "attempting to read addr: 0x%x",addr);
#endif
    byte ret;
    if((addr >= 0x8000 && addr < 0xA000) || addr >= 0xC000){
        ret = read_bus_generic(addr);
    } else {
        ret = bus->mapper->read(addr);
    }
    return ret;
}

address read_bus_addr(address addr){
    address ret = 0;
    ret = read_bus(addr);
    ret |= read_bus(addr+1) << 8;
#ifdef DEBUG_BUS
    LOGF(DEBUG, "read addr 0x%x\n", ret);
#endif
    return ret;
}

void write_bus(address addr, byte chr){
#ifdef DEBUG_BUS
    LOGF(DEBUG, "Writing 0x%x to 0x%x", chr, addr);
#endif
    if((addr >= 0x8000 && addr < 0xA000) || addr >= 0xC000){
        write_bus_generic(addr, chr);
    } else {
        bus->mapper->write(addr, chr);
    }
    return;
}

void write_bus_addr(address dest, address addr){
    write_bus(dest, addr & 0xff);
    write_bus(dest+1, addr >> 8);
    return;
}

//I will start it and update it every clock cycle for run for now
void start_DMA(byte data){
    bus->DMA_info.DMA_addr = data << 8;
    bus->DMA_info.DMA_count = 0;
    bus->DMA_info.DMA_enabled = true;
}

void DMA_tick(){
    byte data = read_bus(bus->DMA_info.DMA_addr++);
    bus->OAM[bus->DMA_info.DMA_count++] = data;

    if(bus->DMA_info.DMA_count >= 0xA0)
        bus->DMA_info.DMA_enabled = false;
}

byte read_VBK(){
    return bus->mapper->cur_VRAM;
}

void write_VBK(byte data){
    bus->VRAM = bus->mapper->VRAM_banks[data];
    bus->mapper->cur_VRAM = data;
}
