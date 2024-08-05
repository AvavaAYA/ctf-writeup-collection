#include "mapper.h"
#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

static mapper_t *map;

static void map_region(uint8_t** bank, size_t size, uint8_t number){
    //map continously for performance?
    bank[0] = Mmap(NULL, size*number, PROT_READ | PROT_WRITE, 
            MAP_PRIVATE | MAP_ANON, -1, 0);

    //populate the ROM_banks list. this will be used for swapping to the specific pages
    for(uint8_t i = 1; i < number; i++)
        bank[i] = bank[0] + size*i;
}

mapper_t* create_mapper(uint8_t num_ROM, uint8_t num_VRAM, uint8_t num_EXRAM, uint8_t num_WRAM, char* filename){
    int rom_fd = 0;
    map = Malloc(sizeof(mapper_t));

    rom_fd = open(filename, O_RDONLY);
    if(rom_fd < 0){
        LOG(ERROR, "open");
        exit(1);
    }

    //setup the arrays to be used 
    map->ROM_banks = Malloc(sizeof(size_t)*(2<<num_ROM));

    //setup the rest
    map->VRAM_banks = Malloc(sizeof(size_t)*num_VRAM);
    LOGF(DEBUG, "VRAM_Banks: %p", map->VRAM_banks);

    if(num_EXRAM)
        map->EXRAM_banks = Malloc(sizeof(size_t)*num_EXRAM);
    else 
        map->EXRAM_banks = NULL;
    map->WRAM_banks = Malloc(sizeof(size_t)*8);

//test is allowed to overwrite rom to test instructions
#ifdef TEST
    map->ROM_banks[0] = Mmap(NULL, ROM_SIZE<<num_ROM, PROT_READ | PROT_WRITE, 
            MAP_PRIVATE, rom_fd, 0);
#else
    map->ROM_banks[0] = Mmap(NULL, ROM_SIZE<<num_ROM, PROT_READ, 
            MAP_PRIVATE, rom_fd, 0);
#endif /* ifdef TEST */

    LOGF(DEBUG, "ENTRY VALUE 0x%x",map->ROM_banks[0][0x100]);

    //populate the ROM_banks list. this will be used for swapping to the specific pages
    for(uint8_t i = 1; i < 2<<num_ROM; i++){
        map->ROM_banks[i] = map->ROM_banks[0] + ROM_BANK_SIZE*i;
    }
    map->num_ROM = 2<<num_ROM;
    LOGF(DEBUG, "ROM: %p",map->ROM_banks[0]);
    map->rom_size = ROM_SIZE<<num_ROM;
    LOGF(DEBUG, "ROM SIZE: 0x%lx",map->rom_size);
    close(rom_fd);

    //for now I will handle the maximal case only. I will handle other cases in the future
    map_region(map->VRAM_banks, RAM_SIZE, num_VRAM);
    map->num_VRAM = num_VRAM;
    LOGF(DEBUG, "VRAM: %p",map->VRAM_banks[0]);

    if(num_EXRAM){
        map_region(map->EXRAM_banks, RAM_SIZE, num_EXRAM);
        LOGF(DEBUG, "EXRAM: %p",map->EXRAM_banks[0]);
    } else {
        LOG(DEBUG, "no exram availible");
    }
    map->num_EXRAM = num_EXRAM;

    map_region(map->WRAM_banks, WRAM_SIZE, num_WRAM);
    map->num_WRAM = num_WRAM;
    LOGF(DEBUG, "WRAM: %p",map->WRAM_banks[0]);

    map->HRAM = Malloc(HRAM_SIZE);
    LOGF(DEBUG, "HRAM: %p",map->HRAM);

    //to be figured out later
    map->read = NULL;
    map->write = NULL; 
    map->cur_ROM = 1;
    map->MCB1.banking_mode_select = false;
    map->MCB1.RAM_enabled = false;
    return map;
}


void release_mapper(mapper_t* map){
    munmap(map->ROM_banks[0], map->rom_size);
    munmap(map->VRAM_banks[0], RAM_SIZE*map->num_VRAM);
    munmap(map->WRAM_banks[0], WRAM_SIZE*map->num_WRAM);
    if(map->EXRAM_banks)
        munmap(map->EXRAM_banks[0], WRAM_SIZE*map->num_EXRAM);

    free(map->ROM_banks);
    free(map->VRAM_banks);
    free(map->WRAM_banks);
    if(map->EXRAM_banks)
        free(map->EXRAM_banks);
    free(map->HRAM);

    memset(map, 0, sizeof(mapper_t));
    LOG(INFO, "mapper freed");
    return;
}

void init_MBC1_regs(mapper_t* mapper){
    return;
}

byte read_rom_only(address addr){
    if(addr < VRAM_START){
     return map->ROM_banks[0][addr];
    } else if(addr >= EXRAM_START && addr < WRAM0_START){
     return map->VRAM_banks[0][addr-EXRAM_START];
    }
    LOG(ERROR, "Invalid address");
    exit(1);
}

void write_rom_only(address addr, byte data){
    if(addr >= EXRAM_START && addr < WRAM0_START){
        map->VRAM_banks[0][addr-EXRAM_START] = data;
    }
}

//https://gbdev.io/pandocs/MBC1.html
byte read_MBC1(address addr){
    byte ret = 0xFF; //for now return -1 if nothing is read
    if(addr >= 0 && addr < 0x4000){ //rom bank 00
        if(!map->MCB1.banking_mode_select){
            ret = map->ROM_banks[0][addr];
        } else{ 
            ret = map->ROM_banks[map->MCB1.reg2 << 5][addr];
        }
    } else if (addr >= 0x4000 && addr < 0x8000) { //rom bank 01, swichable via map
        ret = map->ROM_banks[map->cur_ROM][addr-0x4000];
    } else if (addr >= 0xA000 && addr < 0xC000 && map->MCB1.RAM_enabled) { //vram, switchable if CGB
        if(!map->MCB1.banking_mode_select){
            ret = map->EXRAM_banks[0][addr-0xA000];
        } else {
            ret = map->EXRAM_banks[map->cur_EXRAM][addr-0xA000];
        }
    }
    return ret;
}

void update_rom(){
    map->cur_ROM = map->MCB1.reg1 + (map->MCB1.reg2 << 5);
    //can't exceed the max
    map->cur_ROM %= map->num_ROM;
    if(map->cur_ROM == 0) map->cur_ROM = 1;
}

//https://gbdev.io/pandocs/MBC1.html
void write_MBC1(address addr, byte data){
    if(addr < 0x2000 && (data & 0xF) == 0xA){
        LOG(DEBUG, "enabling RAM");
        map->MCB1.RAM_enabled = true;     
        return;
    } else if(addr >= 0x2000 && addr < 0x4000){
        map->MCB1.reg1 = data & 0x1f;
        update_rom();
    } else if(addr >= 0x4000 && addr < 0x6000){
        map->MCB1.reg2 = data & 0x3;
        update_rom();
    } else if(addr >= 0x6000 && addr < 0x8000){
        map->MCB1.banking_mode_select = data & 1 ? 1 : 0;
        update_rom();
    } else if(addr > 0xA000 && addr < 0xC000 && map->MCB1.RAM_enabled){
        LOGF(DEBUG, "write to memory bank with address %p", map->EXRAM_banks[map->cur_EXRAM]);
        map->EXRAM_banks[map->cur_EXRAM][addr-0xA000] = data;
        return;
    }
    
    //map->cur_ROM = (map->MCB1.reg2 << 5) | map->MCB1.reg2;
    //if(!map->cur_ROM)
    //    map->cur_ROM = 1;
    map->cur_EXRAM = map->MCB1.reg2;

    return;
}
