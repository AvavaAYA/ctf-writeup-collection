#include "emulator.h"
#include "lcd.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

static emulator_t emu;

extern LCD_t *lcd;

void cleanup(int sig){
    LOG(INFO, "cleanup");
    release_bus(emu.main_bus);  
    cleanup_ppu();
    // exit cleanly
    exit(0);
    return;
}


//TODO reset more thouroughly right now just setting things up for a new rom
void reset_cpu(){
    emu.main_bus->ROM_B0 = emu.main_bus->mapper->ROM_banks[0];
    emu.main_bus->ROM_BN = emu.main_bus->mapper->ROM_banks[1];
    memset(emu.cpu, 0, sizeof(CPU_t));
    emu.cpu->bus = emu.main_bus;
    cpu.SP = 0xFFFE;
    cpu.PC = 0x100;
    return;
}

byte read_joycon(){
    return lcd->joycon;
}

void write_joycon(byte data){
    while(lcd->spinlock);
    lcd->spinlock = 1;

    lcd->joycon = data & 0xF0;
    if(((lcd->joycon >> 5) & 1) == 0) lcd->joycon |= lcd->buttons & 0xF;
    else if(((lcd->joycon >> 4) & 1) == 0) lcd->joycon |= lcd->d_pad & 0xF;
    else lcd->joycon |= 0xF;

    lcd->spinlock = 0;
}

void init_io_reg(address addr, read_io read_func, write_io write_func){
    io_reg *reg = malloc(sizeof(*reg));
    memset(reg, 0, sizeof(*reg));
    reg->addr = addr;
    reg->read_callback = read_func;
    reg->write_callback = write_func;

    reg->next = emu.main_bus->head_io_regs; 
    emu.main_bus->head_io_regs = reg;
    return;
}

void init_io(){
    emu.main_bus->head_io_regs = NULL;
    
    //joypad is special since it is only written to by hardware.
    init_io_reg(JOYP, read_joycon, write_joycon);
    init_io_reg(SB, read_SB, write_SB);
    init_io_reg(SC, NULL, write_SC);
    init_io_reg(DIV, read_DIV, write_DIV);

    //timer stuff, seems complicated ignoring until I am sure I need a timer
    init_io_reg(TIMA, read_TIMA, write_TIMA);
    init_io_reg(TMA, read_TMA, write_TIMA);
    init_io_reg(TAC, read_TAC, write_TAC);

    //cpu
    init_io_reg(IF, read_IF, write_IF);
    init_io_reg(IE, read_IE, write_IE);

    //all the registers for the display
    init_io_reg(LCDC, read_LCDC, write_LCDC);
    init_io_reg(STAT, read_STAT, write_STAT);
    init_io_reg(SCX, read_SCX, write_SCX);
    init_io_reg(SCY, read_SCY, write_SCY);
    init_io_reg(WX, read_WX, write_WX);
    init_io_reg(WY, read_WY, write_WY);
    init_io_reg(LY, read_LY, NULL);
    init_io_reg(LYC, read_LYC, write_LYC);
    init_io_reg(BGP, read_BGP, write_BGP);
    init_io_reg(OBP0, read_OBP0, write_OBP0);
    init_io_reg(OBP1, read_OBP1, write_OBP1);

    init_io_reg(VBK, read_VBK, write_VBK);
    init_io_reg(DMA, NULL, start_DMA);
}

void create_emulator(char* filename){
    //deref has higher precidence
    bool is_CGB;
    signal(SIGINT, cleanup);
    signal(SIGPIPE, cleanup);
    signal(SIGCHLD, cleanup);
    load_cart(&emu.cart, filename);
    is_CGB = emu.cart.CGB_flag == 0x80 || emu.cart.CGB_flag == 0xC0;
    emu.main_bus = create_bus(emu.cart.num_ROM, emu.cart.val_RAM, is_CGB, filename);
    select_mapper(emu.cart.cart_type, emu.main_bus->mapper);
    emu.clock = init_timer();
    emu.cpu = init_cpu(emu.main_bus);
    emu.ppu = init_ppu(&emu.main_bus->mem_perms);
    sleep(2); //give the ppu process so time to start up
    emu.ppu->vblank_int = vblank_int;
    emu.ppu->stat_int = stat_int;
    emu.clock->timer_int = timer_int;
    init_io();
    emu.running = true;
    return;
}


void run(){
    uint64_t ticks;
    uint64_t diff;
    struct timeval stop, start;
    uint8_t t_cycles, dots, m_cycles;
    ticks = t_cycles = dots = 0;
    LOG(INFO, "Beginning ROM execution");
    while(emu.running){
#ifndef NATTACH_DB
        start_debugger(emu.main_bus, emu.cpu);
#else
        gettimeofday(&start, NULL);
        ticks = 0;
        for(uint64_t i = 0; i < 0x100; i++){
            if((t_cycles = cpu_cycle(0)) == 0) emu.running = false; //trigger HALT
            m_cycles = t_cycles / 4;

            if(emu.main_bus->DMA_info.DMA_enabled){
                for(uint8_t j = 0; j < m_cycles; j++) //one tick per machine cycle
                    DMA_tick();
            }

            //handle all of the ppu stuff
            dots = t_cycles; //1 dots per t_cycle
            ppu_cycle(dots); //ppu has to be ticked once at a time


            timer_cycle(m_cycles);
            ticks += m_cycles;
        }

        gettimeofday(&stop, NULL);
        diff = stop.tv_usec - start.tv_usec;
        //printf("ticks %ld diff %ld\n", ticks, diff);
        if(ticks > diff)
            usleep(ticks - diff); //align to the real clock as best as possible
#endif
    }
    LOG(INFO, "Ending ROM execution");
    getchar();
    cleanup(0);
}


emulator_t* get_emu(){
    return &emu;
}

#ifdef TEST
test_func tests[] = {
    test_ld,
    test_mem,
    test_arith,
    push_pop,
    call_ret,
    prefixed_instr,
    misc_instr,
    jumps,
    NULL,
};

void test_cpu(){
    uint64_t rc, i;
    LOG(INFO, "running tests");
    for(i = 0; tests[i] != NULL; i++){
        rc = tests[i]();
        if(rc){
            LOGF(ERROR, "Test %ld failed with rc %ld", i+1, rc);
            break;
        } else {
            LOGF(INFO, "Test %ld passed", i+1);
        }
        reset_cpu();
    }
    getchar();
    cleanup(0);
}
#else
void test_cpu(){
    LOG(ERROR, "Testing disabled");
}
#endif
