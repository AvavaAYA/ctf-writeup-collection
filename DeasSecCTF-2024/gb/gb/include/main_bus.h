#ifndef MAIN_BUS_H
#define MAIN_BUS_H
#include "common.h"
#include "mapper.h"
#include "lcd.h"
#include "io_ports.h"
#include <stdint.h>

//filled during mapper creation. mapper will handle swapping
typedef struct main_bus_struct {
    byte* ROM_B0;
    byte* ROM_BN; //switchable rom bank
    byte* VRAM;
    byte* EXRAM;
    byte* WRAM_B0;
    byte* WRAM_BN; //CGB switchable 1-7
    byte* OAM; //stores the display data for all sprites
    mapper_t* mapper;
    io_reg *head_io_regs;
    struct {
        address DMA_addr;
        byte  DMA_count;
        bool  DMA_enabled;
    } DMA_info;
    byte joypad;
    byte mem_perms; //only affect VRAM and OAM
}main_bus_t;


main_bus_t* create_bus(uint8_t num_ROM, uint8_t val_RAM, bool is_CGB, char* filename);
void release_bus(main_bus_t* bus);
byte read_bus(address addr);
void write_bus(address addr, byte chr);
address read_bus_addr(address addr);
void write_bus_addr(address dest, address addr);
//returns the number of regs generically allocated
uint64_t init_generic_regs(mapper_t* mapper, uint64_t num_regs);
void DMA_tick();
void start_DMA(byte data);
byte read_VBK();
void write_VBK(byte data);

#endif
