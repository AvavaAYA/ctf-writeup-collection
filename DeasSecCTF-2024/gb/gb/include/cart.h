#ifndef CART_H
#define CART_H
#include "common.h"
#include "mapper.h"
#include "main_bus.h"
#include <stdint.h>

//sourced from https://gbdev.io/pandocs/The_Cartridge_Header.html
typedef struct cart_struct{
    uint32_t entry;
    uint8_t logo[0x30];
    char title[0x10];
    uint32_t manufacturer_code;
    uint8_t CGB_flag;
    uint16_t new_licensee_code;
    uint8_t SBG_flag;
    uint8_t cart_type; //necessary for mapper
    uint8_t num_ROM; 
    uint8_t val_RAM; 
    uint8_t dest_code;
    uint8_t old_licensee_code;
    uint8_t mask_rom_version_numer;
    uint8_t header_checksum;
    uint16_t global_checksum;
} cart_t;

enum cart_types{
ROM_ONLY,
MBC1,
MBC1_RAM,
MBC1_RAM_BATTERY,
MBC2,
MBC2_BATTERY,
ROM_RAM,
ROM_RAM_BATTERY,
MMM01=0xB,
MMM01_RAM,
MMM01_RAM_BATTERY,
MBC3_TIMER_BATTERY=0xF,
MBC3_TIMER_RAM_BATTERY,
MBC3,
MBC3_RAM,
MBC3_RAM_BATTERY,
MBC5 = 0x19,
MBC5_RAM,
MBC5_RAM_BATTERY,
MBC5_RUMBLE,
MBC5_RUMBLE_RAM,
MBC5_RUMBLE_RAM_BATTERY,
MBC6 = 0x20,
MBC7_SENSOR_RUMBLE_RAM_BATTERY = 0x22,
POCKET_CAMERA = 0xFC,
BANDAI_TAMA5,
HuC3,
HuC1_RAM_BATTERY
};

//read the header and s
void load_cart(cart_t* cart, char* filename);
void select_mapper(uint8_t cart_type, mapper_t* mapper);

#endif
