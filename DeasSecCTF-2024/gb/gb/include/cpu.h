#ifndef CPU_H
#define CPU_H
#include "common.h"
#include "opcodes.h"
#include "main_bus.h"
#include "log.h"
#include <stdint.h>
#include <sys/types.h>


//note to self since cpu uses the main bus, I can not use the CPU inside of main bus
typedef struct CPU_struct{
    main_bus_t* bus;
    union{
        uint16_t AF;
        struct {
            struct{
                uint8_t unused: 4;
                uint8_t C: 1;
                uint8_t HC: 1;
                uint8_t N: 1;
                uint8_t Z: 1;
            }FLAGS;
            uint8_t A;
        };
    };
    union{
        uint16_t BC;
        struct {
            uint8_t C;
            uint8_t B;
        };
    };
    union{
        uint16_t DE;
        struct {
            uint8_t E;
            uint8_t D;
        };
    };
    union{
        uint16_t HL;
        struct {
            uint8_t L;
            uint8_t H;
        };
    };
    uint16_t SP;
    uint16_t PC;
    byte IME; //interrupts enabled
    bool halt;
    union{
        uint8_t data;
        struct{
            uint8_t VBlank: 1;
            uint8_t STAT: 1;
            uint8_t Timer: 1;
            uint8_t Serial: 1;
            uint8_t Joypad: 1;
            uint8_t unused: 3;
        }flags;
    } IF; //interupt flag cpu must check these
    union{
        uint8_t data;
        struct{
            uint8_t VBlank: 1;
            uint8_t STAT: 1;
            uint8_t Timer: 1;
            uint8_t Serial: 1;
            uint8_t Joypad: 1;
            uint8_t unused: 3;
        }flags;
    } IE; //interupt flag cpu must check these
}CPU_t;

CPU_t* init_cpu(main_bus_t* bus);

void reset();

uint8_t cpu_cycle();
void patch(char* bytecode, size_t size);
void dump_cpu();
byte read_IF();
void write_IF(byte data);
byte read_IE();
void write_IE(byte data);
void vblank_int();
void stat_int();
void timer_int();
void serial_int();
void joypad_int();

#endif
