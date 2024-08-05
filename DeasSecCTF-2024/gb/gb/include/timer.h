#ifndef TIMER_H
#define TIMER_H

#include <common.h>
#include <stdint.h>

typedef struct {
    uint64_t total_ticks;
    IRQ timer_int;
    uint8_t cur_M_cycles;
    uint8_t div_M_cycles;
    byte DIV; //divider register 0xff04
    byte TIMA; //time counter register 0xff05
    byte TMA; //timer modulo interupt of overflow
    union{
        byte data;
        struct{
            uint8_t clock_select: 2;
            uint8_t enabled: 1;
            uint8_t unused: 5;
        } flags;
    } TAC; //timer control
}gb_timer;

gb_timer* init_timer();
byte read_DIV();
void write_DIV(byte data);
byte read_TIMA();
void write_TIMA(byte data);
byte read_TMA();
void write_TMA(byte data);
byte read_TAC();
void write_TAC(byte data);
void timer_cycle(uint8_t M_cycles);

#endif
