#include <stdint.h>
#include <timer.h>

gb_timer clock;

//makes use of internal registers to increment the timer and trigger
//interupts if needed
gb_timer* init_timer(){

    return &clock;
}

void timer_cycle(uint8_t M_cycles){
    uint16_t cap;
    if(clock.TAC.flags.enabled){
        clock.cur_M_cycles += M_cycles;
        switch(clock.TAC.flags.clock_select){
            case 0:
                cap = 256;
                break;
            case 1:
                cap = 4;
                break;
            case 2:
                cap = 16;
                break;
            case 3:
                cap = 64;
                break;
            default:
                LOG(ERROR, "invalid clock select value");
                exit(1);
        }
        if(clock.div_M_cycles >= cap){
            clock.TIMA++;
            //detect overflow
            if(clock.TIMA == 0){
                clock.TIMA = clock.TMA;
                clock.timer_int(); //interupt
            }
            clock.cur_M_cycles = clock.cur_M_cycles % cap;
        }

    }

    //update div
    //TODO make a way to reset div reg on stop instruction
    clock.div_M_cycles += M_cycles;
    if(clock.div_M_cycles >= 64){
        clock.DIV++;
        clock.div_M_cycles = clock.div_M_cycles % 64;
    }
}

//register io_ports
byte read_DIV(){
    return clock.DIV;
}

void write_DIV(byte data){
    clock.DIV = 0;
}

byte read_TIMA(){
    return clock.TIMA;
}

void write_TIMA(byte data){
    clock.TIMA = data;
}

byte read_TMA(){
    return clock.TMA;
}

void write_TMA(byte data){
    clock.TMA = data;
}

byte read_TAC(){
    return clock.TAC.data;
}

void write_TAC(byte data){
    clock.TAC.data = data;
}
