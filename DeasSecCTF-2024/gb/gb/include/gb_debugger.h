#ifndef DEBUGGER_H
#define DEBUGGER_H

//I will shim my debugger in between the cpu and the emulator inorder to give me some felxibilty in building

#include <common.h>
#include <cpu.h>
#include <timer.h>
#include <main_bus.h>
#include <stdint.h>
#include <opcodes.h>
#include <ppu.h>

typedef struct {
    main_bus_t* bus;
    CPU_t* cpu;
    address* breakpoints;
    uint64_t num_bp;
    uint64_t max_bp;
}debugger_t;

void start_debugger(main_bus_t* bus, CPU_t* cpu);


#endif
