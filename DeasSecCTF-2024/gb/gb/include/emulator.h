#ifndef EMU_H
#define EMU_H
#include "common.h"
#include <sys/time.h>
#include "gb_debugger.h"
#include "timer.h"
#include "cpu.h"
#include "io_ports.h"
#include "ppu.h"
#include "cart.h"
#include "main_bus.h"
#include "log.h"
#include "signal.h"
#include "tests.h"

typedef struct emulator_struct{
    CPU_t* cpu;
    main_bus_t *main_bus;
    PPU_t* ppu;
    gb_timer* clock;
    cart_t cart;
    bool running;
}emulator_t;


#define NUM_TESTS 5
typedef int(*test_func)();

//initialize all of the variable required to start. includes reading the cartridge header
void create_emulator(char* filename);
void run();
void test_cpu();
emulator_t* get_emu();

#endif
