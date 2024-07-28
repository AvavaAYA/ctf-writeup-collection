#include "cpu.h"
#include <stdint.h>

extern CPU_t cpu;

#define BIT_OP(base, op, reg) ((base) | ((reg) | ((op) << 3)))

/*
 * For now I'm going to skill the conditional call/rets as they are pretty much 
 * the same as regular call and jump. if some issues arise later, I will have to 
 * look into them more closely
 */

int test_ld();
int test_mem();
int test_arith();
int push_pop();
int call_ret();
int prefixed_instr();
int misc_instr();
int jumps();

