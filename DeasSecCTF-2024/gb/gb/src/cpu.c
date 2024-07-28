#include "cpu.h"
#include "common.h"
#include "log.h"
#include "main_bus.h"
#include "mapper.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

static void ld_rr(byte opcode);
static void get_single_reg(byte opcode, uint8_t offset, uint8_t** reg);
static void get_double_reg(byte opcode, uint8_t offset, uint16_t** reg);

CPU_t cpu;
extern const instr instr_table[];

//for arithmetic and logic
#define ADD 0
#define ADC 1
#define SUB 2
#define SBC 3
#define AND 4
#define XOR 5
#define OR  6
#define CP  7

//for the upper ones
#define POP 1
#define PUSH 5
#define IMMI_ARI 6
#define RST 7

//for testing
void patch(char* bytecode, size_t size){
    uint64_t i;
    for(i = 0; i < size; i++)
        cpu.bus->ROM_B0[0x100+i] = bytecode[i];
    return;
}

CPU_t* init_cpu(main_bus_t* bus){
    memset(&cpu, 0, sizeof(CPU_t));
    cpu.AF = 0x100;
    cpu.BC = 0xFF13;
    cpu.DE = 0x00C1;
    cpu.HL = 0x8403;
    cpu.SP = 0xFFFE;
    cpu.PC = 0x100;
    cpu.halt = false;
    cpu.bus = bus;

    //give the emulator a refrence to the CPU
    return &cpu;
}

//register are stored as 3 bit values in the opcode, offset if the number of bits to right shift
static void get_double_reg(byte opcode, uint8_t offset, uint16_t** reg){
    switch((opcode >> offset) & 0x3){
        case BC:
            *reg = &cpu.BC;
            break;
        case DE:
            *reg = &cpu.DE;
            break;
        case HL:
            *reg = &cpu.HL;
            break;
        case SP:
            *reg = &cpu.SP;
            break;
    }
}

//register are stored as 3 bit values in the opcode, offset if the number of bits to right shift
//this can only be used for reading with case MEM
static void get_single_reg(byte opcode, uint8_t offset, uint8_t** reg){
    switch(opcode >> offset & 0x7){
        case B:
            *reg = &cpu.B;
            break;
        case C:
            *reg = &cpu.C;
            break;
        case D:
            *reg = &cpu.D;
            break;
        case E:
            *reg = &cpu.E;
            break;
        case H:
            *reg = &cpu.H;
            break;
        case L:
            *reg = &cpu.L;
            break;
        case MEM:
            *reg = NULL;
            break;
        case A:
            *reg = &cpu.A;
            break;
    }
}

static void check_HC_add(uint8_t val1, uint8_t val2){
    uint8_t chk;

    chk = (val1 & 0xf) + (val2 & 0xf);
    cpu.FLAGS.HC = chk & 0x10 ? 1 : 0;
}

static void check_HC_adc(uint8_t val1, uint8_t val2){
    uint8_t chk;

    chk = (val1 & 0xf) + (val2 & 0xf) + cpu.FLAGS.C;
    cpu.FLAGS.HC = chk & 0x10 ? 1 : 0;
}

static void check_flags_add_16bit(uint16_t val1, uint16_t val2){
    uint16_t chk;
    uint32_t chk2;

    chk2 = val1 + val2;
    chk = (val1 & 0xfff) + (val2 & 0xfff);
    cpu.FLAGS.HC = chk & 0x1000 ? 1 : 0;
    cpu.FLAGS.C = chk2 & 0x10000 ? 1 : 0;
}

static void check_HC_sub(uint8_t val1, uint8_t val2){
    int8_t chk;

    chk = (val1 & 0xF) - (val2 & 0xf);
    cpu.FLAGS.HC = chk < 0 ? 1 : 0; //check if the 4th bit of val1 was borrowed
}

static uint8_t add(byte v1, byte v2){
    uint8_t result;
    result = v1 + v2;
    cpu.FLAGS.C = (result < v1) ? 1 : 0;
    check_HC_add(v1, v2);
    cpu.FLAGS.N = 0;
    return result;
}

static uint8_t adc(byte v1, byte v2){
    uint16_t result;
    check_HC_adc(v1, v2);
    result = v1 + v2 + cpu.FLAGS.C;
    cpu.FLAGS.C = (result >= 0x100) ? 1 : 0;
    cpu.FLAGS.N = 0;
    return result;
}

static uint8_t sub(byte v1, byte v2){
    uint8_t result;

    result = v1 - v2;
    cpu.FLAGS.C = (result > cpu.A) ?  1 : 0;
    check_HC_sub(v1, v2);
    cpu.FLAGS.N = 1;

    return result;
}

static uint8_t sbc(byte v1, byte v2){
    int16_t c_chk;
    int8_t hc_chk;
    uint8_t result;

    result = v1 - v2 - cpu.FLAGS.C;

    //set the flags sbc hc check is different than sub
    hc_chk = (v1 & 0xF) - (v2 & 0xf) - cpu.FLAGS.C;
    cpu.FLAGS.HC = (hc_chk < 0) ? 1 : 0;
    c_chk = v1 - v2 - cpu.FLAGS.C;
    cpu.FLAGS.C = (c_chk < 0) ?  1 : 0;
    cpu.FLAGS.N = 1;

    return result;
}

//push does not take a refrence to anything, as there should be no need to write
static void push(uint16_t reg){
    //need to do the writing still
    cpu.SP -= 2;
    write_bus_addr(cpu.SP, reg);
}

static void pop(uint16_t* reg){
    *reg = read_bus_addr(cpu.SP);
    cpu.SP += 2;
}

static void do_ret(){
    pop(&cpu.PC); //should just be the same as popping a regular register
}

static void do_call(address addr){
#ifdef DEBUG_CPU
    LOGF(DEBUG, "calling addr 0x%x\n", addr);
#endif
    push(cpu.PC);
    cpu.PC = addr;
}

static void prefixed_instr(byte opcode){
    byte *reg;
    byte bit;
    byte mem_val;
    byte tmp_reg;

#ifdef DEBUG_CPU
    LOGF(DEBUG,"PREFIXED OPCODE: 0x%02x",opcode);
#endif
    get_single_reg(opcode, 0, &reg);

    if(reg == NULL){
        mem_val = read_bus(cpu.HL);
        reg = &mem_val;
    }

    switch(opcode >> 3){
        case RLC:
            tmp_reg = *reg; 
            *reg <<= 1;
            cpu.FLAGS.C = tmp_reg >> 7;
            *reg |= cpu.FLAGS.C;
            cpu.FLAGS.HC = 0;
            cpu.FLAGS.N = 0;
            cpu.FLAGS.Z = *reg == 0 ? 1 : 0;
            break;
        case RL:
            tmp_reg = *reg; 
            *reg <<= 1;
            *reg |= cpu.FLAGS.C;
            cpu.FLAGS.C = tmp_reg >> 7;
            cpu.FLAGS.HC = 0;
            cpu.FLAGS.N = 0;
            cpu.FLAGS.Z = *reg == 0 ? 1 : 0;
            break;
        case RRC:
            tmp_reg = *reg;
            *reg >>= 1;
            *reg |= tmp_reg << 7;
            cpu.FLAGS.C = tmp_reg & 1;
            cpu.FLAGS.HC = 0;
            cpu.FLAGS.N = 0;
            cpu.FLAGS.Z = *reg == 0 ? 1 : 0;
            break;
        case RR:
            tmp_reg = *reg;
            *reg >>= 1;
            *reg |= cpu.FLAGS.C << 7;
            cpu.FLAGS.C = tmp_reg & 1;
            cpu.FLAGS.HC = 0;
            cpu.FLAGS.N = 0;
            cpu.FLAGS.Z = *reg == 0 ? 1 : 0;
            break;
        case SLA:
            cpu.FLAGS.C = *reg >> 7;
            *reg <<= 1;
            cpu.FLAGS.N = 0;
            cpu.FLAGS.HC = 0;
            cpu.FLAGS.Z = *reg == 0 ? 1 : 0;
            break;
        case SRA:
            cpu.FLAGS.C = *reg & 1;
            *reg >>= 1;
            *reg |= ((*reg >> 6) & 1) << 7; //set msb to old msb
            cpu.FLAGS.N = 0;
            cpu.FLAGS.HC = 0;
            cpu.FLAGS.Z = *reg == 0 ? 1 : 0;
            break;
        case SWAP:
            tmp_reg = *reg >> 4; //upper nibble
            *reg <<= 4; //push lower nibble over
            *reg |= tmp_reg; //or in lower nibble
            cpu.FLAGS.C = 0;
            cpu.FLAGS.N = 0;
            cpu.FLAGS.HC = 0;
            cpu.FLAGS.Z = *reg == 0 ? 1 : 0;
            break;
        case SRL:
            cpu.FLAGS.C = *reg & 1;
            *reg >>= 1;
            *reg &= ~(1 << 7); //unset msb
            cpu.FLAGS.N = 0;
            cpu.FLAGS.HC = 0;
            cpu.FLAGS.Z = *reg == 0 ? 1 : 0;
            break;
        default:
            bit = (opcode >> 3) & 7;
            if(opcode >= BIT && opcode < RES){
                cpu.FLAGS.Z = *reg & (1 << bit) ? 0 : 1;
                cpu.FLAGS.N = 0;
                cpu.FLAGS.HC = 1;
            } else if(opcode >= RES && opcode < SET){
                *reg &= ~(1 << bit);
            } else if (opcode >= SET) {
                *reg |= 1 << bit;
            } else {
                LOGF(ERROR, "unexpected prefixed opcode 0x%x\n", opcode);
            }
            break;
    }
    //writeback the manipulated value
    if(reg == &mem_val)
        write_bus(cpu.HL, mem_val);
}

//register to register or memory to register load
static void ld_rr(byte opcode){
    uint8_t *dest, *src;
    uint8_t tmp;
    get_single_reg(opcode, 3, &dest);
    get_single_reg(opcode, 0, &src);
    if(src == NULL){
        tmp = read_bus(cpu.HL);
        src = &tmp;
    }
    if(dest == NULL){
        write_bus(cpu.HL, *src);
    } else {
        *dest = *src;
    }
}

//covered in test_arith
void logic_arith_8bit(byte operation, uint8_t value){
    uint8_t result = 1;

    switch(operation){ 
        case ADD:
            result = add(cpu.A, value);
            cpu.A = result;
            break;
        case ADC:
            result = adc(cpu.A, value);
            cpu.A = result;
            break;
        case SUB:
            result = sub(cpu.A, value);
            cpu.A = result;
            break;
        case SBC:
            result = sbc(cpu.A, value);
            cpu.A = result;
            break;
        case AND:
            result = cpu.A & value;
            cpu.FLAGS.HC = 1;
            cpu.FLAGS.N = 0;
            cpu.FLAGS.C = 0;
            cpu.A = result;
            break;
        case XOR:
            result = cpu.A ^ value;
            cpu.FLAGS.HC = 0;
            cpu.FLAGS.N = 0;
            cpu.FLAGS.C = 0;
            cpu.A = result;
            break;
        case OR:
            result = cpu.A | value;
            cpu.FLAGS.HC = 0;
            cpu.FLAGS.N = 0;
            cpu.FLAGS.C = 0;
            cpu.A = result;
            break;
        case CP: //same as sub but does not update A
            result = sub(cpu.A, value);
            break;
        default:
            LOG(ERROR, "something went wrong\n");
    }
    //ZF can be set at the end since the arithmetic is the same
    cpu.FLAGS.Z = !result; //assign to 1 or 0 depending on weather or not the value was set
    return;
}

//handle the remaining instructions that are easier to handle individually
uint8_t exec_instr(byte opcode){
    uint16_t *tmp_double_reg;
    uint8_t *tmp_single_reg;
    uint16_t addr; 
    byte tmp_byte;
    int8_t rel_off;
    uint8_t cycles = 0;
    uint16_t tmp_word = 0;
    tmp_byte = addr = 0;

    //decode step
    if(instr_table[opcode].size == 2){
        tmp_byte = read_bus(cpu.PC++);
    } else if(instr_table[opcode].size == 3){
        tmp_word = read_bus_addr(cpu.PC);
        cpu.PC += 2;
    }

    //jump table
    switch(opcode){
        case LD_B_B ... LD_A_A:
            if(opcode == HALT) {
                cpu.halt = true;
            } else {
                ld_rr(opcode);
            }
            break;
        case ADD_B ... CP_A:
            get_single_reg(opcode, 0, &tmp_single_reg);
            if(tmp_single_reg == NULL){
                tmp_byte = read_bus(cpu.HL);
                tmp_single_reg = &tmp_byte;
            }
            logic_arith_8bit(opcode >> 3 & 7, *tmp_single_reg);
            break;
        case ADD_n:
        case ADC_N:
        case SUB_n:
        case SBC_n:
        case AND_n:
        case XOR_n:
        case OR_n:
        case CP_n:
            logic_arith_8bit((opcode >> 3) & 7, tmp_byte);
            break;
        case NOP: //NOP
            break;
        case LD_BC: 
        case LD_DE: 
        case LD_HL: 
        case LD_SP: 
            get_double_reg(opcode, 4, &tmp_double_reg);
            *tmp_double_reg = tmp_word;
            break;
        case STR_BC:
        case STR_DE:
        case STRI_HL:
        case STRD_HL:
            get_double_reg(opcode, 4, &tmp_double_reg);
            if(opcode == STRD_HL) 
                tmp_double_reg = &cpu.HL;
            write_bus(*tmp_double_reg, cpu.A);
            if(opcode == STRD_HL)
                cpu.HL--;
            else if(opcode == STRI_HL)
                cpu.HL++;
            break;
        case INC_BC: 
        case INC_DE: 
        case INC_HL: 
        case INC_SP: 
            get_double_reg(opcode, 4, &tmp_double_reg);
            *tmp_double_reg += 1;
            break;
        case ADD_HL_BC: 
        case ADD_HL_DE: 
        case ADD_HL_HL: 
        case ADD_HL_SP: //sum reg into HL
            get_double_reg(opcode, 4, &tmp_double_reg);
            cpu.FLAGS.N = 0;
            check_flags_add_16bit(cpu.HL, *tmp_double_reg);
            cpu.HL += *tmp_double_reg;
            //cpu.FLAGS.Z = !cpu.HL;
            cpu.FLAGS.N = 0;
            break;
        case LD_A_BC:
        case LD_A_DE:
        case LDI_A_HL:
        case LDD_A_HL: //load memory value into a
            get_double_reg(opcode, 4, &tmp_double_reg);
            if(opcode == LDD_A_HL) 
                tmp_double_reg = &cpu.HL;
            cpu.A = read_bus(*tmp_double_reg);
            if(opcode == LDD_A_HL)
                cpu.HL--;
            else if(opcode == LDI_A_HL)
                cpu.HL++;
            break;
        case DEC_BC: 
        case DEC_DE: 
        case DEC_HL: 
        case DEC_SP: //dec 16 bit reg
            get_double_reg(opcode, 4, &tmp_double_reg);
            *tmp_double_reg -= 1;
            break;
        case INC_A:
        case INC_B:
        case INC_C:
        case INC_D:
        case INC_E:
        case INC_H:
        case INC_L:
            get_single_reg(opcode, 3, &tmp_single_reg);
            cpu.FLAGS.N = 0;
            check_HC_add(*tmp_single_reg, 1);
            *tmp_single_reg += 1;
            cpu.FLAGS.Z = !(*tmp_single_reg);
            break;
        case INC_MEM: //read write addr so handle seperatly
            tmp_byte = read_bus(cpu.HL);
            cpu.FLAGS.N = 0;
            check_HC_add(tmp_byte, 1);
            tmp_byte++;
            cpu.FLAGS.Z = !tmp_byte;
            write_bus(cpu.HL, tmp_byte);
            break;
        case DEC_A: 
        case DEC_B: 
        case DEC_C: 
        case DEC_D: 
        case DEC_E: 
        case DEC_H: 
        case DEC_L: //dec 8bit register
            get_single_reg(opcode, 3, &tmp_single_reg);
            check_HC_sub(*tmp_single_reg, 1);
            *tmp_single_reg -= 1;
            cpu.FLAGS.Z = !(*tmp_single_reg);
            cpu.FLAGS.N = 1;
            break;
        case DEC_MEM:
            tmp_byte = read_bus(cpu.HL);
            check_HC_sub(tmp_byte, 1);
            cpu.FLAGS.N = 1;
            write_bus(cpu.HL, --tmp_byte);
            cpu.FLAGS.Z = !tmp_byte;
            break;
        case LD_A:  
        case LD_B:  
        case LD_C:  
        case LD_D:  
        case LD_E:  
        case LD_H:  
        case LD_L:  //ld 8 bit register immidiate
            get_single_reg(opcode, 3, &tmp_single_reg);
            *tmp_single_reg = tmp_byte; //replace with read soon
            break;
        case LD_MEM:
            write_bus(cpu.HL, tmp_byte);
            break;
        case RLCA:
            tmp_byte = cpu.A; 
            cpu.A <<= 1;
            cpu.FLAGS.C = tmp_byte >> 7;
            cpu.A |= cpu.FLAGS.C;
            cpu.FLAGS.HC = 0;
            cpu.FLAGS.N = 0;
            cpu.FLAGS.Z = 0;
            break;
        case RLA:
            tmp_byte = cpu.A; 
            cpu.A <<= 1;
            cpu.A |= cpu.FLAGS.C;
            cpu.FLAGS.C = tmp_byte >> 7;
            cpu.FLAGS.HC = 0;
            cpu.FLAGS.N = 0;
            cpu.FLAGS.Z = 0;
            break;
        case RRCA:
            tmp_byte = cpu.A;
            cpu.A >>= 1;
            cpu.A |= tmp_byte << 7;
            cpu.FLAGS.C = tmp_byte & 1;
            cpu.FLAGS.HC = 0;
            cpu.FLAGS.N = 0;
            cpu.FLAGS.Z = 0;
            break;
        case RRA:
            tmp_byte = cpu.A;
            cpu.A >>= 1;
            cpu.A |= cpu.FLAGS.C << 7;
            cpu.FLAGS.C = tmp_byte & 1;
            cpu.FLAGS.HC = 0;
            cpu.FLAGS.N = 0;
            cpu.FLAGS.Z = 0;
            break;
        case CPL:
            cpu.A = ~cpu.A;
            cpu.FLAGS.N = 1;     
            cpu.FLAGS.HC = 1;     
            break;
        case DAA:
            tmp_byte = 0;
            if(cpu.FLAGS.HC || (!cpu.FLAGS.N && (cpu.A & 0x0f) > 0x9))
                tmp_byte += 6;
            if(cpu.FLAGS.C || (!cpu.FLAGS.N && cpu.A > 0x99)){
                tmp_byte += 0x60;
                cpu.FLAGS.C = 1;
            }
            cpu.A += cpu.FLAGS.N ? -tmp_byte : tmp_byte;
            cpu.FLAGS.Z = cpu.A == 0 ? 1 : 0;
            cpu.FLAGS.HC = 0;
            break;
        case CCF:
            cpu.FLAGS.N = 0;
            cpu.FLAGS.HC = 0;
            cpu.FLAGS.C = ~cpu.FLAGS.C;
            break;
        case SCF:
            cpu.FLAGS.N = 0;
            cpu.FLAGS.HC = 0;
            cpu.FLAGS.C = 1;
            break;
        case JR:
            rel_off = tmp_byte;
            cpu.PC += rel_off;
            break;
        case JR_NZ:
            rel_off = tmp_byte;
            if(!cpu.FLAGS.Z){
                cpu.PC += rel_off;
                cycles += 4;
            }
            break;
        case JR_Z:
            rel_off = tmp_byte;
            if(cpu.FLAGS.Z){
                cpu.PC += rel_off;
                cycles += 4;
            }
            break;
        case JR_NC:
            rel_off = tmp_byte;
            if(!cpu.FLAGS.C){
                cpu.PC += rel_off;
                cycles += 4;
            }
            break;
        case JR_C:
            rel_off = tmp_byte;
            if(cpu.FLAGS.C){
                cpu.PC += rel_off;
                cycles += 4;
            }
            break;
        case RET_NZ:
            if(!cpu.FLAGS.Z) {
                do_ret();
                cycles += 12;
            }
            break;
        case RET_Z:
            if(cpu.FLAGS.Z){
                do_ret();
                cycles += 12;
            }
            break;
        case RET_NC:
            if(!cpu.FLAGS.C){
                do_ret();
                cycles += 12;
            }
            break;
        case RET_C:
            if(cpu.FLAGS.C){
                do_ret();
                cycles += 12;
            }
            break;
        case RET:
            do_ret();
            break;
        case RETI:
            cpu.IME = 1;
            do_ret();
            break;
        case JNZ:
            if(!cpu.FLAGS.Z){
                cpu.PC = tmp_word;
                cycles += 4;
            }
            break;
        case JZ:
            if(cpu.FLAGS.Z){
                cpu.PC = tmp_word;
                cycles += 4;
            }
            break;
        case JNC:
            if(!cpu.FLAGS.C){
                cpu.PC = tmp_word;
                cycles += 4;
            }
            break;
        case JC:
            if(cpu.FLAGS.C){
                cpu.PC = tmp_word;
                cycles += 4;
            }
            break;
        case JMP:
            cpu.PC = tmp_word;
            break;
        case CB_PREFIX:
            prefixed_instr(tmp_byte);
            break;
        case CALL_NZ:
            if(!cpu.FLAGS.Z){
                do_call(tmp_word);
                cycles += 12;
            }
            break;
        case CALL_Z:
            if(cpu.FLAGS.Z){
                do_call(tmp_word);
                cycles += 12;
            }
            break;
        case CALL:
            do_call(tmp_word);
            break;
        case CALL_NC:
            if(!cpu.FLAGS.C){
                do_call(tmp_word);
                cycles += 12;
            }
            break;
        case CALL_C:
            if(cpu.FLAGS.C){
                do_call(tmp_word);
                cycles += 12;
            }
            break;
        case POP_BC:
        case POP_DE:
        case POP_HL:
            get_double_reg(opcode, 4, &tmp_double_reg);
            pop(tmp_double_reg);
            break;
        case POP_AF:
            pop(&cpu.AF);
            cpu.AF &= 0xFFF0;
            break;
        case PUSH_BC:
        case PUSH_DE:
        case PUSH_HL:
            get_double_reg(opcode, 4, &tmp_double_reg);
            push(*tmp_double_reg);
            break;
        case PUSH_AF:
            push(cpu.AF);
            break;
        case RST_00:
        case RST_08:
        case RST_10:
        case RST_18:
        case RST_20:
        case RST_28:
        case RST_30:
        case RST_38:
            push(cpu.PC);
            cpu.PC = ((opcode >> 3) & 7)*8;
            break;
        case STR_DIR_n:
            write_bus(0xFF00 + tmp_byte, cpu.A);
            break;
        case STR_DIR:
            write_bus(0xFF00 + cpu.C, cpu.A);
            break;
        case LD_DIR_n:
            cpu.A = read_bus(0xFF00 + tmp_byte);
            break;
        case LD_DIR:
            cpu.A = read_bus(0xFF00 + cpu.C);
            break;
        case ADD_SP: 
            rel_off = tmp_byte;
            tmp_byte = cpu.SP & 0xff;
            tmp_word = tmp_byte + (uint8_t)rel_off;
            check_HC_add(tmp_byte, rel_off); //rel off should be treated as unsigned for this
            cpu.FLAGS.C = tmp_word >= 0x100 ? 1 : 0;
            cpu.FLAGS.Z = 0;
            cpu.FLAGS.N = 0;
            cpu.SP += rel_off;
            break;
        case JMP_HL:
            cpu.PC = cpu.HL;
            break;
        case LD_MEM_A:
            write_bus(tmp_word, cpu.A);
            break;
        case LD_A_MEM:
            cpu.A = read_bus(tmp_word);
            break;
        case DI:
            cpu.IME = 0;
            break;
        case EI:
            cpu.IME = 1;
            break;
        case LD_HL_SP_e:
            rel_off = tmp_byte;
            tmp_byte = cpu.SP & 0xff;
            tmp_word = tmp_byte + (uint8_t)rel_off;
            check_HC_add(tmp_byte, rel_off); //rel off should be treated as unsigned for this
            cpu.FLAGS.C = tmp_word >= 0x100 ? 1 : 0;
            cpu.FLAGS.Z = 0;
            cpu.FLAGS.N = 0;
            cpu.HL = cpu.SP + rel_off;
            break;
        case LD_SP_HL:
            cpu.SP = cpu.HL;
            break;
        case STR_nn_SP:
            write_bus_addr(tmp_word, cpu.SP);
            break;
        case STOP: //break until a button is pressed
            LOG(INFO, "Stopping execution until button is pressed, STOP INST");
            //TODO trigger DIV reset
            getchar();
            break;
        default:
            LOGF(ERROR, "something went wrong opcode: 0x%x\n", opcode);
            dump_cpu();
    }
    cycles += instr_table[opcode].T_cycles;
    return cycles;
}

void dump_cpu(){
    LOG(DEBUG,"---CPU contents---");
    LOGF(DEBUG,"PC: 0x%04x",cpu.PC);
    LOGF(DEBUG,"AF: 0x%04x",cpu.AF);
    LOGF(DEBUG,"BC: 0x%04x",cpu.BC);
    LOGF(DEBUG,"DE: 0x%04x",cpu.DE);
    LOGF(DEBUG,"HL: 0x%04x",cpu.HL);
    LOGF(DEBUG,"SP: 0x%04x",cpu.SP);
    LOG(DEBUG,"------------------");
}

void handle_interrupt(address int_addr){
    cpu.IME = 0; //disallow other interupts from being executed
    do_call(int_addr);
}

uint8_t cpu_cycle(){
    byte opcode;
    uint8_t cycles;

    //check for interupts up front
    if(cpu.IF.data != 0){
        cycles = 0;
        cpu.halt = false;
        if(cpu.IF.flags.VBlank && cpu.IE.flags.VBlank && cpu.IME){
            cpu.IF.flags.VBlank = 0;
            handle_interrupt(0x40);
            cycles = 20;
            goto done;
        }
        if(cpu.IF.flags.STAT && cpu.IE.flags.STAT && cpu.IME){
            cpu.IF.flags.STAT = 0;
            handle_interrupt(0x48);
            cycles = 20;
            goto done;
        }
        if(cpu.IF.flags.Timer && cpu.IE.flags.Timer && cpu.IME){
            cpu.IF.flags.Timer = 0;
            handle_interrupt(0x50);
            cycles = 20;
            goto done;
        }
    }

    if(cpu.halt){
        cycles = 4;
        goto done;
    }
    //fetch
    opcode = read_bus(cpu.PC++); 
    //decode and exec merged together for now
    cycles = exec_instr(opcode);

done:
    return cycles;
}

byte read_IF(){
    return cpu.IF.data;
}

void write_IF(byte data){
    cpu.IF.data = data;
}

byte read_IE(){
    return cpu.IE.data;
}

void write_IE(byte data){
    cpu.IE.data = data;
}

void vblank_int(){
    cpu.IF.flags.VBlank = 1;
}

void stat_int(){
    cpu.IF.flags.STAT = 1;
}

void timer_int(){
    cpu.IF.flags.Timer = 1;
}

void serial_int(){
    cpu.IF.flags.Serial = 1;
}

void joypad_int(){
    cpu.IF.flags.Joypad = 1;
}
