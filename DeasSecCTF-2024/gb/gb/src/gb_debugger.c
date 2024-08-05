#include <string.h>
#ifndef NATTACH_DB
#include <gb_debugger.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

debugger_t db;
extern const instr instr_table[];

char* read_command(){
    char c;
    uint64_t cur, lim, bytes_read;
    char* buf;

    printf("dbg > ");

    buf = malloc(0x10);
    lim = 0x10;
    cur = c = 0;
    do{
        bytes_read = read(STDIN_FILENO,&c,1);
        buf[cur++] = c; 
        if(cur >= lim){
            lim *= 2;
            buf = realloc(buf, lim);
        }
    } while(c != '\n' && c != 0 && bytes_read == 1);

    return buf;
}

void break_point(char *cmd){
    address addr;
    if(db.num_bp >= db.max_bp){
        printf("no availiable breakpoints");
        return;
    }
    sscanf(cmd, "b %hx", &addr);
    db.breakpoints[db.num_bp++] = addr;
    printf("Breakpoint created at 0x%04x\n", addr);
}

void delete_break(char *cmd){
    uint idx;
    idx = atoi(cmd+2);
    if(idx >= db.max_bp){
        printf("invalid index");
        return;
    }
    db.breakpoints[idx] = 0;
}

void examine(char *cmd){
    address addr;
    byte b;
    byte line[0x10];
    uint32_t count;

    sscanf(cmd, "x %hx %d", &addr, &count);

    for(uint32_t i = 0; i < count; i++){
        if(i % 0x10 == 0)
            printf("0x%04x : ", addr + i);
        b = read_bus(addr + i);
        line[i%10] = b;
        printf("0x%02x ", b);
        if(i % 0x10 == 0xF)
            printf(" |%s|\n", line);
    }
    puts("");
    return;
}

void step(){
    uint8_t t_cycles, m_cycles;
    t_cycles = cpu_cycle();
    for(int i = 0; i < t_cycles; i++)
        ppu_cycle(); //tick ppu 1 times per my cycle count
                     
    m_cycles = t_cycles / 4;
    timer_cycle(m_cycles); 
}

void run_until_break(){
    uint64_t i;
    for(;;){
        step();
        //a bit of overhead, but nothing too bad not worrying about DMA right now
        for(i = 0; i < db.num_bp; i++){

            if(db.cpu->PC == db.breakpoints[i]) return;
        }
    }
}

void disassemble(address addr, uint64_t count){
    uint16_t step;
    uint64_t i;
    byte b;
    address a;
    instr inst;
    byte opcode;
    step = i = 0;
    for(; i < count; i++){
        opcode = read_bus(addr + step);
        memcpy(&inst, &instr_table[opcode], sizeof(instr));
        printf("0x%04x: ", addr + step);
        step++;
        if(inst.size == 2){
            b = read_bus(addr + step++);
            printf(inst.instr_fmt, b);
            puts("");
        } else if(inst.size == 3){
            a = read_bus_addr(addr + step);
            printf(inst.instr_fmt, a);
            puts("");
            step += 2;
        } else {
            puts(inst.instr_fmt);
        }
    }
    return;
}

#define SET_PRE "\033[92;1;4m"
#define SUF "\033[m"

void status(){
    puts("-------------CPU contents-------------");
    printf("PC: 0x%04x\n",db.cpu->PC);
    printf("AF: 0x%04x A: 0x%02x\n",db.cpu->AF, db.cpu->A);
    printf("BC: 0x%04x B: 0x%02x C: 0x%02x\n",db.cpu->BC, db.cpu->B, db.cpu->C);
    printf("DE: 0x%04x D: 0x%02x E: 0x%02x\n",db.cpu->DE, db.cpu->D, db.cpu->E);
    printf("HL: 0x%04x H: 0x%02x L: 0x%02x\n",db.cpu->HL, db.cpu->H, db.cpu->L);
    printf("SP: 0x%04x\n",db.cpu->SP);
    printf("FLAGS: ");
    if(db.cpu->FLAGS.Z) printf(SET_PRE);
    printf("ZERO");
    if(db.cpu->FLAGS.Z) printf(SUF);
    printf(" ");
    if(db.cpu->FLAGS.N) printf(SET_PRE);
    printf("NEG");
    if(db.cpu->FLAGS.N) printf(SUF);
    printf(" ");
    if(db.cpu->FLAGS.C) printf(SET_PRE);
    printf("CARRY");
    if(db.cpu->FLAGS.C) printf(SUF);
    printf(" ");
    if(db.cpu->FLAGS.HC) printf(SET_PRE);
    printf("HALF");
    if(db.cpu->FLAGS.HC) printf(SUF);
    puts("");
    puts("-------------DISASSEMBLY--------------");
    disassemble(db.cpu->PC, 10);
    puts("---------------STACK------------------");
    for(uint i = 0; i < 10; i += 2){
        printf("0x%04x: 0x%04x\n", db.cpu->SP + i, read_bus_addr(db.cpu->SP + i));
    }
    puts("--------------------------------------");
}

//like the gdb implementation of ni
void next(){
    address addr = 0;
    byte cur_op;
    cur_op = read_bus(db.cpu->PC);
    if(strncmp(instr_table[cur_op].instr_fmt, "CALL", 4) == 0){
        addr = db.cpu->PC + instr_table[cur_op].size; //address of next instr
        do{
            step();
        }while(db.cpu->PC != addr);
    } else {
        step();
    }
    return;
}

void set(char* cmd){
    address addr;
    
    sscanf(cmd, "p %hx", &addr);
    db.cpu->PC = addr;
    return;
}

void debug(){
    char* cmd;
    char prev_command[0x100];
    bool done = false;
    uint64_t count = 0;
    address addr;

    status();
    while(!done){
        cmd = read_command();
        if(cmd[0] == '\n') {
            free(cmd);
            cmd = prev_command;
        }
        switch(cmd[0]){
            case 'a': 
                sscanf(cmd, "a %hx %ld", &addr, &count);
                if(count < 0x100)
                    disassemble(addr, count);
                break;
            case 'b': 
                break_point(cmd);
                break;
            case 'c':
                run_until_break();
                status();
                break;
            case 'd':
                delete_break(cmd);
                break;
            case 'i':
                status();
                break;
            case 'n':
                next();
                status();
                break;
            case 's':
                step();
                status();
                break;
            case 'p':
                set(cmd);
                break;
            case 'q':
                done = true;
                break;
            case 'x':
                examine(cmd);
                break;
            default:
                puts("Invalid command");
        }
        if(cmd != prev_command){
            strncpy(prev_command, cmd, 0xF8);
            free(cmd);
        }
    }
    exit(0);
}

void start_debugger(main_bus_t *bus, CPU_t *cpu){
    db.bus = bus;
    db.cpu = cpu;
    db.breakpoints = calloc(0x10, sizeof(address));
    db.num_bp = 0;
    db.max_bp = 0x10;

    signal(SIGINT, debug);
    debug();
}
#endif
