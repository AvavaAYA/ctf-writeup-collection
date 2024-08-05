#ifndef COMMON_H
#define COMMON_H
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include "log.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>

#define ROM_SIZE 0x8000
#define ROM_BANK_SIZE 0x4000
#define RAM_SIZE 0x2000
#define WRAM_SIZE 0x1000

#define ROM0_START  0
#define ROMN_START  0x4000
#define VRAM_START  0x8000
#define EXRAM_START 0xA000
#define WRAM0_START 0xC000
#define WRAMN_START 0xD000
#define WRAMN_END   0xF000
#define OAM_START   0xFE00
#define OAM_END     0xFEA0
#define IO_START    0xFF00
#define HRAM_START  0xFF80
#define IE_REG      0xFFFF

#define HRAM_SIZE 0x7e

#define MEM_FREE 0
#define OAM_BLOCKED 1
#define OAM_VRAM_BLOCKED 2

//offer these up to the entire system
void* Malloc(ssize_t size);
uint8_t* Mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);

typedef uint16_t address;
typedef uint8_t byte;

typedef void(*IRQ)();

#define SUCCESS 0;
#define FAIL -1;
//#define DEBUG_CPU
//#define DEBUG_BUS

#endif // !COMMON_H
