// gcc overflow.c -O0 -g -o overflow
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>


int main() {
    void *addr;
    addr = mmap(0x23333000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(addr != MAP_FAILED);
    read(0, addr, 0x1000);
    ((void(*)(void))addr)();
    return 0;
}
