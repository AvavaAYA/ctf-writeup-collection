#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/io.h>
#include <sys/types.h>
#include <inttypes.h>
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN "\033[36m"
#define COLOR_RESET "\033[0m"
#define log(X)                                                                 \
  printf(COLOR_BLUE "[*] %s --> 0x%lx " COLOR_RESET "\n", (#X), (X))
#define success(X) printf(COLOR_GREEN "[+] %s" COLOR_RESET "\n", (X))
#define info(X) printf(COLOR_MAGENTA "[*] %s" COLOR_RESET "\n", (X))
#define errExit(X)                                                             \
  printf(COLOR_RED "[-] %s \033[0m\n", (X));                                   \
  exit(0)

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)

unsigned char *mmio_mem;
int fd;

uint64_t gva_to_gpa(void *);

int main() {
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:05.0/resource0", 2);
    if (mmio_fd == -1) {
        errExit("Failed to open mmio.")
    }

    mmio_mem = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    log(mmio_mem);


    return 0;
}

void mmio_read()


uint32_t page_offset(uint32_t addr)
{
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void *addr)
{
    uint64_t pme, gfn;
    size_t offset;
    offset = ((uintptr_t)addr >> 9) & ~7;
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;
    /* The page frame number is in bits 0-54 so read the first 7 bytes and clear the 55th bit */
    gfn = pme & PFN_PFN;
    return gfn;
}

uint64_t gva_to_gpa(void *addr)
{
    uint64_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}
