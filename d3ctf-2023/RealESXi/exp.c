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

int main() {

    printf("hello esxi");

    return 0;
}
