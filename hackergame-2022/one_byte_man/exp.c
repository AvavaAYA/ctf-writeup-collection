#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

int main() {
    int fd_data = open("/data", 0, 0);
    int fd_sc = open("/shellcode", 0, 0);
    char *buf = mmap(NULL, 0x1000, 3, 4, fd_sc, 0);
    read(fd_data, buf+1, 57);
    close(fd_data);
    close(fd_sc);
    puts("[SUCCESS]");
    return 0;
}
