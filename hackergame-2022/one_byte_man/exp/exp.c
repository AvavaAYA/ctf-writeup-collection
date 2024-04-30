#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

int main(int argc, char **argv){
    char *buf;
    int fd, fd_shellcode;
    struct stat statbuf = { 0 };
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    fd = open(argv[1], O_RDWR);
    buf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    fd_shellcode = open(argv[2], O_RDONLY);
    fstat(fd_shellcode, &statbuf);
    read(fd_shellcode, buf+1, statbuf.st_size);
    close(fd);
    close(fd_shellcode);
}