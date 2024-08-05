#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FLAG_PREFIX "d3ctf{"
#define FLAG_PREFIX_LENGTH (sizeof(FLAG_PREFIX) - 1)
#define FLAG_SUFFIX "}"
#define FLAG_SUFFIX_LENGTH (sizeof(FLAG_SUFFIX) - 1)
#define LIBC_NAME "libc"

char maps[0x1000], flag[0x100];
uint64_t libc_code_addr_start, libc_code_addr_end;

void write_mem(uint64_t addr, uint8_t byte) {
    int fd = open("/proc/self/mem", O_RDWR);
    lseek(fd, addr, SEEK_SET);
    write(fd, &byte, 1);
    close(fd);
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    FILE *maps_stream = fopen("/proc/self/maps", "r");

    int count = 1;
    char *line = NULL;
    uint64_t len = 0;
    uint64_t addr_start = 0, addr_end = 0, offset = 0, major_id = 0,
             minor_id = 0, inode_id = 0;
    char mode[0x10], file_path[0x100];
    memset(mode, 0, sizeof(mode));
    memset(file_path, 0, sizeof(file_path));

    while (getline(&line, &len, maps_stream) != -1) {
        sscanf(line, "%lx-%lx%s%lx%lu:%lu%lu%s", &addr_start, &addr_end, mode,
               &offset, &major_id, &minor_id, &inode_id, file_path);
        if (count == 10) {
            libc_code_addr_start = addr_start;
            libc_code_addr_end = addr_end;
            break;
        }
        count++;
    }

    if (line) {
        printf("%s", line);
        free(line);
    }
    fclose(maps_stream);

    int fd = open("/flag", O_RDONLY);
    read(fd, flag, 0x100);
    close(fd);
}

int main(int argc, char *argv[]) {
    init();

    uint64_t addr = 0;
    uint offset = 0;

    printf("flag: " FLAG_PREFIX "[a-f0-9]{%lu}" FLAG_SUFFIX "\n",
           strlen(flag) - FLAG_PREFIX_LENGTH - FLAG_SUFFIX_LENGTH);

    while (scanf("%lu%u", &addr, &offset) == 2) {
        if (!(libc_code_addr_start <= addr && addr < libc_code_addr_end) ||
                !(offset >= FLAG_PREFIX_LENGTH &&
                  offset < strlen(flag) - FLAG_SUFFIX_LENGTH))
            break;

        write_mem(addr, flag[offset]);
    }

    return 0;
}
