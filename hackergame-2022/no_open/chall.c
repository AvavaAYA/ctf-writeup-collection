// Just for testing
#include <stdio.h>
#include <string.h>

const char* flag_test = "flag{FAKE_FLAG}";

int main() {
    char buf[0x40];
    memset(buf, 0, 0x40);
    puts("INPUT: ");
    gets(buf);
    if (!strncmp(flag_test, buf, strlen(flag_test))) {
        puts(flag_test);
    }
    return 0;
}
