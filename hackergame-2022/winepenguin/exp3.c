#include <stdio.h>
#include <unistd.h>

int main() {
    execve("\\\\?\\unix\\readflag", 0, 0);
    return 0;
}
