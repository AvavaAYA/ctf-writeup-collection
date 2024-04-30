#include <stdio.h>
#include <stdlib.h>

int main() {
  char buf[0x40];
  open("/flag", 2);
  read(3, buf, 0x40);
  write(1, buf, 0x40);

  return 0;
}
