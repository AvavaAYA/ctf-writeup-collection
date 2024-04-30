#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  char buf[0x100];
  size_t *v0 = (size_t *)buf;
  double *v1 = (double *)buf;
  while (1) {
    gets(buf);
    /* scanf("%lf", v1); */
    printf("0x%lx\n", v0);
    printf("%lf\n", *v1);
  }
}
