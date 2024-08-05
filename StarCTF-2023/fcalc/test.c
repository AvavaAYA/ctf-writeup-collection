#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  size_t v0;
  double *v1 = (double *)&v0;
  while (1) {
    /* scanf("%lx", &v0); */
    scanf("%lf", v1);
    printf("0x%lx\n", v0);
    printf("%lf\n", *v1);
  }
}
