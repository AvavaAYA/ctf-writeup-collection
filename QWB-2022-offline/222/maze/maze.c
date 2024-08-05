#include <stdio.h>
#include <string.h>

void recur(int l, int w, int index, char record[][105], char c[][105],
           char *path) {
  if (record[l][w] == 1) {
    return;
  }
  record[l][w] = 1;

  if (l == 100 && w == 99) {
    printf("%s", path);
  }

  if (c[l + 1][w] != '#' && l + 1 <= 100) {
    path[index] = 'd';
    recur(l + 1, w, index + 1, record, c, path);
  }

  if (c[l - 1][w] != '#' && l - 1 >= 0) {
    path[index] = 'w';
    recur(l - 1, w, index + 1, record, c, path);
  }

  if (c[l][w + 1] != '#' && w + 1 <= 100) {
    path[index] = 's';
    recur(l, w + 1, index + 1, record, c, path);
  }

  if (c[l][w - 1] != '#' && w - 1 >= 0) {
    path[index] = 'a';
    recur(l, w - 1, index + 1, record, c, path);
  }

  return;
}

int main(void) {
  char c[105][105];
  char record[105][105];
  char path[10005];

  memset(c, 0, sizeof(c));
  memset(record, 0, sizeof(record));
  memset(path, 0, sizeof(path));

  FILE *f = fopen("/tmp/maze", "r");

  for (int i = 0; i <= 100; i++) {
    fscanf(f, "%s", c[i]);
  }

  recur(0, 1, 0, record, c, path);

  return 0;
}
