#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mount.h>

int main(int argc, char **argv, char **envp) {
  int fd;

  if (unshare(CLONE_NEWNS | CLONE_NEWUSER)) {
    perror("unshare");
    return 1;
  }
}
