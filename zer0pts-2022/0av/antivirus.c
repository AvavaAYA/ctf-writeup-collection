#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/fanotify.h>
#include <unistd.h>

static int scanfile(int fd) {
  char path[PATH_MAX];
  ssize_t path_len;
  char procfd_path[PATH_MAX];
  char buf[0x10];

  if (read(fd, buf, 7) != 7)
    return 0;

  if (memcmp(buf, "zer0pts", 7))
    return 0;

  /* Malware detected! */
  snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d", fd);
  if ((path_len = readlink(procfd_path, path, sizeof(path) - 1)) == -1) {
    perror("readlink");
    exit(EXIT_FAILURE);
  }
  path[path_len] = '\0';
  unlink(path);

  return 1;
}

static void handle_events(int fd) {
  const struct fanotify_event_metadata *metadata;
  struct fanotify_event_metadata buf[200];
  ssize_t len;
  struct fanotify_response response;

  for (;;) {
    /* Check fanotify events */
    len = read(fd, buf, sizeof(buf));
    if (len == -1 && errno != EAGAIN) {
      perror("read");
      exit(EXIT_FAILURE);
    }

    if (len <= 0)
      break;

    metadata = buf;

    while (FAN_EVENT_OK(metadata, len)) {
      if (metadata->vers != FANOTIFY_METADATA_VERSION) {
        fputs("Mismatch of fanotify metadata version.\n", stderr);
        exit(EXIT_FAILURE);
      }

      if ((metadata->fd >= 0) && (metadata->mask & FAN_OPEN_PERM)) {
        /* New access request */
        if (scanfile(metadata->fd)) {
          /* Malware detected! */
          response.response = FAN_DENY;
        } else {
          /* Clean :) */
          response.response = FAN_ALLOW;
        }

        response.fd = metadata->fd;
        write(fd, &response, sizeof(response));
        close(metadata->fd);
      }

      metadata = FAN_EVENT_NEXT(metadata, len);
    }
  }
}

int main(void) {
  int fd;

  /* Setup fanotify */
  fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY);
  if (fd == -1) {
    perror("fanotify_init");
    exit(EXIT_FAILURE);
  }

  /* Monitor every file under root directory */
  if (fanotify_mark(fd,
                    FAN_MARK_ADD | FAN_MARK_MOUNT,
                    FAN_OPEN_PERM, AT_FDCWD, "/") == -1) {
    perror("fanotify_mark");
    exit(EXIT_FAILURE);
  }

  for (;;) {
    handle_events(fd);
  }

  exit(EXIT_SUCCESS);
}
