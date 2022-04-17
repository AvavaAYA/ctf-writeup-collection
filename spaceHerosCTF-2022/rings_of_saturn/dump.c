#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#if DEBUG
#include "hexdump.h"
#endif // DEBUG

#define ROUNDUP(x, y) (((x) + (y)-1) & ~(y - 1))
#define ROUNDDOWN(x, y) (ROUNDUP(x, y) - y)
#define BUF_ENT_MIN_SIZE 1000
#define BUF_ENT_MAX_SIZE 3000
#define BUF_ENT_ALIGN 16
#define RINGBUF_LINK(rb, ent)                                                          \
    {                                                                                  \
        if (rb->head == NULL) {                                                        \
            rb->head = ent;                                                            \
            rb->tail = ent;                                                            \
            ent->next = ent;                                                           \
            rb->write_head = ent;                                                      \
        } else {                                                                       \
            rb->tail->next = ent;                                                      \
            rb->tail = ent;                                                            \
            ent->next = rb->head;                                                      \
        }                                                                              \
    }
#define RINGBUF_UNLINK(rb, idx, ent)                                                   \
    {                                                                                  \
        if (rb->head == rb->tail && rb->head == NULL) {                                \
        } else if (rb->head == rb->tail) {                                             \
            ent = rb->head;                                                            \
            rb->head = NULL;                                                           \
            rb->tail = NULL;                                                           \
        } else {                                                                       \
            size_t i = 0;                                                              \
            struct buf_ent *last = NULL;                                               \
            ent = rb->head;                                                            \
                                                                                       \
            while (i < idx) {                                                          \
                last = ent;                                                            \
                ent = ent->next;                                                       \
                i++;                                                                   \
            }                                                                          \
                                                                                       \
            last->next = ent->next;                                                    \
                                                                                       \
            if (ent == rb->head) {                                                     \
                rb->head = ent->next;                                                  \
            } else if (ent == rb->tail) {                                              \
                rb->tail = last;                                                       \
            }                                                                          \
        }                                                                              \
    }

/* Prototypes */

struct buf_ent {
    char *write_head;
    struct buf_ent *next;
    size_t size;
    char data[];
};

struct ringbuf {
    struct buf_ent *head;
    struct buf_ent *tail;
    struct buf_ent *write_head;
    size_t size;
};

struct menu_opt {
    const char *opt;
    void (*func)(struct ringbuf *);
};

static void ringbuf_add(struct ringbuf *);
static void ringbuf_remove(struct ringbuf *);
static void ringbuf_print(struct ringbuf *);
static void ringbuf_write(struct ringbuf *);

#if DEBUG
static void ringbuf_debug(struct ringbuf *);
#endif // DEBUG

static struct ringbuf *ringbuf_init(size_t size);
static size_t read_size_t(void);
static void exit_wrapper(struct ringbuf *rb) { 
    fprintf(stderr, "You went around the rings %d times...score: %d", 0, 0); 
    exit(EXIT_FAILURE);
}

const struct menu_opt menu[] = {
    {"add", ringbuf_add},     {"remove", ringbuf_remove}, {"print", ringbuf_print},
    {"write", ringbuf_write}, {"quit", exit_wrapper},
#if DEBUG
    {"debug", ringbuf_debug},
#endif // DEBUG
};

static void ringbuf_add(struct ringbuf *rb) {
    printf("What size should the buffer entry be? (>= %d)\n> ", BUF_ENT_MIN_SIZE);
    const size_t sz = read_size_t();
    if (sz < BUF_ENT_MIN_SIZE || sz > BUF_ENT_MAX_SIZE) {
        printf("Bad size!\n");
        return;
    }
    struct buf_ent *const ent = malloc(sizeof(struct buf_ent) + sz);
    ent->size = sz;
    ent->write_head = ent->data;
    RINGBUF_LINK(rb, ent);
    rb->size += ent->size;
}

static void ringbuf_remove(struct ringbuf *rb) {
    if (rb->head == rb->tail) {
        printf("Can't remove the only buffer entry!\n");
        return;
    }
    struct buf_ent *ent = NULL;
    printf("Which buffer segment would you like to delete?\n> ");
    const size_t idx = read_size_t();
    RINGBUF_UNLINK(rb, idx, ent);
    if (ent) {
        rb->size -= ent->size;
        if (rb->write_head == ent) {
            rb->write_head = ent->next;
        }
        free(ent);
    }
}

static void ringbuf_print(struct ringbuf *rb) {
    struct buf_ent *ent = rb->head;
    if (rb->head == NULL) {
        printf("Ring buffer is empty!\n");
        return;
    }
    do {
        printf("%s", ent->data);
        ent = ent->next;
    } while (ent != rb->head);
}

static void ringbuf_write(struct ringbuf *rb) {
    printf("How much would you like to write? It can be as much as you want, but if it "
           "is more than the buffer size, some data will be overwritten.\n> ");
    size_t sz = read_size_t();
    size_t written = 0;
    if (rb->head == NULL) {
        printf("You need at least one buffer entry to write!\n");
        return;
    }
    while (written < sz) {
        size_t writable =
            rb->write_head->size - (rb->write_head->write_head - rb->write_head->data);
        size_t to_write = writable > (sz - written) ? (sz - written) : writable;

        printf("\n> ");
        if ((to_write = read(STDIN_FILENO, rb->write_head->write_head, to_write)) < 0) {
            printf("Error reading from stdin: %s!\n", strerror(errno));
            exit_wrapper(NULL);
        }

        rb->write_head->write_head += to_write;
        if (rb->write_head->write_head >= rb->write_head->data + rb->write_head->size) {
            rb->write_head->write_head = rb->write_head->data;
            rb->write_head = rb->write_head->next;
        }
        written += to_write;
    }
}

static struct ringbuf *ringbuf_init(size_t size) {
    struct ringbuf *rb = calloc(1, sizeof(struct ringbuf));
    size_t allocated = 0;
    size_t idx = 0;
    while (allocated < size - BUF_ENT_MIN_SIZE) {
        printf("What size should the %zuth buffer entry be? (>= %d)\n> ", idx++,
               BUF_ENT_MIN_SIZE);
        size_t sz = read_size_t();

        if (sz < BUF_ENT_MIN_SIZE || sz > BUF_ENT_MAX_SIZE) {
            printf("Bad size!\n");
            continue;
        }

        struct buf_ent *ent = calloc(sizeof(struct buf_ent) + sz, 1);
        ent->size = sz;
        ent->write_head = ent->data;
        RINGBUF_LINK(rb, ent);
        allocated += ent->size;
    }
    size_t remainder = size - allocated;
    struct buf_ent *ent =
        calloc(sizeof(struct buf_ent) + ROUNDDOWN(remainder, BUF_ENT_ALIGN), 1);
    ent->size = remainder;
    ent->write_head = ent->data;
    RINGBUF_LINK(rb, ent);
    allocated += ent->size;
    rb->size = allocated;
    rb->write_head = rb->head;
    return rb;
}

static size_t read_size_t(void) {
    size_t size;
    while (scanf("%zu", &size) == EOF) {
        printf("Bad input! Integer please!\n");
        while (getchar() != '\n')
            ;
        printf("> ");
    }
    while (getchar() != '\n')
        ;
    return size;
}

#if DEBUG

static void buf_ent_debug(struct buf_ent *ent, size_t idx) {
    printf("buf_ent [%zu]: %p\n", idx, (void *)ent);
    printf("\tsize: %zu\n", ent->size);
    printf("\tmalloc_usable_size: %zu\n", malloc_usable_size(ent));
    printf("\tdata: %p\n", (void *)ent->data);
    printf("\tnext: %p\n", (void *)ent->next);
    printf("\twrite_head: %p\n", (void *)ent->write_head);
    hexdump_w(ent->data, ent->size, _HEXDUMP_W, _HEXDUMP_S, "\t");
}

static void ringbuf_debug(struct ringbuf *rb) {
    printf("Ring buffer size: %zu\n", rb->size);
    printf("Head: %p\n", (void *)rb->head);
    printf("Tail: %p\n", (void *)rb->tail);
    printf("Write head: %p\n", (void *)rb->write_head);
    printf("\n");
    struct buf_ent *ent = rb->head;
    if (rb->head == NULL) {
        printf("Ring buffer is empty!\n");
        return;
    }
    size_t idx = 0;
    do {
        buf_ent_debug(ent, idx++);
        ent = ent->next;
    } while (ent != rb->head);
}
#endif

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    printf("Ok...I'll give you a one_gadget lol %p\n", (void *)(((size_t)&exit) + 0xc195));

    size_t size = 0;
    do {
        printf("How large would you like your buffer to be, in bytes?\nMust be (>= "
               "%d)\n> ",
               BUF_ENT_MIN_SIZE);
        size = read_size_t();
        if (size < BUF_ENT_MIN_SIZE) {
            printf("Bad size!\n");
        }
    } while (size < BUF_ENT_MIN_SIZE);

    struct ringbuf *buf = ringbuf_init(size);

    while (1) {
        printf("\n");
        for (size_t i = 0; i < sizeof(menu) / sizeof(struct menu_opt); i++)
            printf("%zu. %s\n", i, menu[i].opt);
        printf("\n");
        printf("What would you like to do?\n> ");
        size_t choice = read_size_t();
        if (choice >= sizeof(menu) / sizeof(struct menu_opt)) {
            printf("Invalid choice.\n");
            continue;
        }
        menu[choice].func(buf);
    }
}