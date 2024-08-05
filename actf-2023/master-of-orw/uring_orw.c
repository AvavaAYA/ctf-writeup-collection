#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <liburing.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/prctl.h>

#define QUEUE_DEPTH 1

int main() {
    struct io_uring ring = {0};
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    int fd, ret;
    char buffer[4096] = {0};

    // 初始化 io_uring
    if (io_uring_queue_init(QUEUE_DEPTH, &ring, 0) < 0) {
        perror("io_uring_queue_init");
        return 1;
    }

    // 准备打开操作
    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        fprintf(stderr, "Failed to get SQE\n");
        return 1;
    }

    int dirfd = AT_FDCWD;  // 当前工作目录的文件描述符
    const char *pathname = "/flag";
    int flags = O_RDONLY;

    io_uring_prep_openat(sqe, dirfd, pathname, flags, 0);
    io_uring_sqe_set_data(sqe, NULL);

    // 提交请求
    ret = io_uring_submit(&ring);
    if (ret < 0) {
        perror("io_uring_submit");
        return 1;
    }

    // 等待完成
    ret = io_uring_wait_cqe(&ring, &cqe);
    if (ret < 0) {
        perror("io_uring_wait_cqe");
        return 1;
    }

    // 处理完成的请求
    if (cqe->res < 0) {
        fprintf(stderr, "Open error: %d\n", cqe->res);
        return 1;
    }

    fd = cqe->res;  // 获取打开的文件描述符

    // 准备读取操作
    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        fprintf(stderr, "Failed to get SQE\n");
        return 1;
    }

    io_uring_prep_read(sqe, fd, buffer, sizeof(buffer), 0);
    io_uring_sqe_set_data(sqe, NULL);

    // 提交请求
    ret = io_uring_submit(&ring);
    if (ret < 0) {
        perror("io_uring_submit");
        return 1;
    }

    // 等待完成
    ret = io_uring_wait_cqe(&ring, &cqe);
    if (ret < 0) {
        perror("io_uring_wait_cqe");
        return 1;
    }

    // 处理完成的请求
    if (cqe->res < 0) {
        fprintf(stderr, "Read error: %d\n", cqe->res);
        return 1;
    }

    // 准备写操作
    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        fprintf(stderr, "Failed to get SQE\n");
        return 1;
    }

    io_uring_prep_write(sqe, 1, buffer, strlen(buffer), 0);
    io_uring_sqe_set_data(sqe, NULL);

    // 提交请求
    ret = io_uring_submit(&ring);
    if (ret < 0) {
        perror("io_uring_submit");
        return 1;
    }

    // 等待完成
    ret = io_uring_wait_cqe(&ring, &cqe);
    if (ret < 0) {
        perror("io_uring_wait_cqe");
        return 1;
    }

    // 处理完成的请求
    if (cqe->res < 0) {
        fprintf(stderr, "Read error: %d\n", cqe->res);
        return 1;
    }

    // printf("Read %d bytes: %s\n", cqe->res, buffer);

    // 清理并关闭文件
    io_uring_cqe_seen(&ring, cqe);
    io_uring_queue_exit(&ring);
    close(fd);
    sleep(1);

    return 0;
}
