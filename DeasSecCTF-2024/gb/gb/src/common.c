#include "common.h"

void* Malloc(ssize_t size){
    void* ret = malloc(size);
    if(!ret){
        LOG(ERROR, "Malloc: Out of memory");
        exit(1);
    }
    return ret;
}

uint8_t* Mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset){
    uint8_t* ret = mmap(addr, length, prot, flags, fd, offset);
    if(ret == MAP_FAILED){
        LOG(ERROR, "Mmap: Out of memory");
        LOGF(ERROR, "addr: %p\nlength: 0x%lx", addr, length);
        exit(1);
    }
    return ret;
}
