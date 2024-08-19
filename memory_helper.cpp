#include "memory_helper.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define MHELPER_ERROR(fmt, ...) fprintf(stderr, "%lu [%s:%d:%s] " fmt "\n", \
        (unsigned long)pthread_self(), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

namespace memory_helper {

void *AllocateLocalMemory(size_t size, size_t alignment) {
    size_t real_allocate_size = size + alignment + sizeof(unsigned int);

    void *real_pointer = malloc(real_allocate_size);

    if(!real_pointer) {
        MHELPER_ERROR("call malloc failed, size=%lu", real_allocate_size);
        return nullptr;
    }

    using UINTPTR = unsigned long;

    UINTPTR aligned_pointer = (UINTPTR)real_pointer + sizeof(unsigned int);
    aligned_pointer = (aligned_pointer - 1u) / alignment * alignment + alignment;

    unsigned int real_offset = aligned_pointer - (UINTPTR)real_pointer;
    assert(real_offset + (UINTPTR)real_pointer == aligned_pointer);

    memcpy( (void *)(aligned_pointer - sizeof(unsigned int)), &real_offset, sizeof(real_offset) );

    return (void *)aligned_pointer;
}

void FreeLocalMemory(void *p) {
    using UINTPTR = unsigned long;

    UINTPTR aligned_pointer = (UINTPTR)p;
    unsigned int real_offset;

    memcpy( &real_offset, (void *)(aligned_pointer - sizeof(unsigned int)), sizeof(real_offset) );

    void *real_pointer = (void *)(aligned_pointer - real_offset);
    free(real_pointer);
}

template<typename Function>
class Defer {
public:
    Defer(Function f) : m_f(f) {
    }

    ~Defer() {
        m_f();
    }
private:
    Function m_f;
};

void *AttachSharedMemory(const char *name, size_t size, std::function<bool (void *)> locked_callback) {
    int fd = shm_open(name, O_CREAT | O_RDWR, 0666);

    if(fd == -1) {
        MHELPER_ERROR("call shm_open failed, name=%s, errcode=%d", name, errno);
        return nullptr;
    }
    Defer<std::function<void()>> defer_close([fd]() {
            close(fd);
            });

    int retcode = flock(fd, LOCK_EX);
    if(retcode != 0) {
        MHELPER_ERROR("call flock failed, name=%s, errcode=%d", name, errno);
        return nullptr;
    }
    Defer<std::function<void()>> defer_unlock([fd]() {
            flock(fd, LOCK_UN);
            });

    struct stat statbuf;

    retcode = fstat(fd, &statbuf);
    if(retcode != 0) {
        MHELPER_ERROR("call fstat failed, name=%s, errcode=%d", name, errno);
        return nullptr;
    }

    if(statbuf.st_size != 0 && (size_t)statbuf.st_size != size) {
        MHELPER_ERROR("shared memory size is NOT match, name=%s, size=%lu, expected=%lu",
                name, statbuf.st_size, size);
        return nullptr;
    }

    if(statbuf.st_size == 0) {
        retcode = ftruncate(fd, size);
        if(retcode != 0) {
            MHELPER_ERROR("call ftruncate failed, name=%s, errcode=%d", name, errno);
            return nullptr;
        }
    }

    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(ptr == MAP_FAILED) {
        MHELPER_ERROR("call mmap failed, name=%s, errcode=%d", name, errno);
        return nullptr;
    }

    if(!locked_callback(ptr)) {
        return nullptr;
    }

    return ptr;
}

void DetachSharedMemory(void *p, size_t size) {
    munmap(p, size);
}

}

#undef MHELPER_ERROR
