#ifndef __MEMORY_HELPER_H__
#define __MEMORY_HELPER_H__

#include <stddef.h>

#include <functional>

namespace memory_helper {

void *AllocateLocalMemory(size_t size, size_t alignment);

void FreeLocalMemory(void *p);

void *AttachSharedMemory(const char *name, size_t size, std::function<bool (void *)> locked_callback);

void DetachSharedMemory(void *p, size_t size);

}



#endif
