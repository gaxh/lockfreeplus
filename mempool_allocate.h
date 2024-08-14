#ifndef __MEMPOOL_ALLOCATE_H__
#define __MEMPOOL_ALLOCATE_H__

#include <atomic>
#include <type_traits>

#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define MALLOCATE_ERROR(fmt, ...) fprintf(stderr, "%lu [%s:%d:%s] " fmt "\n", \
        (unsigned long)pthread_self(), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

// macro to enable memory check: MALLOCATE_MEM_CHECK

namespace mempool_allocate {

struct Version {
    size_t __value__;
};

struct Index {
    size_t __value__;
};

struct alignas(sizeof(Version) + sizeof(Index)) VersionedIndex {
    Version __version__;
    Index __index__;
};

inline
VersionedIndex MakeVersionedIndex(Index index, Version version) {
    return (VersionedIndex) { version, index };
}

inline
Index GetIndex(VersionedIndex &vindex) {
    return vindex.__index__;
}

inline
Version NextVersion(VersionedIndex &vindex) {
    return (Version){ vindex.__version__.__value__ + 1u };
}

template<typename T>
T *AccessByIndex(T* array, Index index) {
    return &array[index.__value__];
}

template<typename T>
T *AccessByIndex(T *array, size_t array_capacity, Index index) {
    return index.__value__ < array_capacity ? &array[index.__value__] : nullptr;
}

template<typename T>
Index GetArrayIndex(T *array, T *object) {
    return (Index) { (size_t)(object - array) };
}

static constexpr Index null_index = { (size_t)-1 };

static constexpr Version zero_version = { 0 };

inline
bool IsNullIndex(Index index) {
    return index.__value__ == null_index.__value__;
}

inline
bool IsSameIndex(Index x, Index y) {
    return x.__value__ == y.__value__;
}

struct MemoryHeader {
    std::atomic<VersionedIndex> stack_top;
};

template<typename ElementType, typename CustomHeader = int>
class MempoolAllocate {
public:

    bool Init(size_t capacity, void *memory, size_t memory_size) {
        size_t required_alignment = QueryMinimalMemoryAlignment();
        if( (size_t)memory % required_alignment != 0 ) {
            MALLOCATE_ERROR("memory is not aligned well, memory=%p, required_alignment=%lu",
                    memory, required_alignment);
            return false;
        }

        size_t required_memory_size = QueryMinimalMemorySize(capacity);
        if( memory_size < required_memory_size ) {
            MALLOCATE_ERROR("memory size is NOT enough, size=%lu, required_size=%lu",
                    memory_size, required_memory_size);
            return false;
        }

        m_capacity = capacity;
        m_memory = memory;
        m_memory_size = memory_size;
        m_memory_layout = (MemoryLayout *)memory;

        return true;
    }

    void Setup() {
        m_memory_layout->header.stack_top.store(MakeVersionedIndex(null_index, zero_version),
                std::memory_order_relaxed);

        for(size_t i = 0; i < m_capacity; ++i) {
            ElementSlot *eslot = &m_memory_layout->elem_slots[i];

#ifdef MALLOCATE_MEM_CHECK
            eslot->dogtag.store(ElementSlotDogtag::DEALLOCATED, std::memory_order_relaxed);
#endif

            StackPush(eslot);
        }
    }

    template<typename Function>
    void ForeachElementUnsafe(Function f) {
        for(size_t i = 0; i < m_capacity; ++i) {
            ElementSlot *eslot = &m_memory_layout->elem_slots[i];

            f(QueryElementType(eslot));
        }
    }

    void Destroy() {
        // nothing to free
    }

    ElementType *Acquire() {
        ElementSlot *eslot = StackPop();

        if(!eslot) {
            return nullptr;
        }

#ifdef MALLOCATE_MEM_CHECK
        {
            ElementSlotDogtag old_dogtag = eslot->dogtag.exchange(
                    ElementSlotDogtag::ALLOCATED, std::memory_order_relaxed);
            if(old_dogtag != ElementSlotDogtag::DEALLOCATED) {
                MALLOCATE_ERROR("eslot old dogtag is INVALID, expected=%u, old=%u",
                        (unsigned)ElementSlotDogtag::DEALLOCATED, (unsigned)old_dogtag);
                assert(0);
            }
        }
#endif

        return QueryElementType(eslot);
    }

    void Release(ElementType *p) {
        if(!p) {
            return;
        }

        ElementSlot *eslot = QueryElementSlot(p);

#ifdef MALLOCATE_MEM_CHECK
        {
            ElementSlotDogtag old_dogtag = eslot->dogtag.exchange(
                    ElementSlotDogtag::DEALLOCATED, std::memory_order_relaxed);
            if(old_dogtag != ElementSlotDogtag::ALLOCATED) {
                MALLOCATE_ERROR("eslot old dogtag is INVALID, expected=%u, old=%u",
                        (unsigned)ElementSlotDogtag::ALLOCATED, (unsigned)old_dogtag);
                assert(0);
            }
        }
#endif

        StackPush(eslot);
    }

    Index QueryIndexOfPointer(ElementType *p) {
        ElementSlot *eslot = QueryElementSlot(p);

        return GetArrayIndex<ElementSlot>(m_memory_layout->elem_slots, eslot);
    }

    ElementType *QueryPointerByIndex(Index index) {
        ElementSlot *eslot = AccessByIndex<ElementSlot>(m_memory_layout->elem_slots, m_capacity, index);
        return eslot ? QueryElementType(eslot) : nullptr;
    }

    size_t QueryMinimalMemoryAlignment() const {
        return alignof(MemoryLayout);
    }

    size_t QueryMinimalMemorySize(size_t capacity) const {
        return sizeof(MemoryLayout) + capacity * sizeof(ElementSlot);
    }

    void *AllocateLocalMemory(size_t capacity) const {
        size_t real_allocate_size = QueryMinimalMemorySize(capacity);
        size_t alignment = QueryMinimalMemoryAlignment();
        real_allocate_size += alignment;
        real_allocate_size += sizeof(unsigned int); // record "real offset" to "real pointer"

        void *real_pointer = malloc(real_allocate_size);

        if(!real_pointer) {
            MALLOCATE_ERROR("call malloc() failed, size=%lu", real_allocate_size);
            return nullptr;
        }

        UINTPTR aligned_pointer = (UINTPTR)real_pointer + sizeof(unsigned int);
        aligned_pointer = (aligned_pointer - 1u) / alignment * alignment + alignment;

        unsigned int real_offset = aligned_pointer - (UINTPTR)real_pointer;
        assert(real_offset + (UINTPTR)real_pointer == aligned_pointer);

        memcpy( (void *)(aligned_pointer - sizeof(unsigned int)), &real_offset, sizeof(real_offset) );
        return (void *)aligned_pointer;
    }

    void FreeLocalMemory(void *p) const {
        UINTPTR aligned_pointer = (UINTPTR)p;
        unsigned int real_offset;

        memcpy( &real_offset, (void *)(aligned_pointer - sizeof(unsigned int)), sizeof(real_offset) );

        void *real_pointer = (void *)(aligned_pointer - real_offset);
        free(real_pointer);
    }

    CustomHeader *AccessCustomHeader() {
        return &m_memory_layout->custom_header;
    }

private:

    struct ElementSlot;

    void StackPush(ElementSlot *eslot) {
        VersionedIndex old_stack_top = m_memory_layout->header.stack_top.
            load(std::memory_order_acquire);

        for(;;) {
            eslot->next_index = GetIndex(old_stack_top);

            VersionedIndex new_stack_top = MakeVersionedIndex( GetArrayIndex<ElementSlot>(
                        m_memory_layout->elem_slots, eslot), NextVersion(old_stack_top) );

            if(m_memory_layout->header.stack_top.compare_exchange_strong(old_stack_top,
                        new_stack_top, std::memory_order_seq_cst, std::memory_order_acquire)) {
                return;
            }
        }
    }

    ElementSlot *StackPop() {
        VersionedIndex old_stack_top = m_memory_layout->header.stack_top.
            load(std::memory_order_acquire);

        for(;;) {
            Index old_stack_top_index = GetIndex(old_stack_top);

            if(IsNullIndex(old_stack_top_index)) {
                // stack is empty
                return nullptr;
            }

            ElementSlot *eslot = AccessByIndex<ElementSlot>(
                    m_memory_layout->elem_slots, old_stack_top_index);

            VersionedIndex new_stack_top = MakeVersionedIndex( eslot->next_index,
                    NextVersion(old_stack_top) );

            if(m_memory_layout->header.stack_top.compare_exchange_strong(old_stack_top,
                        new_stack_top, std::memory_order_seq_cst, std::memory_order_acquire)) {
                return eslot;
            }
        }
    }

    ElementSlot *QueryElementSlot(ElementType *p) {
        return (ElementSlot *)( (UINTPTR)p - (UINTPTR)offsetof(ElementSlot, buffer) );
    }

    ElementType *QueryElementType(ElementSlot *p) {
        return (ElementType *)p->buffer;
    }

private:

    using UINTPTR = unsigned long;

#ifdef MALLOCATE_MEM_CHECK
    enum class ElementSlotDogtag : unsigned {
        ALLOCATED = 0x8765CDEF,
        DEALLOCATED = 0xFEDC5678,
    };
#endif

    struct ElementSlot {
#ifdef MALLOCATE_MEM_CHECK
        std::atomic<ElementSlotDogtag> dogtag;
#endif
        alignas(alignof(ElementType)) char buffer[sizeof(ElementType)];
        Index next_index;
    };

    struct MemoryHeader {
        alignas(64) std::atomic<VersionedIndex> stack_top;
    };

    struct MemoryLayout {
        MemoryHeader header;
        CustomHeader custom_header;
        ElementSlot elem_slots[0];
    };

    static_assert(std::is_trivial<MemoryLayout>::value, "struct MemoryLayout is NOT trivial");

    MemoryLayout *m_memory_layout = nullptr;
    size_t m_capacity = 0;

    void *m_memory = nullptr;
    size_t m_memory_size = 0;
};

}

#undef MALLOCATE_MEM_CHECK

#endif
