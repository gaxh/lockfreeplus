#ifndef __MEMPOOL_ALLOCATE_H__
#define __MEMPOOL_ALLOCATE_H__

#include "versioned_index.h"

#include <atomic>

#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <pthread.h>

#define MALLOCATE_ERROR(fmt, ...) fprintf(stderr, "%lu [%s:%d:%s] " fmt "\n", \
        (unsigned long)pthread_self(), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

// macro to enable memory check: MALLOCATE_MEM_CHECK

namespace mempool_allocate {

using namespace versioned_index;

template<typename ElementType, typename CustomHeader, typename VersionedIndexClass>
class MempoolAllocate {
public:
    using VersionedIndex = typename VersionedIndexClass::VersionedIndex;
    using Index = typename VersionedIndexClass::Index;
    using Version = typename VersionedIndexClass::Version;

    bool Init(size_t capacity, void *memory, size_t memory_size) {
        if(!m_vindex.Init(capacity)) {
            return false;
        }

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
        m_memory_layout->header.stack_top.store(m_vindex.MakeVersionedIndex(
                    m_vindex.NullIndex(), m_vindex.ZeroVersion()),
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
        m_vindex.Destroy();
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

        return m_vindex.GetArrayIndex(m_memory_layout->elem_slots, eslot);
    }

    ElementType *QueryPointerByIndex(Index index) {
        ElementSlot *eslot = m_vindex.AccessByIndex(m_memory_layout->elem_slots, m_capacity, index);
        return eslot ? QueryElementType(eslot) : nullptr;
    }

    size_t QueryMinimalMemoryAlignment() const {
        return alignof(MemoryLayout);
    }

    size_t QueryMinimalMemorySize(size_t capacity) const {
        return sizeof(MemoryLayout) + capacity * sizeof(ElementSlot);
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
            eslot->next_index = m_vindex.GetIndex(old_stack_top);

            VersionedIndex new_stack_top = m_vindex.MakeVersionedIndex( m_vindex.GetArrayIndex(
                        m_memory_layout->elem_slots, eslot), m_vindex.NextVersion(old_stack_top) );

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
            Index old_stack_top_index = m_vindex.GetIndex(old_stack_top);

            if(m_vindex.IsNullIndex(old_stack_top_index)) {
                // stack is empty
                return nullptr;
            }

            ElementSlot *eslot = m_vindex.AccessByIndex(
                    m_memory_layout->elem_slots, old_stack_top_index);

            VersionedIndex new_stack_top = m_vindex.MakeVersionedIndex( eslot->next_index,
                    m_vindex.NextVersion(old_stack_top) );

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

public:

    bool IsSameIndex(Index x, Index y) {
        return m_vindex.IsSameIndex(x, y);
    }

    Index GetIndex(VersionedIndex vindex) {
        return m_vindex.GetIndex(vindex);
    }


    VersionedIndex MakeVersionedIndex(Index index, Version version) {
        return m_vindex.MakeVersionedIndex(index, version);
    }

    Index NullIndex() {
        return m_vindex.NullIndex();
    }

    Version ZeroVersion() {
        return m_vindex.ZeroVersion();
    }

    Version NextVersion(VersionedIndex vindex) {
        return m_vindex.NextVersion(vindex);
    }

    bool IsNullIndex(Index index) {
        return m_vindex.IsNullIndex(index);
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
        alignas(alignof(ElementType)) char buffer[sizeof(ElementType)];
        Index next_index;
#ifdef MALLOCATE_MEM_CHECK
        std::atomic<ElementSlotDogtag> dogtag;
#endif

    };

    struct MemoryHeader {
        alignas(64) std::atomic<VersionedIndex> stack_top;
    };

    struct MemoryLayout {
        CustomHeader custom_header;
        MemoryHeader header;
        ElementSlot elem_slots[0];
    };

    static_assert(std::is_trivial<MemoryLayout>::value, "struct MemoryLayout is NOT trivial");

    MemoryLayout *m_memory_layout = nullptr;
    size_t m_capacity = 0;

    void *m_memory = nullptr;
    size_t m_memory_size = 0;

    VersionedIndexClass m_vindex;
};

}

#undef MALLOCATE_ERROR

#endif
