#ifndef __LOCAL_QUEUE_H__
#define __LOCAL_QUEUE_H__

#include "atomic_wait.h"
#include "mempool_allocate.h"

namespace local_queue {

template<typename ElementType, typename VersionedIndexClass =
    versioned_index::VersionedIndexCompressed>
class LocalQueue {
public:
    LocalQueue(size_t capacity) : m_capacity(capacity) {
        size_t allocate_capacity = capacity + 1u;
        assert(allocate_capacity > capacity);

        size_t memory_size = MA.QueryMinimalMemorySize(allocate_capacity);
        m_local_memory = MA.AllocateLocalMemory(allocate_capacity);
        assert(m_local_memory);

        bool init_ok = MA.Init(allocate_capacity, m_local_memory, memory_size);
        assert(init_ok);

        MA.Setup();

        MA.ForeachElementUnsafe([this](ElementLinkedNode *node) {
                node->next.store(MA.MakeVersionedIndex(MA.NullIndex(), MA.ZeroVersion()),
                        std::memory_order_relaxed);
                node->lifetime.store(ElementLifetime::RECYCLE,
                        std::memory_order_relaxed);
                });

        m_custom_header = MA.AccessCustomHeader();

        m_custom_header->atomic_wait_ctx.Init();

        m_read = &m_custom_header->read;
        m_write = &m_custom_header->write;

        // allocate one pointer as "empty pointer"
        ElementLinkedNode *empty_node = MA.Acquire();
        empty_node->lifetime.store(ElementLifetime::UNSET, std::memory_order_release);

        Index elem_index = MA.QueryIndexOfPointer(empty_node);

        m_read->store(MA.MakeVersionedIndex(
                    elem_index, MA.ZeroVersion()), std::memory_order_relaxed);
        m_write->store(MA.MakeVersionedIndex(
                    elem_index, MA.ZeroVersion()), std::memory_order_seq_cst);
    }

    ~LocalQueue() {

        // force clear all
        Clear([](ElementType *) {});

        // recycle "empty pointer"
        {
            VersionedIndex read = m_read->load(std::memory_order_relaxed);
            VersionedIndex write = m_write->load(std::memory_order_relaxed);

            assert(MA.IsSameIndex(MA.GetIndex(read), MA.GetIndex(write)));

            ElementLinkedNode *empty_node = MA.QueryPointerByIndex(MA.GetIndex(read));
            MA.Release(empty_node);
        }

        // m_custom_header->atomic_wait_ctx.DumpRefcount();
        m_custom_header->atomic_wait_ctx.Destroy();

        MA.Destroy();
        MA.FreeLocalMemory(m_local_memory);
    }

    template<typename Function>
    bool Push(Function f) {
        ElementLinkedNode *elem_node = MA.Acquire();

        if(!elem_node) {
            return false;
        }

        f((ElementType *)elem_node->buffer);

        VersionedIndex elem_node_next = elem_node->next.load(std::memory_order_relaxed);
        elem_node->next.store(MA.MakeVersionedIndex(MA.NullIndex(),
                    MA.NextVersion(elem_node_next)), std::memory_order_relaxed);

        {
            ElementLifetime expected = ElementLifetime::RECYCLE;
            bool ok = elem_node->lifetime.compare_exchange_strong(expected, ElementLifetime::SET,
                    std::memory_order_relaxed);
            assert(ok);
        }

        Index elem_node_index = MA.QueryIndexOfPointer(elem_node);
        VersionedIndex old_write;
        ElementLinkedNode *old_write_node;
        VersionedIndex old_write_next;

        for(;;) {
            old_write = m_write->load(std::memory_order_relaxed);
            old_write_node = MA.QueryPointerByIndex(MA.GetIndex(old_write));
            old_write_next = old_write_node->next.load(std::memory_order_relaxed);

            if(MA.IsNullIndex( MA.GetIndex(old_write_next) )) {
                if( old_write_node->next.compare_exchange_strong(old_write_next,
                            MA.MakeVersionedIndex(elem_node_index, MA.NextVersion(old_write_next)),
                            std::memory_order_seq_cst, std::memory_order_relaxed) ) {
                    // old_write_node->next has been linked to elem_node
                    m_write->compare_exchange_strong(old_write, MA.MakeVersionedIndex(elem_node_index,
                                MA.NextVersion(old_write)),
                            std::memory_order_seq_cst, std::memory_order_relaxed);
                    break;
                }
            } else {
                // old_write->next is NOT nullptr
                // change of m_write is NOT complete
                m_write->compare_exchange_strong(old_write, MA.MakeVersionedIndex(
                            MA.GetIndex(old_write_next), MA.NextVersion(old_write)),
                        std::memory_order_seq_cst, std::memory_order_relaxed);
            }
        }

        return true;
    }

    template<typename Function>
    bool Pop(Function f) {

        VersionedIndex old_read;
        VersionedIndex old_read_next;
        ElementLinkedNode *old_read_node;
        VersionedIndex old_write;

        for(;;) {
            old_write = m_write->load(std::memory_order_acquire);
            old_read = m_read->load(std::memory_order_relaxed);
            old_read_node = MA.QueryPointerByIndex(MA.GetIndex(old_read));
            // load of old_read_next should happen after load of old_write
            old_read_next = old_read_node->next.load(std::memory_order_relaxed);
            
            if(!MA.IsNullIndex( MA.GetIndex(old_read_next) )) {
                if(!MA.IsSameIndex(MA.GetIndex(old_read), MA.GetIndex(old_write))) {
                    if( m_read->compare_exchange_strong(old_read, MA.MakeVersionedIndex(
                                    MA.GetIndex(old_read_next), MA.NextVersion(old_read)),
                                std::memory_order_seq_cst, std::memory_order_relaxed) ) {
                        break;
                    }
                } else {
                    // other Push() NOT complete
                    // help move m_write
                    m_write->compare_exchange_strong(old_write,
                            MA.MakeVersionedIndex( MA.GetIndex(old_read_next),
                                MA.NextVersion(old_write)),
                            std::memory_order_seq_cst, std::memory_order_relaxed);
                }
            } else {
                // queue is empty
                return false;
            }
        }

        {
            ElementLinkedNode *old_read_next_node = MA.QueryPointerByIndex(MA.GetIndex(old_read_next));
            ElementLifetime expected = ElementLifetime::SET;

            bool ok = old_read_next_node->lifetime.compare_exchange_strong(expected, ElementLifetime::READ,
                    std::memory_order_acquire);
            assert(ok);

            f((ElementType *)old_read_next_node->buffer);

            old_read_next_node->lifetime.store(ElementLifetime::UNSET, std::memory_order_release);
            m_custom_header->atomic_wait_ctx.AtomicSignal(&old_read_next_node->lifetime);
        }

        // Release of old_read_node should happen after f( Element-of-old_read_node ) complete
        {
            for(;;) {
                ElementLifetime expected = ElementLifetime::UNSET;
                bool ok = old_read_node->lifetime.compare_exchange_strong(expected, ElementLifetime::RECYCLE, std::memory_order_acquire);

                if(ok) {
                    break;
                }

                // expected is old lifetime value
                // wait until value changed from expected to any other value
                m_custom_header->atomic_wait_ctx.AtomicWait(&old_read_node->lifetime, expected,
                        std::memory_order_acquire);
            }

            MA.Release(old_read_node);
        }

        return true;
    }

    template<typename Function>
    void Clear(Function f) {
        while(Pop(f));
    }

    size_t GetCapacity() const {
        return m_capacity;
    }

private:
    enum class ElementLifetime : unsigned {
        SET = 0,
        READ,
        UNSET,
        RECYCLE,
    };

    using VersionedIndex = typename VersionedIndexClass::VersionedIndex;
    using Index = typename VersionedIndexClass::Index;

    struct ElementLinkedNode {
        alignas(alignof(ElementType)) char buffer[sizeof(ElementType)];
        std::atomic<VersionedIndex> next;
        std::atomic<ElementLifetime> lifetime;
    };

    struct CustomMemoryHeader {
        alignas(64) std::atomic<VersionedIndex> read;
        alignas(64) std::atomic<VersionedIndex> write;

        atomic_wait::AtomicWaitContext<256, false> atomic_wait_ctx;
    };

    mempool_allocate::MempoolAllocate<ElementLinkedNode, CustomMemoryHeader, VersionedIndexClass> MA;
    void *m_local_memory = nullptr;
    CustomMemoryHeader *m_custom_header = nullptr;
    std::atomic<VersionedIndex> *m_read = nullptr;
    std::atomic<VersionedIndex> *m_write = nullptr;
    size_t m_capacity;
};

}

#endif
