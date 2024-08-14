#ifndef __LOCAL_QUEUE_H__
#define __LOCAL_QUEUE_H__

#include "atomic_wait.h"
#include "mempool_allocate.h"

namespace local_queue {

namespace MA = mempool_allocate;
namespace AW = atomic_wait;

template<typename ElementType> class LocalQueue {
public:
    LocalQueue(size_t capacity) : m_capacity(capacity) {
        size_t allocate_capacity = capacity + 1u;
        assert(allocate_capacity > capacity);

        size_t memory_size = m_allocate.QueryMinimalMemorySize(allocate_capacity);
        m_local_memory = m_allocate.AllocateLocalMemory(allocate_capacity);
        assert(m_local_memory);

        bool init_ok = m_allocate.Init(allocate_capacity, m_local_memory, memory_size);
        assert(init_ok);

        m_allocate.Setup();

        m_allocate.ForeachElementUnsafe([](ElementLinkedNode *node) {
                node->next.store(MA::MakeVersionedIndex(MA::null_index, MA::zero_version),
                        std::memory_order_relaxed);
                node->lifetime.store(ElementLifetime::RECYCLE,
                        std::memory_order_relaxed);
                });

        m_custom_header = m_allocate.AccessCustomHeader();

        m_custom_header->atomic_wait_ctx.Init();

        m_read = &m_custom_header->read;
        m_write = &m_custom_header->write;

        // allocate one pointer as "empty pointer"
        ElementLinkedNode *empty_node = m_allocate.Acquire();
        empty_node->lifetime.store(ElementLifetime::UNSET, std::memory_order_release);

        MA::Index elem_index = m_allocate.QueryIndexOfPointer(empty_node);

        m_read->store(MA::MakeVersionedIndex(
                    elem_index, MA::zero_version), std::memory_order_relaxed);
        m_write->store(MA::MakeVersionedIndex(
                    elem_index, MA::zero_version), std::memory_order_seq_cst);
    }

    ~LocalQueue() {

        // force clear all
        Clear([](ElementType *) {});

        // recycle "empty pointer"
        {
            MA::VersionedIndex read = m_read->load(std::memory_order_relaxed);
            MA::VersionedIndex write = m_write->load(std::memory_order_relaxed);

            assert(MA::IsSameIndex(MA::GetIndex(read), MA::GetIndex(write)));

            ElementLinkedNode *empty_node = m_allocate.QueryPointerByIndex(MA::GetIndex(read));
            m_allocate.Release(empty_node);
        }

        m_custom_header->atomic_wait_ctx.Destroy();

        m_allocate.Destroy();
        m_allocate.FreeLocalMemory(m_local_memory);
    }

    template<typename Function>
    bool Push(Function f) {
        ElementLinkedNode *elem_node = m_allocate.Acquire();

        if(!elem_node) {
            return false;
        }

        f((ElementType *)elem_node->buffer);

        MA::VersionedIndex elem_node_next = elem_node->next.load(std::memory_order_relaxed);
        elem_node->next.store(MakeVersionedIndex(MA::null_index,
                    MA::NextVersion(elem_node_next)), std::memory_order_relaxed);

        {
            ElementLifetime expected = ElementLifetime::RECYCLE;
            bool ok = elem_node->lifetime.compare_exchange_strong(expected, ElementLifetime::SET,
                    std::memory_order_relaxed);
            assert(ok);
        }

        MA::Index elem_node_index = m_allocate.QueryIndexOfPointer(elem_node);
        MA::VersionedIndex old_write;
        ElementLinkedNode *old_write_node;
        MA::VersionedIndex old_write_next;

        for(;;) {
            old_write = m_write->load(std::memory_order_relaxed);
            old_write_node = m_allocate.QueryPointerByIndex(GetIndex(old_write));
            old_write_next = old_write_node->next.load(std::memory_order_relaxed);

            if(MA::IsNullIndex( MA::GetIndex(old_write_next) )) {
                if( old_write_node->next.compare_exchange_strong(old_write_next,
                            MA::MakeVersionedIndex(elem_node_index, MA::NextVersion(old_write_next)),
                            std::memory_order_seq_cst, std::memory_order_relaxed) ) {
                    // old_write_node->next has been linked to elem_node
                    m_write->compare_exchange_strong(old_write, MA::MakeVersionedIndex(elem_node_index,
                                MA::NextVersion(old_write)),
                            std::memory_order_seq_cst, std::memory_order_relaxed);
                    break;
                }
            } else {
                // old_write->next is NOT nullptr
                // change of m_write is NOT complete
                m_write->compare_exchange_strong(old_write, MA::MakeVersionedIndex(
                            MA::GetIndex(old_write_next), MA::NextVersion(old_write)),
                        std::memory_order_seq_cst, std::memory_order_relaxed);
            }
        }

        return true;
    }

    template<typename Function>
    bool Pop(Function f) {

        MA::VersionedIndex old_read;
        MA::VersionedIndex old_read_next;
        ElementLinkedNode *old_read_node;
        MA::VersionedIndex old_write;

        for(;;) {
            old_write = m_write->load(std::memory_order_acquire);
            old_read = m_read->load(std::memory_order_relaxed);
            old_read_node = m_allocate.QueryPointerByIndex(MA::GetIndex(old_read));
            // load of old_read_next should happen after load of old_write
            old_read_next = old_read_node->next.load(std::memory_order_relaxed);
            
            if(!MA::IsNullIndex( MA::GetIndex(old_read_next) )) {
                if(!MA::IsSameIndex(MA::GetIndex(old_read), MA::GetIndex(old_write))) {
                    if( m_read->compare_exchange_strong(old_read, MA::MakeVersionedIndex(
                                    MA::GetIndex(old_read_next), MA::NextVersion(old_read)),
                                std::memory_order_seq_cst, std::memory_order_relaxed) ) {
                        break;
                    }
                } else {
                    // other Push() NOT complete
                    // help move m_write
                    m_write->compare_exchange_strong(old_write,
                            MA::MakeVersionedIndex( MA::GetIndex(old_read_next),
                                MA::NextVersion(old_write)),
                            std::memory_order_seq_cst, std::memory_order_relaxed);
                }
            } else {
                // queue is empty
                return false;
            }
        }

        {
            ElementLinkedNode *old_read_next_node = m_allocate.QueryPointerByIndex(MA::GetIndex(old_read_next));
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

            m_allocate.Release(old_read_node);
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

    struct ElementLinkedNode {
        alignas(alignof(ElementType)) char buffer[sizeof(ElementType)];
        std::atomic<MA::VersionedIndex> next;
        std::atomic<ElementLifetime> lifetime;
    };

    struct CustomMemoryHeader {
        alignas(64) std::atomic<MA::VersionedIndex> read;
        alignas(64) std::atomic<MA::VersionedIndex> write;

        AW::AtomicWaitContext<256, false> atomic_wait_ctx;
    };

    MA::MempoolAllocate<ElementLinkedNode, CustomMemoryHeader> m_allocate;
    void *m_local_memory = nullptr;
    CustomMemoryHeader *m_custom_header = nullptr;
    std::atomic<MA::VersionedIndex> *m_read = nullptr;
    std::atomic<MA::VersionedIndex> *m_write = nullptr;
    size_t m_capacity;
};

}

#endif
