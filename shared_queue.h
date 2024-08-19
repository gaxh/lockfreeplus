#ifndef __SHARED_QUEUE_H__
#define __SHARED_QUEUE_H__

#include "atomic_wait.h"
#include "mempool_allocate.h"
#include "memory_helper.h"

#define SQUEUE_ERROR(fmt, ...) fprintf(stderr, "%lu [%s:%d:%s] " fmt "\n", \
        (unsigned long)pthread_self(), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

namespace shared_queue {

template<typename ElementType, typename VersionedIndexClass =
    versioned_index::VersionedIndexCompressed>
class SharedQueue {
public:
    SharedQueue(const char *name, size_t capacity) : m_capacity(capacity), m_shm_name(name) {
        static_assert(std::is_trivial<ElementType>::value, "ElementType is NOT trivial");
    }

    ~SharedQueue() {
    }

    bool Attach() {
        if(m_shm_name.size() > sizeof(CustomMemoryHeader::shm_name) + 1u) {
            SQUEUE_ERROR("length of shm name is too large, shm_name=%s", m_shm_name.c_str());
            return false;
        }

        size_t allocate_capacity = m_capacity + 1u;
        assert(allocate_capacity > m_capacity);

        size_t memory_size = MA.QueryMinimalMemorySize(allocate_capacity);

        if(! memory_helper::AttachSharedMemory(m_shm_name.c_str(), memory_size, [this, memory_size](void *p) {
                    return DoInit(p, memory_size);
                }) ) {
            return false;
        }

        return true;
    }

    void Detach() {
        memory_helper::DetachSharedMemory(m_shared_memory, m_shared_memory_size);
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
    bool DoInit(void *p, size_t memory_size) {
        bool init_ok = MA.Init(m_capacity + 1u, p, memory_size);
        if(!init_ok) {
            return false;
        }

        CustomMemoryHeader *header = MA.AccessCustomHeader();

        if(header->initialized) {
            // validate
            if(m_shm_name.compare(header->shm_name) != 0) {
                SQUEUE_ERROR("validate shm name failed. name=%s, expected=%s",
                        header->shm_name, m_shm_name.c_str());
                return false;
            }

            if(memory_size != header->shm_size) {
                SQUEUE_ERROR("validate shm size failed. size=%lu, expected=%lu",
                        header->shm_size, memory_size);
                return false;
            }

            m_shared_memory = p;
            m_shared_memory_size = memory_size;
            m_custom_header = header;
            m_read = &m_custom_header->read;
            m_write = &m_custom_header->write;

            SQUEUE_ERROR("use initialized queue");
            return true;
        } 
        
        // initialize
        MA.Setup();

        MA.ForeachElementUnsafe([this](ElementLinkedNode *node) {
                node->next.store(MA.MakeVersionedIndex(MA.NullIndex(), MA.ZeroVersion()),
                        std::memory_order_relaxed);
                node->lifetime.store(ElementLifetime::RECYCLE,
                        std::memory_order_relaxed);
                });

        m_shared_memory = p;
        m_shared_memory_size = memory_size;
        m_custom_header = header;

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

        header->shm_size = memory_size;
        snprintf(header->shm_name, sizeof(header->shm_name), "%s", m_shm_name.c_str());
        header->initialized = 1;

        SQUEUE_ERROR("initialize queue");
        return true;
    }

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
        unsigned long tag;
        size_t shm_size;
        int initialized;
        char shm_name[996];
        alignas(64) std::atomic<VersionedIndex> read;
        alignas(64) std::atomic<VersionedIndex> write;

        atomic_wait::AtomicWaitContext<256, true> atomic_wait_ctx;
    };

    mempool_allocate::MempoolAllocate<ElementLinkedNode, CustomMemoryHeader, VersionedIndexClass> MA;
    void *m_shared_memory = nullptr;
    size_t m_shared_memory_size = 0;
    CustomMemoryHeader *m_custom_header = nullptr;
    std::atomic<VersionedIndex> *m_read = nullptr;
    std::atomic<VersionedIndex> *m_write = nullptr;
    size_t m_capacity;
    std::string m_shm_name;
};

}

#undef SQUEUE_ERROR

#endif
