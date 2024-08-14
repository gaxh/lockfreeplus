#include <atomic>

#include <pthread.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

namespace atomic_wait {

struct alignas(64) AtomicWaitHelper {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
};

template<size_t Capacity, bool Shared = false>
struct AtomicWaitContext {
    AtomicWaitHelper helpers[Capacity];

    pthread_mutexattr_t mutexattr;
    pthread_condattr_t condattr;

    void Init() {
        int retcode;
        retcode = pthread_mutexattr_init(&mutexattr);
        assert(retcode == 0);

        retcode = pthread_mutexattr_setprotocol(&mutexattr, PTHREAD_PRIO_INHERIT);
        assert(retcode == 0);

        if(Shared) {
            retcode = pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED);
            assert(retcode == 0);

            retcode = pthread_mutexattr_setrobust(&mutexattr, PTHREAD_MUTEX_ROBUST);
            assert(retcode == 0);
        }

        retcode = pthread_condattr_init(&condattr);
        assert(retcode == 0);

        if(Shared) {
            retcode = pthread_condattr_setpshared(&condattr, PTHREAD_PROCESS_SHARED);
            assert(retcode == 0);
        }

        for(size_t i = 0; i < Capacity; ++i) {
            AtomicWaitHelper *helper = &helpers[i];

            retcode = pthread_mutex_init(&helper->mutex, &mutexattr);
            assert(retcode == 0);

            retcode = pthread_cond_init(&helper->condition, &condattr);
            assert(retcode == 0);
        }
    }

    void Destroy() {
        int retcode;

        for(size_t i = 0; i < Capacity; ++i) {
            AtomicWaitHelper *helper = &helpers[i];

            retcode = pthread_mutex_destroy(&helper->mutex);
            assert(retcode == 0);

            retcode = pthread_cond_destroy(&helper->condition);
            assert(retcode == 0);
        }

        pthread_mutexattr_destroy(&mutexattr);
        pthread_condattr_destroy(&condattr);
    }

    template<typename T, typename std::enable_if<std::is_trivial<T>::value, int>::type = 0>
    bool BitwiseSame(T *x, T *y) {
        return memcmp(x, y, sizeof(T)) == 0;
    }

    template<typename T>
    AtomicWaitHelper *QueryHelper(std::atomic<T> *object) {
        return &helpers[((size_t)object / sizeof(T)) % Capacity];
    }

    template<typename T>
    void AtomicWait(std::atomic<T> *object, T old, std::memory_order morder) {
        T value = object->load(morder);

        if(!BitwiseSame(&value, &old)) {
            return;
        }

        AtomicWaitHelper *helper = QueryHelper(object);
        int retcode;

        retcode = pthread_mutex_lock(&helper->mutex);

        if(retcode != 0) {
            if(retcode == EOWNERDEAD) {
                retcode = pthread_mutex_consistent(&helper->mutex);
                assert(retcode == 0);
            } else {
                assert(0);
            }
        }

        for(;;) {
            value = object->load(std::memory_order_relaxed);

            if(!BitwiseSame(&value, &old)) {
                break;
            } else {
                retcode = pthread_cond_wait(&helper->condition, &helper->mutex);
                assert(retcode == 0);
            }
        }

        retcode = pthread_mutex_unlock(&helper->mutex);
        assert(retcode == 0);
    }

    template<typename T>
    void AtomicSignal(std::atomic<T> *object) {
        AtomicWaitHelper *helper = QueryHelper(object);
        int retcode;

        retcode = pthread_mutex_lock(&helper->mutex);

        if(retcode != 0) {
            if(retcode == EOWNERDEAD) {
                retcode = pthread_mutex_consistent(&helper->mutex);
                assert(retcode == 0);
            } else {
                assert(0);
            }
        }

        retcode = pthread_cond_broadcast(&helper->condition);
        assert(retcode == 0);

        retcode = pthread_mutex_unlock(&helper->mutex);
        assert(retcode == 0);
    }
};


}
