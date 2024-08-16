#ifndef __VERSIONED_INDEX__
#define __VERSIONED_INDEX__

#include <stddef.h>
#include <pthread.h>
#include <stdio.h>

#define ATOMICWAIT_ERROR(fmt, ...) fprintf(stderr, "%lu [%s:%d:%s] " fmt "\n", \
        (unsigned long)pthread_self(), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

namespace versioned_index {

class VersionedIndexGeneral {
public:
    bool Init(size_t index_capacity) {
        if(index_capacity == (size_t)-1) {
            ATOMICWAIT_ERROR("index_capacity is NOT supported, value=%lu", index_capacity);
            return false;
        }

        return true;
    }

    void Destroy() {
    }

    struct Version {
        size_t __value__;
    };

    struct Index {
        size_t __value__;
    };

    Version ZeroVersion() {
        return m_zero_version;
    }

    Index NullIndex() {
        return m_null_index;
    }

    struct alignas(sizeof(Version) + sizeof(Index)) VersionedIndex {
        Version __version__;
        Index __index__;
    };

    bool IsNullIndex(Index index) {
        return index.__value__ == m_null_index.__value__;
    }

    bool IsSameIndex(Index x, Index y) {
        return x.__value__ == y.__value__;
    }

    VersionedIndex MakeVersionedIndex(Index index, Version version) {
        return (VersionedIndex) { version, index };
    }

    Index GetIndex(VersionedIndex vindex) {
        return vindex.__index__;
    }

    Version NextVersion(VersionedIndex vindex) {
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

private:
    Version m_zero_version = { 0 };
    Index m_null_index = { (size_t)-1 };
};

class VersionedIndexCompressed {
public:
    bool Init(size_t index_capacity) {
        if(index_capacity == (size_t)-1) {
            ATOMICWAIT_ERROR("index_capacity is NOT supported, value=%lu", index_capacity);
            return false;
        }

        size_t index_mask = 0;
        while(index_mask <= index_capacity) {
            index_mask = (index_mask << 1) | (size_t)1;
        }

        m_index_mask = index_mask;
        m_version_mask = ~index_mask;
        m_next_version_diff = index_mask + (size_t)1;

        m_zero_version = { 0 };
        m_null_index = { index_mask };

        size_t version_bitsize = 0;
        for(size_t i = m_version_mask; i != 0; i = i << 1) {
            ++version_bitsize;
        }

        if( version_bitsize < 32u ) {
            ATOMICWAIT_ERROR("version bitsize is too small, which may cause ABA problem, "
                    "version_bitsize=%lu", version_bitsize);
        }

        return true;
    }

    void Destroy() {
    }

    struct Version {
        size_t __value__;
    };

    struct Index {
        size_t __value__;
    };

    Version ZeroVersion() {
        return m_zero_version;
    }

    Index NullIndex() {
        return m_null_index;
    }

    struct VersionedIndex {
        size_t __merged__; // low bits are "index", high bits are "version"
    };

    bool IsNullIndex(Index index) {
        return index.__value__ == m_null_index.__value__;
    }

    bool IsSameIndex(Index x, Index y) {
        return x.__value__ == y.__value__;
    }

    VersionedIndex MakeVersionedIndex(Index index, Version version) {
        return (VersionedIndex){ Merge(index.__value__, version.__value__) };
    }

    Index GetIndex(VersionedIndex vindex) {
        return (Index){ IndexOf(vindex.__merged__) };
    }

    Version NextVersion(VersionedIndex vindex) {
        return (Version) { (VersionOf(vindex.__merged__) + m_next_version_diff) & m_version_mask };
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

private:
    size_t IndexOf(size_t merged) {
        return merged & m_index_mask;
    }

    size_t VersionOf(size_t merged) {
        return merged & m_version_mask;
    }

    size_t Merge(size_t index, size_t version) {
        return (index & m_index_mask) | (version & m_version_mask);
    }

    size_t m_version_mask;
    size_t m_next_version_diff;
    size_t m_index_mask;

    Version m_zero_version;
    Index m_null_index;
};

}


#endif
