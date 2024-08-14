#include "local_queue.h"
#include <stdio.h>
#include <thread>
#include <vector>
#include <assert.h>
#include <signal.h>

struct Element {
    unsigned long long value = 0;
    std::vector<std::string> tag;
};

static volatile int stop = 0;

static void sig_handler(int sig) {
    stop = 1;
}

static std::atomic<unsigned long long> push_success(0);
static std::atomic<unsigned long long> pop_success(0);

static std::atomic<unsigned long> generate_sequence(0);

int main() {
    std::vector<std::thread *> pushers;
    std::vector<std::thread *> popers;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    local_queue::LocalQueue<Element> q(200000);

    auto construct_cb = [] (Element *e) {
        Element ee;
        unsigned long seq = generate_sequence.fetch_add(1u);
        ee.value = seq;
        unsigned long tag_size = seq % 20u;
        ee.tag.reserve(tag_size);
        for(unsigned long i = 0; i < tag_size; ++i) {
            ee.tag.emplace_back("___________________________________________________________________"
                    "___________________________________________________________________"
                    "very_long_string"
                    "___________________________________________________________________"
                    "___________________________________________________________________");
        }

        new (e) Element(std::move(ee));
    };

    auto destruct_cb = [] (Element *e) {
        e->~Element();
    };

//*
    for(int i = 0; i < 3; ++i) {
        pushers.emplace_back( new std::thread([&q, construct_cb]() {
                    for(;!stop;) {
                        bool ok = q.Push(construct_cb);

                        if(ok) {
                            push_success.fetch_add(1u, std::memory_order_relaxed);
                        }
                    }
                    }) );
    }
// */
//*
    for(int i = 0; i < 3; ++i) {
        popers.emplace_back( new std::thread([&q, destruct_cb]() {
                    for(;!stop;) {
                        bool ok = q.Pop(destruct_cb);

                        if(ok) {
                            pop_success.fetch_add(1u, std::memory_order_relaxed);
                        }
                    }
                    }) );
    }
// */
    for(std::thread *t: pushers) {
        t->join();
        delete t;
    }

    for(std::thread *t: popers) {
        t->join();
        delete t;
    }

    printf("push_success=%llu, pop_success=%llu\n", push_success.load(), pop_success.load());

    q.Clear(destruct_cb);

    return 0;
}
