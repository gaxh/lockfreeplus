#include "shared_queue.h"

#include <signal.h>

struct Element {
    unsigned long long value;
    char buffer[4000];
};

static volatile int stop = 0;

static void sig_handler(int sig) {
    stop = 1;
}

int main() {

    shared_queue::SharedQueue<Element> q("squeue_fish.shm", 100000);

    if(!q.Attach()) {
        printf("failed to attach shm\n");
        return -1;
    }

    size_t success_count = 0;

    signal(SIGINT, sig_handler);

    while(!stop) {
    
        if(q.Push([](Element *e) {})) {
            ++success_count;
        }
    }

    printf("push success: %lu\n", success_count);

    q.Detach();

    return 0;
}
