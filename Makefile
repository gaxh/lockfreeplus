HEADERS := $(wildcard *.h)

CFLAGP := -g -O3 -Wall -mcx16

all : local_queue_test.out

local_queue_test.out : local_queue_test.cpp ${HEADERS} Makefile
	${CXX} -o $@ $< ${CFLAGP} ${CFLAGS} -latomic -lpthread

all : local_queue_test.asan.out

local_queue_test.asan.out : local_queue_test.cpp ${HEADERS} Makefile
	${CXX} -o $@ $< ${CFLAGP} ${CFLAGS} -fsanitize=address -fno-omit-frame-pointer -latomic -lpthread

clean:
	rm -f *.out
