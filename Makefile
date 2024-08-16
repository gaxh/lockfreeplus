HEADERS := $(wildcard *.h)

CFLAGP := -g -O3 -Wall #-mcx16

CLINKP := -lpthread #-latomic

all : local_queue_test.out

local_queue_test.out : local_queue_test.cpp ${HEADERS} Makefile
	${CXX} -o $@ $< ${CFLAGP} ${CFLAGS} ${CLINKP}

all : local_queue_test.asan.out

local_queue_test.asan.out : local_queue_test.cpp ${HEADERS} Makefile
	${CXX} -o $@ $< ${CFLAGP} ${CFLAGS} -fsanitize=address -fno-omit-frame-pointer ${CLINKP}

clean:
	rm -f *.out
	rm -f *.gch
