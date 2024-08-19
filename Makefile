HEADERS := $(wildcard *.h)

CFLAGP := -g -Wall #-O3 #-mcx16

CLINKP := -lpthread -lrt #-latomic

all : local_queue_test.out

local_queue_test.out : local_queue_test.o memory_helper.o
	${CXX} -o $@ $^ ${CLINKP}

all : local_queue_test.asan.out

local_queue_test.asan.out : local_queue_test.asan.o memory_helper.asan.o
	${CXX} -o $@ $^ ${CLINKP} -fsanitize=address -fno-omit-frame-pointer

%.o : %.cpp ${HEADERS}
	${CXX} -c -o $@ $< ${CFLAGP} ${CFLAGS}

%.asan.o : %.cpp ${HEADERS}
	${CXX} -c -o $@ $< ${CFLAGP} ${CFLAGS} -fsanitize=address -fno-omit-frame-pointer

all : shared_queue_test_read.out

shared_queue_test_read.out : shared_queue_test_read.o memory_helper.o
	${CXX} -o $@ $^ ${CLINKP}

all : shared_queue_test_write.out

shared_queue_test_write.out : shared_queue_test_write.o memory_helper.o
	${CXX} -o $@ $^ ${CLINKP}

clean:
	rm -f *.out
	rm -f *.gch
	rm -f *.o
