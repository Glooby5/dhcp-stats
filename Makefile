GCC=g++
CFLAGS+=-Wall -g
CFLAGS+=-DUSE_SLEEP
LIBS=-lpcap -D_BSD_SOURCE
SRC=$(wildcard *.cpp)
PROGS=$(patsubst %.cpp,%,$(SRC))
#OBJS = $(SRC:.c=.o)

%: %.cpp
	$(GCC) $(CFLAGS+) $< $(LIBS) -o $@

all: $(PROGS)

clean:
	rm -f *.core $(PROGS) *~