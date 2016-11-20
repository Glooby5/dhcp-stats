GCC=g++
CFLAGS+=-Wall -g
CFLAGS+=-DUSE_SLEEP
LIBS=-lpcap -D_BSD_SOURCE
SRC=$(wildcard *.cpp)
PROGS=$(patsubst %.cpp,%,$(SRC))
#OBJS = $(SRC:.c=.o)

%: %.cpp
	$(GCC) -std=c++11 $(CFLAGS+) $< $(LIBS) -o $@

all: $(PROGS)
	sudo cp dhcp-stats.8 /usr/local/share/man/man8

clean:
	rm -f *.core $(PROGS) *~