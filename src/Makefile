default: all

CFLAGS= -Wall -g -Weverything -Wno-packed -Wno-missing-noreturn -DDEBUG

all: ping

datapath.o: datapath.c datapath.h
	$(CC) $(CFLAGS) -c datapath.c

ping.o: ping.c datapath.h
	$(CC) $(CFLAGS) -c ping.c

ping: datapath.o ping.o
	$(CC) ping.o datapath.o -o ping

clean:
	rm -f ping *.o *~

