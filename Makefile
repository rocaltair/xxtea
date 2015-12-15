PLATFORM=$(shell uname)
CC = gcc

CFLAGS = -c -O3 -Wall -DENABLE_XXTEA_MAIN
LIBS = 
LDFLAGS = -O3 -Wall $(LIBS)

BIN = a.out
OBJS = xxtea.o

all : $(BIN)

$(BIN): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) 

$(OBJS) : %.o : %.c
	$(CC) -o $@ $(CFLAGS) $<

clean : 
	rm -f $(OBJS) $(BIN)

.PHONY : clean

