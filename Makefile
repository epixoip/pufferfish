CC     = cc
CFLAGS = -Wall -std=gnu99 -O2 -march=native -DTEST
LIBS   = -lcrypto
OBJS   = pufferfish.o

all: clean $(OBJS)
	$(CC) -o pfcrypt $(OBJS) $(LIBS)

clean:
	rm -f pfcrypt $(OBJS)

distclean: clean
