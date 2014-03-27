CC      = cc
CFLAGS  = -g -O3 -march=native -Wall -pedantic
LIBS    = -lcrypto

all:  pfcrypt pfkdf

pfcrypt: pfcrypt.o pufferfish.o 
	$(CC) -o pfcrypt pfcrypt.o pufferfish.o $(LIBS)

pfkdf: pfkdf.o pufferfish.o
	$(CC) -o pfkdf pfkdf.o pufferfish.o $(LIBS)

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f pfcrypt pfkdf *.o
