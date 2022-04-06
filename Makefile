PROG=tkey
CC=gcc
PROG_FLAGS=-lssl -lcrypto


$(PROG): $(PROG).o base32.o
	$(CC) $(PROG).o base32.o -o $(PROG) $(PROG_FLAGS)

$(PROG).o: $(PROG).c
	$(CC) -c $(PROG).c

base32.o: base32.c base32.h
	$(CC) -c base32.c

clean:
	rm $(PROG) $(PROG).o base32.o
	rm .tinit
	rm .salt
	rm .pk
	rm .tprev
	rm .pprev
	rm .pi

show:
	cat .tinit; echo
	cat .salt; echo
	cat .pk; echo
	cat .tprev; echo
	cat .pprev; echo
	cat .pi; echo	