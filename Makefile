all: mkfloader

mkfloader: mkfloader.c
	gcc -Wall -o $@ mkfloader.c -lcrypto

clean:
	rm -f main.o
	rm -f mkfloader

.PHONY: clean
