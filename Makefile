CC=gcc

all: main.o
	$(CC) main.o -o wss

main.o:
	$(CC) -I /usr/local/include ./src/main.cpp -c 
