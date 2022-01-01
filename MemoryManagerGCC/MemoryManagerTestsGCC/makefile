CC = g++
CFLAGS = -Wall -g

default: main

# make the executable
main: main.o MemoryManager.o
	$(CC) $(CFLAGS) -o main main.o MemoryManager.o

# make main.o
main.o: main.cpp
	$(CC) $(CFLAGS) -I../.. -c main.cpp

# make MemoryManager.o
MemoryManager.o: ../../MemoryManager.cpp ../../MemoryManager.h
	$(CC) $(CFLAGS) -I../.. -c ../../MemoryManager.cpp

clean:
	$(RM) main *.o *~
