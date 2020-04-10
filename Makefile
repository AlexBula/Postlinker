CC=g++
FLAGS=-Wall -Werror

all: postlinker clean

postlinker: postlinker.o
	$(CC) $(FLAGS) postlinker.o -o postlinker

postlinker.o: postlinker.cc
	$(CC) -Wall -Werror postlinker.cc -c

clean:
	rm -f *.o

clean-all: clean
	rm -f postlinker

.PHONY: clean all clean-all

.SILENT: clean clean-all
