CC=g++

all: postlinker clean

postlinker: postlinker.o 
	$(CC) postlinker.o -o postlinker

postlinker.o: postlinker.cc
	$(CC) postlinker.cc -c

clean:
	rm -f *.o

clean-all: clean
	rm -f postlinker

.PHONY: clean all clean-all

.SILENT: clean clean-all
