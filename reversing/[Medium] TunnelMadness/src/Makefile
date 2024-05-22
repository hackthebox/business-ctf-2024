.PHONY := clean

tunnel: main.c maze.h maze.inc
	gcc main.c -fno-inline -O1 -o tunnel

maze.h maze.inc: gen.py
	python3 gen.py

clean:
	rm -f tunnel maze.h maze.inc

