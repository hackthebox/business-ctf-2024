.PHONY := clean

casino: main.c flag.inc
	gcc main.c -o casino

flag.inc: gen.py
	python3 gen.py

clean:
	rm -f casino flag.inc
