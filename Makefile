beacondump: beacondump.c
	gcc -o beacondump beacondump.c -lpcap
clean:
	rm -f beacondump
