all:
	gcc  -m32 -no-pie -nostdlib -o fib fib.c
	gcc  -m32 -no-pie -nostdlib -o sum sum.c
	gcc -m32 -o loader actualloader.c

clean:
	-@rm -f fib loader sum