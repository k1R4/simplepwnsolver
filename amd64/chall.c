// gcc -o chall chall.c -no-pie -fno-stack-protector
#include <stdio.h>

int main(int argc, char *argv[]) {
	char buf[0x20];
	char str[0x10];
	puts("enter some random string:");
	read(0,str,0x10);
	puts("gimme the payload:");
	gets(buf);
	return 0;
}