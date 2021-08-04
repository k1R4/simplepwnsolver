// gcc -o chall chall.c -no-pie -fno-stack-protector

#include <stdio.h>

void gibmeshell() {
	system("/bin/sh");
}

int main(int argc, char *argv[]) {
	char buf[0x10];
	puts("give da overflow:");
	gets(buf);
	return 0;
}