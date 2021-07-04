// gcc -o chall32 chall32.c -no-pie -fno-stack-protector -m32
#include <stdio.h>

int main(int argc, char *argv[]) {
	puts("Entering vulnerable function!");
	vuln();
	return 0;
}

void vuln() {
	char buf[0x18];
	gets(buf);
}
