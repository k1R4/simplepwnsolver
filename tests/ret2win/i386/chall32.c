#include <stdio.h>

int main(int argc, char *argv[]) {
	puts("Enter input:");
	vuln();
	return 0;
}

void vuln() {
	char buf[0x18];
	gets(buf);
	return;
}

void cattheflag() {
	system("/bin/cat tests/ret2win/i386/flag.txt");
}