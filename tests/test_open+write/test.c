#include <stdio.h>
#include <string.h>

int main() {
	FILE *fp;
	char str[100];

	strcpy(str, "new_string");

	fp = fopen("/home/feather/student/licenta/syscall_hooking/tests/test_open+write/file.txt", "r+");
	fwrite(str, sizeof(char), strlen(str), fp);

	fclose(fp);

	return(0);
}
