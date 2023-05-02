#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <fcntl.h>

int main() {
	renameat2(0, "/home/feather/student/licenta/syscall_hooking/tests/test_open+write/file.txt", 0,
		"/home/feather/student/licenta/syscall_hooking/tests/test_open+write/file_new.txt", RENAME_NOREPLACE);

	return(0);
}
