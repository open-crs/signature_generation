#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <fcntl.h>

int main() {
	renameat2(0, "/home/feather/student/licenta/syscall_hooking/tests/test_renameat2/file.txt", 0,
		"/home/feather/student/licenta/syscall_hooking/tests/test_renameat2/file_new.txt", RENAME_NOREPLACE);

	return(0);
}
