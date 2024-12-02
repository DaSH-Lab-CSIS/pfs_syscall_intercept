#include "libsyscall_intercept_hook_point.h"
#include <syscall.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

/* Buffer for logging */
static int log_fd = -1;

/* Function to check if a syscall is a file open operation */
static int
is_open_syscall(long syscall_number)
{
	return syscall_number == SYS_open ||
		syscall_number == SYS_openat ||
		syscall_number == SYS_creat;
}

/* Function to log file open attempts */
static void
log_open_attempt(const char *path, int flags, mode_t mode)
{
	char message[1024];
	int len = snprintf(message, sizeof(message),
		"[file_open_interceptor] Path: %s, Flags: %d, Mode: %o\n",
		path, flags, mode);

	if (len > 0 && log_fd >= 0) {
		syscall_no_intercept(SYS_write, log_fd, message, len);
	}
}

/* Main hook function for intercepting syscalls */
static int
hook(long syscall_number,
	long arg0, long arg1,
	long arg2, long arg3,
	long arg4, long arg5,
	long *result)
{
	if (!is_open_syscall(syscall_number))
		return 1;  /* Ignore other syscalls */

	const char *path;
	int flags;
	mode_t mode;

	/* Extract parameters based on syscall type */
	if (syscall_number == SYS_open) {
		path = (const char *)arg0;
		flags = (int)arg1;
		mode = (mode_t)arg2;
	} else if (syscall_number == SYS_openat) {
		path = (const char *)arg1;
		flags = (int)arg2;
		mode = (mode_t)arg3;
	} else { /* SYS_creat */
		path = (const char *)arg0;
		flags = O_CREAT | O_WRONLY | O_TRUNC;
		mode = (mode_t)arg1;
	}

	/* Log the open attempt */
	log_open_attempt(path, flags, mode);

	/* Execute the original syscall */
	*result = syscall_no_intercept(syscall_number,
		arg0, arg1, arg2, arg3, arg4, arg5);

	return 0;
}

static __attribute__((constructor)) void
start(void)
{
	/* Open log file */
	const char *log_path = getenv("FILE_OPEN_LOG");
	if (log_path == NULL)
		log_path = "/tmp/file_open.log";

	log_fd = (int)syscall_no_intercept(SYS_open,
		log_path, O_CREAT | O_WRONLY | O_APPEND, (mode_t)0644);

	if (log_fd < 0)
		syscall_no_intercept(SYS_exit_group, 1);

	/* Set the hook */
	intercept_hook_point = &hook;
}
