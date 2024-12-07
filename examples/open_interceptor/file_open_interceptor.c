#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif
#define _GNU_SOURCE 1
#include "libsyscall_intercept_hook_point.h"
#include <syscall.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "beegfs.h"

/* Buffer for logging */
static int log_fd = -1;

/* Default striping settings */
#define DEFAULT_STRIPE_COUNT    3
#define DEFAULT_STRIPE_SIZE     1048576  /* 1MB */

/* Function to log a debug message */
static void
log_debug(const char *format, ...)
{
    if (log_fd >= 0) {
        char message[2048];
        va_list args;
        int len;

        va_start(args, format);
        len = vsnprintf(message, sizeof(message), format, args);
        va_end(args);

        if (len > 0) {
            syscall_no_intercept(SYS_write, log_fd, message, len);
        }
    }
}

/* Function to check if a path is on BeeGFS */
static int
is_beegfs_path(const char *path)
{
    int fd;
    bool is_beegfs = false;
    char *config_file = NULL;

    /* Open the parent directory */
    char *parent_dir = strdup(path);
    if (!parent_dir) {
        log_debug("[file_open_interceptor] Failed to allocate memory for parent_dir path\n");
        return 0;
    }
        
    char *last_slash = strrchr(parent_dir, '/');
    if (last_slash)
        *last_slash = '\0';
    else {
        log_debug("[file_open_interceptor] Invalid path: %s (no parent directory)\n", path);
        free(parent_dir);
        return 0;
    }
    
    fd = syscall_no_intercept(SYS_open, parent_dir, O_RDONLY);
    if (fd < 0) {
        log_debug("[file_open_interceptor] Failed to open parent directory: %s (errno: %d)\n", 
                 parent_dir, errno);
        free(parent_dir);
        return 0;
    }

    is_beegfs = beegfs_testIsBeeGFS(fd);
    if (is_beegfs) {
        /* Get BeeGFS config file for debugging */
        if (beegfs_getConfigFile(fd, &config_file)) {
            log_debug("[file_open_interceptor] BeeGFS detected for path: %s (config: %s)\n", 
                     path, config_file);
            free(config_file);
        } else {
            log_debug("[file_open_interceptor] BeeGFS detected for path: %s (config unavailable)\n", 
                     path);
        }
    } else {
        log_debug("[file_open_interceptor] Not a BeeGFS path: %s\n", path);
    }

    syscall_no_intercept(SYS_close, fd);
    free(parent_dir);
    
    return is_beegfs;
}

/* Function to create a file with BeeGFS striping */
static int
create_striped_file(const char *path, mode_t mode, unsigned int stripe_count, unsigned int stripe_size)
{
    int fd;
    int ret = -1;
    
    /* Open the parent directory */
    char *parent_dir = strdup(path);
    if (!parent_dir) {
        log_debug("[file_open_interceptor] Failed to allocate memory for parent_dir path\n");
        return -1;
    }
        
    char *last_slash = strrchr(parent_dir, '/');
    if (!last_slash) {
        log_debug("[file_open_interceptor] Invalid path: %s (no parent directory)\n", path);
        free(parent_dir);
        return -1;
    }
    
    *last_slash = '\0';
    char *filename = last_slash + 1;
    
    fd = syscall_no_intercept(SYS_open, parent_dir, O_RDONLY);
    if (fd < 0) {
        log_debug("[file_open_interceptor] Failed to open parent directory: %s (errno: %d)\n", 
                 parent_dir, errno);
        free(parent_dir);
        return -1;
    }

    log_debug("[file_open_interceptor] Attempting to create striped file: %s (stripe_count: %u, stripe_size: %u)\n",
             path, stripe_count, stripe_size);

    /* Create file with striping using BeeGFS API */
    log_debug("The value of stripe_count is %d\n", stripe_count);
    if (beegfs_createFile(fd, filename, mode, stripe_count, stripe_size)) {
        ret = 0;  /* Success */
        
        /* Get and log the actual stripe info */
        unsigned pattern_type;
        unsigned chunk_size;
        uint16_t num_targets;
        if (beegfs_getStripeInfo(fd, &pattern_type, &chunk_size, &num_targets)) {
            log_debug("[file_open_interceptor] Successfully created striped file: %s\n"
                     "  Pattern Type: %u\n"
                     "  Chunk Size: %u\n"
                     "  Number of Targets: %u\n",
                     path, pattern_type, chunk_size, num_targets);
            
            /* Log individual stripe targets */
            for (uint16_t i = 0; i < num_targets; i++) {
                uint16_t target_id;
                uint16_t node_id;
                char *node_str = NULL;
                if (beegfs_getStripeTarget(fd, i, &target_id, &node_id, &node_str)) {
                    log_debug("  Target %u: ID=%u, NodeID=%u, Node=%s\n",
                             i, target_id, node_id, node_str ? node_str : "unknown");
                    if (node_str)
                        free(node_str);
                }
            }
        } else {
            log_debug("[file_open_interceptor] Created file but failed to get stripe info: %s\n", path);
        }
    } else {
        log_debug("[file_open_interceptor] Failed to create striped file: %s (errno: %d)\n", 
                 path, errno);
    }

    syscall_no_intercept(SYS_close, fd);
    free(parent_dir);
    return ret;
}

/* Function to log file operations */
static void
log_file_operation(const char *path, int flags, mode_t mode, int created, int striped)
{
    char flag_desc[256] = "";
    
    /* Decode flags for better debugging */
    if (flags & O_CREAT) strcat(flag_desc, "O_CREAT ");
    if (flags & O_EXCL) strcat(flag_desc, "O_EXCL ");
    if (flags & O_TRUNC) strcat(flag_desc, "O_TRUNC ");
    if (flags & O_APPEND) strcat(flag_desc, "O_APPEND ");
    if ((flags & O_RDWR) == O_RDWR) strcat(flag_desc, "O_RDWR ");
    else if (flags & O_RDONLY) strcat(flag_desc, "O_RDONLY ");
    else if (flags & O_WRONLY) strcat(flag_desc, "O_WRONLY ");
    
    if (created) {
        log_debug("[file_open_interceptor] Created new file\n"
                 "  Path: %s\n"
                 "  Flags: %s(0x%x)\n"
                 "  Mode: %o\n"
                 "  BeeGFS Striping: %s\n",
                 path, flag_desc, flags, mode, 
                 striped ? "Yes" : "No");
    } else if (flags & O_CREAT) {
        log_debug("[file_open_interceptor] Opened existing file\n"
                 "  Path: %s\n"
                 "  Flags: %s(0x%x)\n"
                 "  Mode: %o\n",
                 path, flag_desc, flags, mode);
    }
}

/* Function to check if a syscall is a file open operation */
static int
is_open_syscall(long syscall_number)
{
    return syscall_number == SYS_open ||
        syscall_number == SYS_openat ||
        syscall_number == SYS_creat;
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
    int striped = 0;

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

    /* Save original errno */
    int old_errno = errno;

    /* Check if this might be a file creation */
    if ((flags & O_CREAT) && !(flags & O_EXCL) && is_beegfs_path(path)) {
        /* Try to create with striping */
        if (create_striped_file(path, mode, DEFAULT_STRIPE_COUNT, DEFAULT_STRIPE_SIZE) == 0) {
            /* File created with striping, open it normally */
            striped = 1;
            flags &= ~O_CREAT;  /* Remove O_CREAT since file exists now */
        }
    }

    /* Execute the original syscall */
    *result = syscall_no_intercept(syscall_number,
        arg0, arg1, arg2, arg3, arg4, arg5);

    /* Check if this was a creation */
    if (*result >= 0 && (flags & O_CREAT)) {
        /* EEXIST is set when O_CREAT is used but file already exists */
        int created = (errno != EEXIST);
        log_file_operation(path, flags, mode, created, striped);
    }

    /* Restore original errno */
    errno = old_errno;

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
