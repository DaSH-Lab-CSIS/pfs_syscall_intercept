#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#define BEEGFS_PATH "/mnt/beegfs/interceptor_scratch"

void test_file_creation(const char *path, const char *content) {
    printf("Testing file creation: %s\n", path);
    
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        write(fd, content, strlen(content));
        printf("Successfully created and wrote to: %s\n", path);
        close(fd);
    } else {
        printf("Failed to create %s: %s\n", path, strerror(errno));
    }
    printf("\n");
}

int main(void) {
    char path[512];

    /* Test regular file creation in /tmp (non-BeeGFS) */
    test_file_creation("/tmp/test1.txt", "Hello Regular File!\n");

    /* Test file creation in BeeGFS with different methods */
    
    /* Test 1: Regular open with O_CREAT */
    snprintf(path, sizeof(path), "%s/test1.txt", BEEGFS_PATH);
    test_file_creation(path, "Hello BeeGFS Open!\n");

    /* Test 2: openat with O_CREAT */
    snprintf(path, sizeof(path), "%s/test2.txt", BEEGFS_PATH);
    printf("Testing openat creation: %s\n", path);
    int fd2 = openat(AT_FDCWD, path, O_CREAT | O_WRONLY, 0644);
    if (fd2 >= 0) {
        write(fd2, "Hello BeeGFS OpenAt!\n", 20);
        printf("Successfully created and wrote using openat\n");
        close(fd2);
    } else {
        printf("Failed to create using openat: %s\n", strerror(errno));
    }
    printf("\n");

    /* Test 3: creat */
    snprintf(path, sizeof(path), "%s/test3.txt", BEEGFS_PATH);
    printf("Testing creat: %s\n", path);
    int fd3 = creat(path, 0644);
    if (fd3 >= 0) {
        write(fd3, "Hello BeeGFS Creat!\n", 19);
        printf("Successfully created and wrote using creat\n");
        close(fd3);
    } else {
        printf("Failed to create using creat: %s\n", strerror(errno));
    }
    printf("\n");

    /* Test 4: Exclusive creation (should fail if file exists) */
    snprintf(path, sizeof(path), "%s/test4.txt", BEEGFS_PATH);
    printf("Testing exclusive creation: %s\n", path);
    int fd4 = open(path, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd4 >= 0) {
        write(fd4, "Hello BeeGFS Exclusive!\n", 23);
        printf("Successfully created file exclusively\n");
        close(fd4);
        
        /* Try creating again - should fail */
        fd4 = open(path, O_CREAT | O_EXCL | O_WRONLY, 0644);
        if (fd4 < 0) {
            printf("Exclusive creation correctly failed on existing file\n");
        }
    } else {
        printf("Failed exclusive creation: %s\n", strerror(errno));
    }
    printf("\n");

    /* Test 5: Create in subdirectory */
    snprintf(path, sizeof(path), "%s/testdir", BEEGFS_PATH);
    printf("Creating test directory: %s\n", path);
    if (mkdir(path, 0755) == 0 || errno == EEXIST) {
        snprintf(path, sizeof(path), "%s/testdir/test5.txt", BEEGFS_PATH);
        test_file_creation(path, "Hello BeeGFS Subdirectory!\n");
    } else {
        printf("Failed to create directory: %s\n", strerror(errno));
    }

    return 0;
}
