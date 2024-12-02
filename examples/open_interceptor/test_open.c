#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    /* Test regular open */
    int fd1 = open("/tmp/test1.txt", O_CREAT | O_WRONLY, 0644);
    if (fd1 >= 0) {
        write(fd1, "Hello World!\n", 13);
        close(fd1);
    }

    /* Test openat */
    int fd2 = openat(AT_FDCWD, "/tmp/test2.txt", O_CREAT | O_WRONLY, 0644);
    if (fd2 >= 0) {
        write(fd2, "Hello OpenAt!\n", 13);
        close(fd2);
    }

    /* Test creat */
    int fd3 = creat("/tmp/test3.txt", 0644);
    if (fd3 >= 0) {
        write(fd3, "Hello Creat!\n", 13);
        close(fd3);
    }

    return 0;
}
