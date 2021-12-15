#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Test the file lock

int main()
{
    struct flock lock, savelock;
    int fd;

    fd = open("/dev/input/by-path/platform-i8042-serio-0-event-kbd", O_RDONLY);
    flock(fd, LOCK_EX);
    printf("File locked\n");
    pause();
}
