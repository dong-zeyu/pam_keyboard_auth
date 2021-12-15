#include <stdlib.h>
// This test shows that we should disable the permission of input group for the unauthenticated user.
// Because they can write to the input device to emulate keystrokes.

#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    const char *dev = "/dev/input/by-path/platform-i8042-serio-0-event-kbd";
    struct input_event ev;
    int fd;

    fd = open(dev, O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "Cannot open %s: %s.\n", dev, strerror(errno));
        return EXIT_FAILURE;
    }

    ev.type = EV_KEY;
    ev.code = KEY_PAUSE;
    while (1) {
        ev.value = 1;
        write(fd, &ev, sizeof ev);
        usleep(50000);
        ev.value = 0;
        write(fd, &ev, sizeof ev);
        usleep(500000);
    }

    return EXIT_SUCCESS;
}
