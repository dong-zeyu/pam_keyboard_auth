// Test reading using epoll

#include <dirent.h> 
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <security/pam_modules.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#define MAX_EVENTS 64

int get_ep() {
    char *path = "/dev/input/by-path/";

    int epollfd = epoll_create1(0);
    if (epollfd == -1) {
        fprintf(stderr, "PAM: Failed to create epoll file descriptor\n");
        return PAM_AUTH_ERR;
    }

    DIR *d;
    d = opendir(path);
    if(d == NULL) {
        fprintf(stderr, "PAM: Failed to open directory\n");
        close(epollfd);
        return PAM_AUTH_ERR;
    }

    struct dirent *dir;
    int fds[MAX_EVENTS];
    int count = 0;
    while ((dir = readdir(d)) != NULL) {
        if (strncmp(dir->d_name + strlen(dir->d_name) - 3, "kbd", 3) == 0) {
            if(count > MAX_EVENTS) {
                fprintf(stderr, "PAM: Too many keyboard (>64)! Are you monster?\n");
                break;
            }

            char *dev = malloc(strlen(path) + strlen(dir->d_name) + 1);
            strcpy(dev, path);
            strcat(dev, dir->d_name);
            int fd = open(dev, O_RDONLY);
            if (fd == -1) {
                fprintf(stderr, "PAM: Failed to open %s: %s\n", dev, strerror(errno));
                free(dev);
                continue;
            }

            struct epoll_event event;
            event.events = EPOLLIN;
            event.data.fd = fd;
            if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event) == -1) {
                fprintf(stderr, "PAM: Failed to add %s to epoll file descriptor: %s\n", dev, strerror(errno));
                close(fd);
                free(dev);
                continue;
            }

            free(dev);
            fds[count++] = fd;
        }
    }
    closedir(d);

    if (count == 0) {
        fprintf(stderr, "PAM: No keyboards found, bypass authencate\n");
        close(epollfd);
        return PAM_SUCCESS;
    }

    struct epoll_event events[count];
    while (true) {
        sigset_t set;
        sigemptyset(&set);
        int nfds = epoll_pwait(epollfd, events, MAX_EVENTS, 5000, &set);
        if (nfds == -1) {
            fprintf(stderr, "PAM: Failed to wait on epoll file descriptor: %s\n", strerror(errno));
            close(epollfd);
            for(int j = 0; j < count; j++)
                close(fds[j]);
            return PAM_AUTH_ERR;
        }

        for(int i = 0; i < nfds; i++) {
            if (events[i].events & EPOLLIN) {
                struct input_event ev;
                ssize_t n;
                n = read(events[i].data.fd, &ev, sizeof ev);
                if (n == -1 || n != sizeof ev)
                    continue;

                if (ev.type == EV_KEY && ev.value == 1 && ev.code == KEY_PAUSE) {
                    close(epollfd);
                    for(int j = 0; j < count; j++)
                        close(fds[j]);
                    return PAM_SUCCESS;
                }
            }
        }
    }
}

int main() {
    get_ep();
    return 0;
}
