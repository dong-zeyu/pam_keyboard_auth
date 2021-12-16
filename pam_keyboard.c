/* Define which PAM interfaces we provide */
#define PAM_SM_AUTH

/* Include headers */
#define _GNU_SOURCE
#include <dirent.h> 
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <security/pam_modules.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <systemd/sd-login.h>
#include <termios.h>
#include <unistd.h>

#define MAX_EVENTS 64
#define MAX_RETRIES 3

void print_pam_message(pam_handle_t *pamh, int msg_style, const char *message, va_list args) {
    struct pam_conv *conv = 0;
    if(pam_get_item(pamh, PAM_CONV, (const void **) &conv) != PAM_SUCCESS || conv == NULL || conv->conv == NULL) {
        return; // No conversation function available
    }

    va_list args_copy;
    va_copy(args_copy, args);
    ssize_t size = vsnprintf(NULL, 0, message, args_copy);
    va_end(args_copy);
    char *buffer = malloc(size + 1);
    vsnprintf(buffer, size + 1, message, args);

    const struct pam_message mymsg = {
        .msg_style = msg_style,
        .msg = buffer,
    };
    const struct pam_message *msgp = &mymsg;
    struct pam_response *resp = 0;
    conv->conv(1, &msgp, &resp, conv->appdata_ptr);

    free(buffer);
}

void print_info(pam_handle_t *pamh, const char *message, ...) {
    va_list args;
    va_start(args, message);
    print_pam_message(pamh, PAM_TEXT_INFO, message, args);
    va_end(args);
}

void print_error(pam_handle_t *pamh, const char *message, ...) {
    va_list args;
    va_start(args, message);
    print_pam_message(pamh, PAM_ERROR_MSG, message, args);
    va_end(args);
}

static bool
is_remote (pam_handle_t *pamh)
{
    const char *rhost = NULL;
    pam_get_item (pamh, PAM_RHOST, (const void **) &rhost);

    if (rhost != NULL && *rhost != '\0') return true;

    if (sd_session_is_remote(NULL) > 0) return true;

    return false;
}

/* PAM entry point for authentication verification */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    if (is_remote(pamh))
        return PAM_AUTHINFO_UNAVAIL;

    char *path = "/dev/input/by-path/";
    int ret = PAM_AUTH_ERR;

    // Enable default singal handling
    sighandler_t previous_handler = signal(SIGINT, SIG_DFL);

    // Terminal settings: disable echo and canonical mode
    static struct termios oldt, newt;
    int in_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, in_flags | O_NONBLOCK);
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON);
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    int epollfd = epoll_create1(0);
    if (epollfd == -1) {
        print_error(pamh, "Failed to create epoll file descriptor");
        goto end1;
    }

    DIR *d;
    d = opendir(path);
    if(d == NULL) {
        print_error(pamh, "Failed to open directory %s", path);
        goto end2;
    }

    // Setup keyboard input
    struct dirent *dir;
    int fds[MAX_EVENTS];
    int count = 0;
    while ((dir = readdir(d)) != NULL) {
        if (strncmp(dir->d_name + strlen(dir->d_name) - 3, "kbd", 3) == 0) {
            if (count > MAX_EVENTS - 1) {
                print_error(pamh, "Too many keyboard (>64)! Ignore remaining");
                break;
            }

            char *dev = malloc(strlen(path) + strlen(dir->d_name) + 1);
            strcpy(dev, path);
            strcat(dev, dir->d_name);

            int fd = open(dev, O_RDONLY);
            if (fd == -1) {
                print_error(pamh, "Failed to open %s: %s", dev, strerror(errno));
                free(dev);
                continue;
            }

            struct epoll_event event;
            event.events = EPOLLIN;
            event.data.fd = fd;
            if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event) == -1) {
                print_error(pamh, "Failed to add %s to epoll file descriptor: %s", dev, strerror(errno));
                close(fd);
                free(dev);
                continue;
            }

            // Directly return failure if we can't lock any of the keyboard devices for security
            if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
                print_error(pamh, "(WARNING) Another program is waiting for authentication.");
                close(fd);
                free(dev);
                goto end3;
            }
            fds[count++] = fd;
        }
    }
    closedir(d);

    if (count == 0) {
        print_error(pamh, "No keyboards found");
        ret = PAM_AUTHINFO_UNAVAIL;
        goto end2;
    }

    struct epoll_event events[MAX_EVENTS];
    int trial = 0;
    sigset_t signals;
    sigemptyset(&signals);
    print_info(pamh, "Press PAUSE key to continue...");
    while (true) {
        if (trial >= MAX_RETRIES) {
            print_error(pamh, "too many trials");
            ret = PAM_MAXTRIES;
            goto end3;
        }

        int nfds = epoll_pwait(epollfd, events, MAX_EVENTS, 5000, &signals);
        if (nfds == 0) {
            print_error(pamh, "Authentication timeout");
            ret = PAM_MAXTRIES;
            goto end3;
        } else if (nfds == -1) {
            print_error(pamh, "Failed to wait for keyboard events: %s", strerror(errno));
            goto end3;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].events & EPOLLIN) {
                struct input_event ev;
                ssize_t n;
                n = read(events[i].data.fd, &ev, sizeof ev);
                if (n == -1 || n != sizeof ev)
                    continue;

                if (ev.type == EV_KEY && ev.value == 1) {  // key pressed
                    trial++;
                    if (ev.code == KEY_PAUSE) {  // Success if PAUSE key is pressed
                        trial--;
                        ret = PAM_SUCCESS;
                        goto end3;
                    } else if (ev.code == KEY_ESC) {  // Cancel if ESC is pressed
                        goto end3;
                    }
                }
            }
        }
    }

end3:
    for (int j = 0; j < count; j++)
    {
        flock(fds[j], LOCK_UN);
        close(fds[j]);
    }
end2:
    close(epollfd);
    char buf[MAX_RETRIES];
end1:
    read(STDIN_FILENO, buf, trial);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fcntl(STDIN_FILENO, F_SETFL, in_flags);
    signal(SIGINT, previous_handler);
    return ret;
}

/*
PAM entry point for setting user credentials (that is, to actually
establish the authenticated user's credentials to the service provider)
*/
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_IGNORE);
}

/* PAM entry point for authentication token (password) changes */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_IGNORE);
}
