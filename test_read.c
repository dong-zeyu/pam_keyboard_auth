// Test the terminal settings

#include <fcntl.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>

int main() {
    char buf[1024];
    static struct termios oldt, newt;
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON);
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    sleep(5);
    int n = read(0, buf, 1024);
    printf("Read %d\n", n);
    fcntl(STDIN_FILENO, F_SETFL, flags);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}
