cmake_minimum_required(VERSION 3.0.0)
project(PAMKeyboard VERSION 0.1.0)

set (CMAKE_C_STANDARD 11)

add_library(pam_keyboard SHARED pam_keyboard.c)
target_link_libraries(pam_keyboard pam systemd)
add_executable(test_keyboard test_keyboard.c)
add_executable(test_read_epoll test_read_epoll.c)
add_executable(test_lock test_lock.c)
add_executable(test_emu test_emu.c)
add_executable(test_read test_read.c)
