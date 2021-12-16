# PAM Keyboard Authentication

This project enable you to authenticate locally with one key press. Use this when you don't want to input password everytime but still need to prevent from remote code execution.

## Build and Installation

```bash
# Build
mkdir build && cd build
cmake ..
make

# Install
sudo install -s ./libpam_keyboard.so /usr/lib/x86_64-linux-gnu/security/pam_keyboard.so  # For Ubuntu
sudo cp ../pam-config/keyboard /usr/share/pam-configs
sudo pam-auth-update
# Select Keyboard Authentication
```

## Issues

- Users in `input` group can still bypass authentication by emulating input. Be sure the user you want to protect is not in the `input` group. Otherwise you need additional configuration on the permission of input devices.

- It will hold a lock on the keyboard devices during authentication, which might conflict with other program.

- This authentication process will drain some input from stdin to make sure all the things you type on the keyboard is correctly digested, but it might read more than you want if redirect some input to the stdin.
