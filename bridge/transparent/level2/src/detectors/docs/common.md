gcc -o core_d core_darwin.c \
    -I/Users/dimaeremin/kryosette-servers/bridge/transparent/level2/src/detectors/core/include \
    -framework CoreFoundation \
    -framework SystemConfiguration \
    -framework Network \
    -D_DARWIN_C_SOURCE \
    -Wall -Wextra -O2 -std=c99