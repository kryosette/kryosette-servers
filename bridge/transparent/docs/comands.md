// core darwin
gcc -o core core_darwin.c \
  -I/Users/dimaeremin/kryosette-servers/bridge/transparent/level2/src/detectors/core/include \
  /Users/dimaeremin/kryosette-db/third-party/smemset/smemset.c \
  -framework CoreFoundation \
  -framework SystemConfiguration \
  -framework Network \
  -D_DARWIN_C_SOURCE