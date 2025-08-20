#include "arp-detector.h"

int main(int argc, char *argv[]) {
    if (argc != 3) { 
        fprintf(stderr, "Usage: %s <interface> <trusted_base_file>\n", argv[0]);
        fprintf(stderr, "Example: %s ens33 trusted_arp.txt\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, signal_handler);

    if (load_trusted_base(argv[2]) != 0) {
        fprintf(stderr, "Failed to load trusted base. Exiting.\n");
        exit(EXIT_FAILURE);
    }

    detect_arp_spoofing(argv[1]);

    return 0;
}