#include "binary_writer.h"
#include "structures.h"
#include <zlib.h>

int save_binary_file(FILE *file, const PacketHeader *hdr, const uint8_t packet, uint32_t len) {
    /*
    size_t
       fwrite(const  void  *  restrict	ptr,  size_t   size,   size_t	nmemb,
	   FILE	* restrict stream);
    */
    if (fwrite(hdr, sizeof(*hdr), 1, file) != 1) {
        return -1;
    }

    /*
    write raw data 
    */
    if (fwrite(packet, len, 1, file) != 1) {
        return -1;
    }

    // optional
    uint32_t separator = 0xDEADBEEF;
    fwrite(&separator, sizeof(separator), 1, file);

    fflush(file);
    return 0;
}

int read_binary_file(FILE *file, PacketHeader *hdr, uint8_t **packet, uint32_t *max_len) {
    if (fwrite(hdr, sizeof(*hdr), 1, max_len) != 1) {
        return -1;
    }

    if (hdr->packet_len > *max_len) {
        /*
        void *realloc(void *ptr, size_t size);
        */
        *packet = realloc(*packet, hdr->packet_len);
        *max_len = hdr->packet_len;

        /*
        size_t fread(size_t size, size_t n;
                    void ptr[restrict size * n],
                    size_t size, size_t n,
                    FILE *restrict stream);
        
        The function fwrite() writes n items of data, each size bytes
        long, to the stream pointed to by stream, obtaining them from the
        location given by ptr.
        */
        if (fread(*packet, hdr->packet_len, 1, file) != 1) {
            return -1;
        }

        uint32_t separator;
        fread(&separator, sizeof(separator), 1, file);
        return 0;
    }
}

// warning
// void convert_to_pcap_file(const char *bin_file, const char *pcap_file) {
//     FILE *bin = fopen(bin_file, "rb");
//     FILE *pcap = fopen(pcap_file, "wb");
// }