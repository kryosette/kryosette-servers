#include <openssl/evp.h> // For high-level EVP operations (RFC 5246 TLS 1.2)
#include <openssl/rand.h> // For cryptographically secure generation
#include <string.h> // For memcpy

/*
* AES-GCM encryption
 * plaintext - source data
 * plaintext_len - their length
 * key - key (16/24/32 bytes for AES-128/192/256)
 * iv initializing vector (12 bytes for GCM)
* ciphertext buffer for ciphertext (must be plaintext_len + 16)
* tag buffer for authentication tag (16 bytes)
*/
int aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *key,
                    const unsigned char *iv,
                    unsigned char *ciphertext,
                    unsigned char *tag) {
EVP_CIPHER_CTX *ctx; // Encryption context (RFC 5116)
int len;
    int ciphertext_len;

    // 1. Creating a context
ctx = EVP_CIPHER_CTX_new();
/* Why EVP? Because it is a unified API of OpenSSL 
     * for all algorithms (RFC 7465) */

    // 2. Initialize GCM mode
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    /* EVP_aes_256_gcm() - specifies AES-256 in GCM mode
     * (NIST SP 800-38D) */

    // 3. Set the IV length (12 bytes is optimal for GCM)
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
/* 12 bytes is recommended by NIST as a balance of security and performance */

    // 4. Initialize the key and IV
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    /* The key must be 256 bits (32 bytes) for AES-256
     * The IV must be unique for each key (RFC 5116 §3.1) */

    // 5. We encrypt the data
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    /* This is the basic encryption operation (NIST SP 800-38D §6.4) */

    // 6. Finalize (addition is not required in GCM)
EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    /* GCM uses CTR mode, which does not require padding (RFC 5288) */

    // 7. We receive the authentication tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    /* The 16 byte tag provides 128-bit security (RFC 5116 §5.1) */

    // 8. Freeing the context
    EVP_CIPHER_CTX_free(ctx);
    /* Important to prevent memory leaks */

    return ciphertext_len;
}