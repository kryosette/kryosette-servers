#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>

#define AES_256_KEY_SIZE 32   // 256 бит
#define GCM_IV_SIZE 12        // 96 бит (оптимально для GCM)
#define GCM_TAG_SIZE 16       // 128-битный тег аутентификации

// Шифрование AES-GCM
int aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *key,
                    const unsigned char *iv,
                    unsigned char *ciphertext,
                    unsigned char *tag);

// // Дешифрование AES-GCM
// int aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
//                     const unsigned char *key,
//                     const unsigned char *iv,
//                     const unsigned char *tag,
//                     unsigned char *plaintext);

#endif