/* 
crypto.c

Implementations for cryptography primatives and functions
  making use of them.

Skeleton written by Aidan Dang for COMP20007 Assignment 2 2022
  with Minor modifications by Grady Fitzpatrick
  implementation by <You>
*/
#include <crypto.h>
#include <sponge.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// The sponge's rate, in bytes. This represents the maximum number of bytes
// which can be read from or written the start of the sponge's state before a
// permutation must occur.
#define RATE 16
// Delimiter byte value used after absorption of the message
#define DELIMITER_A 0xAD
// Delimiter byte used at the end of the last-used block
#define DELIMITER_B 0X77

// Helpful min function that might be useful.
uint64_t min(uint64_t a, uint64_t b) { return a < b ? a : b; }

void hash(uint8_t *output, uint64_t output_len, uint8_t const *msg,
          uint64_t msg_len) {
  sponge_t sponge;
  sponge_init(&sponge);
  for(int i = 0; i < msg_len / RATE; i++){
    sponge_write(&sponge, msg + i * RATE, RATE, true);
    sponge_permute(&sponge);
  }
  sponge_write(&sponge, msg + msg_len / RATE * RATE, msg_len % RATE, true);
  sponge_demarcate(&sponge, msg_len % RATE, DELIMITER_A);
  sponge_demarcate(&sponge, RATE - 1, DELIMITER_B);
  sponge_permute(&sponge);
  for(int i = 0; i < ouput_len / RATE; i++){
    sponge_read(output + i * RATE, &sponge, RATE);
    sponge_permute(&sponge);
  }
  sponge_read(output + output_len / RATE * RATE, &sponge, output_len % RATE);
}

void mac(uint8_t *tag, uint64_t tag_len, uint8_t const *key, uint8_t const *msg,
         uint64_t msg_len) {
  sponge_t sponge;
  sponge_init(&sponge);
  for(int i = 0; i < CRYPTO_KEY_SIZE / RATE; i++){
    sponge_write(&sponge, key + i * RATE, RATE, true);
    sponge_permute(&sponge); 
  }
  for(int i = 0; i < msg_len / RATE; i++){
    sponge_write(&sponge, msg + i * RATE, RATE, true);
    sponge_permute(&sponge);
  }
  sponge_write(&sponge, msg + msg_len / RATE * RATE, msg_len % RATE, true);
  sponge_demarcate(&sponge, msg_len % RATE, DELIMITER_A);
  sponge_demarcate(&sponge, RATE - 1, DELIMITER_B);
  sponge_permute(&sponge);
  for(int i = 0; i < tag_len / RATE; i++){
    sponge_read(tag + i * RATE, &sponge, RATE);
    sponge_permute(&sponge);
  }
  sponge_read(tag + tag_len / RATE * RATE, &sponge, tag_len % RATE);
  // TODO: fill the rest of this function.
  // Your implementation should like very similar to that of the hash
  // function's, but should include a keying phase before the absorbing phase.
  // If you wish, you may also treat this as calculating the hash of the key
  // prepended to the message.
}

void auth_encr(uint8_t *ciphertext, uint8_t *tag, uint64_t tag_len,
               uint8_t const *key, uint8_t const *plaintext,
               uint64_t text_len) {
  sponge_t sponge;
  sponge_init(&sponge);
  for(int i = 0; i < CRYPTO_KEY_SIZE / RATE; i++){
    sponge_write(&sponge, key + i * RATE, RATE, true);
    sponge_permute(&sponge);
  }
  for(int i = 0; i < text_len / RATE; i++){
    sponge_write(&sponge, plaintext + i * RATE, RATE, true);
    sponge_read(ciphertext + i * RATE, &sponge, RATE);
    sponge_permute(&sponge);
  }
  sponge_write(&sponge, plaintext + text_len / RATE * RATE, text_len % RATE, true);
  sponge_read(ciphertext + text_len / RATE * RATE, &sponge, text_len % RATE);
  sponge_demarcate(&sponge, text_len % RATE, DELIMITER_A);
  sponge_demarcate(&sponge, RATE - 1, DELIMITER_B);
  sponge_permute(&sponge);
  for(int i = 0; i < tag_len / RATE; i++){
    sponge_read(tag + i * RATE, &sponge, RATE);
    sponge_permute(&sponge);
  }
  sponge_read(tag + tag_len / RATE * RATE, &sponge, tag_len % RATE);
  // TODO: fill the rest of this function.
  // Your implementation should like very similar to that of the mac function's,
  // but should after each write into the sponge's state, there should
  // immediately follow a read from the sponge's state of the same number of
  // bytes, into the ciphertext buffer.
}

int auth_decr(uint8_t *plaintext, uint8_t const *key, uint8_t const *ciphertext,
              uint64_t text_len, uint8_t const *tag, uint64_t tag_len) {
  sponge_t sponge;
  sponge_init(&sponge);
  uint8_t test_key[CRYPTO_KEY_SIZE];
  for(int i = 0; i < CRYPTO_KEY_SIZE / RATE; i++){
    sponge_write(&sponge, key + i * RATE, RATE, true);
    sponge_permute(&sponge);
  }
  for(int i = 0; i < tag_len / RATE; i++){
    sponge_write(&sponge, tag + i * RATE, RATE, false);
    sponge_permute(&sponge);
  }
  sponge_write(&sponge, tag + tag_len / RATE * RATE, tag_len % RATE, false);
  sponge_permute(&sponge);
  for(int i = 0; i < text_len / RATE; i++){
    sponge_write(&sponge, ciphertext + i * RATE, RATE, true);
    sponge_read(plaintext + i * RATE, &sponge, RATE);
    sponge_permute(&sponge);
  }
  sponge_write(&sponge, ciphertext + text_len / RATE * RATE, text_len % RATE, true);
  sponge_read(plaintext + text_len / RATE * RATE, &sponge, text_len % RATE);
  sponge_demarcate(&sponge, text_len % RATE, DELIMITER_A);
  sponge_demarcate(&sponge, RATE - 1, DELIMITER_B);
  sponge_permute(&sponge);
  for(int i = 0; i < CRYPTO_KEY_SIZE / RATE; i++){
    sponge_read(test_key + i * RATE, &sponge, RATE);
    sponge_permute(&sponge);
  }
  // TODO: fill the rest of this function.
  // The implementation of this function is left as a challenge. It may assist
  // you to know that a ^ b ^ b = a. Remember to return 0 on success, and 1 on
  // failure.
  for(int i = 0; i < CRYPTO_KEY_SIZE; i++){
    if(test_key[i] != key[i]) return 1;
  }
  return 0;
}
