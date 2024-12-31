/*
 * Algorithmif.h
 *
 * Purpose: This header file declares functions and macros for cryptographic algorithms,
 *          including CMAC calculation, RSA signing, verification, encryption, and decryption,
 *          as well as AES encryption and decryption functionality.
 * Author: <kxx> <gss>
 * License: Copyright (C) 2024
 */

#ifndef ALGORITHMIF_H_
#define ALGORITHMIF_H_

/* Include standard header files */
#include <stdio.h>
#include <string.h>

/* Typedefs */

/**
 * Enumeration for message digest types.
 */
typedef enum {
    ZY_MBEDTLS_MD_NONE = 0,       /**< None. */
    ZY_MBEDTLS_MD_MD5 = 0x03,     /**< The MD5 message digest. */
    ZY_MBEDTLS_MD_RIPEMD160 = 0x04,/**< The RIPEMD-160 message digest. */
    ZY_MBEDTLS_MD_SHA1 = 0x05,    /**< The SHA-1 message digest. */
    ZY_MBEDTLS_MD_SHA224 = 0x08,  /**< The SHA-224 message digest. */
    ZY_MBEDTLS_MD_SHA256 = 0x09,  /**< The SHA-256 message digest. */
    ZY_MBEDTLS_MD_SHA384 = 0x0a,  /**< The SHA-384 message digest. */
    ZY_MBEDTLS_MD_SHA512 = 0x0b,  /**< The SHA-512 message digest. */
    ZY_MBEDTLS_MD_SHA3_224 = 0x10,/**< The SHA3-224 message digest. */
    ZY_MBEDTLS_MD_SHA3_256 = 0x11,/**< The SHA3-256 message digest. */
    ZY_MBEDTLS_MD_SHA3_384 = 0x12,/**< The SHA3-384 message digest. */
    ZY_MBEDTLS_MD_SHA3_512 = 0x13,/**< The SHA3-512 message digest. */
} mbedtls_md_type_t_1;

/**
 * Function to calculate CMAC using AES-128.
 * 
 * @param key: Pointer to the key used for CMAC calculation.
 * @param key_len: Length of the key in bytes.
 * @param input: Pointer to the input data used for CMAC calculation.
 * @param input_len: Length of the input data in bytes.
 * @param cmac_output: Pointer to the output buffer where the CMAC result will be stored.
 * @return 0 if successful, or an error code if unsuccessful.
 */
int Calculate_CMAC(unsigned char *key, size_t key_len, const unsigned char *input, size_t input_len, unsigned char *cmac_output);

/**
 * Function to start the hash calculation.
 * 
 * @param md_type: The type of the message digest to use (e.g. SHA-256).
 * @return 0 if successful, or an error code if unsuccessful.
 */
int Calculate_hash_start(mbedtls_md_type_t_1 md_type);

/**
 * Function to update the hash with more data.
 * 
 * @param input: Pointer to the input data to be added to the hash.
 * @param input_len: Length of the input data in bytes.
 * @return 0 if successful, or an error code if unsuccessful.
 */
int Calculate_hash_update(const unsigned char *input, size_t input_len);

/**
 * Function to finish the hash calculation and produce the final output.
 * 
 * @param output: Pointer to the output buffer for the final hash value.
 * @return 0 if successful, or an error code if unsuccessful.
 */
int Calculate_hash_finish(unsigned char *output);

/**
 * Function to verify an RSA signature using a public key in DER format.
 * 
 * @param pub_key_der: Pointer to the DER encoded public key used for signature verification.
 * @param pub_key_len: Length of the DER encoded public key in bytes.
 * @param message: Pointer to the message that was signed.
 * @param message_len: Length of the message in bytes.
 * @param signature: Pointer to the signature to be verified.
 * @param sig_len: Pointer to length of the signature in bytes.
 * @return 0 if the signature is valid, non-zero if it is invalid or an error occurred.
 */
int rsa_signature(const unsigned char *priv_key_der, size_t priv_key_len,
                  const unsigned char *signature, size_t *sig_len,
                  const unsigned char *hash, size_t hash_len);

/**
 * Function to verify an RSA signature.
 * 
 * @param der_key: Pointer to the DER encoded key (either public or private key).
 * @param der_key_len: Length of the DER encoded key in bytes.
 * @param message: Pointer to the message that was signed.
 * @param message_len: Length of the message in bytes.
 * @param signature: Pointer to the signature to be verified.
 * @param sig_len: Length of the signature in bytes.
 * @return 0 if the signature is valid, non-zero if it is invalid or an error occurred.
 */
int rsa_verify(const unsigned char *der_key, size_t der_key_len,
               const unsigned char *signature, size_t sig_len,
               const unsigned char *hash, size_t hash_len);

/**
 * Function to encrypt data using RSA with a public key in DER format.
 * 
 * @param pub_key_der: Pointer to the DER encoded public key used for encryption.
 * @param pub_key_len: Length of the DER encoded public key in bytes.
 * @param input: Pointer to the input data to be encrypted.
 * @param ilen: Length of the input data in bytes.
 * @param output: Pointer to the output buffer where the encrypted data will be stored.
 * @return 0 if successful, or an error code if unsuccessful.
 */
int rsa_encrypt(const unsigned char *pub_key_der, size_t pub_key_len,
                const unsigned char *input, size_t ilen,
                unsigned char *output);

/**
 * Function to decrypt data using RSA with a private key in DER format.
 * 
 * @param priv_key_der: Pointer to the DER encoded private key used for decryption.
 * @param priv_key_len: Length of the DER encoded private key in bytes.
 * @param input: Pointer to the input data to be decrypted.
 * @param ilen: Length of the input data in bytes.
 * @param output: Pointer to the output buffer where the decrypted data will be stored.
 * @param olen: Pointer to the variable that will receive the length of the decrypted data in bytes.
 * @return 0 if successful, or an error code if unsuccessful.
 */
int rsa_decrypt(const unsigned char *priv_key_der, size_t priv_key_len,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen);

/**
 * Function to encrypt data using AES in CBC mode.
 * 
 * @param input: Pointer to the data to be encrypted.
 * @param input_length: Length of the data to be encrypted.
 * @param encrypted_data: Pointer to the buffer where the encrypted data will be stored.
 * @param key: Pointer to the AES encryption key.
 * @return Length of the encrypted data, or a negative value if an error occurred.
 */
int encrypt_data_by_aes_cbc(unsigned char *input, int input_length, unsigned char *encrypted_data, unsigned char *key);

/**
 * Function to decrypt data using AES in CBC mode.
 * 
 * @param encrypted_data: Pointer to the data to be decrypted.
 * @param encrypted_length: Length of the encrypted data.
 * @param decrypted_data: Pointer to the buffer where the decrypted data will be stored.
 * @param key: Pointer to the AES decryption key.
 * @return Length of the decrypted data, or a negative value if an error occurred.
 */
int decrypt_data_by_aes_cbc(unsigned char *encrypted_data, int encrypted_length, unsigned char *decrypted_data, unsigned char *key);

/**
 * Function to run the main test cases for the implemented algorithms.
 */
void TestMainfunction();

#endif /* ALGORITHMIF_H_ */
