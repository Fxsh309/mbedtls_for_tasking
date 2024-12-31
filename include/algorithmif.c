/*
 *  EQ_Interface/Algorithmif.c
 *
 *  Copyright (C) 2024.  <kxx>
 *
 *  This file is based on the mbedtls library.The mbedtls library version is 3.6.2.
 * 
 */

/* Include files */

#include "cmac.h"
#include "rsa.h"
#include "ctr_drbg.h"
#include "pk.h"
#include "entropy_poll.h"
#include "sha256.h"
#include "md.h"
#include "Algorithmif.h"
#include "aes.h"
#include "memory_buffer_alloc.h"

/* Global variables */

mbedtls_md_context_t md_ctx_area;

/* Macros */
#define RSA_KEY_SIZE 2048
#define EXPONENT 65537
#define MAX_INPUT_LENGTH 1024


/* Functions */

int Calculate_CMAC(unsigned char *key, size_t key_len, const unsigned char *input, size_t input_len, unsigned char *cmac_output)
{
    int32_t ret;
    mbedtls_cipher_context_t cipher_ctx;
    unsigned char cmac_result[16];  // AES-128 produces 16-byte CMAC

    /* Initialize the cipher context */
    mbedtls_cipher_init(&cipher_ctx);

    // Set up AES-128 CMAC
    if ((ret = mbedtls_cipher_setup(&cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB))) != 0) {
        goto end;
    }

    // Start CMAC operation
    if ((ret = mbedtls_cipher_cmac_starts(&cipher_ctx, key, key_len)) != 0) {
        goto end;
    }

    // Update CMAC with the input data
    if ((ret = mbedtls_cipher_cmac_update(&cipher_ctx, input, input_len)) != 0) {
        goto end;
    }

    // Finish the CMAC calculation
    if ((ret = mbedtls_cipher_cmac_finish(&cipher_ctx, cmac_result)) != 0) {
        goto end;
    }

    // Copy the CMAC result to the output buffer
    memcpy(cmac_output, cmac_result, 16);

end:

    mbedtls_cipher_free(&cipher_ctx);

    return ret;
}

int Calculate_hash_start(mbedtls_md_type_t_1 md_type)
{
    int ret;

    mbedtls_md_init(&md_ctx_area);
    ret = mbedtls_md_setup(&md_ctx_area, mbedtls_md_info_from_type(md_type), 0);

    if(ret == 0)
    {
        ret = mbedtls_md_starts(&md_ctx_area);
    }
    else
    {
        mbedtls_md_free(&md_ctx_area);
    }
    
    return ret;
}

int Calculate_hash_update(const unsigned char *input, size_t input_len)
{   
    int ret;

    ret = mbedtls_md_update(&md_ctx_area, input, input_len);

    return ret;
}

int Calculate_hash_finish(unsigned char *output)
{
    int ret;

    ret = mbedtls_md_finish(&md_ctx_area, output);

    mbedtls_md_free(&md_ctx_area);
    
    return ret;
}

int get_entropy_from_lcg(void *data, unsigned char *output, size_t len, size_t *olen) {
    unsigned long seed = 1;
    seed = (1103515245 * seed + 12345) % (1U << 31);
    if (len < sizeof(unsigned long)) {
        return 0; 
    }

    for (size_t i = 0; i < len / sizeof(unsigned long); i++) {
        unsigned long random_number = seed;
        memcpy(output + i * sizeof(unsigned long), &random_number, sizeof(unsigned long));
    }

    *olen = len; 
    return 0; 
}

int rsa_signature(const unsigned char *priv_key_der, size_t priv_key_len,
                  const unsigned char *signature, size_t *sig_len, 
                  const unsigned char *hash, size_t hash_len) {
    int ret;
    const char *personalization = "Fr789jj-ikrkjfjs@";
    // mbedtls_rsa_context *rsa;
    
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy_context;
    mbedtls_ctr_drbg_context ctr_drbg_context;
    
    /* initialize the entropy context */
    mbedtls_entropy_init(&entropy_context);

    mbedtls_ctr_drbg_init(&ctr_drbg_context);

    /* initialize the PK context */
    mbedtls_pk_init(&pk);

    /* add entropy source */
    ret = mbedtls_entropy_add_source(&entropy_context,get_entropy_from_lcg,NULL,MBEDTLS_ENTROPY_MIN_PLATFORM,MBEDTLS_ENTROPY_SOURCE_STRONG);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg_context, mbedtls_entropy_func, &entropy_context, personalization,sizeof(personalization));

    /* parse the private key (der format) */
    ret = mbedtls_pk_parse_key(&pk, priv_key_der, priv_key_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg_context);
    if (ret != 0) {
        goto end;
    }

    /* set the RSA padding mode to PKCS#1 v1.5/rsassa-pss with SHA-256 */
    ret = mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk),MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
    if (ret != 0) {
        goto end;
    }

    /* sign the hash value with the private key */
    ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, hash_len, \
                            signature, 256, sig_len, mbedtls_ctr_drbg_random, &ctr_drbg_context);
    if (ret != 0) {
        goto end;
    }

end:

    /* clean up */
    mbedtls_pk_free(&pk);
    mbedtls_entropy_free(&entropy_context);
    mbedtls_ctr_drbg_free(&ctr_drbg_context);

    return ret;
}

/* RSA verify signature */
int rsa_verify(const unsigned char *der_key, size_t der_key_len,
               const unsigned char *signature, size_t sig_len,
               const unsigned char *hash, size_t hash_len) {
    int ret;
    mbedtls_rsa_context *rsa;
    mbedtls_pk_context pk;

    /* initialize the pk contest */
    mbedtls_pk_init(&pk);

    /* parse the public key (der format) */
    ret = mbedtls_pk_parse_public_key(&pk, der_key, der_key_len);
    if (ret != 0) {
        goto end;
    }

    /* extract the RSA key from the PK context */
    rsa = mbedtls_pk_rsa(pk);
    if (rsa == NULL) {
        goto end;
    }

    /* set the RSA padding mode to PKCS#1 v1.5/rsassa-pss with SHA-256 */
    ret = mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    if (ret != 0) {
        goto end;
    }

    /* verify the signature with the public key */
    ret = mbedtls_rsa_pkcs1_verify(rsa, MBEDTLS_MD_SHA256, hash_len, hash, signature);
    if (ret != 0) {
        goto end;
    }

end:

    /* clean up */
    mbedtls_rsa_free(rsa);
    mbedtls_pk_free(&pk);

    return ret;
}

/* RSA encrypt data */
int rsa_encrypt(const unsigned char *pub_key_der, size_t pub_key_len,
                const unsigned char *input, size_t ilen,
                unsigned char *output) {
    int ret;
    
    const char *pers = "rsa_example";
    mbedtls_rsa_context *rsa;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;


    /* initialize the entropy context and the DRBG context */
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    /* add entropy source */
    mbedtls_entropy_add_source(&entropy,get_entropy_from_lcg,NULL,MBEDTLS_ENTROPY_MIN_PLATFORM,MBEDTLS_ENTROPY_SOURCE_STRONG);
    
    /* generate a random number for the DRBG */
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        goto end;
    }

    /* load the public key (DER format) */
    ret = mbedtls_pk_parse_public_key(&pk, pub_key_der, pub_key_len);
    if (ret != 0) {
        goto end;
    }

    /* extract the RSA key from the PK context */
    rsa = mbedtls_pk_rsa(pk);
    if (rsa == NULL) {

        ret = -1;  
        goto end;
    }

    /* set the RSA padding mode to PKCS#1 v1.5/OAEP with SHA-256 */
    ret = mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    if (ret != 0) {
        goto end;
    }

    /* encrypt the input data with the public key */
    ret = mbedtls_rsa_pkcs1_encrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, ilen, input, output);
    if (ret != 0) {
        goto end;
    }

end:

    /* clean up */
    mbedtls_pk_free(&pk);
    mbedtls_rsa_free(rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

int rsa_decrypt(const unsigned char *priv_key_der, size_t priv_key_len,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen) {
    int ret;
    const char *pers = "rsa_example";
    mbedtls_pk_context pk;  
    mbedtls_rsa_context *rsa;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    /* initialize the entropy context and the DRBG context */
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    /* add entropy source */
    mbedtls_entropy_add_source(&entropy,get_entropy_from_lcg,NULL,MBEDTLS_ENTROPY_MIN_PLATFORM,MBEDTLS_ENTROPY_SOURCE_STRONG);
    
    /* generate a random number for the DRBG */
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        goto end;
    }

    /* initialize the PK context */
    mbedtls_pk_init(&pk);

    /* parse the private key (der format) */
    ret = mbedtls_pk_parse_key(&pk, priv_key_der, priv_key_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        goto end;
    }

    /* extract the RSA key from the PK context */
    rsa = mbedtls_pk_rsa(pk);
    if (rsa == NULL) {
       goto end;
    }

    /* set the RSA padding mode to PKCS#1 v1.5/OAEP with SHA-256 
     ret = mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
     if (ret != 0) {
         goto end;
    } */

    /* use the private key to decrypt the input data */
    ret = mbedtls_rsa_pkcs1_decrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, olen, input, output, 256);
    if (ret != 0) {
        goto end;
    }

end:
    /* clean up */
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}


int encrypt_data_by_aes_cbc(unsigned char *input,int input_length,unsigned char *encrypted_data,unsigned char *key){
    mbedtls_aes_context aes_context;
    int result = 0;
    int padding = 0;
    int real_input_length = 0;
    unsigned char padding_code;
    // unsigned char *input_tmp;
    unsigned char input_tmp[MAX_INPUT_LENGTH];
    // //AES keys
    // const unsigned char key[16] = "1234567890ABCDEF";
    //When using CBC/CBF/OFB and other modes, an initialization vector IV is required
    unsigned char iv[16] = "0099887766554433";
    /*
    AES is a block cipher algorithm, where a block length must be 16 bytes and all data to be encrypted must be
     an integer multiple of 16 bytes.If the data to be encrypted is not an integer multiple of 16 bytes, it must 
     be filled to an integer multiple of 16 bytes first. Common filling methods include PKCS5 and PKCS7, with PKCS7 
     commonly used for filling
    */
    /* PKCS7 is padded to an integer multiple of 16 bytes. If the data to be encrypted happens to be an integer 
    multiple of 16 bytes, 16 bytes still need to be padded
    */
    //Calculate the difference between the current length distance and multiples of 16, which is the value for filling in the recharge
    padding = 16 - (input_length%16);
    padding_code = (char)padding;
    //real_input_length-The length of the data to be encrypted after being filled must be a multiple of 16, and this length is also the length of the encrypted ciphertext
    real_input_length = input_length + padding;

    memcpy(input_tmp,input,input_length);
    memset(input_tmp + input_length,padding_code,padding);

    mbedtls_aes_init(&aes_context);
    //If AES-128 is used, the necessary length is 128 bits. If AES-256 is used, the key length is 256 bits
    result = mbedtls_aes_setkey_enc(&aes_context, key, 128);
    if(result != 0){

       goto end;
    }

    result = mbedtls_aes_crypt_cbc(&aes_context, MBEDTLS_AES_ENCRYPT, real_input_length,iv,input_tmp,encrypted_data);
    if(result != 0){

        goto end;
    }

    // goto end;
    //Return ciphertext length
    return real_input_length;

    end:
    /* clean up */
        mbedtls_aes_free(&aes_context);

    goto end;

}


int decrypt_data_by_aes_cbc(unsigned char *encrypted_data,int encrypted_length,unsigned char *decrypted_data,unsigned char *key){
    mbedtls_aes_context aes_context;
    int result = 0;
    int padding = 0;
    unsigned char padding_code;
    //AES key
    // const unsigned char key[16] = "1234567890ABCDEF";
    unsigned char iv[16] = "0099887766554433";
    //After decryption, the plaintext containing the filled value needs to be removed in the future
    unsigned char decrypted_data_include_padding[encrypted_length];

    mbedtls_aes_init(&aes_context);
    result = mbedtls_aes_setkey_dec(&aes_context, key, 128);

    if(result != 0){
        goto end;
    }

    result = mbedtls_aes_crypt_cbc(&aes_context, MBEDTLS_AES_DECRYPT, encrypted_length,iv,encrypted_data,decrypted_data_include_padding);
    if(result != 0){
        goto end;
    }

//Remove the padding value of PKCS # 7
//Read the last value, which is the length of the recharge filled in
    padding_code = decrypted_data_include_padding[encrypted_length-1];
    padding = (int)padding_code;
    if(padding < 1 || padding > 16){
        goto end;
    }
    int real_decrypted_data_length = encrypted_length - padding;

    memcpy(decrypted_data,decrypted_data_include_padding,real_decrypted_data_length);

    

end:
    /* clean up */
    mbedtls_aes_free(&aes_context);
    return real_decrypted_data_length;
}

#ifdef MBEDTLS_PK_WRITE_C
uint8_t public_key_test[1024];
uint8_t private_key_test[1500]; 
void Generate_RSA_Key(uint8_t *public_key_der, uint8_t *private_key_der)
{
    int ret;
    mbedtls_pk_context pk_context;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    size_t public_key_len, private_key_len;

    /* Initialize the context */
    mbedtls_pk_init(&pk_context);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    /* add entropy source */
    ret = mbedtls_entropy_add_source(&entropy, get_entropy_from_lcg, NULL, MBEDTLS_ENTROPY_MIN_PLATFORM, MBEDTLS_ENTROPY_SOURCE_STRONG);
    if (ret != 0) {
        goto end;
    }

    const char *pers = "rsa_example";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        goto end;
    }

    /* generate pk_context with RSA key pair */
    ret = mbedtls_pk_setup(&pk_context, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0) {
        goto end;
    }

    /* generate RSA key pair */
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk_context), mbedtls_ctr_drbg_random, &ctr_drbg, RSA_KEY_SIZE, EXPONENT);
    if (ret != 0) {
        goto end;
    }

    /* output public key in DER format */
    public_key_len = sizeof(public_key_test);  
    ret = mbedtls_pk_write_pubkey_der(&pk_context, public_key_der, public_key_len);
    if (ret < 0) {
        goto end;
    }
    public_key_len = ret; 

    /* output private key in DER format */
    private_key_len = sizeof(private_key_test);  
    ret = mbedtls_pk_write_key_der(&pk_context, private_key_der, private_key_len);
    if (ret < 0) {
        goto end;
    }
    private_key_len = ret;  

end:
    /* clean up */
    mbedtls_pk_free(&pk_context);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

}
#endif


#if 0 /*for test only*/
unsigned char private_key[] = {
0x30,0x82,0x04,0xbc,0x02,0x01,0x00,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,
0x05,0x00,0x04,0x82,0x04,0xa6,0x30,0x82,0x04,0xa2,0x02,0x01,0x00,0x02,0x82,0x01,0x01,0x00,0xc5,0xca,
0x01,0x37,0x15,0x42,0x3e,0xd3,0x7b,0xc5,0x5d,0xa8,0x06,0x0f,0x24,0xbb,0x81,0x97,0x64,0xbe,0x17,0x92,
0xeb,0x05,0xfa,0x37,0x53,0xcf,0x76,0x60,0x36,0x23,0xea,0xe7,0x59,0x04,0x85,0x74,0x50,0xbb,0x1a,0x2f,
0xab,0x60,0xd6,0x7f,0x56,0x91,0xc5,0x7a,0x89,0xe7,0x04,0xae,0xd5,0x05,0x79,0x85,0xe5,0xb3,0x44,0xd4,
0xb9,0xcd,0x72,0xc1,0xae,0xd7,0xce,0x30,0xca,0xf8,0xd8,0xd4,0x5d,0x0c,0xdf,0xa7,0xb4,0x34,0x08,0xd8,
0x55,0x0c,0xab,0x3f,0xc0,0xd4,0xd1,0x63,0x22,0xda,0xf2,0x90,0x9f,0x7b,0x9a,0x46,0x7f,0x44,0x43,0x0f,
0x84,0x06,0x0f,0xd6,0x4d,0x29,0xff,0x0c,0xaa,0x78,0x21,0xdf,0x76,0x47,0xab,0x79,0x52,0xee,0xe2,0xf2,
0x93,0x8d,0x9f,0xc8,0xa1,0x76,0xaa,0x53,0x15,0x55,0x55,0xf2,0x54,0xcc,0x19,0x60,0xea,0x3c,0x4b,0x34,
0x6b,0x0c,0x4c,0x01,0x5d,0x4e,0x39,0xda,0xaa,0x40,0x25,0x96,0xd6,0xf8,0x02,0xc3,0x4a,0x2f,0x6b,0x00,
0x1c,0xae,0xee,0x25,0x84,0x5c,0x6e,0x69,0x8e,0x4b,0xf9,0x97,0xd0,0x1b,0x2e,0x25,0x12,0xf8,0xcf,0x53,
0x9d,0x3e,0xf1,0xd6,0x1d,0x3b,0xcf,0xf1,0xd3,0x80,0xa1,0xd8,0xb6,0x1f,0xd8,0x4c,0x5b,0xd9,0x5e,0xa1,
0xd4,0x42,0x92,0x9c,0x1b,0x61,0xb4,0xc0,0x9e,0x4f,0x79,0x2a,0xdd,0xf6,0x3f,0x80,0x10,0x86,0xec,0xda,
0x21,0x2e,0xc5,0x96,0xda,0x3b,0x0a,0xfc,0x57,0xd4,0x96,0xf7,0xc1,0x90,0xd7,0x80,0x7e,0x94,0xc0,0xab,
0x9c,0xc5,0xa4,0x93,0xed,0x5a,0x34,0x1d,0x34,0x72,0xb6,0xaf,0x98,0x17,0x02,0x03,0x01,0x00,0x01,0x02,
0x82,0x01,0x00,0x3b,0xc6,0xec,0x8d,0x18,0x48,0xb8,0x32,0x34,0x83,0x16,0xe6,0x34,0x46,0x99,0x64,0x6e,
0x2b,0x32,0x50,0x5d,0x51,0x92,0xe4,0x70,0x96,0x0e,0x27,0x72,0x70,0x6b,0x8c,0x79,0x6f,0x48,0x31,0x1c,
0xa0,0x65,0xd1,0xd6,0x7d,0x37,0xbf,0x81,0xb4,0x64,0x96,0x93,0xe7,0x90,0x0c,0x19,0x17,0x39,0xdc,0x78,
0xb8,0xe6,0x0e,0x43,0x2c,0x43,0xa7,0x7b,0x1a,0x5c,0x5c,0x6e,0xbd,0xc2,0x6a,0x69,0x25,0xed,0xa5,0x79,
0x66,0xf7,0x08,0x8e,0xef,0xca,0xec,0x94,0x49,0x25,0x5f,0x6c,0x95,0x18,0xb0,0xb1,0x84,0xd2,0x1e,0x8a,
0x26,0xea,0x49,0xd8,0x36,0xb5,0x41,0x1b,0xc2,0x39,0xfa,0x0a,0x52,0x6a,0xa6,0xfa,0x1d,0xce,0x62,0xa4,
0xc9,0x7b,0x2e,0x25,0xbb,0x08,0xab,0x51,0xf2,0x52,0x11,0xc1,0xc4,0x60,0x5b,0x61,0xba,0x2d,0x56,0x32,
0xcd,0x0e,0x78,0x94,0x79,0x30,0x82,0xce,0xc5,0xb8,0xe3,0xd2,0xd5,0x51,0x51,0x0c,0xa8,0xd6,0x2d,0x67,
0x62,0xb2,0xa2,0xff,0x32,0xab,0xbc,0x37,0xd2,0x58,0x4e,0xbe,0x67,0xe6,0xd8,0xc7,0x3a,0x2a,0xa4,0x73,
0x95,0x33,0x48,0xe1,0xb9,0xbb,0xba,0x54,0x04,0x1e,0x45,0xf5,0x58,0x46,0x93,0x0a,0x73,0xb5,0x6f,0xc6,
0x4f,0x98,0x0d,0xad,0x3f,0x88,0x5a,0x01,0x32,0x85,0x31,0xcc,0xbf,0x4f,0xbe,0x0e,0x6f,0x62,0xd6,0x29,
0xb1,0x9e,0x37,0x18,0x6a,0xc4,0x1a,0x6c,0xa2,0x90,0x0c,0xc8,0x07,0xfd,0xc3,0x4b,0xc8,0xe9,0x92,0x7b,
0x87,0xcd,0x03,0xc8,0xf3,0xb3,0x31,0xb7,0x8f,0x7e,0xaa,0x4e,0x63,0xd0,0x94,0xa6,0xc4,0x0a,0xb1,0x02,
0x81,0x81,0x00,0xf3,0x46,0x28,0x7f,0x0d,0x52,0x44,0x0b,0x1b,0x42,0x11,0x46,0x87,0x12,0xa7,0x86,0x5e,
0x16,0xfc,0x19,0xb6,0x6f,0x66,0xcd,0x9f,0x9e,0x04,0x2a,0xd1,0x2c,0xc5,0x03,0x64,0xad,0x90,0x51,0x26,
0x0c,0xa8,0x71,0xf4,0x0e,0x20,0xa2,0xd0,0xa2,0x32,0x68,0x6b,0xd0,0xe4,0x22,0xcd,0xae,0x92,0x87,0x82,
0x5f,0x35,0x8a,0x56,0x99,0xeb,0x09,0xe1,0x8f,0xef,0x42,0xac,0x88,0x93,0x1c,0xae,0x17,0xec,0x88,0x53,
0x14,0xc9,0x18,0x30,0xad,0x84,0xa6,0xf7,0xb2,0x70,0xcf,0x71,0xd8,0x20,0x00,0xf7,0x09,0x1d,0xa9,0x30,
0x7f,0xfa,0x7b,0xfc,0x55,0xae,0x52,0xc0,0x60,0x78,0x6c,0x68,0xbc,0xa5,0x9a,0x24,0xe4,0x29,0xd8,0x23,
0x80,0xda,0x0d,0xfd,0x38,0x4a,0xc7,0x82,0x9d,0x6c,0x99,0x02,0x81,0x81,0x00,0xd0,0x22,0xba,0x40,0xb7,
0xbb,0x5c,0x94,0x10,0x85,0xa2,0x62,0x34,0x8d,0xda,0x7a,0x3d,0xe3,0x0a,0xf6,0xdd,0xb2,0x45,0x1c,0x22,
0x81,0x38,0x5c,0x64,0x72,0x08,0x8e,0x44,0x85,0x40,0xbb,0x77,0x3b,0x96,0x0b,0x31,0xb2,0xec,0xeb,0xf7,
0x89,0x37,0xd1,0x4f,0x6b,0x6c,0x5e,0x98,0x42,0xef,0xf6,0x29,0x93,0x21,0x00,0x20,0x39,0x72,0x0e,0x6f,
0x71,0x81,0x09,0xd0,0xf3,0x6e,0xd0,0xf6,0xef,0xdc,0x4e,0xdc,0xca,0x33,0xaa,0x13,0xc8,0x7e,0x0d,0x7f,
0x4b,0x18,0x8a,0x0b,0xa2,0x05,0x6d,0x1f,0xa7,0xd4,0x30,0x62,0xcf,0xf5,0xca,0x9c,0x62,0xf0,0x72,0x80,
0xa0,0x3c,0xe9,0x11,0x6e,0x93,0x7c,0xf1,0x1d,0x62,0x2f,0x51,0xef,0x70,0x62,0x57,0x41,0x92,0x0b,0xc9,
0x0e,0xe8,0x2f,0x02,0x81,0x80,0x43,0x84,0x8c,0x46,0xbe,0xde,0xbf,0x2d,0xc9,0xf1,0xeb,0x33,0x84,0xd7,
0x83,0x91,0x42,0x59,0xe4,0xbc,0x0a,0x2b,0x1f,0x00,0x20,0xb5,0xcd,0x78,0x48,0xb7,0xc1,0x32,0x30,0xe6,
0x0e,0xf0,0xc6,0xbb,0xaa,0xa0,0x7d,0xd8,0xd1,0xeb,0xfe,0x35,0x96,0x01,0xef,0x32,0x79,0xae,0xc3,0x21,
0x19,0x5f,0xec,0xaa,0x1a,0x04,0xfc,0x06,0x19,0xfa,0x93,0x14,0xcc,0x95,0xd7,0xa6,0xcc,0x15,0xa0,0xa7,
0xd9,0x28,0xf8,0xce,0x03,0x05,0xe8,0xb4,0xaf,0xe5,0x5b,0x47,0xb6,0x11,0x8d,0x0a,0x2b,0xcf,0xb8,0xc0,
0x59,0xf0,0x14,0x1a,0xe0,0xdd,0x3a,0x6a,0x59,0x48,0x74,0x46,0x12,0x06,0x1c,0x87,0x86,0xfa,0xa2,0x14,
0x85,0x1c,0x8c,0xb5,0xfd,0x4e,0xf6,0xa1,0x81,0xf7,0x9f,0x63,0xab,0xb9,0x02,0x81,0x80,0x2f,0x64,0xa8,
0xfa,0x91,0x9b,0xb5,0x41,0xf5,0xdd,0x28,0x13,0xaa,0x99,0xde,0x74,0xd5,0x60,0xbc,0x9f,0x67,0xed,0xee,
0xf4,0xb0,0x1a,0xb2,0x85,0xbf,0x4d,0x84,0x0b,0x39,0x29,0x0a,0x8b,0x65,0x64,0x09,0x0f,0x75,0x7a,0xa3,
0x9e,0x3b,0x98,0x60,0x40,0x66,0x10,0x34,0xf5,0xf9,0x3f,0xcc,0xba,0x45,0xcf,0x3d,0xc5,0x74,0x91,0x00,
0x1a,0xaf,0x5f,0xae,0x1d,0x59,0x1a,0x05,0x52,0xc9,0xd7,0xe6,0x57,0x82,0xc8,0xfc,0x28,0xaf,0x26,0x89,
0x25,0x73,0xa5,0xda,0xe9,0x9c,0x2a,0x81,0x87,0xce,0x9c,0x7d,0xa1,0xa2,0xee,0x6d,0xae,0x7c,0x1b,0xbf,
0x5a,0xa3,0x55,0x59,0x69,0x4c,0xd1,0xdb,0xfd,0xa8,0x3d,0xa3,0x9c,0xd8,0xd0,0x67,0xcb,0xcc,0xc8,0x9e,
0x83,0xd6,0x7d,0x71,0x7b,0x02,0x81,0x80,0x56,0x74,0x2a,0x38,0xa7,0x9e,0xff,0x43,0x7b,0x03,0x68,0x4c,
0xba,0x9b,0x2f,0xce,0xfe,0xd3,0xeb,0x60,0x98,0xef,0x28,0x41,0x77,0x72,0x3e,0x75,0xad,0x4d,0xee,0x09,
0x4b,0xb2,0xcd,0x5f,0x3f,0x83,0x5a,0x74,0xa8,0x5d,0x75,0x0e,0xfe,0xb3,0xe8,0xa9,0xd6,0xe0,0x84,0x1f,
0xfa,0x90,0x61,0x0a,0x5c,0x5d,0x32,0xc0,0x15,0xab,0x4e,0x30,0xf3,0x82,0xc7,0xfd,0xb8,0xbf,0xec,0xff,
0x26,0xe7,0x83,0x10,0xdc,0x86,0x4e,0xc6,0x72,0x8d,0x69,0x04,0xf6,0x84,0x69,0xe8,0x3e,0xd1,0xe0,0x55,
0xe4,0x74,0x9e,0x65,0xb6,0xfa,0x81,0x6e,0xbc,0xa1,0x96,0xe7,0xaa,0x89,0x21,0x2a,0x6b,0x04,0x46,0x23,
0x47,0x78,0x55,0xaf,0xc3,0x57,0xae,0xe7,0xdb,0xb4,0xb0,0x20,0x5a,0xc6,0xd0,0xd5
};


unsigned char public_key[] = {
0x30,0x82,0x01,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,
0x82,0x01,0x0f,0x00,0x30,0x82,0x01,0x0a,0x02,0x82,0x01,0x01,0x00,0xc5,0xca,0x01,0x37,0x15,0x42,0x3e,
0xd3,0x7b,0xc5,0x5d,0xa8,0x06,0x0f,0x24,0xbb,0x81,0x97,0x64,0xbe,0x17,0x92,0xeb,0x05,0xfa,0x37,0x53,
0xcf,0x76,0x60,0x36,0x23,0xea,0xe7,0x59,0x04,0x85,0x74,0x50,0xbb,0x1a,0x2f,0xab,0x60,0xd6,0x7f,0x56,
0x91,0xc5,0x7a,0x89,0xe7,0x04,0xae,0xd5,0x05,0x79,0x85,0xe5,0xb3,0x44,0xd4,0xb9,0xcd,0x72,0xc1,0xae,
0xd7,0xce,0x30,0xca,0xf8,0xd8,0xd4,0x5d,0x0c,0xdf,0xa7,0xb4,0x34,0x08,0xd8,0x55,0x0c,0xab,0x3f,0xc0,
0xd4,0xd1,0x63,0x22,0xda,0xf2,0x90,0x9f,0x7b,0x9a,0x46,0x7f,0x44,0x43,0x0f,0x84,0x06,0x0f,0xd6,0x4d,
0x29,0xff,0x0c,0xaa,0x78,0x21,0xdf,0x76,0x47,0xab,0x79,0x52,0xee,0xe2,0xf2,0x93,0x8d,0x9f,0xc8,0xa1,
0x76,0xaa,0x53,0x15,0x55,0x55,0xf2,0x54,0xcc,0x19,0x60,0xea,0x3c,0x4b,0x34,0x6b,0x0c,0x4c,0x01,0x5d,
0x4e,0x39,0xda,0xaa,0x40,0x25,0x96,0xd6,0xf8,0x02,0xc3,0x4a,0x2f,0x6b,0x00,0x1c,0xae,0xee,0x25,0x84,
0x5c,0x6e,0x69,0x8e,0x4b,0xf9,0x97,0xd0,0x1b,0x2e,0x25,0x12,0xf8,0xcf,0x53,0x9d,0x3e,0xf1,0xd6,0x1d,
0x3b,0xcf,0xf1,0xd3,0x80,0xa1,0xd8,0xb6,0x1f,0xd8,0x4c,0x5b,0xd9,0x5e,0xa1,0xd4,0x42,0x92,0x9c,0x1b,
0x61,0xb4,0xc0,0x9e,0x4f,0x79,0x2a,0xdd,0xf6,0x3f,0x80,0x10,0x86,0xec,0xda,0x21,0x2e,0xc5,0x96,0xda,
0x3b,0x0a,0xfc,0x57,0xd4,0x96,0xf7,0xc1,0x90,0xd7,0x80,0x7e,0x94,0xc0,0xab,0x9c,0xc5,0xa4,0x93,0xed,
0x5a,0x34,0x1d,0x34,0x72,0xb6,0xaf,0x98,0x17,0x02,0x03,0x01,0x00,0x01,
};

uint8 hash_output[32];
uint8 signature[256];
uint8 signature_len;
uint8 encrypted_data[256];
uint8 encrypted_data_len = 256;
uint8 decrypted_data[20];
uint8 decrypted_data_len;
uint8 cmac_encrypted_data[16];
uint8 cmac_encrypted_data_len;
uint8 cmac_decrypted_data[16];
uint8 cmac_decrypted_data_len;
uint8 AES_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
int SSSTATUS;

Calculate_hash_start(ZY_MBEDTLS_MD_SHA256);
Calculate_hash_update("hello world", 11);
Calculate_hash_finish(hash_output);

SSSTATUS = rsa_signature(private_key,sizeof(private_key),signature,&signature_len,hash_output,32);
SSSTATUS = rsa_verify(public_key, sizeof(public_key), signature, signature_len, hash_output, 32);

SSSTATUS = rsa_encrypt(public_key, sizeof(public_key), "hello world", 11, encrypted_data);
SSSTATUS = rsa_decrypt(private_key, sizeof(private_key), encrypted_data, encrypted_data_len, decrypted_data, &decrypted_data_len);

SSSTATUS = encrypt_data_by_aes_cbc("hello world", 11, cmac_encrypted_data, AES_key);
SSSTATUS = decrypt_data_by_aes_cbc(cmac_encrypted_data, 16, cmac_decrypted_data, AES_key);

#endif