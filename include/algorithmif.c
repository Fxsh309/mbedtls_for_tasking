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
unsigned char plaint_buffer[256];

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
                  const unsigned char *hash, size_t hash_len,
                  mbedtls_rsa_pkcs_version_t_1 padding_mode) {
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
    ret = mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk),padding_mode,MBEDTLS_MD_SHA256);
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
               const unsigned char *hash, size_t hash_len,
               mbedtls_rsa_pkcs_version_t_1 padding_mode) {
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
    ret = mbedtls_rsa_set_padding(rsa, padding_mode, MBEDTLS_MD_SHA256);
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
                unsigned char *output,mbedtls_rsa_pkcs_version_t_1 padding_mode) {
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
    ret = mbedtls_rsa_set_padding(&rsa, padding_mode, MBEDTLS_MD_SHA256);
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
                size_t *olen,mbedtls_rsa_pkcs_version_t_1 padding_mode)
{
    int ret;
    const char *pers = "rsa_example";
    mbedtls_pk_context pk;  
    //mbedtls_rsa_context *rsa;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;


    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_add_source(&entropy, get_entropy_from_lcg, NULL, MBEDTLS_ENTROPY_MIN_PLATFORM, MBEDTLS_ENTROPY_SOURCE_STRONG);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        goto end;
    }


    mbedtls_pk_init(&pk);

    ret = mbedtls_pk_parse_key(&pk, priv_key_der, priv_key_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        goto end;
    }

   
    // rsa = mbedtls_pk_rsa(pk);
    // if (rsa == NULL) {
    //     ret = -1;  
    //     goto end;
    // }

    size_t key_len = mbedtls_rsa_get_len(mbedtls_pk_rsa(pk));


    if(padding_mode == ZY_MBEDTLS_RSA_PKCS_V15)
    {
        ret = mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), padding_mode, MBEDTLS_MD_SHA256);
        if (ret != 0) {
            goto end;
        }
    }
    else if(padding_mode == ZY_MBEDTLS_RSA_PKCS_V21)
    {
        //DO NOTHING
    }
    else
    {
        ret = MBEDTLS_ERR_RSA_INVALID_PADDING;
        goto end;
    }


    ret = mbedtls_rsa_pkcs1_decrypt(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctr_drbg, olen, input, plaint_buffer, sizeof(plaint_buffer));
    if (ret != 0) {
        goto end;
    }

end:

    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

int aes_cbc_encrypt(unsigned char *input,int input_length,unsigned char *encrypted_data,unsigned char *key,
                    unsigned char key_len, unsigned char *iv,char padding)
{
    mbedtls_aes_context aes_context;
    int result = 0;
    //int padding = 0;
    int real_input_length = 0;
    unsigned char padding_code;
    // unsigned char *input_tmp;
    unsigned char input_tmp[MAX_INPUT_LENGTH];
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
    if(padding == 0)
    {
        padding = 0;
    }
    else if(padding == 1)
    {
        padding = 16 - (input_length%16);
        padding_code = (char)padding;
    }
    else
    {
        result = MBEDTLS_ERR_AES_BAD_INPUT_DATA;
        goto end;
    }
    
    //real_input_length-The length of the data to be encrypted after being filled must be a multiple of 16, and this length is also the length of the encrypted ciphertext
    real_input_length = input_length + padding;

    memcpy(input_tmp,input,input_length);
    memset(input_tmp + input_length,padding_code,padding);

    mbedtls_aes_init(&aes_context);
    //If AES-128 is used, the necessary length is 128 bits. If AES-256 is used, the key length is 256 bits
    result = mbedtls_aes_setkey_enc(&aes_context, key, key_len*8);
    if(result != 0){

       goto end;
    }

    result = mbedtls_aes_crypt_cbc(&aes_context, MBEDTLS_AES_ENCRYPT, real_input_length,iv,input_tmp,encrypted_data);
    if(result != 0){

        goto end;
    }

end:
    /* clean up */
    mbedtls_aes_free(&aes_context);

    if(result != 0)
    {
        return result;
    }
    else
    {
        return real_input_length;
    }
}

int aes_cbc_decrypt(unsigned char *encrypted_data,int encrypted_length,unsigned char *decrypted_data,
        unsigned char *key,unsigned char key_len,unsigned char *iv, char padding)
{
    mbedtls_aes_context aes_context;
    int result = 0;
    //int padding = 0;
    unsigned char padding_code;

    //After decryption, the plaintext containing the filled value needs to be removed in the future
    unsigned char decrypted_data_include_padding[encrypted_length];

    mbedtls_aes_init(&aes_context);
    result = mbedtls_aes_setkey_dec(&aes_context, key, key_len*8);

    if(result != 0){
        goto end;
    }

    result = mbedtls_aes_crypt_cbc(&aes_context, MBEDTLS_AES_DECRYPT, encrypted_length,iv,encrypted_data,decrypted_data_include_padding);
    if(result != 0){
        goto end;
    }

//Remove the padding value of PKCS # 7
//Read the last value, which is the length of the recharge filled in
    if(padding == 1)
    {
        padding_code = decrypted_data_include_padding[encrypted_length-1];
        padding = (int)padding_code;
        if(padding < 1 || padding > 16){
            goto end;
        }
    }
    else if(padding == 0)
    {
        padding = 0;
    }
    else
    {
        result = MBEDTLS_ERR_AES_BAD_INPUT_DATA;
        goto end;
    }

    int real_decrypted_data_length = encrypted_length - padding;

    memcpy(decrypted_data,decrypted_data_include_padding,real_decrypted_data_length);

end:

    /* clean up */
    mbedtls_aes_free(&aes_context);

    if(result != 0)
    {
        return result;
    }
    else
    {
        return real_decrypted_data_length;
    }
    
}

int aes_ecb_encrypt(unsigned char *input,unsigned char *encrypted_data,unsigned char *key,
                    unsigned char key_len)
{
    mbedtls_aes_context aes_context;
    int result = 0;
    

    mbedtls_aes_init(&aes_context);
    //If AES-128 is used, the necessary length is 128 bits. If AES-256 is used, the key length is 256 bits
    result = mbedtls_aes_setkey_enc(&aes_context, key, key_len*8);
    if(result != 0){

       goto end;
    }

    result = mbedtls_aes_crypt_ecb(&aes_context, MBEDTLS_AES_ENCRYPT,input,encrypted_data);
    if(result != 0){

        goto end;
    }

end:
    /* clean up */
    mbedtls_aes_free(&aes_context);

    return result;

}

int aes_ecb_decrypt(unsigned char *encrypted_data, unsigned char *decrypted_data,
        unsigned char *key,unsigned char key_len)
{
    mbedtls_aes_context aes_context;
    int result = 0;
    
    mbedtls_aes_init(&aes_context);
    result = mbedtls_aes_setkey_dec(&aes_context, key, key_len*8);

    if(result != 0){
        goto end;
    }

    result = mbedtls_aes_crypt_ecb(&aes_context, MBEDTLS_AES_DECRYPT,encrypted_data,decrypted_data);
    if(result != 0){
        goto end;
    }


end:

    /* clean up */
    mbedtls_aes_free(&aes_context);

    return result;
    
}

int verify_ecdsa_signature(const unsigned char *pub_key, size_t pub_key_len,
                           const unsigned char *signature, size_t sig_len,
                           const unsigned char *hash_buf, size_t hash_len) {
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi r, s;
    int ret;

    // 初始化资源
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    // 加载椭圆曲线（例如 SECP256R1）
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        printf("Error loading curve: %d\n", ret);
        return ret;
    }

    // 从公钥数据加载公钥（64字节的未压缩公钥）
    ret = mbedtls_ecp_point_read_binary(&grp, &Q, pub_key, pub_key_len);
    if (ret != 0) {
        printf("Error reading public key: %d\n", ret);
        return ret;
    }

    // 提取签名中的 r 和 s（64字节签名数据）
    ret = mbedtls_mpi_read_binary(&r, signature, 32);  // 前32字节为 r
    if (ret != 0) {
        printf("Error reading r from signature: %d\n", ret);
        return ret;
    }

    ret = mbedtls_mpi_read_binary(&s, signature + 32, 32);  // 后32字节为 s
    if (ret != 0) {
        printf("Error reading s from signature: %d\n", ret);
        return ret;
    }

    // 使用公钥 Q 和签名数据 r, s 来验证签名
    ret = mbedtls_ecdsa_verify(&grp, hash_buf, hash_len, &Q, &r, &s);
    if (ret == 0) {
        printf("Signature is valid!\n");
    } else {
        printf("Signature verification failed, error code: %d\n", ret);
    }

    // 清理资源
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);

    return ret;
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

