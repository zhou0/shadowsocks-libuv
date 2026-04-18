//
//  crypt.c
//  shadowsocks-libuv
//
//  Created by Cube on 14/11/9.
//  Copyright (c) 2014年 Cube. All rights reserved.
//


#include <string.h>
#include "utils.h"
#include "crypt.h"

extern config_t conf;

cipher_t * cipher_new(const config_t * conf)
{
    OpenSSL_add_all_algorithms();

    // const char * name;
    // name = "aes-128-cfb";
    // name = "bf-cfb";
    cipher_t * cipher = calloc(1, sizeof(cipher_t));

    cipher -> type = EVP_get_cipherbyname(conf -> method);
    cipher -> keyl = EVP_CIPHER_key_length(cipher -> type);
    pr_info("%s %zu", __FUNCTION__,cipher->keyl);
    cipher -> key  = malloc(cipher -> keyl);

    cipher->encrypt.ctx = EVP_CIPHER_CTX_new();
    cipher->decrypt.ctx = EVP_CIPHER_CTX_new();
    //EVP_BytesToKey(cipher -> type, EVP_md5(), NULL, (uint8_t *) conf -> pass, (int) strlen(conf -> pass), 1,
    //                   cipher -> key, NULL);
    EVP_BytesToKey(cipher -> type, EVP_md5(), NULL,  conf -> pass, (int) strlen(conf -> pass), 1,
                       cipher -> key, NULL);
    pr_info("%s %zu", __FUNCTION__,strlen(cipher->key));
    //pr_info("%s %s",__FUNCTION__, cipher->key);
    //pr_info("%s %zu", __FUNCTION__,sizeof(cipher->key));
    dump("KEY", cipher->key, cipher->keyl);
    return cipher;
}

void cipher_free(cipher_t * cipher)
{
    if (!cipher) return;
    if (cipher->encrypt.ctx) EVP_CIPHER_CTX_free(cipher->encrypt.ctx);
    if (cipher->decrypt.ctx) EVP_CIPHER_CTX_free(cipher->decrypt.ctx);
    if (cipher -> key)
    {
        free(cipher -> key);
    }

    free(cipher);
}

void
dump(unsigned char *tag, unsigned char *text, int len)
{
    int i;
    printf("%s: ", tag);
    for (i = 0; i < len; i++)
        printf("0x%02x ", text[i]);
    printf("\n");
}


uv_buf_t cipher_encrypt(shadow_t * shadow, size_t * encryptl,
                      char     *  plain, size_t     plainl)
{
    cipher_t * cipher   = shadow->cipher;
    char     * encrypt  = NULL;
    uint8_t * dst;
    int ivl = 0;
    int olength = 0;
    if (!cipher->encrypt.init) {
        ivl = EVP_CIPHER_iv_length(cipher->type);
        uint8_t * iv  = malloc(ivl);
        RAND_bytes(iv, ivl);
        EVP_CipherInit_ex(cipher->encrypt.ctx, cipher->type, NULL, cipher->key, iv, 1);
        size_t prepend = shadow->socks5->len - 3;
        size_t total_plainl = prepend + plainl;
        uint8_t * tmp_src = malloc(total_plainl);
        memcpy(tmp_src, &shadow->socks5->data->atyp, prepend);
        memcpy(tmp_src + prepend, plain, plainl);
        *encryptl = ivl + total_plainl;
        encrypt  = malloc(*encryptl);
        memcpy(encrypt, iv, ivl);
        dst      = (uint8_t *)encrypt + ivl;
        EVP_CipherUpdate(cipher->encrypt.ctx, dst, &olength, tmp_src, (int)total_plainl);
        free(tmp_src); free(iv);
        cipher->encrypt.init = 1;
    } else {
        *encryptl = plainl;
        encrypt  = malloc(*encryptl);
        dst      = (uint8_t *)encrypt;
        EVP_CipherUpdate(cipher->encrypt.ctx, dst, &olength, (uint8_t *)plain, (int)plainl);
    }
    return uv_buf_init(encrypt, ivl + olength);
}

uv_buf_t  cipher_decrypt(shadow_t * shadow,  size_t *   plainl,
                      char     * encrypt, size_t   encryptl)
{
    cipher_t      * cipher = shadow->cipher;
    char          * plain  = NULL;
    uint8_t * src;
    int ivl = 0;
    int olength = 0;
    if (!cipher->decrypt.init) {
        ivl = EVP_CIPHER_iv_length(cipher->type);
        uint8_t * iv  = malloc(ivl);
        memcpy(iv, encrypt, ivl);
        *plainl = encryptl - ivl;
        plain  = malloc(*plainl);
        src    = (uint8_t *)encrypt + ivl;
        EVP_CipherInit_ex(cipher->decrypt.ctx, cipher->type, NULL, cipher->key, iv, 0);
        free(iv);
        cipher->decrypt.init = 1;
    } else {
        *plainl = encryptl;
        src    = (uint8_t *)encrypt;
        plain  = malloc(*plainl);
    }
    EVP_CipherUpdate(cipher->decrypt.ctx, (uint8_t *)plain, &olength, src, (int)*plainl);
    return uv_buf_init(plain, olength);
}