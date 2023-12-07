/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* OS_crypto/blowfish Library
 * APIs for many crypto operations
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>

#include "bf_op.h"

typedef unsigned char uchar;

int OS_BF_Str(const char *input, char *output, const char *charkey, long size, short int action)
{
    int len, final_len;
    static unsigned char iv[8] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    int ret = 0;

    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *legacy = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;

    // Create a new library context
    libctx = OSSL_LIB_CTX_new();
    if (!libctx) {
        goto cleanup;
    }

    // Load the legacy provider into the new context
    legacy = OSSL_PROVIDER_load(libctx, "legacy");
    if (!legacy) {
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        goto cleanup;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    cipher = EVP_CIPHER_fetch(libctx, "BF-CBC", NULL);
    if (!cipher || !EVP_CipherInit_ex(ctx, cipher, NULL, (const unsigned char *)charkey, iv, action)) {
        goto cleanup;
    }

    if (!EVP_CipherUpdate(ctx, (unsigned char *)output, &len, (const unsigned char *)input, size)) {
        goto cleanup;
    }

    if (!EVP_CipherFinal_ex(ctx, (unsigned char *)output + len, &final_len)) {
        goto cleanup;
    }

    ret = 1;

cleanup:
    if (cipher) {
        EVP_CIPHER_free(cipher);
    }

    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

    if (legacy) {
        OSSL_PROVIDER_unload(legacy);
    }

    if (libctx) {
        OSSL_LIB_CTX_free(libctx);
    }

    return ret;
}
