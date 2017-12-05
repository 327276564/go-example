package gmsm4

import (
	"unsafe"
)

/*
#cgo  CFLAGS:  -I ../usr/include
#cgo  LDFLAGS: -L ../usr/lib -lciphersuite_crypto -lciphersuite_smengine
#include "openssl/engine.h"
#include "openssl/evp.h"
#include "openssl/SMEngine.h"

int sm4_ecb_encrypt(const unsigned char *plaintext, int plen,
					const unsigned char *key,
					unsigned char *ciphertext, int *clen,
                    ENGINE *engine) {
    int tmplen = 0, ret = 0;

    const EVP_CIPHER *cipher = ENGINE_get_cipher(engine, NID_sm4_ecb);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	ret = EVP_EncryptInit_ex(ctx, cipher, engine, key, NULL);
	if (ret != 1) {
		goto end;
	}
	ret = EVP_EncryptUpdate(ctx, ciphertext, clen, plaintext, plen);
	if (ret != 1) {
		goto end;
	}
	ret = EVP_EncryptFinal_ex(ctx, ciphertext + *clen, &tmplen);
	if (ret != 1) {
		goto end;
	}
    *clen += tmplen;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int sm4_ecb_decrypt(const unsigned char *ciphertext, int clen,
                    const unsigned char *key,
					unsigned char *plaintext, int *plen,
                    ENGINE *engine) {
    int tmplen = 0, ret = 0;

    const EVP_CIPHER *cipher = ENGINE_get_cipher(engine, NID_sm4_ecb);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    ret = EVP_DecryptInit_ex(ctx, cipher, engine, key, NULL);
	if (ret != 1) {
		goto end;
	}
    ret = EVP_DecryptUpdate(ctx, plaintext, plen, ciphertext, clen);
	if (ret != 1) {
		goto end;
	}
    ret = EVP_DecryptFinal_ex(ctx, plaintext + *plen, &tmplen);
	if (ret != 1) {
		goto end;
	}
    *plen += tmplen;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int sm4_cbc_encrypt(const unsigned char *plaintext, int plen,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *ciphertext, ENGINE *engine) {
    int tmplen = 0, clen = 0;

    const EVP_CIPHER *cipher = ENGINE_get_cipher(engine, NID_sm4_cbc);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, engine, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &clen, plaintext, plen);
    EVP_EncryptFinal_ex(ctx, ciphertext + clen, &tmplen);
    clen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    return clen;
}

int sm4_cbc_decrypt(const unsigned char *ciphertext, int clen,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *plaintext, ENGINE *engine) {
    int tmplen = 0, plen = 0;

    const EVP_CIPHER *cipher = ENGINE_get_cipher(engine, NID_sm4_cbc);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, engine, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &plen, ciphertext, clen);
    EVP_DecryptFinal_ex(ctx, plaintext + plen, &tmplen);
    plen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    return plen;
}

int sm4_ctr_encrypt(const unsigned char *plaintext, int plen,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *ciphertext, ENGINE *engine) {
    int tmplen = 0, clen = 0;

    const EVP_CIPHER *cipher = ENGINE_get_cipher(engine, NID_sm4_ctr);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, engine, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &clen, plaintext, plen);
    EVP_EncryptFinal_ex(ctx, ciphertext + clen, &tmplen);
    clen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    return clen;
}

int sm4_ctr_decrypt(const unsigned char *ciphertext, int clen,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *plaintext, ENGINE *engine) {
    int tmplen = 0, plen = 0;

    const EVP_CIPHER *cipher = ENGINE_get_cipher(engine, NID_sm4_ctr);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, engine, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &plen, ciphertext, clen);
    EVP_DecryptFinal_ex(ctx, plaintext + plen, &tmplen);
    plen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    return plen;
}

void sm4_gcm_encrypt(unsigned char *msg, int m_len, unsigned char *aad, int aad_len,
                     unsigned char *key, unsigned char *iv, int iv_len,
                     unsigned char *ciphertext, int *clen, unsigned char *tag, int tag_len, ENGINE *engine)
{
    int tmplen = 0;
    const EVP_CIPHER *cipher = ENGINE_get_cipher(engine, NID_sm4_gcm);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, engine, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
    EVP_EncryptInit_ex(ctx, NULL, engine, key, iv);
    if(aad)
        EVP_EncryptUpdate(ctx, NULL, &tmplen, aad, aad_len);
    EVP_EncryptUpdate(ctx, ciphertext, &tmplen, msg, m_len);
    *clen += tmplen;
    EVP_EncryptFinal_ex(ctx, ciphertext + *clen, &tmplen);
    *clen += tmplen;
    EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag);
    EVP_CIPHER_CTX_free(ctx);
}

void sm4_gcm_decrypt(unsigned char *ciphertext, int clen, unsigned char *aad, int aad_len,
                     unsigned char *key, unsigned char *iv, int iv_len,
                     unsigned char *tag, int tag_len,
                     unsigned char *plaintext, int *plen, ENGINE *engine)
{
    int tmplen = 0, ret = 0;
    const EVP_CIPHER *cipher = ENGINE_get_cipher(engine, NID_sm4_gcm);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, engine, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
    EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_DecryptUpdate(ctx, NULL, &tmplen, aad, aad_len);
    EVP_DecryptUpdate(ctx, plaintext, &tmplen, ciphertext, clen);
    *plen += tmplen;
    ret = EVP_DecryptFinal (ctx, plaintext + *plen, &tmplen);
    *plen += tmplen;

    if (ret <= 0)
        printf("Plaintext not available: tag verify failed.\n");
    EVP_CIPHER_CTX_free(ctx);
}

void sm4_ccm_encrypt(unsigned char *msg, int m_len, unsigned char *aad, int aad_len,
                     unsigned char *key, unsigned char *iv, int iv_len,
                     unsigned char *ciphertext, int *clen, unsigned char *tag, int tag_len, ENGINE *engine)
{
    const EVP_CIPHER *cipher = ENGINE_get_cipher(engine, NID_sm4_ccm);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen, tmplen;

    EVP_EncryptInit_ex(ctx, cipher, engine, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, NULL, &outlen, NULL, m_len);
    EVP_EncryptUpdate(ctx, NULL, &outlen, aad, aad_len);
    EVP_EncryptUpdate(ctx, ciphertext, clen, msg, m_len);

    EVP_EncryptFinal_ex(ctx, tag, &outlen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag);

    EVP_CIPHER_CTX_free(ctx);
}

void sm4_ccm_decrypt(unsigned char *ciphertext, int clen, unsigned char *aad, int aad_len,
                    unsigned char *key, unsigned char *iv, int iv_len,
                    unsigned char *tag, int tag_len,
                    unsigned char *plaintext, int *plen, ENGINE *engine)
{
    const EVP_CIPHER *cipher = ENGINE_get_cipher(engine, NID_sm4_ccm);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen, tmplen, ret = 0;

    EVP_DecryptInit_ex(ctx, cipher, engine, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, (void *)tag);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_DecryptUpdate(ctx, NULL, &outlen, NULL, clen);
    EVP_DecryptUpdate(ctx, NULL, &outlen, aad, aad_len);
    ret = EVP_DecryptUpdate(ctx, plaintext, plen, ciphertext, clen);

    if (ret <= 0)
        printf("Plaintext not available: tag verify failed.\n");
    EVP_CIPHER_CTX_free(ctx);
}


int sm4_encrypt(const unsigned char *plaintext, int plen,
				unsigned char *ciphertext, int *clen,
				const unsigned char *key,
                ENGINE *engine, int mode) {
	int ret = 0;
	switch(mode) {
		case NID_sm4_ecb:
			ret = sm4_ecb_encrypt(plaintext, plen, key, ciphertext, clen, engine);
		break;
		default:
			ret = -1;
	}

	return ret;
}

int sm4_decrypt(const unsigned char *ciphertext, int clen,
				unsigned char *plaintext, int *plen,
				const unsigned char *key,
                ENGINE *engine, int mode) {
	int ret = 0;
	switch(mode) {
		case NID_sm4_ecb:
			ret = sm4_ecb_decrypt(ciphertext, clen, key, plaintext, plen, engine);
		break;
		default:
			ret = -1;
	}

	return ret;
}

*/
import "C"

import (
	"test/cipher/go-example/engine"
)

const (
	BLOCK_SIZE  = 1024
	NID_sm4_ecb = C.NID_sm4_ecb
)

type SM4 struct {
	mode   int
	engine *C.ENGINE
}

func New_DefaultSM4() *SM4 {
	return &SM4{
		engine: (*C.ENGINE)(unsafe.Pointer(engine.Engine)),
		mode:   NID_sm4_ecb,
	}
}

func (this *SM4) SM4_Encrypt(msg, key string) (string, int) {
	out := make([]byte, len(msg)+BLOCK_SIZE)
	out_len := len(out)
	ret := C.sm4_encrypt(
		(*C.uchar)(unsafe.Pointer(C.CString(msg))), C.int(len(msg)),
		(*C.uchar)(unsafe.Pointer(&out[0])), (*C.int)(unsafe.Pointer(&out_len)),
		(*C.uchar)(unsafe.Pointer(C.CString(key))), this.engine,
		C.int(this.mode),
	)

	return string(out[:out_len]), int(ret)
}

func (this *SM4) SM4_Decrypt(msg, key string) (string, int) {
	out := make([]byte, len(msg)+BLOCK_SIZE)
	out_len := len(out)
	ret := C.sm4_decrypt(
		(*C.uchar)(unsafe.Pointer(C.CString(msg))), C.int(len(msg)),
		(*C.uchar)(unsafe.Pointer(&out[0])), (*C.int)(unsafe.Pointer(&out_len)),
		(*C.uchar)(unsafe.Pointer(C.CString(key))), this.engine,
		C.int(this.mode),
	)

	return string(out[:out_len]), int(ret)
}
