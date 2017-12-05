package gmsm2

import (
	"unsafe"
)

/*
#cgo  CFLAGS:  -I ../usr/include
#cgo  LDFLAGS: -L ../usr/lib -lciphersuite_crypto -lciphersuite_smengine
# include "openssl/evp.h"
# include "openssl/engine.h"
# include "openssl/sm2.h"
# include "openssl/SMEngine.h"

EVP_PKEY *genpkey()
{
	int curve_id = NID_sm2p256v1;
    int ok = 0;
	EVP_PKEY *ret = NULL;
	EVP_PKEY_CTX *pkctx = NULL;

	if (!(pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_keygen_init(pkctx)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkctx, curve_id)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_keygen(pkctx, &ret)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	ok = 1;
end:
	if (!ok && ret) {
		EVP_PKEY_free(ret);
		ret = NULL;
	}
	EVP_PKEY_CTX_free(pkctx);
	return ret;
}

size_t sm2_sign_with_sm3hash(const EVP_MD *id_md, const EVP_MD *msg_md,
                             const char *id, size_t id_len, const unsigned char *msg, size_t msg_len,
                             unsigned char *sig, EVP_PKEY *pkey, ENGINE *engine) {

    unsigned char dgest[64];
	size_t dgest_len;
    unsigned int sig_len = 0;
    EVP_PKEY_CTX *pkctx = NULL;
	EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = ENGINE_get_digest(engine, NID_sm3);

    sig_len = (unsigned int)EVP_PKEY_size(pkey);
    if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
    SM2_compute_message_digest(id_md, msg_md, msg, msg_len, id, id_len, dgest, &dgest_len, EVP_PKEY_get0_EC_KEY(EVP_PKEY_CTX_get0_pkey(pkctx)));
	if (!(mdctx = EVP_MD_CTX_create())) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_SignInit_ex(mdctx, md, engine)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_SignUpdate(mdctx, dgest, dgest_len)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_SignFinal(mdctx, sig, &sig_len, pkey)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

end:
	EVP_PKEY_CTX_free(pkctx);
	EVP_MD_CTX_destroy(mdctx);
    return (size_t)sig_len;
}

int sm2_verify_with_sm3hash(const EVP_MD *id_md, const EVP_MD *msg_md,
                            const char *id, size_t id_len, const unsigned char *msg, size_t msg_len,
                            unsigned char *sig, size_t sig_len, EVP_PKEY *pkey, ENGINE *engine) {

    unsigned char dgest[64];
	size_t dgest_len;
    EVP_PKEY_CTX *pkctx = NULL;
	EVP_MD_CTX *mdctx = NULL;
    int ret = 0;
    const EVP_MD *md = ENGINE_get_digest(engine, NID_sm3);

    if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
    SM2_compute_message_digest(id_md, msg_md, msg, msg_len, id, id_len, dgest, &dgest_len, EVP_PKEY_get0_EC_KEY(EVP_PKEY_CTX_get0_pkey(pkctx)));
	if (!(mdctx = EVP_MD_CTX_create())) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	if (!EVP_VerifyInit_ex(mdctx, md, engine)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_VerifyUpdate(mdctx, dgest, dgest_len)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if ((ret = EVP_VerifyFinal(mdctx, sig, sig_len, pkey)) != 1) {
        fprintf(stderr, "SM2 sign and verify with SM3 hash failed!\n");
        goto end;
	}
    ret = 1;

    return ret;

end:
	EVP_PKEY_CTX_free(pkctx);
	EVP_MD_CTX_destroy(mdctx);
    return 0;
}

size_t sm2_encrypt(unsigned char *msg, size_t mlen,
                   unsigned char *ciphertext, size_t *clen, EVP_PKEY *pkey) {
    EVP_PKEY_CTX *pkctx = NULL;
    int ret = 0;

    if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
    if (!EVP_PKEY_encrypt_init(pkctx)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if (!EVP_PKEY_encrypt(pkctx, ciphertext, clen, msg, mlen)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
    ret = 1;

end:
	EVP_PKEY_CTX_free(pkctx);
    return ret;
}

size_t sm2_decrypt(unsigned char *ciphertext, size_t clen,
                   unsigned char *plaintext, size_t *plen, EVP_PKEY *pkey) {
     EVP_PKEY_CTX *pkctx = NULL;
    int ret = 0;

    if (!(pkctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

    if (!EVP_PKEY_decrypt_init(pkctx)) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

    if (!(ret = EVP_PKEY_decrypt(pkctx, plaintext, plen, ciphertext, clen))) {
//        const char *fuc = malloc(100);
//        int line = 0;
//        unsigned long num = 0;
//        do {
//            num = ERR_get_error_line(&fuc, &line);
//            printf("func: %s, line = %d.\n", fuc, line);
//            printf("num = %ld.\n", num);
//        }while(num != 0);
//        printf("####################### ret = %d\n", ret);
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
        goto end;
	}
    ret = 1;

end:
	EVP_PKEY_CTX_free(pkctx);
    return ret;
}
*/
import "C"

import (
	"test/cipher/go-example/digest"
	"test/cipher/go-example/engine"
)

const (
	MAX_ENCRYPT_SIZE = 1024
)

type SM2 struct {
	Key    *C.EVP_PKEY
	id     string
	md     *C.EVP_MD
	digest *digest.Digest
}

func New_SM2() *SM2 {
	id := "1234567812345678"
	return &SM2{
		digest: digest.EVP_MD_CTX_create(),
		id:     id,
		md:     (*C.EVP_MD)(unsafe.Pointer(digest.GetEVP_MD())),
		Key:    C.genpkey(),
	}
}

func (this *SM2) SM2_Encrypt(msg string) (string, int) {
	if len(msg) > MAX_ENCRYPT_SIZE {
		return "", -1
	}
	out := make([]byte, 1200)
	out_len := 1200
	ret := C.sm2_encrypt(
		(*C.uchar)(unsafe.Pointer(C.CString(msg))), C.size_t(len(msg)),
		(*C.uchar)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(&out_len)),
		this.Key,
	)
	return string(out[:out_len]), int(ret)
}

func (this *SM2) SM2_Decrypt(msg string) (string, int) {
	if len(msg) > 1200 {
		return "", -1
	}
	out := make([]byte, MAX_ENCRYPT_SIZE)
	out_len := MAX_ENCRYPT_SIZE
	ret := C.sm2_decrypt(
		(*C.uchar)(unsafe.Pointer(C.CString(msg))), C.size_t(len(msg)),
		(*C.uchar)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(&out_len)),
		this.Key,
	)
	return string(out[:out_len]), int(ret)
}

func (this *SM2) SM2_Sign(msg string) (string, int) {
	out := make([]byte, len(msg)+MAX_ENCRYPT_SIZE)
	ret := C.sm2_sign_with_sm3hash(
		this.md, this.md,
		C.CString(this.id), C.size_t(len(this.id)),
		(*C.uchar)(unsafe.Pointer(C.CString(msg))), C.size_t(len(msg)),
		(*C.uchar)(unsafe.Pointer(&out[0])),
		this.Key, (*C.ENGINE)(unsafe.Pointer(engine.Engine)),
	)
	if int(ret) <= 0 {
		return "", -1
	}

	return string(out[:int(ret)]), 1
}

func (this *SM2) SM2_Verify(msg, sig string) int {
	ret := C.sm2_verify_with_sm3hash(
		this.md, this.md,
		C.CString(this.id), C.size_t(len(this.id)),
		(*C.uchar)(unsafe.Pointer(C.CString(msg))), C.size_t(len(msg)),
		(*C.uchar)(unsafe.Pointer(C.CString(sig))), C.size_t(len(sig)),
		this.Key, (*C.ENGINE)(unsafe.Pointer(engine.Engine)),
	)
	return int(ret)
}
