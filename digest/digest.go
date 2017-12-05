package digest

/*
#cgo  CFLAGS:  -I ../usr/include
#cgo  LDFLAGS: -L ../usr/lib -lciphersuite_crypto -lciphersuite_smengine
#include "openssl/engine.h"
#include "openssl/evp.h"
*/
import "C"

import (
	"test/cipher/go-example/engine"
	"unsafe"
)

const (
	NID_sm3 = C.NID_sm3
)

var md *C.EVP_MD

type Digest struct {
	md_ctx *C.EVP_MD_CTX
}

func init() {
	md = C.ENGINE_get_digest((*C.ENGINE)(unsafe.Pointer(engine.Engine)), C.int(NID_sm3))
}

func GetEVP_MD() *C.EVP_MD {
	return md
}

func EVP_MD_CTX_create() *Digest {
	return &Digest{md_ctx: C.EVP_MD_CTX_new()}
}

func (this *Digest) EVP_DigestInit_ex() int {
	return int(C.EVP_DigestInit_ex(this.md_ctx, md, (*C.ENGINE)(unsafe.Pointer(engine.Engine))))
}

func (this *Digest) EVP_DigestUpdate(msg string, msg_len int) int {
	return int(C.EVP_DigestUpdate(this.md_ctx, unsafe.Pointer(C.CString(msg)), C.size_t(msg_len)))
}

func (this *Digest) EVP_DigestFinal_ex(digest_value_len int) (string, int) {
	digest_value := make([]byte, digest_value_len)
	ret := C.EVP_DigestFinal_ex(this.md_ctx, (*C.uchar)(unsafe.Pointer(&digest_value[0])), (*C.uint)(unsafe.Pointer(&digest_value_len)))
	return string(digest_value), int(ret)
}
