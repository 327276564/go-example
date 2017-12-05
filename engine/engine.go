package engine

/*
#cgo  CFLAGS:  -I ../usr/include
#cgo  LDFLAGS: -L ../usr/lib -lciphersuite_crypto -lciphersuite_smengine
#include "openssl/engine.h"
#include "openssl/evp.h"
#include "openssl/ossl_typ.h"
#include <stdio.h>
*/
import "C"

import (
	"unsafe"
)

const (
	ENGINEID                     = "GM"
	OPENSSL_INIT_ADD_ALL_CIPHERS = C.OPENSSL_INIT_ADD_ALL_CIPHERS
	OPENSSL_INIT_ADD_ALL_DIGESTS = C.OPENSSL_INIT_ADD_ALL_DIGESTS
	OPENSSL_INIT_LOAD_CONFIG     = C.OPENSSL_INIT_LOAD_CONFIG
	OPENSSL_INIT_ENGINE_DYNAMIC  = C.OPENSSL_INIT_ENGINE_DYNAMIC
)

var Engine *C.ENGINE

func ENGINE_init(engine *C.ENGINE) int {
	return int(C.ENGINE_init(engine))
}

func init() {
	engine_id := "CipherSuite_SM"
	var engine_null *C.ENGINE = nil
	NULL := 0
	C.OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC|OPENSSL_INIT_ADD_ALL_CIPHERS|OPENSSL_INIT_ADD_ALL_DIGESTS, (*C.OPENSSL_INIT_SETTINGS)(unsafe.Pointer(&NULL)))
	// C.OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC|OPENSSL_INIT_ADD_ALL_CIPHERS|OPENSSL_INIT_ADD_ALL_DIGESTS|OPENSSL_INIT_LOAD_CONFIG, (*C.OPENSSL_INIT_SETTINGS)(unsafe.Pointer(NULL)))
	Engine = C.ENGINE_by_id((*C.char)(unsafe.Pointer(C.CString(engine_id))))
	if Engine == (*C.ENGINE)(unsafe.Pointer(engine_null)) {
		panic("Get engine by id failed")
	}

	ENGINE_init(Engine)
}
