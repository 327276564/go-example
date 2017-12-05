package main

import (
	"fmt"
	"test/cipher/go-example/gmsm2"
	"test/cipher/go-example/gmsm3"
	"test/cipher/go-example/gmsm4"
)

func sm3_test() {
	msg := "aaaaaaaaaa"
	hash := ""
	sm3_test := gmsm3.New_SM3(32)
	sm3_test.EVP_DigestInit_ex()
	sm3_test.EVP_DigestUpdate(msg)
	hash, ret := sm3_test.EVP_DigestFinal_ex()
	fmt.Printf("digest ret = %d\n", ret)
	fmt.Printf("digest value := %x\n", hash)
}

func sm2_test() {
	msg := "aaaaaaaaaa"
	fmt.Printf("origin data : %x\n", msg)
	sm2_test := gmsm2.New_SM2()
	encrypt, ret := sm2_test.SM2_Encrypt(msg)
	fmt.Printf("encrypt ret = %d\n", ret)
	fmt.Printf("encrypt len = %d, value := %x\n", len(encrypt), encrypt)

	decrypt, ret := sm2_test.SM2_Decrypt(encrypt)
	fmt.Printf("decrypt ret = %d\n", ret)
	fmt.Printf("decrypt len = %d, value := %x\n", len(decrypt), decrypt)

	sig, ret := sm2_test.SM2_Sign(msg)
	fmt.Printf("sig ret = %d\n", ret)
	fmt.Printf("sig len = %d, value := %x\n", len(sig), sig)

	ret = sm2_test.SM2_Verify(msg, sig)
	fmt.Printf("decrypt ret = %d\n", ret)
}

func sm4_test() {
	msg := "aaaaaaaaaa"
	key := "1111111111111111"
	fmt.Printf("origin data : %x\n", msg)
	sm4_test := gmsm4.New_DefaultSM4()
	encrypt, ret := sm4_test.SM4_Encrypt(msg, key)
	fmt.Printf("encrypt ret = %d\n", ret)
	fmt.Printf("encrypt len = %d, value := %x\n", len(encrypt), encrypt)

	decrypt, ret := sm4_test.SM4_Decrypt(encrypt, key)
	fmt.Printf("decrypt ret = %d\n", ret)
	fmt.Printf("decrypt len = %d, value := %x\n", len(decrypt), decrypt)
}

func main() {
	fmt.Println("***********************  sm3_test ************************")
	sm3_test()
	fmt.Println("***********************  sm2_test ************************")
	sm2_test()
	fmt.Println("***********************  sm4_test ************************")
	sm4_test()
}
