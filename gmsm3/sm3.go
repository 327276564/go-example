package gmsm3

import (
	"test/cipher/go-example/digest"
)

type SM3 struct {
	hash_len int
	digest   *digest.Digest
}

func New_SM3(hash_len int) *SM3 {
	return &SM3{
		hash_len: hash_len,
		digest:   digest.EVP_MD_CTX_create(),
	}
}

func (this *SM3) EVP_DigestInit_ex() int {
	return this.digest.EVP_DigestInit_ex()
}

func (this *SM3) EVP_DigestUpdate(msg string) int {
	return this.digest.EVP_DigestUpdate(msg, len(msg))
}

func (this *SM3) EVP_DigestFinal_ex() (string, int) {
	return this.digest.EVP_DigestFinal_ex(this.hash_len)
}
