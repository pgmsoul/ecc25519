package ecc25519

import (
	"crypto/curve25519"
	"crypto/sha512"
	"crypto/rand"
	"errors"
)

type Curve struct {
	key [64]byte;
	// 前32字节是私钥，后32字节是公钥，但是真正签名的时候，私钥是
	// 整个 key 的 64 字节，所以不能只设置 32 字节私钥，必须同时设置 32 字节的公钥。
	// 而验证签名的时候，只需要设置后 32 字节公钥

	_public,_private [32]byte;
	//用于加密的私钥和公钥可以通过用于签名的密钥换算得到，这样就可以共用一套密钥
}

/*func (cr *Curve) MakeKey() (error) {
	//生成一个随机私钥
	if _, err := rand.Read(cr._private[:]); err != nil {
		return err;
	}

	cr._private[0] &= 248
	cr._private[31] &= 127
	cr._private[31] |= 64
	//获得公钥
	curve25519.ScalarBaseMult(&cr._public, &cr._private)
	return nil;
}
*/
//最多加密 64 字节
func (cr *Curve) Encrypt(plainText []byte) ([]byte, error) {
	var r, R, S, K_B [32]byte

	if _, err := rand.Read(r[:]); err != nil {
		return nil, err
	}
	r[0] &= 248
	r[31] &= 127
	r[31] |= 64

	copy(K_B[:], cr._public[:])

	curve25519.ScalarBaseMult(&R, &r)
	curve25519.ScalarMult(&S, &r, &K_B)
	k_E := sha512.Sum512(S[:])

	srclen := len(plainText);
	if srclen>64{
		return nil,errors.New("source data is exceed 64 bytes");
	}
	cipherText := make([]byte, 32+srclen)
	copy(cipherText[:32], R[:])
	for i := 0; i < srclen; i++ {
		cipherText[32+i] = plainText[i] ^ k_E[i]
	}

	return cipherText, nil
}

func (cr *Curve) Decrypt(cipherText []byte) ([]byte, error) {
	var R, S, k_B [32]byte
	copy(R[:], cipherText[:32])
	copy(k_B[:], cr._private[:])

	curve25519.ScalarMult(&S, &k_B, &R)

	k_E := sha512.Sum512(S[:])

	plainText := make([]byte, len(cipherText)-32)
	for i := 0; i < len(plainText); i++ {
		plainText[i] = cipherText[32+i] ^ k_E[i]
	}

	return plainText, nil
}
