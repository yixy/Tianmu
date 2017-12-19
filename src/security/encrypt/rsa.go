package encrypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
)

// RSA签名方法
//
// 支持SHA1和SHA256
func RsaSign(originData []byte, priKey []byte, algorithm string) ([]byte, error) {
	private, err := x509.ParsePKCS8PrivateKey(priKey)
	if err != nil {
		return nil, err
	}
	var shaType crypto.Hash
	if algorithm == SHA1 {
		shaType = crypto.SHA1
	} else if algorithm == SHA256 {
		shaType = crypto.SHA256
	} else {
		return nil, errors.New("only support SHA1 and SHA256.")
	}
	hash := crypto.Hash.New(shaType)
	hash.Write(originData)
	hashed := hash.Sum(nil)
	signed, err := rsa.SignPKCS1v15(rand.Reader, private.(*rsa.PrivateKey), shaType, hashed)
	if err != nil {
		return nil, err
	}
	return signed, nil
}

// RSA验签方法
//
// 支持SHA1和SHA256
func RsaVerify(originData []byte, publicKey []byte, sign []byte, algorithm string) (bool, error) {
	public, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return false, err
	}
	var shaType crypto.Hash
	if algorithm == SHA1 {
		shaType = crypto.SHA1
	} else if algorithm == SHA256 {
		shaType = crypto.SHA256
	} else {
		return false, errors.New("only support SHA1 and SHA256.")
	}
	hash := crypto.Hash.New(shaType)
	hash.Write(originData)
	hashed := hash.Sum(nil)
	err = rsa.VerifyPKCS1v15(public.(*rsa.PublicKey), shaType, hashed, sign)
	if err != nil {
		return false, err
	}
	return true, nil
}
