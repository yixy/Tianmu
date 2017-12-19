package encrypt

import (
	"crypto/des"
	"errors"
)

// Des加密方法
//
// ECB方式
func DesEncrypt(originData, key []byte) ([]byte, error) {
	if len(originData) < 1 || len(key) < 1 {
		return nil, errors.New("wrong data or key.")
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(originData)%bs != 0 {
		return nil, errors.New("wrong padding.")
	}
	out := make([]byte, len(originData))
	dst := out
	for len(originData) > 0 {
		block.Encrypt(dst, originData[:bs])
		originData = originData[bs:]
		dst = dst[bs:]
	}
	return out, nil
}

// DES解密方法
//
// ECB方式
func DesDecrypt(crypted, key []byte) ([]byte, error) {
	if len(crypted) < 1 || len(key) < 1 {
		return nil, errors.New("wrong data or key.")
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(crypted))
	dst := out
	bs := block.BlockSize()
	if len(crypted)%bs != 0 {
		return nil, errors.New("wrong crypted size.")
	}
	for len(crypted) > 0 {
		block.Decrypt(dst, crypted[:bs])
		crypted = crypted[bs:]
		dst = dst[bs:]
	}
	return out, nil
}

// 3DES加密方法
//
// ECB 加-解-加
func TripleECBDesEncrypt(originData, key []byte) ([]byte, error) {
	tkey := make([]byte, 24, 24)
	copy(tkey, key)
	k1 := tkey[:8]
	k2 := tkey[8:16]
	k3 := tkey[16:]

	block, err := des.NewCipher(k1)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	originData = Pkcs5Padding(originData, bs)

	buf1, err := DesEncrypt(originData, k1)
	if err != nil {
		return nil, err
	}
	buf2, err := DesDecrypt(buf1, k2)
	if err != nil {
		return nil, err
	}
	out, err := DesEncrypt(buf2, k3)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// 3DES解密方法
//
// ECB 解-加-解
func TripleECBDesDecrypt(crypted, key []byte) ([]byte, error) {
	tkey := make([]byte, 24, 24)
	copy(tkey, key)
	k1 := tkey[:8]
	k2 := tkey[8:16]
	k3 := tkey[16:]

	buf1, err := DesDecrypt(crypted, k3)
	if err != nil {
		return nil, err
	}
	buf2, err := DesEncrypt(buf1, k2)
	if err != nil {
		return nil, err
	}
	out, err := DesDecrypt(buf2, k1)
	if err != nil {
		return nil, err
	}
	out = Pkcs5UnPadding(out)
	return out, nil

}
