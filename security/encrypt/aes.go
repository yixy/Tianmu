package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// AES加密方法
//
// 填充的blockSize为16
//
// 密钥长度需要是AES-128（16bytes）或者AES-256（32bytes）
//
// 原文必须填充至blockSize的整数倍，填充方法可以参考RFC5246
//
// 注意：正常来说，对IV有随机性要求，但没有保密性要求，所以常见的做法是将IV包含在加密文本当中。
// 但此处为兼容原来API网关的加解密算法，IV硬编码为全0，且不放入加密文本中。
func AesNewCBCEncrypter(content []byte, aesKey []byte) ([]byte, error) {
	padContent := Pkcs5Padding(content, aes.BlockSize) //原文必须填充至blockSize的整数倍，填充方法可以参考RFC5246
	if len(padContent)%aes.BlockSize != 0 {
		return nil, errors.New("padContent is not a multiple of the block size.")
	}
	block, err := aes.NewCipher(aesKey) //生成加密用的block
	if err != nil {
		return nil, errors.New("aes.NewCipher error:" + err.Error())
	}
	// 注意：正常来说，对IV有随机性要求，但没有保密性要求，所以常见的做法是将IV包含在加密文本当中。
	// 但此处为兼容原来API网关的加解密算法，IV硬编码为全0，且不放入加密文本中
	cipherText := make([]byte, len(padContent))
	// 随机一个block大小作为IV
	// 采用不同的IV时相同的密钥将会产生不同的密文，可以理解为一次加密的session
	iv := make([]byte, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[:], padContent)
	return cipherText, nil
}

//AES解密方法
func AesNewCBCDecrypter(content []byte, aesKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, errors.New("aes.NewCipher error:" + err.Error())
	}
	if len(content) < aes.BlockSize {
		return nil, errors.New("Decrypt content is too short.")
	}
	iv := make([]byte, aes.BlockSize)
	if len(content)%aes.BlockSize != 0 {
		return nil, errors.New("padContent is not a multiple of the block size.")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	//CryptBlocks可以原地更新
	mode.CryptBlocks(content, content)
	content = Pkcs5UnPadding(content)
	return content, nil
}
