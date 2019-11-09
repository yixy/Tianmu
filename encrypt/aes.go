package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// AES加密方法
//
//在某些场合，ECB方式不能提供严格的数据保密性，因此并不推荐用于密码协议中。
//
// 填充的blockSize为16
//
// 密钥长度需要是AES-128（16bytes）或者AES-256（32bytes）
//
// 原文必须填充至blockSize的整数倍，填充方法可以参考RFC5246
//
// 注意：正常来说，对IV有随机性要求，但没有保密性要求，所以常见的做法是将IV包含在加密文本当中。
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
	cipherText := make([]byte, aes.BlockSize+len(padContent))
	// 随机一个block大小作为IV
	// 采用不同的IV时相同的密钥将会产生不同的密文，可以理解为一次加密的session
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.New("iv random error:" + err.Error())
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], padContent)
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
	iv := content[:aes.BlockSize]
	content = content[aes.BlockSize:]
	if len(content)%aes.BlockSize != 0 {
		return nil, errors.New("padContent is not a multiple of the block size.")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	//CryptBlocks可以原地更新
	mode.CryptBlocks(content, content)
	content = Pkcs5UnPadding(content)
	return content, nil
}
