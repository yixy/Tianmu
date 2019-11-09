package encrypt

import "bytes"

// PKCSPadding填充函数。
//
// 需要填充的字节，均以padding的数目赋值。
//
// blockSize需要小于256，因为只有小于256才能放到一个byte中。
func Pkcs5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize //需要padding的byte数目
	// 最少填充一个byte
	// 如果原文刚好是blockSize的整数倍，则再填充blockSize个字节
	padText := bytes.Repeat([]byte{byte(padding)}, padding) //生成填充的文本
	return append(cipherText, padText...)
}

// PkCS5UnPadding截取函数。
//
// 去掉最后一个字节unPadding次。
func Pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	//去掉最后一个字节unPadding次
	unPadding := int(origData[length-1])
	return origData[:(length - unPadding)]
}
