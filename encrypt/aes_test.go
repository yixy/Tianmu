package encrypt

import (
	"fmt"
	"testing"
)

func TestAesNewCBCEncrypter(t *testing.T) {
	t.Log("TestAesNewCBCEncrypter start...")
	originData := []byte("Hello,AES")
	key := []byte("1234567890123456")
	encrypted, err := AesNewCBCEncrypter(originData, key)
	if err != nil {
		t.Error("AES encrypt error:" + err.Error())
	}
	result, err := AesNewCBCDecrypter(encrypted, key)
	if err != nil {
		t.Error("AES decrypt error:" + err.Error())
	}
	t.Log(string(result))
	if string(result) == string(originData) {
		t.Log("TestAesNewCBCEncrypter success.")
	} else {
		t.Error("TestAesNewCBCEncrypter error.")
	}
	t.Log("TestAesNewCBCEncrypter end...")
}

func ExampleAesNewCBCEncrypter() {
	//原文
	originData := []byte("Hello,AES")
	//密钥
	key := []byte("1234567890123456")
	//加密
	encrypted, err := AesNewCBCEncrypter(originData, key)
	if err != nil {
		_ = fmt.Sprintf("AES encrypt error:%s", err.Error())
	}
	//解密
	result, err := AesNewCBCDecrypter(encrypted, key)
	if err != nil {
		_ = fmt.Sprintf("AES decrypt error%s", err.Error())
	}
	fmt.Println(string(result))
}
