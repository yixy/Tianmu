package encrypt

import (
	"fmt"
	"testing"
)

func TestTripleECBDesEncrypt(t *testing.T) {
	t.Log("TestTripleECBDesEncrypt start...")
	key := []byte("123456789012345678901234")
	origData := []byte("Hello,3DES")
	crypted, err := TripleECBDesEncrypt(origData, key)
	if err != nil {
		t.Error("TripleECBDesEncrypt error." + err.Error())
	}
	result, err := TripleECBDesDecrypt(crypted, key)
	if err != nil {
		t.Error("TripleECBDesDecrypt error." + err.Error())
	}
	t.Log(string(result))
	if string(result) == string(origData) {
		t.Log("TestTripleECBDesEncrypt success.")
	} else {
		t.Error("TestTripleECBDesEncrypt error.")
	}
	t.Log("TestTripleECBDesEncrypt end...")
}

func ExampleTripleECBDesEncrypt() {
	//密钥
	key := []byte("123456789012345678901234")
	//原文
	origData := []byte("Hello,3DES")
	//3des加密
	crypted, err := TripleECBDesEncrypt(origData, key)
	if err != nil {
		_ = fmt.Sprintf("TripleECBDesEncrypt error: %s", err.Error())
	}
	//3des解密
	result, err := TripleECBDesDecrypt(crypted, key)
	if err != nil {
		_ = fmt.Sprintf("TripleECBDesDecrypt error: %s", err.Error())
	}
	fmt.Println(string(result))
}
