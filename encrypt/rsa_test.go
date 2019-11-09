package encrypt

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestRsaSign(t *testing.T) {
	t.Log("TestRsaSign start ...")
	var priKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDWqjG6dpVIjV0JTlr5qytAUXM191ilTWT3Fd+dU/4wyMOh6duyPFZ5gLbUndDr7sjAVGISLPp4xMLDaU1jPex+9Me3HnG2H1X9ppdKoIyZ3MElO3LdWVRGBLxSX2jzjfuLyL/APKWTM2Lw9ziu5WrQwP7No5xGpOT3sQ7s1slyEQCaZeG2gzUPsg+VTBA6uTzuVuQDFS0FSLrH9tGUiartHj7UocXpM4H2QKJj4wMXTX9nhR04YSC6yrNs4CUPbHHtg5W+TH0qKrJxm9rmwxJ42U8rp5UmZm+Pm0AGiDInZmJ/P4S3bgydHd1grkwR01wOq1I7DLTGQG0YkCw5AiJ1AgMBAAECggEAT1Gj/lpC3wQdFIs3Ynm1CZcPEynKP4pRfFtAvUmD61LDtthKrZlN+qds5zNJN2SMGUUU19J22pkZvkrypXEEKgUYprlBGyKJC6i6zoB0c4X2eGN3FgMj+JtXWriWdyhHgmczMz01kSazsIYpE7cBuREXFbUW0aOsVzm9YhYbaWHhcdpomfXhGv7tr1zzlp/fa53pHPrMsAlzqzJSeJ0wD4bzOHSv6lu4TCiY6r07s5hdQxtv8N/uVjVevpo5kYcqQGmpfW/bVuhwEQAVEgAkv+dc/j/D3mKH+0gA68P0vPa4idcZ8vbOjllz4yelnOvRgEmjQWf4r3XW+vhr+8UUAQKBgQD3TAHvyxV0UlLtbutMP0qyg/KF6KBV/Nc1owHyS9ZXVkkyI4kllaQddhtypQgrWmOb4eA3ue34D79AszLOfh8e7Ms7ekdOwHFQgznMx6ecZ3GChP6Ax3NjBl9mG5GmjP9AvpvHaI62cLn1HD+NjlLAcqFpwV96kw1rSmygwoaXYQKBgQDeODEXVsRSiG3XfaDstUjtPluw9BqVdaVS2/3yMnYsd40MsrQ8M/ns6rJeTz03dwOW8pDSFNIOo7t5nkP1m7JZGLJ/O7fKH5lXLOFbUFuUg3MqNo1RSE0NEQ6Pif3l1PmNfdTV+zj3kTNBMERdi7DUpv/5x8mJczxpOnttJERnlQKBgE3+BbpXxUtrT0Ycrk7cwzUr0ggThsW3uTPsVgfRjSb8Spdqh6131UuJXTy5+aqalkGqaimJFRkf9kR0f7iKJEx/h9UZSnX20YX/7PG9ogn8wdrVEOMShDyd3OZ6GWR6oWIM+1pXinLVeIBqSUzerxCM1oVg/DjPOfM1hK7qysHhAoGBAMa+zvkmuxNtvX+7dk/+myjEWtFaoOQHgkMnSmpxQ0vl6JrwwU4O1npUNg8vI3sV0HoSm/+oa254ddYB/JoQFGSnOA2fZXM667QSCcPXjPC42Clq/N0zouYK2VD7g78oycEIR3DR7VNN499rwdlAdHjcm5fUXaW3ENK0YWttwlg5AoGAGBtO5NDWfJTpJUOlAJmq4gOWI/FHczU5vaxmCMSPo65GLlecMXfoOWStfZFr9pHzO5fLNpnrJNClrumpoZM+3XYyzQW9bWRSeXuA2Jk2I7Y0oGgfkumN7+Oqp3Z9ul9Tsp3yns8skVyhhEk7LqMlHJBgJnotaI2sMlr36D6v6WA="
	var pubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1qoxunaVSI1dCU5a+asrQFFzNfdYpU1k9xXfnVP+MMjDoenbsjxWeYC21J3Q6+7IwFRiEiz6eMTCw2lNYz3sfvTHtx5xth9V/aaXSqCMmdzBJTty3VlURgS8Ul9o8437i8i/wDylkzNi8Pc4ruVq0MD+zaOcRqTk97EO7NbJchEAmmXhtoM1D7IPlUwQOrk87lbkAxUtBUi6x/bRlImq7R4+1KHF6TOB9kCiY+MDF01/Z4UdOGEgusqzbOAlD2xx7YOVvkx9KiqycZva5sMSeNlPK6eVJmZvj5tABogyJ2Zifz+Et24MnR3dYK5MEdNcDqtSOwy0xkBtGJAsOQIidQIDAQAB"
	priKeybyte, err := base64.StdEncoding.DecodeString(priKey)
	if err != nil {
		t.Error("priKey base64 decode error:", err.Error())
	}
	pubKeybyte, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		t.Error("pubkey base64 decode error:", err.Error())
	}
	originData := []byte("Hello,RSA.")
	sign, err := RsaSign(originData, priKeybyte, SHA256)
	if err != nil {
		t.Error("RSA sign by SHA256 error:", err.Error())
	}
	isOk, err := RsaVerify(originData, pubKeybyte, sign, SHA256)
	if err != nil {
		t.Error("RSA verify by SHA256 error:", err.Error())
	}
	if !isOk {
		t.Error("RSA verify by SHA256 not pass")
	} else {
		t.Log("RSA verify by SHA256 pass")
	}
	t.Log("TestRsaSign end ...")
}

func ExampleRsaSign() {
	//私钥
	var priKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDWqjG6dpVIjV0JTlr5qytAUXM191ilTWT3Fd+dU/4wyMOh6duyPFZ5gLbUndDr7sjAVGISLPp4xMLDaU1jPex+9Me3HnG2H1X9ppdKoIyZ3MElO3LdWVRGBLxSX2jzjfuLyL/APKWTM2Lw9ziu5WrQwP7No5xGpOT3sQ7s1slyEQCaZeG2gzUPsg+VTBA6uTzuVuQDFS0FSLrH9tGUiartHj7UocXpM4H2QKJj4wMXTX9nhR04YSC6yrNs4CUPbHHtg5W+TH0qKrJxm9rmwxJ42U8rp5UmZm+Pm0AGiDInZmJ/P4S3bgydHd1grkwR01wOq1I7DLTGQG0YkCw5AiJ1AgMBAAECggEAT1Gj/lpC3wQdFIs3Ynm1CZcPEynKP4pRfFtAvUmD61LDtthKrZlN+qds5zNJN2SMGUUU19J22pkZvkrypXEEKgUYprlBGyKJC6i6zoB0c4X2eGN3FgMj+JtXWriWdyhHgmczMz01kSazsIYpE7cBuREXFbUW0aOsVzm9YhYbaWHhcdpomfXhGv7tr1zzlp/fa53pHPrMsAlzqzJSeJ0wD4bzOHSv6lu4TCiY6r07s5hdQxtv8N/uVjVevpo5kYcqQGmpfW/bVuhwEQAVEgAkv+dc/j/D3mKH+0gA68P0vPa4idcZ8vbOjllz4yelnOvRgEmjQWf4r3XW+vhr+8UUAQKBgQD3TAHvyxV0UlLtbutMP0qyg/KF6KBV/Nc1owHyS9ZXVkkyI4kllaQddhtypQgrWmOb4eA3ue34D79AszLOfh8e7Ms7ekdOwHFQgznMx6ecZ3GChP6Ax3NjBl9mG5GmjP9AvpvHaI62cLn1HD+NjlLAcqFpwV96kw1rSmygwoaXYQKBgQDeODEXVsRSiG3XfaDstUjtPluw9BqVdaVS2/3yMnYsd40MsrQ8M/ns6rJeTz03dwOW8pDSFNIOo7t5nkP1m7JZGLJ/O7fKH5lXLOFbUFuUg3MqNo1RSE0NEQ6Pif3l1PmNfdTV+zj3kTNBMERdi7DUpv/5x8mJczxpOnttJERnlQKBgE3+BbpXxUtrT0Ycrk7cwzUr0ggThsW3uTPsVgfRjSb8Spdqh6131UuJXTy5+aqalkGqaimJFRkf9kR0f7iKJEx/h9UZSnX20YX/7PG9ogn8wdrVEOMShDyd3OZ6GWR6oWIM+1pXinLVeIBqSUzerxCM1oVg/DjPOfM1hK7qysHhAoGBAMa+zvkmuxNtvX+7dk/+myjEWtFaoOQHgkMnSmpxQ0vl6JrwwU4O1npUNg8vI3sV0HoSm/+oa254ddYB/JoQFGSnOA2fZXM667QSCcPXjPC42Clq/N0zouYK2VD7g78oycEIR3DR7VNN499rwdlAdHjcm5fUXaW3ENK0YWttwlg5AoGAGBtO5NDWfJTpJUOlAJmq4gOWI/FHczU5vaxmCMSPo65GLlecMXfoOWStfZFr9pHzO5fLNpnrJNClrumpoZM+3XYyzQW9bWRSeXuA2Jk2I7Y0oGgfkumN7+Oqp3Z9ul9Tsp3yns8skVyhhEk7LqMlHJBgJnotaI2sMlr36D6v6WA="
	//公钥
	var pubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1qoxunaVSI1dCU5a+asrQFFzNfdYpU1k9xXfnVP+MMjDoenbsjxWeYC21J3Q6+7IwFRiEiz6eMTCw2lNYz3sfvTHtx5xth9V/aaXSqCMmdzBJTty3VlURgS8Ul9o8437i8i/wDylkzNi8Pc4ruVq0MD+zaOcRqTk97EO7NbJchEAmmXhtoM1D7IPlUwQOrk87lbkAxUtBUi6x/bRlImq7R4+1KHF6TOB9kCiY+MDF01/Z4UdOGEgusqzbOAlD2xx7YOVvkx9KiqycZva5sMSeNlPK6eVJmZvj5tABogyJ2Zifz+Et24MnR3dYK5MEdNcDqtSOwy0xkBtGJAsOQIidQIDAQAB"
	priKeybyte, err := base64.StdEncoding.DecodeString(priKey)
	if err != nil {
		_ = fmt.Sprintf("priKey base64 decode error: %s", err.Error())
	}
	pubKeybyte, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		_ = fmt.Sprintf("pubkey base64 decode error: %s", err.Error())
	}
	//原文
	originData := []byte("Hello,RSA.")
	//使用私钥签名
	sign, err := RsaSign(originData, priKeybyte, SHA256)
	if err != nil {
		_ = fmt.Sprintf("RSA sign by SHA256 error: %s", err.Error())
	}
	//使用公钥验签
	isOk, err := RsaVerify(originData, pubKeybyte, sign, SHA256)
	if err != nil {
		_ = fmt.Sprintf("RSA verify by SHA256 error: %s", err.Error())
	}
	if !isOk {
		fmt.Println("RSA verify by SHA256 not pass")
	} else {
		fmt.Println("RSA verify by SHA256 pass")
	}
}
