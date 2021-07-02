package hashpump

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"testing"
)

const KEY = "43f55d8396d0982fd62666883a9b3730"

func checkSum(sign, data []byte, hash crypto.Hash) bool {
	h := hash.New()
	h.Write(data)
	newSign := h.Sum(nil)
	return bytes.Equal(sign, newSign)
}

func TestMD5(t *testing.T) {
	data := "orderIds=11111,999"
	injectData := ",22222,33333"

	md5Sign := md5.Sum([]byte(KEY + data))
	fmt.Println("origin md5:", hex.EncodeToString(md5Sign[:]))
	fmt.Println("origin query:", data)

	b := NewBuilder([]byte(data), md5Sign[:], len(KEY), crypto.MD5)
	padding, newMD5, err := b.Build()
	if err != nil {
		t.Error(err)
	}

	newMD5.Write([]byte(injectData))
	newSign := newMD5.Sum(nil)
	fmt.Println("new md5: ", hex.EncodeToString(newSign))
	fmt.Println("new query: ", data+string(padding)+injectData)

	if checkSum(newSign, []byte(KEY+data+string(padding)+injectData), crypto.MD5) {
		fmt.Println("It works for " + crypto.MD5.String())
	}
}
