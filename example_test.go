package hashpump

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"
)

const KEY = "43f55d8396d0982fd62666883a9b3730"

func checkSum(sign, data []byte, hash crypto.Hash) bool {
	h := hash.New()
	h.Write(data)
	newSign := h.Sum(nil)
	//fmt.Println(newSign)
	//fmt.Println(hex.EncodeToString(newSign))
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

func TestSHA1(t *testing.T) {
	data := "orderIds=11111,999"
	injectData := ",22222,33333"

	sha1Sign := sha1.Sum([]byte(KEY + data))
	fmt.Println("origin sha1:", hex.EncodeToString(sha1Sign[:]))
	fmt.Println("origin query:", data)

	b := NewBuilder([]byte(data), sha1Sign[:], len(KEY), crypto.SHA1)
	padding, newSha1, err := b.Build()
	if err != nil {
		t.Error(err)
	}

	newSha1.Write([]byte(injectData))
	newSign := newSha1.Sum(nil)
	fmt.Println("new sha1: ", hex.EncodeToString(newSign))
	fmt.Println("new query: ", data+string(padding)+injectData)

	if checkSum(newSign, []byte(KEY+data+string(padding)+injectData), crypto.SHA1) {
		fmt.Println("It works for " + crypto.SHA1.String())
	}
}

func TestSHA256(t *testing.T) {
	data := "orderIds=11111,999"
	injectData := ",22222,33333"

	sha256Sign := sha256.Sum256([]byte(KEY + data))
	fmt.Println("origin sha256:", hex.EncodeToString(sha256Sign[:]))
	fmt.Println("origin query:", data)

	b := NewBuilder([]byte(data), sha256Sign[:], len(KEY), crypto.SHA256)
	padding, newSha256, err := b.Build()
	if err != nil {
		t.Error(err)
	}

	newSha256.Write([]byte(injectData))
	newSign := newSha256.Sum(nil)
	fmt.Println("new sha256: ", hex.EncodeToString(newSign))
	fmt.Println("new query: ", data+string(padding)+injectData)

	if checkSum(newSign, []byte(KEY+data+string(padding)+injectData), crypto.SHA256) {
		fmt.Println("It works for " + crypto.SHA256.String())
	}
}

func TestSHA512(t *testing.T) {
	data := "orderIds=11111,999"
	injectData := ",22222,33333"

	sha512Sign := sha512.Sum512([]byte(KEY + data))
	fmt.Println("origin sha512:", hex.EncodeToString(sha512Sign[:]))
	fmt.Println("origin query:", data)

	b := NewBuilder([]byte(data), sha512Sign[:], len(KEY), crypto.SHA512)
	padding, newSha512, err := b.Build()
	if err != nil {
		t.Error(err)
	}

	newSha512.Write([]byte(injectData))
	newSign := newSha512.Sum(nil)
	fmt.Println("new sha512: ", hex.EncodeToString(newSign))
	fmt.Println("new query: ", data+string(padding)+injectData)

	if checkSum(newSign, []byte(KEY+data+string(padding)+injectData), crypto.SHA512) {
		fmt.Println("It works for " + crypto.SHA512.String())
	}
}
