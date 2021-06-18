package test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/coredumptoday/hashpump/md5"
)

const STR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

const KEY = "43f55d8396d0982fd62666883a9b3730"

func TestMD5(t *testing.T) {
	m := md5.Sum([]byte(STR))
	fmt.Println(hex.EncodeToString(m[:]))
}

func TestMD5Pump(t *testing.T) {
	data := "orderIds=11111,999"
	injectData := ",22222,33333"

	originMd5Str := md5.Sum([]byte(KEY + data))
	fmt.Println("origin:", hex.EncodeToString(originMd5Str[:]), KEY+data)

	newSign, newStr, err := md5.HashPump(hex.EncodeToString(originMd5Str[:]), data, injectData, len(KEY))
	fmt.Println(hex.EncodeToString(newSign))
	fmt.Println(string(newStr))
	fmt.Println(err)

	m := md5.Sum([]byte(KEY + string(newStr)))
	fmt.Println(hex.EncodeToString(m[:]))

	d := bytes.Split(newStr, []byte("="))
	no := bytes.Split(d[1], []byte(","))

	for _, v := range no {
		fmt.Println(strconv.Atoi(strings.TrimSpace(string(v))))
	}
}
