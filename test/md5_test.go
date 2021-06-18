package test

import (
	"testing"

	"github.com/coredumptoday/hashpump/md5"
)

const STR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func TestMD5(t *testing.T) {
	md5.Sum([]byte(STR))
}
