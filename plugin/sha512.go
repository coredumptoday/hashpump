package plugin

import (
	"crypto/sha512"
	"encoding/binary"
)

const (
	sha512chunk = 128
)

const (
	sha512magic384      = "sha\x04"
	sha512magic512_224  = "sha\x05"
	sha512magic512_256  = "sha\x06"
	sha512magic512      = "sha\x07"
	sha512marshaledSize = len(sha512magic512) + 8*8 + sha512chunk + 8
)

func sha512padding(l uint64) []byte {
	padding := make([]byte, 0)

	var tmp [128]byte
	tmp[0] = 0x80
	if l%128 < 112 {
		padding = append(padding, tmp[0:112-l%128]...)
	} else {
		padding = append(padding, tmp[0:128+112-l%128]...)
	}

	// Length in bits.
	l <<= 3
	binary.BigEndian.PutUint64(tmp[0:], 0) // upper 64 bits are always zero, because len variable has type uint64
	binary.BigEndian.PutUint64(tmp[8:], l)
	padding = append(padding, tmp[0:16]...)
	return padding
}

var SHA512Build = func(Origin, Sign []byte, KeyLen int) (padding, mb []byte, err error) {
	originLen := uint64(len(Origin) + KeyLen)
	padding = sha512padding(originLen)

	mb = make([]byte, 0, sha512marshaledSize)
	mb = append(mb, sha512magic512...)

	mb = appendUint64B2B(mb, Sign[:8])
	mb = appendUint64B2B(mb, Sign[8:16])
	mb = appendUint64B2B(mb, Sign[16:24])
	mb = appendUint64B2B(mb, Sign[24:32])
	mb = appendUint64B2B(mb, Sign[32:40])
	mb = appendUint64B2B(mb, Sign[40:48])
	mb = appendUint64B2B(mb, Sign[48:56])
	mb = appendUint64B2B(mb, Sign[56:])

	mb = mb[:len(mb)+sha512.BlockSize] // already zero
	mb = appendUint64(mb, originLen+uint64(len(padding)))

	return
}
