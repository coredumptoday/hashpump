package plugin

import (
	"crypto/sha1"
	"encoding/binary"
)

const (
	sha1chunk = 64
)

const (
	sha1magic         = "sha\x01"
	sha1marshaledSize = len(sha1magic) + 5*4 + sha1chunk + 8
)

func sha1padding(l uint64) []byte {
	padding := make([]byte, 0)

	var tmp [64]byte
	tmp[0] = 0x80
	if l%64 < 56 {
		padding = append(padding, tmp[0:56-l%64]...)
	} else {
		padding = append(padding, tmp[0:64+56-l%64]...)
	}
	l <<= 3
	binary.BigEndian.PutUint64(tmp[:], l)
	padding = append(padding, tmp[0:8]...)
	return padding
}

var SHA1Build = func(Origin, Sign []byte, KeyLen int) (padding, mb []byte, err error) {
	originLen := uint64(len(Origin) + KeyLen)
	padding = sha1padding(originLen)

	mb = make([]byte, 0, sha1marshaledSize)
	mb = append(mb, sha1magic...)
	mb = appendUint32B2B(mb, Sign[:4])
	mb = appendUint32B2B(mb, Sign[4:8])
	mb = appendUint32B2B(mb, Sign[8:12])
	mb = appendUint32B2B(mb, Sign[12:16])
	mb = appendUint32B2B(mb, Sign[16:])
	mb = mb[:len(mb)+sha1.BlockSize] // already zero
	mb = appendUint64(mb, originLen+uint64(len(padding)))

	return
}
