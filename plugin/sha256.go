package plugin

import (
	"crypto/sha256"
	"encoding/binary"
)

const (
	sha256chunk = 64
)

const (
	sha256magic224      = "sha\x02"
	sha256magic256      = "sha\x03"
	sha256marshaledSize = len(sha256magic256) + 8*4 + sha256chunk + 8
)

func sha256padding(l uint64) []byte {
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

func buildMb(sign []byte, l uint64, is224 bool) []byte {

	mb := make([]byte, 0, sha256marshaledSize)
	if is224 {
		mb = append(mb, sha256magic224...)
	} else {
		mb = append(mb, sha256magic256...)
	}

	mb = appendUint32B2B(mb, sign[:4])
	mb = appendUint32B2B(mb, sign[4:8])
	mb = appendUint32B2B(mb, sign[8:12])
	mb = appendUint32B2B(mb, sign[12:16])
	mb = appendUint32B2B(mb, sign[16:20])
	mb = appendUint32B2B(mb, sign[20:24])
	mb = appendUint32B2B(mb, sign[24:28])
	if is224 {
		mb = appendUint32B2B(mb, make([]byte, 4))
	} else {
		mb = appendUint32B2B(mb, sign[28:])
	}

	mb = mb[:len(mb)+sha256.BlockSize] // already zero
	mb = appendUint64(mb, l)
	return mb
}

var SHA256Build = func(Origin, Sign []byte, KeyLen int) (padding, mb []byte, err error) {
	originLen := uint64(len(Origin) + KeyLen)
	padding = sha256padding(originLen)

	mb = buildMb(Sign, originLen+uint64(len(padding)), false)

	return
}

var SHA224Build = func(Origin, Sign []byte, KeyLen int) (padding, mb []byte, err error) {
	originLen := uint64(len(Origin) + KeyLen)
	padding = sha256padding(originLen)

	mb = buildMb(Sign, originLen+uint64(len(padding)), true)

	return
}
