package plugin

import (
	"crypto/md5"
	"encoding/binary"
)

const (
	md5magic         = "md5\x01"
	md5marshaledSize = len(md5magic) + 4*4 + md5.BlockSize + 8
)

func md5padding(l uint64) []byte {
	tmp := [1 + 63 + 8]byte{0x80}
	pad := (55 - l) % 64                             // calculate number of padding bytes
	binary.LittleEndian.PutUint64(tmp[1+pad:], l<<3) // append length in bits
	return tmp[:1+pad+8]
}

var MD5Build = func(Origin, Sign []byte, KeyLen int) (padding, mb []byte, err error) {
	originLen := uint64(len(Origin) + KeyLen)
	padding = md5padding(originLen)

	mb = make([]byte, 0, md5marshaledSize)
	mb = append(mb, md5magic...)
	mb = appendUint32(mb, Sign[:4])
	mb = appendUint32(mb, Sign[4:8])
	mb = appendUint32(mb, Sign[8:12])
	mb = appendUint32(mb, Sign[12:])
	mb = mb[:len(mb)+md5.BlockSize] // already zero
	mb = appendUint64(mb, originLen+uint64(len(padding)))

	return
}
