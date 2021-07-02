package pump

import (
	"crypto/md5"
	"encoding/binary"
)

const (
	magic         = "md5\x01"
	marshaledSize = len(magic) + 4*4 + md5.BlockSize + 8
)

func md5padding(l uint64) []byte {
	tmp := [1 + 63 + 8]byte{0x80}
	pad := (55 - l) % 64                             // calculate number of padding bytes
	binary.LittleEndian.PutUint64(tmp[1+pad:], l<<3) // append length in bits
	return tmp[:1+pad+8]
}

func appendUint32(b, s []byte) []byte {
	l32 := binary.LittleEndian.Uint32(s)
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], l32)
	return append(b, a[:]...)
}

func appendUint64(b []byte, x uint64) []byte {
	var a [8]byte
	binary.BigEndian.PutUint64(a[:], x)
	return append(b, a[:]...)
}

var MD5Build = func(Origin, Sign []byte, KeyLen int) (padding, mb []byte, err error) {
	originLen := uint64(len(Origin) + KeyLen)
	padding = md5padding(originLen)

	mb = make([]byte, 0, marshaledSize)
	mb = append(mb, magic...)
	mb = appendUint32(mb, Sign[:4])
	mb = appendUint32(mb, Sign[4:8])
	mb = appendUint32(mb, Sign[8:12])
	mb = appendUint32(mb, Sign[12:])
	mb = mb[:len(mb)+md5.BlockSize] // already zero
	mb = appendUint64(mb, originLen+uint64(len(padding)))

	return
}
