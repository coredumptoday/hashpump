package plugin

import "encoding/binary"

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

func appendUint32B2B(b, s []byte) []byte {
	l32 := binary.BigEndian.Uint32(s)
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], l32)
	return append(b, a[:]...)
}

func appendUint64B2B(b, s []byte) []byte {
	l64 := binary.BigEndian.Uint64(s)
	var a [8]byte
	binary.BigEndian.PutUint64(a[:], l64)
	return append(b, a[:]...)
}
