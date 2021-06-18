package md5

import (
	"encoding/binary"
	"encoding/hex"
)

// The size of an MD5 checksum in bytes.
const Size = 16

// The blocksize of MD5 in bytes.
const BlockSize = 64

const (
	init0 = 0x67452301
	init1 = 0xEFCDAB89
	init2 = 0x98BADCFE
	init3 = 0x10325476
)

// digest represents the partial evaluation of a checksum.
type digest struct {
	s   [4]uint32
	x   [BlockSize]byte
	nx  int
	len uint64
}

func (d *digest) Reset() {
	d.s[0] = init0
	d.s[1] = init1
	d.s[2] = init2
	d.s[3] = init3
	d.nx = 0
	d.len = 0
}

func (d *digest) Write(p []byte) (nn int, err error) {
	// Note that we currently call block or blockGeneric
	// directly (guarded using haveAsm) because this allows
	// escape analysis to see that p and d don't escape.
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == BlockSize {
			blockGeneric(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= BlockSize {
		n := len(p) &^ (BlockSize - 1)
		blockGeneric(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest) checkSum() [Size]byte {
	// Append 0x80 to the end of the message and then append zeros
	// until the length is a multiple of 56 bytes. Finally append
	// 8 bytes representing the message length in bits.
	//
	// 1 byte end marker :: 0-63 padding bytes :: 8 byte length
	tmp := [1 + 63 + 8]byte{0x80}
	pad := (55 - d.len) % 64                             // calculate number of padding bytes
	binary.LittleEndian.PutUint64(tmp[1+pad:], d.len<<3) // append length in bits
	d.Write(tmp[:1+pad+8])

	// The previous write ensures that a whole number of
	// blocks (i.e. a multiple of 64 bytes) have been hashed.
	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [Size]byte
	binary.LittleEndian.PutUint32(digest[0:], d.s[0])
	binary.LittleEndian.PutUint32(digest[4:], d.s[1])
	binary.LittleEndian.PutUint32(digest[8:], d.s[2])
	binary.LittleEndian.PutUint32(digest[12:], d.s[3])
	return digest
}

// Sum returns the MD5 checksum of the data.
func Sum(data []byte) [Size]byte {
	var d digest
	d.Reset()
	d.Write(data)
	return d.checkSum()
}

//md5延长攻击
func HashPump(sign, origStr, extendStr string, keyLen int) (s, e []byte, err error) {
	var d digest
	d.Reset()

	signByteArr, err := hex.DecodeString(sign)
	if err != nil {
		return nil, nil, err
	}

	d.s[0] = binary.LittleEndian.Uint32(signByteArr[:4])
	d.s[1] = binary.LittleEndian.Uint32(signByteArr[4:8])
	d.s[2] = binary.LittleEndian.Uint32(signByteArr[8:12])
	d.s[3] = binary.LittleEndian.Uint32(signByteArr[12:])

	d.len = uint64(len(origStr) + keyLen)

	tmp := [1 + 63 + 8]byte{0x80}
	pad := (55 - d.len) % 64                             // calculate number of padding bytes
	binary.LittleEndian.PutUint64(tmp[1+pad:], d.len<<3) // append length in bits

	e = []byte(origStr)
	e = append(e, tmp[:1+pad+8]...)
	d.len = uint64(len(e) + keyLen)
	e = append(e, []byte(extendStr)...)

	d.Write([]byte(extendStr))
	si := d.checkSum()

	return si[:], e, nil
}
