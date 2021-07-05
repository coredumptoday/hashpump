package hashpump

import (
	"crypto"
	"errors"
	"hash"

	"github.com/coredumptoday/hashpump/plugin"
)

func init() {
	RegisterPump(crypto.MD5, plugin.MD5Build)
	RegisterPump(crypto.SHA1, plugin.SHA1Build)
	RegisterPump(crypto.SHA256, plugin.SHA256Build)
	//RegisterPump(crypto.SHA224, plugin.SHA224Build)
	RegisterPump(crypto.SHA512, plugin.SHA512Build)
}

type BuildFunc func([]byte, []byte, int) (padding, mb []byte, err error)

var pumpMap = make(map[crypto.Hash]BuildFunc)

func RegisterPump(h crypto.Hash, f BuildFunc) {
	pumpMap[h] = f
}

type pump interface {
	hash.Hash
	MarshalBinary() ([]byte, error)
	UnmarshalBinary(b []byte) error
}

type Builder struct {
	Origin []byte
	KeyLen int
	Sign   []byte
	h      crypto.Hash
}

func NewBuilder(o, s []byte, kl int, h crypto.Hash) *Builder {
	return &Builder{
		Origin: o,
		KeyLen: kl,
		Sign:   s,
		h:      h,
	}
}

func (b *Builder) getFunc(h crypto.Hash) (BuildFunc, error) {
	if bf, ok := pumpMap[h]; ok {
		return bf, nil
	} else {
		return nil, errors.New("can not support " + h.String())
	}
}

func (b *Builder) Build() (padding []byte, nh hash.Hash, err error) {
	bf, err := b.getFunc(b.h)
	if err != nil {
		return nil, nil, err
	}

	padding, mb, err := bf(b.Origin, b.Sign, b.KeyLen)
	if err != nil {
		return nil, nil, err
	}

	nh = b.h.New()
	err = nh.(pump).UnmarshalBinary(mb)
	if err != nil {
		return nil, nil, err
	}

	return
}
