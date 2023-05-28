package signature

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"hash"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
)

type Sign struct {
	sync.Mutex
	hash      hash.Hash
	dirty     bool
	timestamp bool
	epoch     int64
}

var ErrInvalidSignature = errors.New("invalid signature")

var ErrShortToken = errors.New("token is too small to be valid")

func New(key []byte, options ...func(*Sign)) *Sign {
	var err error
	for i := 0; i < len(encodeBase58Map); i++ {
		decodeBase58Map[encodeBase58Map[i]] = byte(i)
	}

	s := &Sign{}

	for _, opt := range options {
		opt(s)
	}

	s.hash, err = blake2b.New256(key)
	if err != nil {
		s.hash, _ = blake2b.New256(key[0:64])
	}

	return s
}

func Epoch(e int64) func(*Sign) {
	return func(s *Sign) {
		s.epoch = e
	}
}

func Timestamp(s *Sign) {
	s.timestamp = true
}

// Sign signs data and returns []byte in the format `data.signature`
func (s *Sign) Sign(data []byte) []byte {
	el := base64.RawURLEncoding.EncodedLen(s.hash.Size())
	var t []byte

	if s.timestamp {
		ts := time.Now().Unix() - s.epoch
		etl := encodeBase58Len(ts)
		t = make([]byte, 0, len(data)+etl+el+2)
		t = append(t, data...)
		t = append(t, '.')
		t = t[0 : len(t)+etl]
		encodeBase58(ts, t)
	} else {
		t = make([]byte, 0, len(data)+el+1)
		t = append(t, data...)
	}

	t = append(t, '.')
	tl := len(t)
	t = t[0 : tl+el]

	s.sign(t[tl:], t[0:tl-1])

	return t
}

// Unsign validates a signature and if successful returns the data
func (s *Sign) Unsign(token []byte) ([]byte, error) {
	tl := len(token)
	el := base64.RawURLEncoding.EncodedLen(s.hash.Size())

	if tl < el+2 {
		return nil, ErrShortToken
	}

	dst := make([]byte, el)
	s.sign(dst, token[0:tl-(el+1)])

	if subtle.ConstantTimeCompare(token[tl-el:], dst) != 1 {
		return nil, ErrInvalidSignature
	}

	return token[0 : tl-(el+1)], nil
}

const encodeBase58Map = "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"

var decodeBase58Map [256]byte

func (s *Sign) sign(dst, payload []byte) {
	s.Lock()
	if s.dirty {
		s.hash.Reset()
	}
	s.dirty = true
	s.hash.Write(payload)
	h := s.hash.Sum(nil)
	s.Unlock()

	base64.RawURLEncoding.Encode(dst, h)
}

func encodeBase58Len(i int64) int {
	var l = 1
	for i >= 58 {
		l++
		i /= 58
	}
	return l
}

// encode time int64 into b []byte
func encodeBase58(i int64, b []byte) {
	p := len(b) - 1
	for i >= 58 {
		b[p] = encodeBase58Map[i%58]
		p--
		i /= 58
	}
	b[p] = encodeBase58Map[i]
}

// parses a base58 []byte into a int64
func decodeBase58(b []byte) int64 {
	var id int64
	for p := range b {
		id = id*58 + int64(decodeBase58Map[b[p]])
	}
	return id
}
