package prudp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"io"
)

type BlockCrypt interface {
	// Encrypt encrypts the whole block in src into dst.
	// Dst and src may point at the same memory.
	Encrypt(dst, src []byte)

	// Decrypt decrypts the whole block in src into dst.
	// Dst and src may point at the same memory.
	Decrypt(dst, src []byte)
}

func (c *sm4BlockCrypt) Encrypt(dst, src []byte) { encrypt(c.block, dst, src, c.encbuf[:]) }
func (c *sm4BlockCrypt) Decrypt(dst, src []byte) { decrypt(c.block, dst, src, c.decbuf[:]) }

func encrypt(block cipher.Block, dst, src, buf []byte) {
	switch block.BlockSize() {
	case 8:
		encrypt8(block, dst, src, buf)
	case 16:
		encrypt16(block, dst, src, buf)
	default:
		panic("unsupported cipher block size")
	}
}

func decrypt(block cipher.Block, dst, src, buf []byte) {
	switch block.BlockSize() {
	case 8:
		decrypt8(block, dst, src, buf)
	case 16:
		decrypt16(block, dst, src, buf)
	default:
		panic("unsupported cipher block size")
	}
}

// ¬¬¬¬¬¬¬¬¬¬¬¬¬¬
//    Entropy
// ¬¬¬¬¬¬¬¬¬¬¬¬¬¬

type Entropy interface {
	Init()
	Fill(nonce []byte)
}

// nonceMD5 nonce generator for packet header
type nonceMD5 struct {
	seed [md5.Size]byte
}

func (n *nonceMD5) Fill(nonce []byte) {
	if n.seed[0] == 0 { // entropy update
		io.ReadFull(rand.Reader, n.seed[:])
	}
	n.seed = md5.Sum(n.seed[:])
	copy(nonce, n.seed[:])
}

// nonceAES128 nonce generator for packet headers
type nonceAES128 struct {
	seed  [aes.BlockSize]byte
	block cipher.Block
}

func (n *nonceAES128) Init() {
	var key [16]byte //aes-128
	io.ReadFull(rand.Reader, key[:])
	io.ReadFull(rand.Reader, n.seed[:])
	block, _ := aes.NewCipher(key[:])
	n.block = block
}

func (n *nonceAES128) Fill(nonce []byte) {
	if n.seed[0] == 0 { // entropy update
		io.ReadFull(rand.Reader, n.seed[:])
	}
	n.block.Encrypt(n.seed[:], n.seed[:])
	copy(nonce, n.seed[:])
}
