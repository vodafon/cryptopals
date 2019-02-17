package c51_compression_ratio

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/vodafon/cryptopals/set2/c10_implement_cbc_mode"
	"github.com/vodafon/cryptopals/set3/c18_ctr_stream_mode"
)

const (
	CTRMode = iota
	CBCMode
)

type CompressSystem struct {
	sessionID string
	encMode   int
}

func (obj CompressSystem) CompressLen(body []byte) int {
	req := obj.formatRequest(body)
	comp := obj.compress(req)
	enc := obj.encrypt(comp)
	return len(enc)
}

func NewCompressSystem(sessionID string, encMode int) CompressSystem {
	return CompressSystem{
		sessionID: sessionID,
		encMode:   encMode,
	}
}

func (obj CompressSystem) formatRequest(body []byte) []byte {
	req := "POST / HTTP/1.1\r\nHost: hapless.com\r\nCookie: sessionid="
	req += obj.sessionID + "\r\n"
	req += fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
	return []byte(req)
}

func (obj CompressSystem) compress(req []byte) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(req)
	w.Close()
	return b.Bytes()
}

func (obj CompressSystem) encrypt(req []byte) []byte {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	if obj.encMode == CTRMode {
		ctr := c18_ctr_stream_mode.NewCTRSystem(key)
		nonce := binary.BigEndian.Uint32(iv)
		res, err := ctr.Encrypt(req, nonce)
		if err != nil {
			panic(err)
		}
		return res
	}
	return c10_implement_cbc_mode.Encrypt(req, key, iv)
}

func ExploitCTR(cs CompressSystem) []byte {
	prefix := []byte("sessionid=")
	sid := []byte{}

	for {
		payload := append(prefix, sid...)
		startLen := cs.CompressLen(append(payload, '\r'))
		tmpLen := startLen
		for i := 0; i < 256; i++ {
			tmpLen = cs.CompressLen(append(payload, byte(i)))
			if tmpLen < startLen {
				sid = append(sid, byte(i))
				break
			}
		}
		if tmpLen >= startLen || bytes.HasSuffix(sid, []byte("\r")) {
			break
		}
	}
	return bytes.TrimSpace(sid)
}

func ExploitCBC(cs CompressSystem) []byte {
	prefix := []byte("sessionid=")
	sid := []byte{}

	for {
		payload := append(prefix, sid...)
		pb := findPrefixBytes(payload, cs)
		payload = append(pb, payload...)
		startLen := cs.CompressLen(append(payload, '\r'))
		tmpLen := startLen
		for i := 0; i < 256; i++ {
			tmpLen = cs.CompressLen(append(payload, byte(i)))
			if tmpLen < startLen {
				sid = append(sid, byte(i))
				break
			}
		}
		if tmpLen >= startLen || bytes.HasSuffix(sid, []byte("\r")) {
			break
		}
	}
	return bytes.TrimSpace(sid)
}

func findPrefixBytes(prefix []byte, cs CompressSystem) []byte {
	payload := append(prefix, '\r')
	pb := prefixBytes(32)
	startLen := cs.CompressLen(append(pb, payload...))
	for i := 1; i < 64; i++ {
		tmpLen := cs.CompressLen(append(pb[:len(pb)-i], payload...))
		if tmpLen < startLen {
			return pb[:len(pb)-i+1]
		}
	}
	return []byte{}
}

func prefixBytes(l int) []byte {
	prefix := make([]byte, l)
	for i := 0; i < l; i++ {
		prefix[i] = byte(i)
	}
	return prefix
}
