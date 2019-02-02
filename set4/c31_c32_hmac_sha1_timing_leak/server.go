package c31_hmac_sha1_timing_leak

import (
	"net/url"
	"time"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
)

type Server struct {
	sleep time.Duration
	hmac  HMACSystem
}

func NewServer(hmac HMACSystem, sleep time.Duration) Server {
	return Server{
		sleep: sleep,
		hmac:  hmac,
	}
}

// file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
func (obj Server) CheckFile(sQuery string) int {
	vals, err := url.ParseQuery(sQuery)
	if err != nil {
		return 400
	}
	file := vals.Get("file")
	sign := c1_hex_to_base64.ParseHex(vals.Get("signature"))
	mac := obj.hmac.HMAC([]byte(file))
	if !obj.insecureEqual(sign, mac) {
		return 500
	}
	return 200
}

func (obj Server) insecureEqual(sign, mac []byte) bool {
	if len(sign) != len(mac) {
		return false
	}
	for i := 0; i < len(sign); i++ {
		if sign[i] != mac[i] {
			return false
		}
		time.Sleep(obj.sleep)
	}
	return true
}
