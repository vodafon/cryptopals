package c31_hmac_sha1_timing_leak

import (
	"errors"
	"fmt"
	"time"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
)

type ServerExp struct {
	BasePath     string
	BaseDuration time.Duration
}

func Exploit(server Server, fn string, dur time.Duration) ([]byte, error) {
	se := ServerExp{
		BasePath:     "file=" + fn + "&signature=",
		BaseDuration: dur,
	}
	mac := make([]byte, 20)
	retry := 3
	pos := 0
	for pos < len(mac) {
		bt, err := se.findByte(server, mac, pos)
		if err != nil {
			if retry == 0 {
				return nil, err
			}
			retry -= 1
			if pos > 0 {
				pos -= 1
			}
			continue
		}
		mac[pos] = bt
		fmt.Printf("%d:\t%x\n", pos, mac)
		pos += 1
		retry = 3
	}
	return mac, nil
}

func (obj ServerExp) findByte(server Server, mac []byte, pos int) (byte, error) {
	targetDuration := time.Duration(pos+1) * obj.BaseDuration
	for i := 0; i < 256; i++ {
		mac[pos] = byte(i)
		sign := c1_hex_to_base64.EncodeHex(mac)
		start := time.Now()
		server.CheckFile(obj.BasePath + string(sign))
		t := time.Now()
		elapsed := t.Sub(start)
		// fmt.Printf("%d: %d %d %s %t\n", i, targetDuration.Nanoseconds(), elapsed.Nanoseconds(), elapsed, elapsed >= targetDuration)
		if elapsed >= targetDuration {
			return byte(i), nil
		}
	}
	return byte(0), errors.New("Byte not found")
}
