package c13_ecb_cut_and_paste

import (
	"fmt"
	"strings"
)

type Profile struct {
	Email string
	UID   int64
	Role  string
}

func (obj Profile) ToQuery() string {
	return fmt.Sprintf("email=%s&uid=%d&role=%s", obj.Email, obj.UID, obj.Role)
}

func ParseQuery(query string) map[string]string {
	mp := make(map[string]string)
	for _, v := range strings.Split(query, "&") {
		q := strings.Split(v, "=")
		if len(q) == 1 {
			mp[q[0]] = ""
		} else {
			mp[q[0]] = q[1]
		}
	}
	return mp
}

func ProfileFor(email string) Profile {
	email = strings.Replace(email, "=", "-", -1)
	email = strings.Replace(email, "&", "-", -1)
	return Profile{
		Email: email,
		UID:   10,
		Role:  "user",
	}
}
