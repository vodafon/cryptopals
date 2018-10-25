package c13_ecb_cut_and_paste

import (
	"strings"
	"testing"
)

func TestParseQuery(t *testing.T) {
	inp := "foo=bar&baz=qux&zap=zazzle"
	mp := ParseQuery(inp)

	if len(mp) != 3 {
		t.Errorf("invalid length for result ParseQuery. Expected 3, got %d\n", len(mp))
	}
	if mp["foo"] != "bar" || mp["baz"] != "qux" || mp["zap"] != "zazzle" {
		t.Errorf("invalid result %v for %s in ParseQuery\n", mp, inp)
	}
}

func TestProfileFor(t *testing.T) {
	pr := ProfileFor("a@email.com")
	if pr.Email != "a@email.com" || pr.UID != 10 || pr.Role != "user" {
		t.Errorf("invalid result in ProfileFor: %v\n", pr)
	}

	emails := []string{"a@email.com&role=admin", "role=admin&a@email.com", "a@email.com&role=admin&role=admin"}
	for _, email := range emails {
		q := ProfileFor(email).ToQuery()
		if strings.Contains(q, "role=admin") {
			t.Errorf("invalid quoting parameters in ProfileFor. For %s result %s\n", email, q)
		}
	}
}
