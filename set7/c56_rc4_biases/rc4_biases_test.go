package c56_rc4_biases

// go test -run Exploit -v -timeout 99999s
// === RUN   TestExploit
// "E"
// "NE"
// "INE"
// "TINE"
// "LTINE"
// "ALTINE"
// "VALTINE"
// "OVALTINE"
// " OVALTINE"
// "R OVALTINE"
// "UR OVALTINE"
// "OUR OVALTINE"
// "YOUR OVALTINE"
// " YOUR OVALTINE"
// "K YOUR OVALTINE"
// "NK YOUR OVALTINE"
// "INK YOUR OVALTINE"
// "RINK YOUR OVALTINE"
// "DRINK YOUR OVALTINE"
// " DRINK YOUR OVALTINE"
// "O DRINK YOUR OVALTINE"
// "TO DRINK YOUR OVALTINE"
// " TO DRINK YOUR OVALTINE"
// "E TO DRINK YOUR OVALTINE"
// "RE TO DRINK YOUR OVALTINE"
// "URE TO DRINK YOUR OVALTINE"
// "SURE TO DRINK YOUR OVALTINE"
// " SURE TO DRINK YOUR OVALTINE"
// "E SURE TO DRINK YOUR OVALTINE"
// "BE SURE TO DRINK YOUR OVALTINE"
// --- PASS: TestExploit (1609.54s)
// PASS
// ok      github.com/vodafon/cryptopals/set7/c56_rc4_biases       1609.537s

// func TestExploit(t *testing.T) {
// 	cookie, err := c1_hex_to_base64.DecodeBase64([]byte("QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F"))
// 	if err != nil {
// 		t.Fatalf("DecodeBase64 error: %s\n", err)
// 	}
//
// 	rc := NewRC4System(cookie)
// 	res := Exploit(rc)
// 	if !bytes.Equal(cookie, res) {
// 		t.Errorf("Incorrect result. Expected %q, got %q\n", cookie, res)
// 	}
// }
