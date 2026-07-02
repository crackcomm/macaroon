package macaroon

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func BenchmarkNew(b *testing.B) {
	rootKey := randomBytes(24)
	id := []byte(base64.StdEncoding.EncodeToString(randomBytes(100)))
	loc := base64.StdEncoding.EncodeToString(randomBytes(40))
	b.ResetTimer()
	for i := b.N - 1; i >= 0; i-- {
		NewRoot(rootKey, id, loc)
	}
}

func BenchmarkAddCaveat(b *testing.B) {
	rootKey := randomBytes(24)
	id := []byte(base64.StdEncoding.EncodeToString(randomBytes(100)))
	loc := base64.StdEncoding.EncodeToString(randomBytes(40))
	b.ResetTimer()
	for i := b.N - 1; i >= 0; i-- {
		b.StopTimer()
		m := NewRoot(rootKey, id, loc)
		b.StartTimer()
		m = WithCondition(m, Condition("some caveat stuff"))
	}
}

func benchmarkVerify(b *testing.B, mspecs []macaroonSpec) {
	rootKey, macaroons := makeMacaroons(mspecs)
	check := func(Condition) error {
		return nil
	}
	b.ResetTimer()
	for i := b.N - 1; i >= 0; i-- {
		err := verify(macaroons[0], rootKey, check, macaroons[1:])
		if err != nil {
			b.Fatalf("verification failed: %v", err)
		}
	}
}

func BenchmarkVerifyLarge(b *testing.B) {
	benchmarkVerify(b, multilevelThirdPartyCaveatMacaroons)
}

func BenchmarkVerifySmall(b *testing.B) {
	benchmarkVerify(b, []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "wonderful",
		}},
	}})
}
