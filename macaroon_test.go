package macaroon

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func never(Condition) error {
	return fmt.Errorf("condition is never true")
}

func TestNoCaveats(t *testing.T) {
	rootKey := []byte("secret")
	m := NewRoot(rootKey, []byte("some id"), "a location")
	assert.Equal(t, "a location", m.GetLocation())
	assert.Equal(t, []byte("some id"), m.GetId())

	err := verify(m, rootKey, never, nil)
	assert.Nil(t, err)
}

func TestFirstPartyCaveat(t *testing.T) {
	rootKey := []byte("secret")
	m := NewRoot(rootKey, []byte("some id"), "a location")

	caveats := map[string]bool{
		"a caveat":       true,
		"another caveat": true,
	}
	tested := make(map[string]bool)

	for cav := range caveats {
		m = WithCondition(m, Condition(cav))
	}
	expectErr := fmt.Errorf("condition not met")
	check := func(cav Condition) error {
		tested[string(cav)] = true
		if caveats[string(cav)] {
			return nil
		}
		return expectErr
	}
	err := verify(m, rootKey, check, nil)
	assert.Nil(t, err)

	assert.Equal(t, caveats, tested)

	m = WithCondition(m, Condition("not met"))
	err = verify(m, rootKey, check, nil)
	assert.Equal(t, expectErr, err)

	assert.True(t, tested["not met"])
}

func TestThirdPartyCaveat(t *testing.T) {
	rootKey := []byte("secret")
	m := NewRoot(rootKey, []byte("some id"), "a location")

	dischargeRootKey := []byte("shared root key")
	thirdPartyCaveatId := []byte("3rd party caveat")
	var err error
	m, err = WithThirdPartyCaveat(m, dischargeRootKey, thirdPartyCaveatId, "remote.com")
	assert.Nil(t, err)

	dm := NewRoot(dischargeRootKey, thirdPartyCaveatId, "remote location")
	dm = BindForDischarge(dm, m.Signature)
	err = verify(m, rootKey, never, []*Macaroon{dm})
	assert.Nil(t, err)
}

func TestSetLocation(t *testing.T) {
	rootKey := []byte("secret")
	m := NewRoot(rootKey, []byte("some id"), "a location")
	assert.Equal(t, "a location", m.GetLocation())
	m.Location = proto.String("another location")
	assert.Equal(t, "another location", m.GetLocation())
}

type conditionTest struct {
	conditions map[string]bool
	expectErr  string
}

var verifyTests = []struct {
	about      string
	macaroons  []macaroonSpec
	conditions []conditionTest
}{{
	about: "single third party caveat without discharge",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "wonderful",
		}, {
			condition: "bob-is-great",
			location:  "bob",
			rootKey:   "bob-caveat-root-key",
		}},
	}},
	conditions: []conditionTest{{
		conditions: map[string]bool{
			"wonderful": true,
		},
		expectErr: fmt.Sprintf(`cannot find discharge macaroon for caveat %x`, "bob-is-great"),
	}},
}, {
	about: "single third party caveat with discharge",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "wonderful",
		}, {
			condition: "bob-is-great",
			location:  "bob",
			rootKey:   "bob-caveat-root-key",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key",
		id:       "bob-is-great",
	}},
	conditions: []conditionTest{{
		conditions: map[string]bool{
			"wonderful": true,
		},
	}, {
		conditions: map[string]bool{
			"wonderful": false,
		},
		expectErr: `condition "wonderful" not met`,
	}},
}, {
	about: "single third party caveat with discharge with mismatching root key",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "wonderful",
		}, {
			condition: "bob-is-great",
			location:  "bob",
			rootKey:   "bob-caveat-root-key",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key-wrong",
		id:       "bob-is-great",
	}},
	conditions: []conditionTest{{
		conditions: map[string]bool{
			"wonderful": true,
		},
		expectErr: `signature mismatch after caveat verification`,
	}},
}, {
	about: "single third party caveat with two discharges",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "wonderful",
		}, {
			condition: "bob-is-great",
			location:  "bob",
			rootKey:   "bob-caveat-root-key",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key",
		id:       "bob-is-great",
		caveats: []caveat{{
			condition: "splendid",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key",
		id:       "bob-is-great",
		caveats: []caveat{{
			condition: "top of the world",
		}},
	}},
	conditions: []conditionTest{{
		conditions: map[string]bool{
			"wonderful": true,
		},
		expectErr: `condition "splendid" not met`,
	}, {
		conditions: map[string]bool{
			"wonderful":        true,
			"splendid":         true,
			"top of the world": true,
		},
		expectErr: `discharge macaroon "bob-is-great" was not used`,
	}, {
		conditions: map[string]bool{
			"wonderful":        true,
			"splendid":         false,
			"top of the world": true,
		},
		expectErr: `condition "splendid" not met`,
	}, {
		conditions: map[string]bool{
			"wonderful":        true,
			"splendid":         true,
			"top of the world": false,
		},
		expectErr: `discharge macaroon "bob-is-great" was not used`,
	}},
}, {
	about: "one discharge used for two macaroons",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "somewhere else",
			location:  "bob",
			rootKey:   "bob-caveat-root-key",
		}, {
			condition: "bob-is-great",
			location:  "charlie",
			rootKey:   "bob-caveat-root-key",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key",
		id:       "somewhere else",
		caveats: []caveat{{
			condition: "bob-is-great",
			location:  "charlie",
			rootKey:   "bob-caveat-root-key",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key",
		id:       "bob-is-great",
	}},
	conditions: []conditionTest{{
		expectErr: `discharge macaroon "bob-is-great" was used more than once`,
	}},
}, {
	about: "two third party caveats",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "wonderful",
		}, {
			condition: "bob-is-great",
			location:  "bob",
			rootKey:   "bob-caveat-root-key",
		}, {
			condition: "charlie-is-great",
			location:  "charlie",
			rootKey:   "charlie-caveat-root-key",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key",
		id:       "bob-is-great",
		caveats: []caveat{{
			condition: "splendid",
		}},
	}, {
		location: "charlie",
		rootKey:  "charlie-caveat-root-key",
		id:       "charlie-is-great",
		caveats: []caveat{{
			condition: "top of the world",
		}},
	}},
	conditions: []conditionTest{{
		conditions: map[string]bool{
			"wonderful":        true,
			"splendid":         true,
			"top of the world": true,
		},
	}, {
		conditions: map[string]bool{
			"wonderful":        true,
			"splendid":         false,
			"top of the world": true,
		},
		expectErr: `condition "splendid" not met`,
	}, {
		conditions: map[string]bool{
			"wonderful":        true,
			"splendid":         true,
			"top of the world": false,
		},
		expectErr: `condition "top of the world" not met`,
	}},
}, {
	about: "third party caveat with undischarged third party caveat",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "wonderful",
		}, {
			condition: "bob-is-great",
			location:  "bob",
			rootKey:   "bob-caveat-root-key",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key",
		id:       "bob-is-great",
		caveats: []caveat{{
			condition: "splendid",
		}, {
			condition: "barbara-is-great",
			location:  "barbara",
			rootKey:   "barbara-caveat-root-key",
		}},
	}},
	conditions: []conditionTest{{
		conditions: map[string]bool{
			"wonderful": true,
			"splendid":  true,
		},
		expectErr: fmt.Sprintf(`cannot find discharge macaroon for caveat %x`, "barbara-is-great"),
	}},
}, {
	about:     "multilevel third party caveats",
	macaroons: multilevelThirdPartyCaveatMacaroons,
	conditions: []conditionTest{{
		conditions: map[string]bool{
			"wonderful":   true,
			"splendid":    true,
			"high-fiving": true,
			"spiffing":    true,
		},
	}, {
		conditions: map[string]bool{
			"wonderful":   true,
			"splendid":    true,
			"high-fiving": false,
			"spiffing":    true,
		},
		expectErr: `condition "high-fiving" not met`,
	}},
}, {
	about: "unused discharge",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
	}, {
		rootKey: "other-key",
		id:      "unused",
	}},
	conditions: []conditionTest{{
		expectErr: `discharge macaroon "unused" was not used`,
	}},
}}

var multilevelThirdPartyCaveatMacaroons = []macaroonSpec{{
	rootKey: "root-key",
	id:      "root-id",
	caveats: []caveat{{
		condition: "wonderful",
	}, {
		condition: "bob-is-great",
		location:  "bob",
		rootKey:   "bob-caveat-root-key",
	}, {
		condition: "charlie-is-great",
		location:  "charlie",
		rootKey:   "charlie-caveat-root-key",
	}},
}, {
	location: "bob",
	rootKey:  "bob-caveat-root-key",
	id:       "bob-is-great",
	caveats: []caveat{{
		condition: "splendid",
	}, {
		condition: "barbara-is-great",
		location:  "barbara",
		rootKey:   "barbara-caveat-root-key",
	}},
}, {
	location: "charlie",
	rootKey:  "charlie-caveat-root-key",
	id:       "charlie-is-great",
	caveats: []caveat{{
		condition: "splendid",
	}, {
		condition: "celine-is-great",
		location:  "celine",
		rootKey:   "celine-caveat-root-key",
	}},
}, {
	location: "barbara",
	rootKey:  "barbara-caveat-root-key",
	id:       "barbara-is-great",
	caveats: []caveat{{
		condition: "spiffing",
	}, {
		condition: "ben-is-great",
		location:  "ben",
		rootKey:   "ben-caveat-root-key",
	}},
}, {
	location: "ben",
	rootKey:  "ben-caveat-root-key",
	id:       "ben-is-great",
}, {
	location: "celine",
	rootKey:  "celine-caveat-root-key",
	id:       "celine-is-great",
	caveats: []caveat{{
		condition: "high-fiving",
	}},
}}

func TestVerify(t *testing.T) {
	for i, test := range verifyTests {
		t.Logf("test %d: %s", i, test.about)
		rootKey, macaroons := makeMacaroons(test.macaroons)
		for _, cond := range test.conditions {
			t.Logf("conditions %#v", cond.conditions)
			check := func(cav Condition) error {
				if cond.conditions[string(cav)] {
					return nil
				}
				return fmt.Errorf("condition %q not met", string(cav))
			}
			err := verify(macaroons[0], rootKey, check, macaroons[1:])
			if cond.expectErr != "" {
				assert.Regexp(t, cond.expectErr, err)
			} else {
				assert.Nil(t, err)
			}
		}
	}
}

func TestFirstPartyCaveatWithInvalidUTF8(t *testing.T) {
	m := NewRoot([]byte("secret"), []byte("some id"), "a location")
	m = WithCondition(m, Condition("foo\xff"))
	assert.NotNil(t, m)
}

type caveat struct {
	rootKey   string
	location  string
	condition string
}

type macaroonSpec struct {
	rootKey  string
	id       string
	caveats  []caveat
	location string
}

func makeMacaroons(mspecs []macaroonSpec) (rootKey []byte, macaroons []*Macaroon) {
	for _, mspec := range mspecs {
		macaroons = append(macaroons, makeMacaroon(mspec))
	}
	primary := macaroons[0]
	for i, m := range macaroons {
		if i > 0 {
			macaroons[i] = BindForDischarge(m, primary.Signature)
		}
	}
	return []byte(mspecs[0].rootKey), macaroons
}

func makeMacaroon(mspec macaroonSpec) *Macaroon {
	m := NewRoot([]byte(mspec.rootKey), []byte(mspec.id), mspec.location)
	for _, cav := range mspec.caveats {
		if cav.location != "" {
			var err error
			m, err = WithThirdPartyCaveat(m, []byte(cav.rootKey), []byte(cav.condition), cav.location)
			if err != nil {
				panic(err)
			}
		} else {
			m = WithCondition(m, Condition(cav.condition))
		}
	}
	return m
}

func verify(m *Macaroon, keySeed []byte, check CheckFunc, discharges []*Macaroon) error {
	if err := CheckConditions(m, discharges, check); err != nil {
		return err
	}
	return m.VerifySignature(keySeed, discharges)
}
