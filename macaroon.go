// Package macaroon implements macaroons as described in the paper:
// "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization
// in the Cloud".
package macaroon

import (
	"bytes"
	"crypto/hmac"
	"fmt"

	"google.golang.org/protobuf/proto"
)

// Condition represents a macaroon caveat condition.
type Condition []byte

// CheckFunc is called for every first-party caveat ID during verification.
type CheckFunc func(condition Condition) error

// NewRoot creates a new root macaroon with no caveats.
func NewRoot(keySeed, id []byte, loc string) *Macaroon {
	m := &Macaroon{Id: bytes.Clone(id)}
	if loc != "" {
		m.Location = proto.String(loc)
	}
	derivedKey := hashKey(keySeed)
	m.Signature = hmacDigest(derivedKey, m.Id)
	return m
}

// New creates a new root macaroon with the given caveats.
// Returns an error if no conditions are provided.
func New(keySeed, id []byte, loc string, conditions []Condition) (*Macaroon, error) {
	if len(conditions) == 0 {
		return nil, fmt.Errorf("insufficient macaroon conditions")
	}
	m := NewRoot(keySeed, id, loc)
	for _, condition := range conditions {
		m.addCaveat(&Caveat{Id: condition})
	}
	return m, nil
}

// VerifySignature verifies the signature of the given macaroon.
func (m *Macaroon) VerifySignature(keySeed []byte, discharges []*Macaroon) error {
	vctx := newVerificationContext(m, discharges)
	return vctx.verifySignatures(m, keySeed)
}

// IsThirdParty checks if the caveats verification id is not empty.
func (c *Caveat) IsThirdParty() bool {
	return len(c.VerificationId) > 0
}

// BindForDischarge prepares the macaroon for being used to discharge the
// macaroon with the given signature.
//
// Macaroon must be bound for discharge before using it in the discharges
// argument to Verify.
func BindForDischarge(m *Macaroon, sig []byte) *Macaroon {
	bound := proto.Clone(m).(*Macaroon)
	bound.Signature = bindForRequest(sig, m.Signature)
	return bound
}

// bindForRequest binds the given discharge signature to the given signature of
// its parent macaroon.
func bindForRequest(rootSig []byte, dischargeSig []byte) []byte {
	if bytes.Equal(rootSig, dischargeSig) {
		return dischargeSig
	}
	return hmacConcat(nil, rootSig, dischargeSig)
}

// WithCondition attenuates a macaroon with a new first-party caveat.
func WithCondition(prev *Macaroon, condition Condition) *Macaroon {
	m := proto.Clone(prev).(*Macaroon)
	m.addCaveat(&Caveat{Id: condition})
	return m
}

// WithConditions attenuates a macaroon with new first-party caveats.
func WithConditions(prev *Macaroon, conditions []Condition) *Macaroon {
	m := proto.Clone(prev).(*Macaroon)
	for _, condition := range conditions {
		m.addCaveat(&Caveat{Id: condition})
	}
	return m
}

// addCaveat adds a caveat to a macaroon, modifying it's signature.
func (m *Macaroon) addCaveat(caveat *Caveat) {
	m.Caveats = append(m.Caveats, caveat)
	if len(caveat.VerificationId) == 0 {
		m.Signature = hmacDigest(m.Signature, caveat.Id)
	} else {
		m.Signature = hmacConcat(m.Signature, caveat.VerificationId, caveat.Id)
	}
}

// WithThirdPartyCaveat attenuates a macaroon with a new third-party caveat.
func WithThirdPartyCaveat(prev *Macaroon, rootKey, caveatID []byte, loc string) (*Macaroon, error) {
	derivedKey := hashKey(rootKey)
	verificationID, err := encryptKey(prev.Signature, derivedKey)
	if err != nil {
		return nil, err
	}

	m := proto.Clone(prev).(*Macaroon)
	m.addCaveat(&Caveat{
		Id:             caveatID,
		VerificationId: verificationID,
		Location:       loc,
	})

	return m, nil
}

// CheckConditions invokes the given check for all first-party caveats.
func CheckConditions(m *Macaroon, discharges []*Macaroon, check CheckFunc) error {
	for _, cav := range m.Caveats {
		if cav.IsThirdParty() {
			discharge, _, err := findDischarge(discharges, cav.Id)
			if err != nil {
				return err
			}
			if err := CheckConditions(discharge, discharges, check); err != nil {
				return err
			}
		} else if err := check(cav.Id); err != nil {
			return err
		}
	}
	return nil
}

type verificationContext struct {
	used       []bool
	discharges []*Macaroon
	rootSig    []byte
}

func newVerificationContext(root *Macaroon, discharges []*Macaroon) *verificationContext {
	return &verificationContext{
		used:       make([]bool, len(discharges)),
		discharges: discharges,
		rootSig:    root.Signature,
	}
}

func (vctx *verificationContext) verifySignatures(root *Macaroon, keySeed []byte) error {
	if len(root.Signature) != hashLen {
		return fmt.Errorf("invalid signature length: %d", len(root.Signature))
	}
	derivedKey := hashKey(keySeed)
	if err := vctx.verifySignaturesNested(root, derivedKey, false); err != nil {
		return err
	}
	for i, wasUsed := range vctx.used {
		if !wasUsed {
			return fmt.Errorf("discharge macaroon %q was not used", vctx.discharges[i].Id)
		}
	}
	return nil
}

func (vctx *verificationContext) verifySignaturesNested(m *Macaroon, key []byte, thirdParty bool) error {
	digest := hmacDigest(key, m.Id)
	for i, cav := range m.Caveats {
		if cav.IsThirdParty() {
			cavKey, err := decryptKey(digest, cav.VerificationId)
			if err != nil {
				return fmt.Errorf("failed to decrypt caveat key %d: %v", i, err)
			}
			dm, didx, err := findDischarge(vctx.discharges, cav.Id)
			if err != nil {
				return err
			}
			if err := vctx.markUsed(didx); err != nil {
				return err
			}
			if err := vctx.verifySignaturesNested(dm, cavKey, true); err != nil {
				return err
			}
			digest = hmacConcat(digest, cav.VerificationId, cav.Id)
		} else {
			digest = hmacDigest(digest, cav.Id)
		}
	}
	if thirdParty {
		digest = bindForRequest(vctx.rootSig, digest)
	}
	if !hmac.Equal(digest, m.Signature) {
		return fmt.Errorf("signature mismatch after caveat verification")
	}
	return nil
}

// markUsed marks a discharge as used or returns an error if it was already used.
func (vctx *verificationContext) markUsed(idx int) error {
	if vctx.used[idx] {
		m := vctx.discharges[idx]
		return fmt.Errorf("discharge macaroon %q was used more than once", m.Id)
	}
	vctx.used[idx] = true
	return nil
}

func findDischarge(discharges []*Macaroon, id []byte) (*Macaroon, int, error) {
	for idx, m := range discharges {
		if bytes.Equal(m.Id, id) {
			return m, idx, nil
		}
	}
	return nil, 0, fmt.Errorf("cannot find discharge macaroon for caveat %x", id)
}
