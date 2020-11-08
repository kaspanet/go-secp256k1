package secp256k1

// // **This is CGO's build system. CGO parses the following comments as build instructions.**
// // Including the headers and code, and defining the default macros
// #cgo CFLAGS: -I./depend/secp256k1 -I./depend/secp256k1/src/
// #cgo CFLAGS: -DSECP256K1_BUILD=1 -DECMULT_WINDOW_SIZE=15 -DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_MULTISET=1
// // Consider using libgmp. these macros are set to use the slower in-project implementation of nums
// #cgo CFLAGS: -DUSE_NUM_NONE=1 -DUSE_FIELD_INV_BUILTIN=1 -DUSE_SCALAR_INV_BUILTIN=1 -DECMULT_GEN_PREC_BITS=4
// // x86_64 can use the Assembly implementation.
// #cgo amd64 CFLAGS: -DUSE_ASM_X86_64=1
// #include "./depend/secp256k1/include/secp256k1.h"
// #include "./depend/secp256k1/src/secp256k1.c"
import "C"

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/pkg/errors"
)

// A global context for using secp256k1. this is generated once and used to speed computation
// and aid resisting side channel attacks.
var context *C.secp256k1_context

// Initialize the context for both signing and verifying.
// and randomize it to help resist side channel attacks.
func init() {
	context = C.secp256k1_context_create(C.SECP256K1_CONTEXT_SIGN | C.SECP256K1_CONTEXT_VERIFY)
	seed := [32]byte{}
	n, err := rand.Read(seed[:])
	if err != nil || n != len(seed) {
		panic("Failed getting random values on initializing")
	}
	cPtr := (*C.uchar)(&seed[0])
	ret := C.secp256k1_context_randomize(context, cPtr)
	if ret != 1 {
		panic("Failed randomizing the context. Should never happen")
	}
}

const (
	// HashSize of array used to store hashes. See Hash.
	HashSize = 32

	// SerializedPrivateKeySize defines the length in bytes of SerializedPrivateKey
	SerializedPrivateKeySize = 32
)

// Hash is a type encapsulating the result of hashing some unknown sized data.
// it typically represents Sha256 / Double Sha256.
type Hash [HashSize]byte

// IsEqual returns true if target is the same as hash.
func (hash *Hash) IsEqual(target *Hash) bool {
	if hash == nil && target == nil {
		return true
	}
	if hash == nil || target == nil {
		return false
	}
	return *hash == *target
}

// SetBytes sets the bytes which represent the hash. An error is returned if
// the number of bytes passed in is not HashSize.
func (hash *Hash) SetBytes(newHash []byte) error {
	if len(newHash) != HashSize {
		return errors.Errorf("invalid hash length got %d, expected %d", len(newHash),
			HashSize)
	}
	copy(hash[:], newHash)
	return nil
}

// String returns the Hash as the hexadecimal string
func (hash *Hash) String() string {
	return hex.EncodeToString(hash[:])
}

// PrivateKey is a type representing a Secp256k1 private key.
// This private key can be used to create Schnorr/ECDSA signatures
type PrivateKey struct {
	privateKey [SerializedPrivateKeySize]byte
}

// SerializedPrivateKey is a byte array representing the storage representation of a PrivateKey
type SerializedPrivateKey [SerializedPrivateKeySize]byte

// String returns the PrivateKey as the hexadecimal string
func (key *SerializedPrivateKey) String() string {
	return hex.EncodeToString(key[:])
}

// String returns the PrivateKey as the hexadecimal string
func (key *PrivateKey) String() string {
	return key.Serialize().String()
}

// DeserializePrivateKey returns a PrivateKey type from a 32 byte private key.
// will verify it's a valid private key(Group Order > key > 0)
func DeserializePrivateKey(data *SerializedPrivateKey) (key *PrivateKey, err error) {
	cPtr := (*C.uchar)(&data[0])

	ret := C.secp256k1_ec_seckey_verify(C.secp256k1_context_no_precomp, cPtr)
	if ret != 1 {
		return nil, errors.New("invalid PrivateKey (zero or bigger than the group order)")
	}

	return &PrivateKey{*data}, nil
}

// DeserializePrivateKeyFromSlice returns a PrivateKey type from a serialized private key slice.
// will verify that it's 32 byte and it's a valid private key(Group Order > key > 0)
func DeserializePrivateKeyFromSlice(data []byte) (key *PrivateKey, err error) {
	if len(data) != SerializedPrivateKeySize {
		return nil, errors.Errorf("invalid private key length got %d, expected %d", len(data),
			SerializedPrivateKeySize)
	}

	serializedKey := &SerializedPrivateKey{}
	copy(serializedKey[:], data)
	return DeserializePrivateKey(serializedKey)
}

// GeneratePrivateKey generates a random valid private key from `crypto/rand`
func GeneratePrivateKey() (key *PrivateKey, err error) {
	key = &PrivateKey{}
	cPtr := (*C.uchar)(&key.privateKey[0])
	for {
		n, tmpErr := rand.Read(key.privateKey[:])
		if tmpErr != nil || n != len(key.privateKey) {
			return nil, tmpErr
		}
		ret := C.secp256k1_ec_seckey_verify(C.secp256k1_context_no_precomp, cPtr)
		if ret == 1 {
			return
		}
	}
}

// Serialize a private key
func (key *PrivateKey) Serialize() *SerializedPrivateKey {
	ret := SerializedPrivateKey(key.privateKey)
	return &ret
}

// Negate a private key in place.
func (key *PrivateKey) Negate() {
	cPtr := (*C.uchar)(&key.privateKey[0])
	ret := C.secp256k1_ec_privkey_negate(C.secp256k1_context_no_precomp, cPtr)
	if ret != 1 {
		panic("Failed Negating the private key. Should never happen")
	}
}

// Add a tweak to the public key by doing `key + tweak % Group Order`. this adds it in place.
// This is meant for creating BIP-32(HD) wallets
func (key *PrivateKey) Add(tweak [32]byte) error {
	cPtrKey := (*C.uchar)(&key.privateKey[0])
	cPtrTweak := (*C.uchar)(&tweak[0])
	ret := C.secp256k1_ec_privkey_tweak_add(C.secp256k1_context_no_precomp, cPtrKey, cPtrTweak)
	if ret != 1 {
		return errors.New("failed Adding to private key. Tweak is bigger than the order or the complement of the private key")
	}
	return nil
}
