package secp256k1

// #include "./depend/secp256k1/include/secp256k1_oldschnorr.h"
import "C"
import (
	"bytes"
	"encoding/hex"
	"github.com/pkg/errors"
)

// SchnorrPublicKey is a PublicKey type used to sign and verify Schnorr signatures.
// The struct itself is an opaque data type that should only be created via the supplied methods.
type SchnorrPublicKey struct {
	pubkey C.secp256k1_pubkey
}

// SchnorrSignature is a type representing a Schnorr Signature.
// The struct itself is an opaque data type that should only be created via the supplied methods.
type SchnorrSignature struct {
	signature [64]byte
}

// SerializedSchnorrPublicKey is a is a byte array representing the storage representation of a compressed or uncompressed SchnorrPublicKey
type SerializedSchnorrPublicKey []byte

// SerializedSchnorrSignature is a is a byte array representing the storage representation of a SchnorrSignature
type SerializedSchnorrSignature [64]byte

// IsEqual returns true if target is the same as key.
func (key *SchnorrPublicKey) IsEqual(target *SchnorrPublicKey) bool {
	if key == nil && target == nil {
		return true
	}
	if key == nil || target == nil {
		return false
	}
	serializedKey, err1 := key.SerializeCompressed()
	serializedTarget, err2 := target.SerializeCompressed()

	if err1 != nil && err2 != nil { // They're both zeroed, shouldn't happen if a constructor is used.
		return true
	}
	if err1 != nil || err2 != nil {
		return false
	}
	return bytes.Equal(serializedKey, serializedTarget)
}

// IsEqual returns true if target is the same as signature.
func (signature *SchnorrSignature) IsEqual(target *SchnorrSignature) bool {
	if signature == nil && target == nil {
		return true
	}
	if signature == nil || target == nil {
		return false
	}
	return *signature.Serialize() == *target.Serialize()
}

// String returns the SerializedSchnorrPublicKey as the hexadecimal string
func (serialized *SerializedSchnorrPublicKey) String() string {
	return hex.EncodeToString(*serialized)
}

// String returns the SerializedSchnorrSignature as the hexadecimal string
func (serialized *SerializedSchnorrSignature) String() string {
	return hex.EncodeToString(serialized[:])
}

// String returns the SchnorrSignature as the hexadecimal string
func (signature *SchnorrSignature) String() string {
	return signature.Serialize().String()
}

// Serialize returns a 64 byte serialized signature
func (signature *SchnorrSignature) Serialize() *SerializedSchnorrSignature {
	ret := SerializedSchnorrSignature(signature.signature)
	return &ret
}

// DeserializeSchnorrSignature deserializes a 64 byte serialized schnorr signature into a SchnorrSignature type.
func DeserializeSchnorrSignature(serializedSignature *SerializedSchnorrSignature) *SchnorrSignature {
	return &SchnorrSignature{signature: *serializedSignature}
}

// String returns the SchnorrPublicKey as the hexadecimal string
func (key *SchnorrPublicKey) String() string {
	serialized, err := key.SerializeCompressed()
	if err != nil { // This can only happen if the user calls this function skipping a constructor. i.e. `SchnorrPublicKey{}.String()`
		return "<Invalid SchnorrPublicKey>"
	}
	return serialized.String()
}

// SchnorrPublicKey generates a PublicKey for the corresponding private key.
func (key *PrivateKey) SchnorrPublicKey() (*SchnorrPublicKey, error) {
	pubkey := SchnorrPublicKey{}
	cPtrPrivateKey := (*C.uchar)(&key.privateKey[0])
	ret := C.secp256k1_ec_pubkey_create(context, &pubkey.pubkey, cPtrPrivateKey)
	if ret != 1 {
		return nil, errors.New("failed Generating an SchnorrPublicKey. You should call `DeserializePrivateKey` before calling this")
	}
	return &pubkey, nil
}

// SchnorrSign creates a schnorr signature using the private key and the input hashed message.
// Notice: the [32] byte array *MUST* be a hash of a message.
func (key *PrivateKey) SchnorrSign(hash *Hash) (*SchnorrSignature, error) {
	signature := SchnorrSignature{}
	cPtrSig := (*C.uchar)(&signature.signature[0])
	cPtrHash := (*C.uchar)(&hash[0])
	cPtrPrivKey := (*C.uchar)(&key.privateKey[0])
	ret := C.secp256k1_schnorr_sign(context, cPtrSig, cPtrHash, cPtrPrivKey, nil, nil)
	if ret != 1 {
		return nil, errors.New("failed Signing. You should call `DeserializePrivateKey` before calling this")
	}
	return &signature, nil
}

// SchnorrVerify verifies a schnorr signature using the public key and the input hashed message.
// Notice: the [32] byte array *MUST* be a hash of a message you hashed yourself.
func (key *SchnorrPublicKey) SchnorrVerify(hash *Hash, signature *SchnorrSignature) bool {
	cPtrHash := (*C.uchar)(&hash[0])
	cPtrSig := (*C.uchar)(&signature.signature[0])
	return C.secp256k1_schnorr_verify(context, cPtrSig, cPtrHash, &key.pubkey) == 1
}

// DeserializeSchnorrPubKey deserializes a serialized schnorr public key, verifying it's valid.
// it supports both compressed(33 bytes) and uncompressed(65 bytes) public keys.
// it does not support hybrid(65 bytes) keys.
func DeserializeSchnorrPubKey(serializedPubKey SerializedSchnorrPublicKey) (*SchnorrPublicKey, error) {
	key := SchnorrPublicKey{}
	cPtr := (*C.uchar)(&serializedPubKey[0])
	cLen := C.size_t(len(serializedPubKey))
	if !supportedKey(serializedPubKey) {
		return nil, errors.New("unsupported public key format")
	}
	ret := C.secp256k1_ec_pubkey_parse(C.secp256k1_context_no_precomp, &key.pubkey, cPtr, cLen)
	if ret != 1 {
		return nil, errors.New("failed parsing the public key")
	}
	return &key, nil
}

// SerializeCompressed serializes a schnorr public key into a compressed form (33 bytes)
func (key *SchnorrPublicKey) SerializeCompressed() (compressedPubKey SerializedSchnorrPublicKey, err error) {
	return key.serializeInternal(C.SECP256K1_EC_COMPRESSED)
}

// SerializeUncompressed serializes a schnorr public key into a uncompressed form (65 bytes)
func (key *SchnorrPublicKey) SerializeUncompressed() (uncompressedPubKey SerializedSchnorrPublicKey, err error) {
	return key.serializeInternal(C.SECP256K1_EC_UNCOMPRESSED)
}

// Add a tweak to the public key by doing `key + tweak*Generator`. this adds it in place.
// This is meant for creating BIP-32(HD) wallets
func (key *SchnorrPublicKey) Add(tweak [32]byte) error {
	cPtrTweak := (*C.uchar)(&tweak[0])
	ret := C.secp256k1_ec_pubkey_tweak_add(context, &key.pubkey, cPtrTweak)
	if ret != 1 {
		return errors.New("failed adding to the public key. Tweak is bigger than the order or the complement of the private key")
	}
	return nil
}

// Negate a public key in place.
// Equivalent to negating the private key and then generating the public key.
func (key *SchnorrPublicKey) Negate() {
	ret := C.secp256k1_ec_pubkey_negate(C.secp256k1_context_no_precomp, &key.pubkey)
	if ret != 1 {
		panic("failed Negating the public key. Should never happen")
	}
}

// Should only be called with 33/65 byte data slice
// and only with SECP256K1_EC_UNCOMPRESSED/SECP256K1_EC_COMPRESSED as flags.
func (key *SchnorrPublicKey) serializeInternal(flag C.uint) (SerializedSchnorrPublicKey, error) {
	data := [65]byte{}
	cPtr := (*C.uchar)(&data[0])
	cLen := C.size_t(len(data))
	if isZeroed(key.pubkey.data[:32]) || isZeroed(key.pubkey.data[32:]) {
		return nil, errors.New("the public key is zeroed, which isn't a valid SchnorrPublicKey")
	}

	ret := C.secp256k1_ec_pubkey_serialize(C.secp256k1_context_no_precomp, cPtr, &cLen, &key.pubkey, flag)
	if ret != 1 {
		panic("failed serializing a pubkey. Should never happen (upstream promise to return 1)")
	} else if cLen != 33 && cLen != 65 {
		panic("Returned length doesn't match compressed length(33) nor uncompressed length(64), should never happen")
	}
	return data[:cLen], nil
}

func supportedKey(key []byte) bool {
	if len(key) == 33 && (key[0] == 0x02 || key[0] == 0x03) {
		return true
	} else if len(key) == 65 && key[0] == 0x04 {
		return true
	} else {
		return false
	}
}

func isZeroed(slice []C.uchar) bool {
	for _, byte := range slice {
		if byte != 0 {
			return false
		}
	}
	return true
}
