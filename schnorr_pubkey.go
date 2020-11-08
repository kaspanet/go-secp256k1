package secp256k1

// #include "./depend/secp256k1/include/secp256k1_extrakeys.h"
// #include "./depend/secp256k1/include/secp256k1_schnorrsig.h"
import "C"
import (
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
)

// SerializedSchnorrPublicKeySize defines the length in bytes of a SerializedSchnorrPublicKey
const SerializedSchnorrPublicKeySize = 32

// errZeroedPubkey is the error returned when using a zeroed pubkey
var errZeroedPubkey = errors.New("the public key is zeroed, which isn't a valid SchnorrPublicKey")

// SchnorrPublicKey is a PublicKey type used to sign and verify Schnorr signatures.
// The struct itself is an opaque data type that should only be created via the supplied methods.
type SchnorrPublicKey struct {
	pubkey C.secp256k1_xonly_pubkey
}

// SerializedSchnorrPublicKey is a is a byte array representing the storage representation of a compressed or uncompressed SchnorrPublicKey
type SerializedSchnorrPublicKey [SerializedSchnorrPublicKeySize]byte

// IsEqual returns true if target is the same as key.
func (key *SchnorrPublicKey) IsEqual(target *SchnorrPublicKey) bool {
	if key == nil && target == nil {
		return true
	}
	if key == nil || target == nil {
		return false
	}
	serializedKey, err1 := key.Serialize()
	if err1 != nil && !errors.Is(err1, errZeroedPubkey) {
		panic(errors.Wrap(err1, "Unexpected error when serrializing key"))
	}
	serializedTarget, err2 := target.Serialize()
	if err2 != nil && !errors.Is(err2, errZeroedPubkey) {
		panic(errors.Wrap(err1, "Unexpected error when serrializing key"))
	}

	if errors.Is(err1, errZeroedPubkey) && errors.Is(err2, errZeroedPubkey) { // They're both zeroed, shouldn't happen if a constructor is used.
		return true
	}
	if errors.Is(err1, errZeroedPubkey) || errors.Is(err2, errZeroedPubkey) { // Only one of them is zeroed
		return false
	}
	return *serializedKey == *serializedTarget
}

// String returns the SerializedSchnorrPublicKey as a hexadecimal string
func (serialized SerializedSchnorrPublicKey) String() string {
	return hex.EncodeToString(serialized[:])
}

// String returns the SchnorrPublicKey as the hexadecimal string
func (key SchnorrPublicKey) String() string {
	serialized, err := key.Serialize()
	if err != nil { // This can only happen if the user calls this function skipping a constructor. i.e. `SchnorrPublicKey{}.String()`
		return "<Invalid SchnorrPublicKey>"
	}
	return serialized.String()
}

// SchnorrVerify verifies a schnorr signature using the public key and the input hashed message.
// Notice: the [32] byte array *MUST* be a hash of a message you hashed yourself.
func (key *SchnorrPublicKey) SchnorrVerify(hash *Hash, signature *SchnorrSignature) bool {
	cPtrHash := (*C.uchar)(&hash[0])
	cPtrSig := (*C.uchar)(&signature.signature[0])
	return C.secp256k1_schnorrsig_verify(context, cPtrSig, cPtrHash, &key.pubkey) == 1
}

// DeserializeSchnorrPubKey deserializes a serialized schnorr public key, verifying it's valid.
// it supports both compressed(33 bytes) and uncompressed(65 bytes) public keys.
// it does not support hybrid(65 bytes) keys.
func DeserializeSchnorrPubKey(serializedPubKey []byte) (*SchnorrPublicKey, error) {
	if len(serializedPubKey) != SerializedSchnorrPublicKeySize {
		return nil, errors.New(fmt.Sprintf("serializedPubKey has to be %d bytes, instead got :%d", SerializedSchnorrPublicKeySize, len(serializedPubKey)))
	}
	key := SchnorrPublicKey{}
	cPtr := (*C.uchar)(&serializedPubKey[0])
	ret := C.secp256k1_xonly_pubkey_parse(C.secp256k1_context_no_precomp, &key.pubkey, cPtr)
	if ret != 1 {
		return nil, errors.New("failed parsing the public key")
	}
	return &key, nil
}

// Serialize serializes a schnorr public key
func (key *SchnorrPublicKey) Serialize() (*SerializedSchnorrPublicKey, error) {
	serialized := SerializedSchnorrPublicKey{}
	cPtr := (*C.uchar)(&serialized[0])
	if isZeroed(key.pubkey.data[:]) {
		return nil, errZeroedPubkey
	}

	ret := C.secp256k1_xonly_pubkey_serialize(C.secp256k1_context_no_precomp, cPtr, &key.pubkey)
	if ret != 1 {
		panic("failed serializing a pubkey. Should never happen (upstream promise to return 1)")
	}
	return &serialized, nil
}

// Add a tweak to the public key by doing `key + tweak*Generator`. this adds it in place.
// This is meant for creating BIP-32(HD) wallets
func (key *SchnorrPublicKey) Add(tweak [32]byte) error {
	_, err := key.addInternal(tweak)
	return err
}

func (key *SchnorrPublicKey) addInternal(tweak [32]byte) (bool, error) {
	cPtrTweak := (*C.uchar)(&tweak[0])
	fullKey := C.secp256k1_pubkey{}
	ret := C.secp256k1_xonly_pubkey_tweak_add(context, &fullKey, &key.pubkey, cPtrTweak)
	if ret != 1 {
		return false, errors.New("failed adding to the public key. Tweak is bigger than the order or the complement of the private key")
	}
	var cParity C.int
	ret = C.secp256k1_xonly_pubkey_from_pubkey(context, &key.pubkey, &cParity, &fullKey)
	if ret != 1 {
		panic("Should never fail. we just created the public key so it can't be invalid")
	}
	return parityBitToBool(cParity), nil
}

func isZeroed(slice []C.uchar) bool {
	for _, byte := range slice {
		if byte != 0 {
			return false
		}
	}
	return true
}
