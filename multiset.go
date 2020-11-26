package secp256k1

import "C"

// #include "./depend/secp256k1/include/secp256k1_multiset.h"
// void secp256k1_multiset_add_multi(const secp256k1_context* ctx, secp256k1_multiset *multiset, const unsigned char **inputs, const size_t *inputsLen, size_t inputsAmount) {
//
//	for (size_t i = 0; i < inputsAmount; ++i) {
//		secp256k1_multiset_add(ctx, multiset, inputs[i], inputsLen[i]);
// }
//}
import "C"
import (
	"encoding/hex"
	"github.com/pkg/errors"
)

// SerializedMultiSetSize defines the length in bytes of SerializedMultiSet
const SerializedMultiSetSize = 64

// MultiSet is a type used to create an Elliptic Curve Multiset Hash
// which is a rolling(homomorphic) hash that you can add and remove elements from
// and receiving the same resulting hash as-if you never hashed that element.
// Because of that the order of adding and removing elements doesn't matter.
// Use NewMultiset to initialize a MultiSet, or DeserializeMultiSet to parse a MultiSet.
type MultiSet struct {
	set C.secp256k1_multiset
}

// SerializedMultiSet is a is a byte array representing the storage representation of a MultiSet
type SerializedMultiSet [SerializedMultiSetSize]byte

// String returns the SerializedMultiSet as the hexadecimal string
func (serialized *SerializedMultiSet) String() string {
	return hex.EncodeToString(serialized[:])
}

// String returns the MultiSet as the hexadecimal string
func (multiset *MultiSet) String() string {
	return multiset.Serialize().String()
}

// NewMultiset return an empty initialized set.
// when finalized it should be equal to a finalized set with all elements removed.
func NewMultiset() *MultiSet {
	multiset := MultiSet{}
	ret := C.secp256k1_multiset_init(context, &multiset.set)
	if ret != 1 {
		panic("failed initializing a multiset. Should never happen")
	}
	return &multiset
}

// Reset clears the multiset from all data. Equivalent to creating a new empty set
func (multiset *MultiSet) Reset() {
	ret := C.secp256k1_multiset_init(context, &multiset.set)
	if ret != 1 {
		panic("failed resetting a multiset. Should never happen")
	}
}

// Add hashes the data onto the curve and adds it to the multiset.
// Supports arbitrary length data (subject to the underlying hash function(SHA256) limits)
func (multiset *MultiSet) Add(data []byte) {
	cPtrData := (*C.uchar)(&data[0])
	CLenData := (C.size_t)(len(data))
	ret := C.secp256k1_multiset_add(context, &multiset.set, cPtrData, CLenData)
	if ret != 1 {
		panic("failed adding to the multiset. Should never happen")
	}
}

// AddMulti hashes the data onto the curve and adds it to the multiset.
// Supports arbitrary length data (subject to the underlying hash function(SHA256) limits)
func (multiset *MultiSet) AddMulti(data [][]byte) {
	lens := make([]C.size_t, len(data))
	ptrs := make([]*C.uchar, len(data))
	for i, _ := range data {
		lens[i] = (C.size_t)(len(data[i]))
		ptrs[i] = (*C.uchar)(&data[i][0])
	}
	cPtrData := (**C.uchar)(&ptrs[0])
	CLenPtr := (*C.size_t)(&lens[0])
	CLenData := (C.size_t)(len(data))
	C.secp256k1_multiset_add_multi(context, &multiset.set, cPtrData, CLenPtr, CLenData)
}

// Remove hashes the data onto the curve and removes it from the multiset.
// Supports arbitrary length data (subject to the underlying hash function(SHA256) limits)
func (multiset *MultiSet) Remove(data []byte) {
	cPtrData := (*C.uchar)(&data[0])
	CLenData := (C.size_t)(len(data))
	ret := C.secp256k1_multiset_remove(context, &multiset.set, cPtrData, CLenData)
	if ret != 1 {
		panic("failed removing from the multiset. Should never happen")
	}
}

// Combine will add the MultiSets together. Equivalent to manually adding all the data elements
// from one set to the other.
func (multiset *MultiSet) Combine(input *MultiSet) {
	ret := C.secp256k1_multiset_combine(context, &multiset.set, &input.set)
	if ret != 1 {
		panic("failed combining 2 multisets. Should never happen")
	}
}

// Finalize will return a hash(SHA256) of the multiset.
// Because the returned value is a hash of a multiset you cannot "Un-Finalize" it.
// If this is meant for storage then Serialize should be used instead.
func (multiset *MultiSet) Finalize() *Hash {
	hash := Hash{}
	cPtrHash := (*C.uchar)(&hash[0])
	ret := C.secp256k1_multiset_finalize(context, cPtrHash, &multiset.set)
	if ret != 1 {
		panic("failed finalizing the multiset. Should never happen")
	}
	return &hash
}

// Serialize returns a serialized version of the MultiSet. This is the only right way to serialize a multiset for storage.
// This multiset is not finalized, this is meant for storage.
func (multiset *MultiSet) Serialize() *SerializedMultiSet {
	serialized := SerializedMultiSet{}
	cPtrData := (*C.uchar)(&serialized[0])
	ret := C.secp256k1_multiset_serialize(context, cPtrData, &multiset.set)
	if ret != 1 {
		panic("failed serializing the multiset. Should never happen")
	}
	return &serialized
}

// DeserializeMultiSet will deserialize the multiset that `Serialize()` serialized.
func DeserializeMultiSet(serialized *SerializedMultiSet) (multiset *MultiSet, err error) {
	multiset = &MultiSet{}
	cPtrData := (*C.uchar)(&serialized[0])
	ret := C.secp256k1_multiset_parse(context, &multiset.set, cPtrData)
	if ret != 1 {
		return nil, errors.New("failed parsing the multiset")
	}
	return
}

// DeserializeMultiSetFromSlice returns a MultiSet type from a from a a serialized multiset slice.
// will verify that it's SerializedMultiSetSize bytes long and a valid multiset.
func DeserializeMultiSetFromSlice(newMultiSet []byte) (multiset *MultiSet, err error) {
	if len(newMultiSet) != SerializedMultiSetSize {
		return nil, errors.Errorf("invalid multiset length got %d, expected %d", len(newMultiSet),
			SerializedMultiSetSize)
	}
	serializedMultiSet := &SerializedMultiSet{}
	copy(serializedMultiSet[:], newMultiSet)
	return DeserializeMultiSet(serializedMultiSet)
}
