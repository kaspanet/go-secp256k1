package secp256k1

import (
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
	"math/rand"
	"os"
	"testing"
)

type testVector struct {
	dataElement    []byte
	ecmhHash       Hash
	cumulativeHash Hash
}

var testVectors []testVector

var testVectorsStrings = []struct {
	dataElementHex string
	point          [2]string
	ecmhHash       string
	cumulativeHash string
}{
	{
		"982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e00000000010000000100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac",
		[2]string{"4f9a5dce69067bf28603e73a7af4c3650b16539b95bad05eee95dfc94d1efe2c", "346d5b777881f2729e7f89b2de4e8e79c7f2f42d1a0b25a8f10becb66e2d0f98"},
		"f883195933a687170c34fa1adec66fe2861889279fb12c03a3fb0ca68ad87893",
		"f883195933a687170c34fa1adec66fe2861889279fb12c03a3fb0ca68ad87893",
	},
	{
		"d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9b00000000020000000100f2052a010000004341047211a824f55b505228e4c3d5194c1fcfaa15a456abdf37f9b9d97a4040afc073dee6c89064984f03385237d92167c13e236446b417ab79a0fcae412ae3316b77ac",
		[2]string{"68cf91eb2388a0287c13d46011c73fb8efb6be89c0867a47feccb2d11c390d2d", "f42ba72b1079d3d941881836f88b5dcd7c207a6a4839f129272c77ebb7194d42"},
		"ef85d123a15da95d8aff92623ad1e1c9fcda3baa801bd40bc567a83a6fdcf3e2",
		"fabafd38d07370982a34547daf5b57b8a4398696d6fd2294788abda07b1faaaf",
	},
	{
		"44f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e9900000000030000000100f2052a0100000043410494b9d3e76c5b1629ecf97fff95d7a4bbdac87cc26099ada28066c6ff1eb9191223cd897194a08d0c2726c5747f1db49e8cf90e75dc3e3550ae9b30086f3cd5aaac",
		[2]string{"359c6f59859d1d5af8e7081905cb6bb734c010be8680c14b5a89ee315694fc2b", "fb6ba531d4bd83b14c970ad1bec332a8ae9a05706cd5df7fd91a2f2cc32482fe"},
		"cfadf40fc017faff5e04ccc0a2fae0fd616e4226dd7c03b1334a7a610468edff",
		"1cbccda23d7ce8c5a8b008008e1738e6bf9cffb1d5b86a92a4e62b5394a636e2",
	},
}

func TestMain(m *testing.M) {
	for _, vector := range testVectorsStrings {
		res := testVector{}
		err := errors.New("")
		res.dataElement, err = hex.DecodeString(vector.dataElementHex)
		if err != nil {
			panic(fmt.Sprintf("failed parsing the hex: '%s', err: '%s'", vector.dataElementHex, err))
		}
		data, err := hex.DecodeString(vector.ecmhHash)
		if err != nil {
			panic(fmt.Sprintf("failed parsing the hex: '%s', err: '%s'", vector.ecmhHash, err))
		}
		err = res.ecmhHash.SetBytes(data)
		if err != nil {
			panic(fmt.Sprintf("failed setting the hash: '%x', err: '%s'", data, err))
		}
		data, err = hex.DecodeString(vector.cumulativeHash)
		if err != nil {
			panic(fmt.Sprintf("failed parsing the hex: '%s', err: '%s'", vector.cumulativeHash, err))
		}
		err = res.cumulativeHash.SetBytes(data)
		if err != nil {
			panic(fmt.Sprintf("failed setting the hash: '%x', err: '%s'", data, err))
		}
		testVectors = append(testVectors, res)
	}

	os.Exit(m.Run())
}

func TestVectorsMultiset_Hash(t *testing.T) {
	for _, test := range testVectors {
		m := NewMultiset()
		m.Add(test.dataElement)
		mFinal := m.Finalize()
		if !m.Finalize().IsEqual(&test.ecmhHash) {
			t.Fatalf("Multiset-Hash returned incorrect hash serialization, expected: '%s', found: '%s'", mFinal, test.ecmhHash)
		}
	}
	m := NewMultiset()
	if !m.Finalize().IsEqual(&Hash{}) {
		t.Fatalf("Empty set did not return zero hash, got: '%s' instead", m.Finalize())
	}
}

func TestVectorsMultiset_AddRemove(t *testing.T) {
	m := NewMultiset()
	for i, test := range testVectors {
		m.Add(test.dataElement)
		mFinal := m.Finalize()
		if !mFinal.IsEqual(&test.cumulativeHash) {
			t.Fatalf("Test #%d: Multiset-Add returned incorrect hash. Expected '%s' but got '%s'", i, test.cumulativeHash, mFinal)
		}
	}

	for i := len(testVectors) - 1; i > 0; i-- {
		m.Remove(testVectors[i].dataElement)
		mFinal := m.Finalize()
		if !mFinal.IsEqual(&testVectors[i-1].cumulativeHash) {
			t.Fatalf("Test #%d: Multiset-Remove returned incorrect hash. Expected '%s' but got '%s'", i, testVectors[i].cumulativeHash, mFinal)
		}
	}
}

func TestVectorsMultiset_CombineSubtract(t *testing.T) {
	m1 := NewMultiset()
	zeroHash := m1.Finalize()

	for _, test := range testVectors {
		m1.Add(test.dataElement)
	}

	m2 := NewMultiset()
	for _, test := range testVectors {
		m2.Remove(test.dataElement)
	}
	m1.Combine(m2)
	if !m1.Finalize().IsEqual(zeroHash) {
		t.Fatalf("m1 was expected to have a zero hash, but was '%s' instead", m1.Finalize())
	}
}

func TestVectorsMultiset_Commutativity(t *testing.T) {
	m := NewMultiset()
	zeroHash := m.Finalize()

	// Check that if we subtract values from zero and then re-add them, we return to zero.
	for _, test := range testVectors {
		m.Remove(test.dataElement)
	}

	for _, test := range testVectors {
		m.Add(test.dataElement)
	}
	if !m.Finalize().IsEqual(zeroHash) {
		t.Fatalf("m was expected to be zero hash, but was '%s' instead", m.Finalize())
	}

	// Here we first remove an element from an empty multiset, and then add some other
	// elements, and then we create a new empty multiset, then we add the same elements
	// we added to the previous multiset, and then we remove the same element we remove
	// the same element we removed from the previous multiset. According to commutativity
	// laws, the result should be the same.
	removeIndex := 0
	removeData := testVectors[removeIndex].dataElement

	m1 := NewMultiset()
	m1.Remove(removeData)

	for i, test := range testVectors {
		if i != removeIndex {
			m1.Add(test.dataElement)
		}
	}

	m2 := NewMultiset()
	for i, test := range testVectors {
		if i != removeIndex {
			m2.Add(test.dataElement)
		}
	}
	m2.Remove(removeData)

	if !m1.Finalize().IsEqual(m2.Finalize()) {
		t.Fatalf("m1 and m2 was exepcted to have the same hash, but got instead m1 '%s' and m2 '%s'", m1.Finalize(), m2.Finalize())
	}
}

func TestParseMultiSetFail(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	data := SerializedMultiSet{}
	copy(data[:], Secp256k1Order.Bytes())
	_, err := DeserializeMultiSet(&data)
	if err == nil {
		t.Errorf("shouldn't be able to parse a multiset bigger with x bigger than the field size: '%s'", err)
	}
	data = [64]byte{}
	copy(data[32:], Secp256k1Order.Bytes())
	_, err = DeserializeMultiSet(&data)
	if err == nil {
		t.Errorf("shouldn't be able to parse a multiset bigger with y bigger than the field size: '%s'", err)
	}
	set := NewMultiset()
	n, err := r.Read(data[:])
	if err != nil || n != len(data) {
		t.Fatalf("failed generating random data '%s' '%d' ", err, n)
	}
	set.Add(data[:])

}

func TestMultiSet_Reset(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	set := NewMultiset()
	emptySet := NewMultiset()
	data := [100]byte{}
	n, err := r.Read(data[:])
	if err != nil || n != len(data) {
		t.Fatalf("failed generating random data '%s' '%d' ", err, n)
	}
	set.Add(data[:])
	if set.Finalize().IsEqual(emptySet.Finalize()) {
		t.Errorf("expected set to be empty. found: '%s'", set.Finalize())
	}
	set.Reset()
	if !set.Finalize().IsEqual(emptySet.Finalize()) {
		t.Errorf("expected set to be empty. found: '%s'", set.Finalize())
	}
}

func TestMultiSetAddRemove(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	list := [loopsN][100]byte{}
	set := NewMultiset()
	set2 := *set
	serializedEmpty := *set.Serialize()
	for i := 0; i < loopsN; i++ {
		data := [100]byte{}
		n, err := r.Read(data[:])
		if err != nil || n != len(data) {
			t.Fatalf("Failed generating random data. read: '%d' bytes. .'%s'", n, err)
		}
		set.Add(data[:])
		list[i] = data
	}
	if set.Finalize().IsEqual(set2.Finalize()) {
		t.Errorf("sets are the same when they should be different: set '%s'\n", set.Finalize())
	}

	for i := 0; i < loopsN; i++ {
		set.Remove(list[i][:])
	}
	if !set.Finalize().IsEqual(set2.Finalize()) {
		t.Errorf("sets are different when they should be the same: set1: '%s', set2: '%s'\n", set.Finalize(), set2.Finalize())
	}
	if *set.Serialize() != serializedEmpty {
		t.Errorf("serialized sets are different when they should be the same: set1: '%s', set2: '%s'\n", set.Serialize(), serializedEmpty)
	}
	parsedSet, err := DeserializeMultiSet(&serializedEmpty)
	if err != nil {
		t.Errorf("error: '%s' happened when parsing: '%s'", err, serializedEmpty)
	} else if !parsedSet.Finalize().IsEqual(set.Finalize()) {
		t.Errorf("sets are different when they should be the same: set1: '%s', parsedSet: '%s'\n", set.Finalize(), parsedSet.Finalize())
	}
}

func BenchmarkMultiSet_Add(b *testing.B) {
	b.ReportAllocs()
	r := rand.New(rand.NewSource(1))
	list := make([][100]byte, b.N)
	for i := 0; i < b.N; i++ {
		n, err := r.Read(list[i][:])
		if err != nil || n != len(list[i]) {
			b.Fatalf("Failed generating random data. read: '%d' bytes. .'%s'", n, err)
		}
	}
	set := NewMultiset()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.Add(list[i][:])
		tmpSer := set.Serialize()
		tmpSet, err := DeserializeMultiSet(tmpSer)
		if err != nil || !tmpSet.Finalize().IsEqual(set.Finalize()) {
			panic("bad benchmark")
		}
	}
}

func BenchmarkMultiSet_Remove(b *testing.B) {
	b.ReportAllocs()
	r := rand.New(rand.NewSource(1))
	list := make([][100]byte, b.N)
	for i := 0; i < b.N; i++ {
		n, err := r.Read(list[i][:])
		if err != nil || n != len(list[i]) {
			b.Fatalf("Failed generating random data. read: '%d' bytes. .'%s'", n, err)
		}
	}
	set := NewMultiset()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.Remove(list[i][:])
	}
}

func BenchmarkMultiSet_Combine(b *testing.B) {
	b.ReportAllocs()
	r := rand.New(rand.NewSource(1))
	set := NewMultiset()
	sets := make([]MultiSet, b.N)
	for i := 0; i < b.N; i++ {
		data := [100]byte{}
		n, err := r.Read(data[:])
		if err != nil || n != len(data) {
			b.Fatalf("Failed generating random data. read: '%d' bytes. .'%s'", n, err)
		}
		set.Add(data[:])
		sets[i] = *set
	}
	set.Reset()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.Combine(&sets[i])
	}
}
