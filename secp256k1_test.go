package secp256k1

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"testing"
)

const loopsN = 150

var Secp256k1Order = new(big.Int).SetBytes([]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 186, 174, 220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65})

func intTo32Bytes(i *big.Int) [32]byte {
	res := [32]byte{}
	serialized := i.Bytes()
	copy(res[32-len(serialized):], serialized)
	return res
}

func fastGeneratePrivateKey(t *testing.T, r *rand.Rand) (key *PrivateKey) {
	buf := SerializedPrivateKey{}
	for {
		n, err := r.Read(buf[:])
		if err != nil || n != len(buf) {
			t.Fatalf("Failed generating a privatekey '%s'", err)
		}
		privkey, err := DeserializePrivateKey(&buf)
		if err == nil {
			return privkey
		}
	}
}

func TestParseSerializePrivateKey(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < loopsN; i++ {
		privkey := fastGeneratePrivateKey(t, r)

		serialized := privkey.Serialize()
		privkey2, err := DeserializePrivateKey(serialized)
		if err != nil {
			t.Errorf("Failed parsing privateKey '%s'", err)
		}

		if *privkey != *privkey2 {
			t.Errorf("Privkeys aren't equal '%s' '%s'", privkey2, privkey)
		}
	}
}

func TestGeneratePrivateKey(t *testing.T) {
	_, err := GeneratePrivateKey()
	if err != nil {
		t.Errorf("Failed generating a privatekey '%s'", err)
	}
}

func TestPrivateKey_Add_Fail(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	privkey := fastGeneratePrivateKey(t, r)
	privkeyInverse := *privkey
	privkeyInverse.Negate()
	err := privkey.Add(privkeyInverse.privateKey)
	if err == nil {
		t.Errorf("Adding the inverse of itself should fail, '%s', '%s', '%s'", privkey, privkeyInverse, err)
	}
	privkey = fastGeneratePrivateKey(t, r)
	oufOfBounds := [32]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	err = privkey.Add(oufOfBounds)
	if err == nil {
		t.Errorf("Adding a tweak bigger than the order should fail, '%s', '%x' '%s'", privkey, oufOfBounds, err)
	}
}

func TestPrivateKey_Add(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	privkey := fastGeneratePrivateKey(t, r)
	pubkey, err := privkey.SchnorrPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	originalPubKey := *pubkey
	originalPrivatekey := *privkey
	privkeyBig := new(big.Int).SetBytes(privkey.privateKey[:])
	seedBig := big.Int{}
	seeds := make([]big.Int, loopsN)
	privkeyBigOriginal := new(big.Int).Set(privkeyBig)

	for i := 0; i < loopsN; i++ {
		seed := fastGeneratePrivateKey(t, r)
		err := privkey.Add(seed.privateKey)
		if err != nil {
			t.Errorf("failed adding seed: '%s' to key: '%s'", seed, privkey)
		}
		err = pubkey.Add(seed.privateKey)
		if err != nil { // This shouldn't fail if the same operation for the privateKey didn't fail.
			t.Error(err)
		}
		seedBig.SetBytes(seed.privateKey[:])
		privkeyBig.Add(privkeyBig, &seedBig)
		privkeyBig.Mod(privkeyBig, Secp256k1Order)
		if intTo32Bytes(privkeyBig) != privkey.privateKey {
			t.Errorf("Add operation failed, '%s' != '%s'", intTo32Bytes(privkeyBig), privkey.privateKey)
		}
		tmpPubKey, err := privkey.SchnorrPublicKey()
		if err != nil {
			t.Fatalf("Failed generating pubkey from '%s'. '%s'", privkey, err)
		}
		if !pubkey.IsEqual(tmpPubKey) {
			t.Fatalf("tweaked pubkey '%s' doesn't match tweaked privateKey '%s', '%s'", pubkey, tmpPubKey, privkey)
		}
		seeds[i].Set(&seedBig)
	}

	for i := 0; i < loopsN; i++ {
		slicedSeed := seeds[i].Bytes()
		seed := [32]byte{}
		copy(seed[32-len(slicedSeed):], slicedSeed)
		// By negating before and after it has the same affect as subtracting
		// -(-A+B) = A-B
		privkey.Negate()
		err := privkey.Add(seed)
		if err != nil {
			t.Errorf("failed adding seed: '%x' to key: '%s' i: '%d'", seed, privkey, i)
		}
		privkey.Negate()

		pubkey.Negate()
		err = pubkey.Add(seed)
		if err != nil { // This shouldn't fail if the same operation for the privateKey didn't fail.
			t.Fatal(err)
		}
		pubkey.Negate()

		t.Logf("seed: big: %x, array: %x", seeds[i].Bytes(), seed)
		privkeyBig.Sub(privkeyBig, &seeds[i])
		privkeyBig.Mod(privkeyBig, Secp256k1Order)
		if intTo32Bytes(privkeyBig) != privkey.privateKey {
			t.Fatalf("Add operation failed, '%x' != '%s'", intTo32Bytes(privkeyBig), privkey)
		}
		tmpPubKey, err := privkey.SchnorrPublicKey()
		if err != nil {
			t.Fatalf("Failed generating pubkey from '%s' '%s'", err, privkey)
		}
		if !pubkey.IsEqual(tmpPubKey) {
			t.Errorf("tweaked pubkey '%s' doesn't match tweaked privateKey '%s', '%s'", pubkey, privkey, tmpPubKey)
		}
	}
	if privkey.privateKey != originalPrivatekey.privateKey {
		t.Errorf("resulting privateKey: '%s' doesn't match original: '%s'", privkey, originalPrivatekey)
	}
	if privkeyBigOriginal.Cmp(privkeyBig) != 0 {
		t.Errorf("resulting bigint privateKey: '%x' doesn't match original: '%x'", privkeyBig.Bytes(), privkeyBigOriginal.Bytes())
	}

	if !pubkey.IsEqual(&originalPubKey) {
		t.Errorf("resulting privateKey: '%s' doesn't match original: '%s'", privkey, originalPrivatekey)
	}
}

func TestParseSchnorrPubKeyFail(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	zeros := [65]byte{}
	_, err := DeserializeSchnorrPubKey(zeros[:])
	if err == nil {
		t.Errorf("Shouldn't parse 65 zeros as a pubkey '%x'", zeros)
	}
	_, err = DeserializeSchnorrPubKey(zeros[:33])
	if err == nil {
		t.Errorf("Shouldn't parse 33 zeros as a pubkey '%x'", zeros[:33])
	}
	zeros[0] = 0x04
	_, err = DeserializeSchnorrPubKey(zeros[:])
	if err == nil {
		t.Errorf("Shouldn't parse zeroed x and y as pubkey '%x'", zeros)
	}
	pubkey, err := fastGeneratePrivateKey(t, r).SchnorrPublicKey()
	if err != nil {
		t.Fatalf("Failed generating a random pubkey: '%s'", err)
	}
	compressed, err := pubkey.SerializeCompressed()
	if err != nil {
		t.Fatalf("Failed serializing a pubkey: '%s' '%s'", pubkey, err)
	}
	oddnessByte := compressed[0]
	compressed[0] = 0x07
	_, err = DeserializeSchnorrPubKey(compressed[:])
	if err == nil {
		t.Errorf("Shouldn't parse a compressed key starting with 0x07 '%x'", compressed)
	}
	uncompressed, err := pubkey.SerializeUncompressed()
	if err != nil {
		t.Fatalf("Failed serializing a pubkey: '%s' '%s'", pubkey, err)
	}
	uncompressed[0] = oddnessByte
	_, err = DeserializeSchnorrPubKey(uncompressed[:])
	if err == nil {
		t.Errorf("Shouldn't parse an uncompressed key starting with 0x2/0x03 '%x'", uncompressed)
	}
	uncompressed[0] = oddnessByte + 0x04
	_, err = DeserializeSchnorrPubKey(uncompressed[:])
	if err == nil {
		t.Errorf("Shouldn't parse a weird hybrid pubkey '%x'", uncompressed)
	}
	uncompressed[0] = 0x04
	uncompressed[64] += 0x01
	_, err = DeserializeSchnorrPubKey(uncompressed[:])
	if err == nil {
		t.Errorf("Shouldn't parse a point with invalid y coordinate '%x'", uncompressed)
	}
}

func TestSchnorrPublicKey_SerializeFail(t *testing.T) {
	pubkey := SchnorrPublicKey{}
	_, err := pubkey.SerializeCompressed()
	if err == nil {
		t.Errorf("Zeroed public key isn't serializable as compressed")
	}
	_, err = pubkey.SerializeUncompressed()
	if err == nil {
		t.Errorf("Zeroed public key isn't serializable as uncompressed")
	}
}

func TestBadPrivateKeyPublicKeyFail(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	goodPrivateKey := fastGeneratePrivateKey(t, r)
	goodPublicKey, err := goodPrivateKey.SchnorrPublicKey()
	if err != nil {
		t.Fatalf("Failed generating pubkey from: '%s'. '%s'", goodPrivateKey, err)
	}
	goodPublicKeyBackup := *goodPublicKey
	goodPrivateKeyBackup := *goodPrivateKey
	msg := Hash(fastGeneratePrivateKey(t, r).privateKey)
	privkey := PrivateKey{}

	_, err1 := privkey.SchnorrPublicKey()
	_, err2 := privkey.SchnorrSign(&msg)
	_, err3 := DeserializePrivateKey(privkey.Serialize())
	err4 := goodPrivateKey.Add(privkey.privateKey)
	err5 := goodPublicKey.Add(privkey.privateKey)
	if err1 == nil || err2 == nil || err3 == nil {
		t.Errorf("A zeroed key is invalid, err1: '%s', err2: '%s', err3: '%s'", err1, err2, err3)
	}
	if err4 != nil || err5 != nil {
		t.Errorf("It should be possible to add zero to a key, err4: '%s', err5: '%s'", err4, err5)
	}
	copy(privkey.privateKey[:], Secp256k1Order.Bytes())
	_, err1 = privkey.SchnorrPublicKey()
	_, err2 = privkey.SchnorrSign(&msg)
	_, err3 = DeserializePrivateKey(privkey.Serialize())
	*goodPrivateKey = goodPrivateKeyBackup
	*goodPublicKey = goodPublicKeyBackup
	err4 = goodPrivateKey.Add(privkey.privateKey)
	err5 = goodPublicKey.Add(privkey.privateKey)
	if err1 == nil || err2 == nil || err3 == nil || err4 == nil || err5 == nil {
		t.Errorf("the group order isn't a valid key, err1: '%s', err2: '%s', err3: '%s', err4: '%s', err5: '%s'", err1, err2, err3, err4, err5)
	}
	orderPlusOne := new(big.Int).SetInt64(1)
	orderPlusOne.Add(orderPlusOne, Secp256k1Order)
	copy(privkey.privateKey[:], orderPlusOne.Bytes())
	_, err1 = privkey.SchnorrPublicKey()
	_, err2 = privkey.SchnorrSign(&msg)
	_, err3 = DeserializePrivateKey(privkey.Serialize())
	*goodPrivateKey = goodPrivateKeyBackup
	*goodPublicKey = goodPublicKeyBackup
	err4 = goodPrivateKey.Add(privkey.privateKey)
	err5 = goodPublicKey.Add(privkey.privateKey)
	if err1 == nil || err2 == nil || err3 == nil || err4 == nil || err5 == nil {
		t.Errorf("A key bigger than the group order isn't a valid key, err1: '%s', err2: '%s', err3: '%s', err4: '%s', err5: '%s'", err1, err2, err3, err4, err5)
	}
	OrderMinusOne := new(big.Int).SetInt64(1)
	orderPlusOne.Sub(Secp256k1Order, OrderMinusOne)
	copy(privkey.privateKey[:], orderPlusOne.Bytes())
	_, err1 = privkey.SchnorrPublicKey()
	_, err2 = privkey.SchnorrSign(&msg)
	_, err3 = DeserializePrivateKey(privkey.Serialize())
	*goodPrivateKey = goodPrivateKeyBackup
	*goodPublicKey = goodPublicKeyBackup
	err4 = goodPrivateKey.Add(privkey.privateKey)
	err5 = goodPublicKey.Add(privkey.privateKey)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
		t.Errorf("Group order - 1 should be a valid key, err1: '%s', err2: '%s', err3: '%s', err4: '%s', err5: '%s'", err1, err2, err3, err4, err5)
	}
}

func TestParseSchnorrPubKey(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < loopsN; i++ {
		privkey := fastGeneratePrivateKey(t, r)
		pubkey, err := privkey.SchnorrPublicKey()
		if err != nil {
			t.Errorf("Failed Generating a pubkey from privateKey: '%s'. '%s'", privkey, err)
		}
		serializedCompressed, err1 := pubkey.SerializeCompressed()
		serializedUncompressed, err2 := pubkey.SerializeUncompressed()
		if err1 != nil || err2 != nil {
			t.Errorf("Failed serializing the key: %s, errors: %s, '%s'", pubkey, err1, err2)
		}
		pubkeyNew1, err := DeserializeSchnorrPubKey(serializedCompressed[:])
		if err != nil {
			t.Errorf("Failed Parsing the compressed public key from privkey: '%s'. '%s'", pubkeyNew1, err)
		}
		pubkeyNew2, err := DeserializeSchnorrPubKey(serializedUncompressed[:])
		if err != nil {
			t.Errorf("Failed Parsing the uncompressed public key from privkey: '%s'. '%s'", pubkeyNew2, err)
		}

		if !pubkey.IsEqual(pubkeyNew1) || !pubkey.IsEqual(pubkeyNew2) {
			t.Errorf("Pubkeys aren't the same: '%s', '%s', '%s'", pubkey, pubkeyNew1, pubkeyNew2)
		}
	}
}

func TestSignVerifyParseSchnorr(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < loopsN; i++ {
		privkey := fastGeneratePrivateKey(t, r)

		pubkey, err := privkey.SchnorrPublicKey()
		if err != nil {
			t.Errorf("Failed generating a pubkey, privateKey: '%s', error: %s", privkey, err)
		}
		msg := Hash{}
		n, err := r.Read(msg[:])
		if err != nil || n != 32 {
			t.Errorf("Failed generating a msg. read: '%d' bytes. .'%s'", n, err)
		}
		sig1, err := privkey.SchnorrSign(&msg)
		if err != nil {
			t.Errorf("Failed signing schnorr: key: '%s', msg: '%s', error: '%s'", privkey, msg, err)
		}
		sig2, err := privkey.SchnorrSign(&msg)
		if err != nil {
			t.Errorf("Failed signing schnorr: key: '%s', msg: '%s', error: '%s'", privkey, msg, err)
		}
		if *sig1 != *sig2 {
			t.Errorf("Signing isn't deterministic '%s' '%s'", sig1, sig2)
		}
		serialized := sig1.Serialize()
		sigDeserialized := DeserializeSchnorrSignature(serialized)
		if *sig1 != *sigDeserialized {
			t.Errorf("Failed Deserializing schnorr signature '%s'", serialized)
		}
		if !pubkey.SchnorrVerify(&msg, sig1) {
			t.Errorf("Failed verifying schnorr signature privateKey: '%s' pubkey: '%s' signature: '%s'", privkey, pubkey, sig1)
		}
	}
}

// decodeHex decodes the passed hex string and returns the resulting bytes. It
// panics if an error occurs. This is only used in the tests as a helper since
// the only way it can fail is if there is an error in the test source code.
func decodeHex(hexStr string) []byte {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		panic("invalid hex string in test source: err " + err.Error() +
			", hex: " + hexStr)
	}

	return b
}

func TestSchnorrSignatureVerify(t *testing.T) {
	// Test vectors taken from https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/test-vectors.csv
	tests := []struct {
		pubKey    []byte
		message   []byte
		signature []byte
		valid     bool
	}{
		{
			decodeHex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
			decodeHex("0000000000000000000000000000000000000000000000000000000000000000"),
			decodeHex("787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF67031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05"),
			true,
		},
		{
			decodeHex("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD"),
			true,
		},
		{
			decodeHex("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B"),
			decodeHex("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"),
			decodeHex("00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380"),
			true,
		},
		{
			decodeHex("03DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"),
			decodeHex("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703"),
			decodeHex("00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D"),
			true,
		},
		{
			decodeHex("031B84C5567B126440995D3ED5AABA0565D71E1834604819FF9C17F5E9D5DD078F"),
			decodeHex("0000000000000000000000000000000000000000000000000000000000000000"),
			decodeHex("52818579ACA59767E3291D91B76B637BEF062083284992F2D95F564CA6CB4E3530B1DA849C8E8304ADC0CFE870660334B3CFC18E825EF1DB34CFAE3DFC5D8187"),
			true,
		},
		{
			decodeHex("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B"),
			decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
			decodeHex("570DD4CA83D4E6317B8EE6BAE83467A1BF419D0767122DE409394414B05080DCE9EE5F237CBD108EABAE1E37759AE47F8E4203DA3532EB28DB860F33D62D49BD"),
			true,
		},
		{
			decodeHex("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFA16AEE06609280A19B67A24E1977E4697712B5FD2943914ECD5F730901B4AB7"),
			false,
		},
		{
			decodeHex("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B"),
			decodeHex("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"),
			decodeHex("00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BED092F9D860F1776A1F7412AD8A1EB50DACCC222BC8C0E26B2056DF2F273EFDEC"),
			false,
		},
		{
			decodeHex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
			decodeHex("0000000000000000000000000000000000000000000000000000000000000000"),
			decodeHex("787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF68FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C"),
			false,
		},
		{
			decodeHex("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD"),
			false,
		},
		{
			decodeHex("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("00000000000000000000000000000000000000000000000000000000000000009E9D01AF988B5CEDCE47221BFA9B222721F3FA408915444A4B489021DB55775F"),
			false,
		},
		{
			decodeHex("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("0000000000000000000000000000000000000000000000000000000000000001D37DDF0254351836D84B1BD6A795FD5D523048F298C4214D187FE4892947F728"),
			false,
		},
		{
			decodeHex("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD"),
			false,
		},
		{
			decodeHex("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC2F1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD"),
			false,
		},
		{
			decodeHex("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
			false,
		},
	}

	msg32 := Hash{}
	for i, test := range tests {
		pubkey, err := DeserializeSchnorrPubKey(test.pubKey)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := DeserializeSchnorrSignatureFromSlice(test.signature)
		if err != nil {
			t.Fatal(err)
		}

		err = msg32.SetBytes(test.message)
		if err != nil {
			t.Fatal(err)
		}
		valid := pubkey.SchnorrVerify(&msg32, sig)
		if valid != test.valid {
			t.Errorf("Schnorr test vector '%d' expected verification: '%t', got: '%t'", i, valid, test.valid)
		}
	}
}

func TestDeterministicSchnorrSignatureGen(t *testing.T) {
	// Test vector from Bitcoin-ABC

	privKey, err := DeserializePrivateKeyFromSlice(decodeHex("12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747"))
	if err != nil {
		t.Fatal(err)
	}

	msg := Hash{}
	err = msg.SetBytes(decodeHex("5255683da567900bfd3e786ed8836a4e7763c221bf1ac20ece2a5171b9199e8a"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := privKey.SchnorrSign(&msg)
	if err != nil {
		t.Fatal(err)
	}
	serializedSig := sig.Serialize()
	if !bytes.Equal(serializedSig[:32], decodeHex("2c56731ac2f7a7e7f11518fc7722a166b02438924ca9d8b4d111347b81d07175")) ||
		!bytes.Equal(serializedSig[32:], decodeHex("71846de67ad3d913a8fdf9d8f3f73161a4c48ae81cb183b214765feb86e255ce")) {
		t.Error("Failed to generate deterministic schnorr signature")
	}
}

func TestSchnorrPublicKey_IsEqual(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	goodPrivateKey := fastGeneratePrivateKey(t, r)
	goodPublicKey, err := goodPrivateKey.SchnorrPublicKey()
	if err != nil {
		t.Fatalf("Failed generating pubkey from: '%s'. '%s'", goodPrivateKey, err)
	}
	badPublicKey := SchnorrPublicKey{}
	if badPublicKey.IsEqual(goodPublicKey) {
		t.Errorf("Empty publickey shouldn't be equal to good one")
	}
	if !badPublicKey.IsEqual(&SchnorrPublicKey{}) {
		t.Errorf("Empty publickey should be equal to another empty pubkey")
	}
	var nilPubKey *SchnorrPublicKey = nil
	if nilPubKey.IsEqual(goodPublicKey) {
		t.Errorf("nil publickey shouldn't be equal to good one")
	}

	if !nilPubKey.IsEqual(nil) {
		t.Errorf("two nil pubkeys should be equal")
	}

	copyGoodPubkey := *goodPublicKey
	if !copyGoodPubkey.IsEqual(goodPublicKey) {
		t.Errorf("A pubkey and its copy should be the same")
	}
	goodPrivateKey2 := fastGeneratePrivateKey(t, r)
	goodPublicKey2, err := goodPrivateKey2.SchnorrPublicKey()
	if err != nil {
		t.Fatalf("Failed generating pubkey from: '%s'. '%s'", goodPrivateKey2, err)
	}

	if goodPublicKey.IsEqual(goodPublicKey2) {
		t.Errorf("'%s' shouldn't be equal to %s", goodPublicKey, goodPublicKey2)
	}
}

func TestSchnorrSignature_IsEqual(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	serializedSig := SerializedSchnorrSignature{}
	n, err := r.Read(serializedSig[:])
	if err != nil || n != len(serializedSig) {
		t.Errorf("Failed generating a random signature. read: '%d' bytes.. '%s'", n, err)
	}
	goodSignature := DeserializeSchnorrSignature(&serializedSig)

	emptySignature := SchnorrSignature{}
	if emptySignature.IsEqual(goodSignature) {
		t.Errorf("Empty signature shouldn't be equal to good one")
	}
	if !emptySignature.IsEqual(&SchnorrSignature{}) {
		t.Errorf("Empty signature should be equal to another empty signature")
	}
	var nilSignature *SchnorrSignature = nil
	if nilSignature.IsEqual(goodSignature) {
		t.Errorf("nil signature shouldn't be equal to good one")
	}

	if !nilSignature.IsEqual(nil) {
		t.Errorf("two nil signatures should be equal")
	}

	copyGoodSignature := *goodSignature
	if !copyGoodSignature.IsEqual(goodSignature) {
		t.Errorf("A signature and its copy should be the same")
	}

	serializedSig2 := SerializedSchnorrSignature{}
	n, err = r.Read(serializedSig2[:])
	if err != nil || n != len(serializedSig2) {
		t.Errorf("Failed generating a random signature. read: '%d' bytes.. '%s'", n, err)
	}

	goodSignature2 := DeserializeSchnorrSignature(&serializedSig2)
	if goodSignature.IsEqual(goodSignature2) {
		t.Errorf("'%s' shouldn't be equal to %s", goodSignature, goodSignature2)
	}
}

func TestHash_IsEqual(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	goodHash := &Hash{}
	n, err := r.Read(goodHash[:])
	if err != nil || n != len(goodHash) {
		t.Errorf("Failed generating a random hash. read: '%d' bytes.. '%s'", n, err)
	}

	emptyHash := Hash{}
	if emptyHash.IsEqual(goodHash) {
		t.Errorf("Empty hash shouldn't be equal to filled one")
	}
	if !emptyHash.IsEqual(&Hash{}) {
		t.Errorf("Empty hash should be equal to another empty hash")
	}
	var nilHash *Hash = nil
	if nilHash.IsEqual(goodHash) {
		t.Errorf("nil hash shouldn't be equal to good one")
	}

	if !nilHash.IsEqual(nil) {
		t.Errorf("two nil hashes should be equal")
	}

	copyGoodHash := *goodHash
	if !copyGoodHash.IsEqual(goodHash) {
		t.Errorf("A hash and its copy should be the same")
	}

	goodHash2 := &Hash{}
	n, err = r.Read(goodHash2[:])
	if err != nil || n != len(goodHash2) {
		t.Errorf("Failed generating a random hash. read: '%d' bytes. .'%s'", n, err)
	}

	if goodHash.IsEqual(goodHash2) {
		t.Errorf("'%s' shouldn't be equal to %s", goodHash, goodHash2)
	}
}

func BenchmarkSchnorrVerify(b *testing.B) {
	b.ReportAllocs()
	r := rand.New(rand.NewSource(1))
	sigs := make([]*SchnorrSignature, b.N)
	msgs := make([]Hash, b.N)
	pubkeys := make([]SchnorrPublicKey, b.N)
	for i := 0; i < b.N; i++ {
		msg := Hash{}
		n, err := r.Read(msg[:])
		if err != nil || n != 32 {
			panic(fmt.Sprintf("benchmark failed: '%s', n: %d", err, n))
		}
		privkey, err := GeneratePrivateKey()
		if err != nil {
			panic("benchmark failed: " + err.Error())
		}
		sigTmp, err := privkey.SchnorrSign(&msg)
		if err != nil {
			panic("benchmark failed: " + err.Error())
		}
		sigs[i] = sigTmp
		pubkeyTmp, err := privkey.SchnorrPublicKey()
		if err != nil {
			panic("benchmark failed: " + err.Error())
		}
		pubkeys[i] = *pubkeyTmp
		msgs[i] = msg
	}
	b.ResetTimer()
	sum := 0
	for i := 0; i < b.N; i++ {
		ret := pubkeys[i].SchnorrVerify(&msgs[i], sigs[i])
		if ret {
			sum++
		}
	}
}
