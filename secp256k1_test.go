package secp256k1

import (
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

func negateSecp256k1Tweak(tweak []byte) {
	bigTweak := new(big.Int).SetBytes(tweak)
	bigTweak.Neg(bigTweak)
	bigTweak.Mod(bigTweak, Secp256k1Order)
	res := intTo32Bytes(bigTweak)
	copy(tweak, res[:])
}

func fastGenerateTweak(t *testing.T, r *rand.Rand) *[32]byte {
	buf := [32]byte{}
	for {
		n, err := r.Read(buf[:])
		if err != nil || n != len(buf) {
			t.Fatalf("Failed generating 32 random bytes '%s'", err)
		}
		_, err = DeserializePrivateKey((*SerializedPrivateKey)(&buf))
		if err == nil {
			return &buf
		}
	}
}

func fastGenerateKeyPair(t *testing.T, r *rand.Rand) (key *SchnorrKeyPair) {
	buf := fastGenerateTweak(t, r)
	keypair, err := DeserializePrivateKey((*SerializedPrivateKey)(buf))
	if err != nil {
		t.Fatalf("A valid tweak should be a valid private key: '%s'", err)
	}
	return keypair
}

func setPrivateKey(keypair *SchnorrKeyPair, bytes []byte) {
	for i := 0; i < len(bytes); i++ {
		keypair.keypair.data[i] = _Ctype_uchar(bytes[i])
	}
}

func TestParseSerializePrivateKey(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < loopsN; i++ {
		keypair := fastGenerateKeyPair(t, r)

		serialized := keypair.SerializePrivateKey()
		privkey2, err := DeserializePrivateKey(serialized)
		if err != nil {
			t.Errorf("Failed parsing privateKey '%s'", err)
		}

		if *keypair != *privkey2 {
			t.Errorf("Privkeys aren't equal '%s' '%s'", privkey2, keypair)
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
	keypair := fastGenerateKeyPair(t, r)
	privkeyInverse := keypair.SerializePrivateKey()
	negateSecp256k1Tweak(privkeyInverse[:])
	err := keypair.Add(*privkeyInverse)
	if err == nil {
		t.Errorf("Adding the inverse of itself should fail, '%s', '%s', '%s'", keypair, privkeyInverse, err)
	}
	keypair = fastGenerateKeyPair(t, r)
	oufOfBounds := [32]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	err = keypair.Add(oufOfBounds)
	if err == nil {
		t.Errorf("Adding a tweak bigger than the order should fail, '%s', '%x' '%s'", keypair, oufOfBounds, err)
	}
}

func TestPrivateKey_Add(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	keypair := fastGenerateKeyPair(t, r)
	pubkey, wasOdd, err := keypair.schnorrPublicKeyInternal()
	if err != nil {
		t.Fatal(err)
	}
	privkeyBig := new(big.Int).SetBytes(keypair.SerializePrivateKey()[:])
	seedBig := big.Int{}

	for i := 0; i < loopsN; i++ {
		if wasOdd { // Schnorr secret keys are always even
			privkeyBig.Neg(privkeyBig)
		}
		seed := *fastGenerateTweak(t, r)
		seedBig.SetBytes(seed[:])

		privkeyBig.Add(privkeyBig, &seedBig)
		privkeyBig.Mod(privkeyBig, Secp256k1Order)
		err := keypair.Add(seed)
		if err != nil {
			t.Fatalf("failed adding seed: '%s' to key: '%s'", seed, keypair)
		}
		wasOdd, err = pubkey.addInternal(seed)
		if err != nil { // This shouldn't fail if the same operation for the privateKey didn't fail.
			t.Fatal(err)
		}

		tmpPubKey, err := keypair.SchnorrPublicKey()
		if err != nil {
			t.Fatalf("Failed generating pubkey from '%s'. '%s'", keypair, err)
		}

		if intTo32Bytes(privkeyBig) != *keypair.SerializePrivateKey() {
			t.Fatalf("Add operation failed, i=%d '%x' != '%s'", i, intTo32Bytes(privkeyBig), keypair.SerializePrivateKey())
		}
		if !pubkey.IsEqual(tmpPubKey) {
			t.Fatalf("tweaked pubkey '%s' doesn't match tweaked privateKey '%s', '%s'", pubkey, tmpPubKey, keypair)
		}
	}
}

func TestParseSchnorrPubKeyFail(t *testing.T) {
	zeros := [32]byte{}
	max := [32]byte{}
	for i := range max {
		max[i] = 0xff
	}
	_, err := DeserializeSchnorrPubKey(zeros[:])
	if err == nil {
		t.Errorf("Shouldn't parse 32 zeros as a pubkey '%x'", zeros)
	}
	_, err = DeserializeSchnorrPubKey(zeros[:30])
	if err == nil {
		t.Errorf("Shouldn't parse 30 zeros as a pubkey '%x'", zeros[:30])
	}
	_, err = DeserializeSchnorrPubKey(max[:])
	if err == nil {
		t.Errorf("Shouldn't parse 32 0xFF as a pubkey '%x' (it's above the field order)", max)
	}
}

func TestSchnorrPublicKey_SerializeFail(t *testing.T) {
	pubkey := SchnorrPublicKey{}
	_, err := pubkey.Serialize()
	if err == nil {
		t.Errorf("Zeroed public key isn't serializable as compressed")
	}
}

func TestBadPrivateKeyPublicKeyFail(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	goodKeyPair := fastGenerateKeyPair(t, r)
	goodPublicKey, err := goodKeyPair.SchnorrPublicKey()
	if err != nil {
		t.Fatalf("Failed generating pubkey from: '%s'. '%s'", goodKeyPair, err)
	}
	goodPublicKeyBackup := *goodPublicKey
	goodKeyPairBackup := *goodKeyPair
	msg := Hash(*fastGenerateTweak(t, r))
	keypair := SchnorrKeyPair{}
	var zeros32 [32]byte

	_, err1 := keypair.SchnorrPublicKey()
	_, err2 := keypair.SchnorrSign(&msg)
	err3 := keypair.Add(zeros32)
	_, err4 := DeserializePrivateKey(keypair.SerializePrivateKey())
	if err1 == nil || err2 == nil || err3 == nil || err4 == nil {
		t.Errorf("A zeroed key is invalid, err1: '%s', err2: '%s', err3: '%s', err4: '%s'", err1, err2, err3, err4)
	}

	err5 := goodKeyPair.Add(zeros32)
	err6 := goodPublicKey.Add(zeros32)
	if err5 != nil || err6 != nil {
		t.Errorf("It should be possible to add zero to a key, err4: '%s', err5: '%s'", err5, err6)
	}

	setPrivateKey(&keypair, Secp256k1Order.Bytes())
	_, err1 = keypair.SchnorrPublicKey()
	_, err2 = keypair.SchnorrSign(&msg)
	_, err3 = DeserializePrivateKey(keypair.SerializePrivateKey())
	*goodKeyPair = goodKeyPairBackup
	*goodPublicKey = goodPublicKeyBackup
	err4 = goodKeyPair.Add(intTo32Bytes(Secp256k1Order))
	err5 = goodPublicKey.Add(intTo32Bytes(Secp256k1Order))
	if err1 == nil || err2 == nil || err3 == nil || err4 == nil || err5 == nil {
		t.Errorf("the group order isn't a valid key, err1: '%s', err2: '%s', err3: '%s', err4: '%s', err5: '%s'", err1, err2, err3, err4, err5)
	}
	keypair = *fastGenerateKeyPair(t, r)
	orderPlusOne := new(big.Int).SetInt64(1)
	orderPlusOne.Add(orderPlusOne, Secp256k1Order)
	setPrivateKey(&keypair, orderPlusOne.Bytes())
	orderPlusOneArray := intTo32Bytes(orderPlusOne)
	_, err = DeserializePrivateKeyFromSlice(orderPlusOneArray[:])
	if err1 == nil || err2 == nil || err3 == nil || err4 == nil {
		t.Errorf("A key bigger than the group order isn't a valid key, err: '%s'", err)
	}
	*goodKeyPair = goodKeyPairBackup
	*goodPublicKey = goodPublicKeyBackup

	err1 = goodKeyPair.Add(intTo32Bytes(orderPlusOne))
	err2 = goodPublicKey.Add(intTo32Bytes(orderPlusOne))
	if err1 == nil || err2 == nil {
		t.Errorf("A tweak bigger than the group order isn't a valid tweak, err1: '%s', err2: '%s'", err1, err2)
	}
	orderMinusOne := new(big.Int).Sub(Secp256k1Order, new(big.Int).SetInt64(1))
	orderPlusOne = nil
	setPrivateKey(&keypair, orderMinusOne.Bytes())
	_, err1 = keypair.SchnorrPublicKey()
	_, err2 = keypair.SchnorrSign(&msg)
	_, err3 = DeserializePrivateKey(keypair.SerializePrivateKey())
	*goodKeyPair = goodKeyPairBackup
	*goodPublicKey = goodPublicKeyBackup
	err4 = goodKeyPair.Add(intTo32Bytes(orderMinusOne))
	err5 = goodPublicKey.Add(intTo32Bytes(orderMinusOne))
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
		t.Errorf("Group order - 1 should be a valid key, err1: '%s', err2: '%s', err3: '%s', err4: '%s', err5: '%s'", err1, err2, err3, err4, err5)
	}
}

func TestParseSchnorrPubKey(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < loopsN; i++ {
		keypair := fastGenerateKeyPair(t, r)
		pubkey, err := keypair.SchnorrPublicKey()
		if err != nil {
			t.Errorf("Failed Generating a pubkey from privateKey: '%s'. '%s'", keypair, err)
		}
		serializedPubkey, err := pubkey.Serialize()
		if err != nil {
			t.Errorf("Failed serializing the key: %s, error: '%s'", pubkey, err)
		}
		pubkeyNew1, err := DeserializeSchnorrPubKey(serializedPubkey[:])
		if err != nil {
			t.Errorf("Failed Parsing the compressed public key from keypair: '%s'. '%s'", pubkeyNew1, err)
		}
		if !pubkey.IsEqual(pubkeyNew1) {
			t.Errorf("Pubkeys aren't the same: '%s', '%s',", pubkey, pubkeyNew1)
		}
	}
}

func TestSignVerifyParseSchnorr(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < loopsN; i++ {
		keypair := fastGenerateKeyPair(t, r)

		pubkey, err := keypair.SchnorrPublicKey()
		if err != nil {
			t.Errorf("Failed generating a pubkey, privateKey: '%s', error: %s", keypair, err)
		}
		msg := Hash{}
		n, err := r.Read(msg[:])
		if err != nil || n != 32 {
			t.Errorf("Failed generating a msg. read: '%d' bytes. .'%s'", n, err)
		}
		sig1, err := keypair.SchnorrSign(&msg)
		if err != nil {
			t.Errorf("Failed signing schnorr: key: '%s', msg: '%s', error: '%s'", keypair, msg, err)
		}
		sig2, err := keypair.SchnorrSign(&msg)
		if err != nil {
			t.Errorf("Failed signing schnorr: key: '%s', msg: '%s', error: '%s'", keypair, msg, err)
		}
		if *sig1 == *sig2 {
			t.Errorf("Signing uses auxilary randomness, the odds of 2 signatures being the same is 1/2^128 '%s' '%s'", sig1, sig2)
		}
		serialized := sig1.Serialize()
		sigDeserialized := DeserializeSchnorrSignature(serialized)
		if *sig1 != *sigDeserialized {
			t.Errorf("Failed Deserializing schnorr signature '%s'", serialized)
		}
		if !pubkey.SchnorrVerify(&msg, sig1) {
			t.Errorf("Failed verifying schnorr signature privateKey: '%s' pubkey: '%s' signature: '%s'", keypair, pubkey, sig1)
		}
		if !pubkey.SchnorrVerify(&msg, sig2) {
			t.Errorf("Failed verifying schnorr signature privateKey: '%s' pubkey: '%s' signature: '%s'", keypair, pubkey, sig2)
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
	// Test vectors taken from https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
	tests := []struct {
		secKey    []byte
		pubKey    []byte
		auxRand   []byte
		message   []byte
		signature []byte
		valid     bool
	}{
		{
			decodeHex("0000000000000000000000000000000000000000000000000000000000000003"),
			decodeHex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
			decodeHex("0000000000000000000000000000000000000000000000000000000000000000"),
			decodeHex("0000000000000000000000000000000000000000000000000000000000000000"),
			decodeHex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
			true,
		},
		{
			decodeHex("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"),
			decodeHex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("0000000000000000000000000000000000000000000000000000000000000001"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"),
			true,
		},
		{
			decodeHex("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"),
			decodeHex("DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8"),
			decodeHex("C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906"),
			decodeHex("7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"),
			decodeHex("5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"),
			true,
		},
		{ // test fails if msg is reduced modulo p or n
			decodeHex("0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710"),
			decodeHex("25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517"),
			decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
			decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
			decodeHex("7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3"),
			true,
		},
		{
			nil,
			decodeHex("D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9"),
			nil,
			decodeHex("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703"),
			decodeHex("00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4"),
			true,
		},
		{ //public key not on the curve
			nil,
			decodeHex("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"),
			nil,
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"),
			false,
		},
		{ // has_even_y(R) is false
			nil,
			decodeHex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			nil,
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2"),
			false,
		},
		{ // negated message
			nil,
			decodeHex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			nil,
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD"),
			false,
		},
		{ // negated s value
			nil,
			decodeHex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			nil,
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6"),
			false,
		},
		{ // sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0
			nil,
			decodeHex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			nil,
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051"),
			false,
		},
		{ // sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1
			nil,
			decodeHex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			nil,
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197"),
			false,
		},
		{ // sig[0:32] is not an X coordinate on the curve
			nil,
			decodeHex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			nil,
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"),
			false,
		},
		{ // sig[0:32] is equal to field size
			nil,
			decodeHex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			nil,
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"),
			false,
		},
		{ // sig[32:64] is equal to curve order
			nil,
			decodeHex("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			nil,
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
			false,
		},
		{ // public key is not a valid X coordinate because it exceeds the field size
			nil,
			decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"),
			nil,
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"),
			false,
		},
	}

	msg32 := Hash{}
	for i, test := range tests {
		sig, err := DeserializeSchnorrSignatureFromSlice(test.signature)
		if err != nil {
			t.Fatal(err)
		}
		err = msg32.SetBytes(test.message)
		if err != nil {
			t.Fatal(err)
		}
		pubkey, err := DeserializeSchnorrPubKey(test.pubKey)
		if err != nil && test.valid {
			t.Fatalf("Schnorr test vector '%d': %s, pubkey: %x", i, err, test.pubKey)
		}
		if err == nil {
			valid := pubkey.SchnorrVerify(&msg32, sig)
			if valid != test.valid {
				t.Errorf("Schnorr test vector '%d' expected verification: '%t', got: '%t'", i, valid, test.valid)
			}
		}
		if test.secKey != nil {
			var auxRandPtr *[32]byte
			keypair, err := DeserializePrivateKeyFromSlice(test.secKey)
			if err != nil {
				t.Fatal(err)
			}
			if test.auxRand != nil {
				auxRandPtr = &[32]byte{}
				if len(auxRandPtr) != len(test.auxRand) {
					t.Fatalf("Schnorr test vector '%d': invalid auxilary randomness length: %d != %d", i, len(auxRandPtr), len(test.auxRand))
				}
				copy(auxRandPtr[:], test.auxRand)
			}

			newSig, err := keypair.schnorrSignInternal(&msg32, auxRandPtr)
			if err != nil {
				t.Fatal(err)
			}
			if !newSig.IsEqual(sig) {
				t.Errorf("Schnorr test vector '%d' expected sig: %s. got: %s", i, sig, newSig)
			}
		}
	}
}

func TestSchnorrPublicKey_IsEqual(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	goodKeyPair := fastGenerateKeyPair(t, r)
	goodPublicKey, err := goodKeyPair.SchnorrPublicKey()
	if err != nil {
		t.Fatalf("Failed generating pubkey from: '%s'. '%s'", goodKeyPair, err)
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
	goodKeyPair2 := fastGenerateKeyPair(t, r)
	goodPublicKey2, err := goodKeyPair2.SchnorrPublicKey()
	if err != nil {
		t.Fatalf("Failed generating pubkey from: '%s'. '%s'", goodKeyPair2, err)
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
