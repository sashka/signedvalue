package signedvalue

import (
	"strings"
	"testing"
)

// Test field decoder.
func TestConsumeField(t *testing.T) {
	tests := []struct {
		field string
		value string
		next  int
		err   error
	}{
		{field: "0:|", value: "", next: 3, err: nil},
		{field: "1:1|", value: "1", next: 4, err: nil},
		// empty field
		{field: "", value: "", next: -1, err: ErrMalformedField},
		// no field separator
		{field: "1:1", value: "", next: -1, err: ErrMalformedField},
		// length mismatch
		{field: "0:11|", value: "", next: -1, err: ErrMalformedField},
		{field: "8:|", value: "", next: -1, err: ErrMalformedField},
		{field: "4:Hello|", value: "", next: -1, err: ErrMalformedField},
		// malformed fields
		{field: "|", value: "", next: -1, err: ErrMalformedField},
		{field: ":|", value: "", next: -1, err: ErrMalformedField},
		{field: "|1:", value: "", next: -1, err: ErrMalformedField},
		{field: "|1:1", value: "", next: -1, err: ErrMalformedField},
		{field: "sdf8|", value: "", next: -1, err: ErrMalformedField},
		{field: ":adf|", value: "", next: -1, err: ErrMalformedField},
		{field: "1:|||||||||", value: "", next: -1, err: ErrMalformedField},
		{field: "[:||||:]", value: "", next: -1, err: ErrMalformedField},
		{field: "4:1|23|1:1", value: "", next: -1, err: ErrMalformedField},
	}

	for _, tt := range tests {
		// The first attempt to decode a field.
		got, next, err := consumeField(tt.field, 0)
		if got != tt.value || next != tt.next || err != tt.err {
			t.Errorf(`consumeField("%v", %v): want: ("%v", "%v", %v), got ("%v", "%v", "%v")`,
				tt.field, 0, tt.value, tt.next, tt.err, got, next, err)
		}

		// The second attempt to decode the next field.
		// This attempt is specifically designed for malformed fields with many pipes.
		// consumeField should always return an error.
		if err == nil {
			got2, next2, err2 := consumeField(tt.field, next)
			if err2 != ErrMalformedField {
				t.Errorf(`consumeField("%v", %d): want ("%v", "%v", "%v"), got: ("%v", "%v", "%v")`,
					tt.field, next, "", -1, ErrMalformedField, got2, next2, err2)
			}
		}
	}

	// Try to read from after the end of the string.
	// consumeField should always return an error.
	for _, tt := range tests {
		offset := len(tt.field) + 1
		got, next, err := consumeField(tt.field, offset)
		if err != ErrMalformedField {
			t.Errorf(`consumeField("%v", %v): want: ("%v", "%v", "%v"), got ("%v", "%v", "%v")`,
				tt.field, offset, tt.value, tt.next, ErrMalformedField, got, next, err)
		}
	}
}

func TestConsumeIntField(t *testing.T) {
	tests := []struct {
		field string
		value int
		next  int
		err   error
	}{
		{field: "1:1|", value: 1, next: 4, err: nil},
		// empty value
		{field: "0:|", value: 0, next: -1, err: ErrMalformedField},
		// float
		{field: "4:10.1|", value: 0, next: -1, err: ErrMalformedField},
	}

	for _, tt := range tests {
		got, next, err := consumeIntField(tt.field, 0)
		if got != tt.value || next != tt.next || err != tt.err {
			t.Errorf(`consumeIntField("%v", 0): want: ("%v", "%v", "%v"), got ("%v", "%v", "%v")`,
				tt.field, tt.value, tt.next, tt.err, got, next, err)
		}
	}
}

// The following tests are mostly adopted from Tornado's SignedValueTest.
const secret = "It's a secret to everybody"
const present = 1300000000
const past = present - 86400*31
const future = present + 86400*31

var secretKeys = map[int]string{
	0: "ajklasdf0ojaisdf",
	1: "aslkjasaolwkjsdf",
}

func TestKnownValues(t *testing.T) {
	wantSigned := "2|1:0|10:1300000000|3:key|8:dmFsdWU=|3d4e60b996ff9c5d5788e333a0cba6f238a22c6c0f94788870e1a9ecd482e152"
	wantDecoded := "value"

	signed := encode(secret, 0, "key", wantDecoded, present)
	if signed != wantSigned {
		t.Fatalf(`createSignedValue: want "%v", got "%v"`, wantSigned, signed)
	}

	decoded, err := decode(secret, "key", signed, present, 0)
	if err != nil || decoded != wantDecoded {
		t.Fatalf(`decode: want ("%v", "%v"), got ("%v", "%v")`, wantDecoded, nil, decoded, err)
	}
}

func TestNameSwap(t *testing.T) {
	wantDecoded := ""
	signed := encode(secret, 0, "key2", "value", present)
	decoded, err := decode(secret, "key1", signed, present, 0)
	if err != ErrInvalidName || decoded != wantDecoded {
		t.Fatalf(`decode: want ("%v", "%v"), got ("%v", "%v")`, wantDecoded, ErrInvalidName, decoded, err)
	}
}

func TestExpired(t *testing.T) {
	value := "value"
	ttl := 30 * 86400

	// Sign the value in the past.
	signed := encode(secret, 0, "key1", value, past)

	// Decode in the past. Should never fail.
	decoded, err := decode(secret, "key1", signed, past, ttl)
	if err != nil || decoded != value {
		t.Fatalf(`decode: want ("%v", "%v"), got ("%v", "%v")`, value, nil, decoded, err)
	}

	// Decode in present time. Should fail.
	decoded, err = decode(secret, "key1", signed, present, ttl)
	if err != ErrSignatureExpired || decoded != "" {
		t.Fatalf(`decode: want ("%v", "%v"), got ("%v", "%v")`, "", ErrSignatureExpired, decoded, err)
	}
}

func TestFuture(t *testing.T) {
	value := "value"
	ttl := 30 * 86400

	// Sign the value in the future.
	signed := encode(secret, 0, "key1", value, future)

	// Decode in the future. Should never fail.
	decoded, err := decode(secret, "key1", signed, future, ttl)
	if err != nil || decoded != value {
		t.Fatalf(`decode: want ("%v", "%v"), got ("%v", "%v")`, value, nil, decoded, err)
	}

	// Decode in present time. Should fail.
	decoded, err = decode(secret, "key1", signed, present, ttl)
	if err != ErrSignatureInFuture || decoded != "" {
		t.Fatalf(`decode: want ("%v", "%v"), got ("%v", "%v")`, "", ErrSignatureInFuture, decoded, err)
	}
}

func TestPayloadTampering(t *testing.T) {
	// These  are variants of the one in TestKnownValues.
	sig := "3d4e60b996ff9c5d5788e333a0cba6f238a22c6c0f94788870e1a9ecd482e152"

	tests := []struct {
		prefix string
		value  string
		err    error
	}{
		{prefix: "2|1:0|10:1300000000|3:key|8:dmFsdWU=|", value: "value", err: nil},
		// change key version
		{prefix: "2|1:1|10:1300000000|3:key|8:dmFsdWU=|", value: "", err: ErrInvalidKey},
		// zero length key version
		{prefix: "2|0:|10:1300000000|3:key|8:dmFsdWU=|", value: "", err: ErrMalformedField},
		// malformed
		{prefix: "2|1:0|:1300000000|3:key|8:dmFsdWU=|", value: "", err: ErrMalformedField},
		// length mismatch (field too short)
		{prefix: "2|1:0|10:130000000|3:key|8:dmFsdWU=|", value: "", err: ErrMalformedField},
		// length mismatch (field too long)
		{prefix: "2|1:0|10:1300000000|3:keey|8:dmFsdWU=|", value: "", err: ErrMalformedField},
	}

	for _, tt := range tests {
		got, err := decode(secret, "key", tt.prefix+sig, present, 0)
		if got != tt.value || err != tt.err {
			t.Errorf(`decode("%v"): want: ("%v", "%v"), got ("%v", "%v")`, tt.prefix+sig, tt.value, tt.err, got, err)
		}
	}
}

func TestSignatureTampering(t *testing.T) {
	prefix := "2|1:0|10:1300000000|3:key|8:dmFsdWU=|"

	tests := []struct {
		sig   string
		value string
		err   error
	}{
		{sig: "3d4e60b996ff9c5d5788e333a0cba6f238a22c6c0f94788870e1a9ecd482e152", value: "value", err: nil},
		// all zeros
		{sig: strings.Repeat("0", 32), value: "", err: ErrInvalidSignature},
		// no signature
		{sig: "", value: "", err: ErrInvalidSignature},
		// change one character
		{sig: "4d4e60b996ff9c5d5788e333a0cba6f238a22c6c0f94788870e1a9ecd482e152", value: "", err: ErrInvalidSignature},
		// change another character
		{sig: "3d4e60b996ff9c5d5788e333a0cba6f238a22c6c0f94788870e1a9ecd482e153", value: "", err: ErrInvalidSignature},
		// truncate
		{sig: "3d4e60b996ff9c5d5788e333a0cba6f238a22c6c0f94788870e1a9ecd482e15", value: "", err: ErrInvalidSignature},
		// lengthen
		{sig: "3d4e60b996ff9c5d5788e333a0cba6f238a22c6c0f94788870e1a9ecd482e1538", value: "", err: ErrInvalidSignature},
	}

	for _, tt := range tests {
		got, err := decode(secret, "key", prefix+tt.sig, present, 0)
		if got != tt.value || err != tt.err {
			t.Errorf(`decode("%v"): want: ("%v", "%v"), got ("%v", "%v")`, prefix+tt.sig, tt.value, tt.err, got, err)
		}
	}
}

func TestNonASCII(t *testing.T) {
	name := "hello"
	value := "こんにちは"

	signed := encode(secret, 0, name, value, present)
	decoded, err := decode(secret, name, signed, present, 0)
	if err != nil || decoded != value {
		t.Fatalf(`decode: want ("%v", "%v"), got ("%v", "%v")`, value, err, decoded, err)
	}
}

func TestFormatVersion(t *testing.T) {
	tests := []struct {
		signed string
		value  string
		err    error
	}{
		// valid v2
		{signed: "2|1:0|10:1300000000|3:key|8:dmFsdWU=|3d4e60b996ff9c5d5788e333a0cba6f238a22c6c0f94788870e1a9ecd482e152", value: "value", err: nil},
		// valid v1
		{signed: "dmFsdWU=|1300000000|31c934969f53e48164c50768b40cbd7e2daaaa4f", value: "", err: ErrMalformedField},
		// invalid v1 starting with "2"
		{signed: "2mFsdWU=|1300000000|31c934969f53e48164c50768b40cbd7e2daaaa4f", value: "", err: ErrMalformedField},
		// malformed value
		{signed: "2|1300000000|31c934969f53e48164c50768b40cbd7e2daaaa4f", value: "", err: ErrMalformedField},
	}

	for _, tt := range tests {
		got, err := decode(secret, "key", tt.signed, present, 0)
		if got != tt.value || err != tt.err {
			t.Errorf(`decode("%v"): want: ("%v", "%v"), got ("%v", "%v")`, tt.signed, tt.value, tt.err, got, err)
		}
	}
}

func TestKeyVersioningReadWriteNonDefaultKey(t *testing.T) {
	name := "key"
	value := "\xe9"

	signed, err := EncodeWithKeyVersioning(secretKeys, 1, name, value)
	if err != nil {
		t.Fatalf(`EncodeWithKeyVersioning: want (..., "%v"), got ("%v", "%v")`, nil, signed, err)
	}

	decoded, err := DecodeWithKeyVersioning(secretKeys, name, signed, 0)
	if err != nil || decoded != value {
		t.Fatalf(`DecodeWithKeyVersioning: want ("%v", "%v"), got ("%v", "%v")`, value, nil, decoded, err)
	}
}

func TestKeyVersioningInvalidKey(t *testing.T) {
	name := "key"
	value := "\xe9"

	signed, err := EncodeWithKeyVersioning(secretKeys, 0, name, value)
	if err != nil {
		t.Fatalf(`EncodeWithKeyVersioning: want (..., "%v"), got ("%v", "%v")`, nil, signed, err)
	}

	// Remove 0th secret key from the global map.
	delete(secretKeys, 0)

	decoded, err := DecodeWithKeyVersioning(secretKeys, name, signed, 0)
	if err != ErrInvalidKey || decoded != "" {
		t.Fatalf(`DecodeWithKeyVersioning: want ("%v", "%v"), got ("%v", "%v")`, "", ErrInvalidKey, decoded, err)
	}
}

func TestPublicMethods(t *testing.T) {
	name := "name"
	value := "value"

	// Unversioned secret key
	signed := Encode(secret, name, value)
	decoded, err := Decode(secret, name, signed, 0)
	if err != nil || decoded != value {
		t.Fatalf(`Encode: want ("%v", "%v"), got ("%v", "%v")`, value, nil, decoded, err)
	}

	// Empty string
	decoded, err = Decode(secret, "key", "", 0)
	if err != ErrMalformedField || decoded != "" {
		t.Fatalf(`Decode: want ("%v", "%v"), got ("%v", "%v")`, value, nil, decoded, err)
	}

	// Versioned secret key
	signed, err = EncodeWithKeyVersioning(secretKeys, 1, name, value)
	if err != nil {
		t.Fatalf(`EncodeWithKeyVersioning: want (..., "%v"), got ("%v", "%v")`, nil, signed, err)
	}
	decoded, err = DecodeWithKeyVersioning(secretKeys, name, signed, 0)
	if err != nil || decoded != value {
		t.Fatalf(`DecodeWithKeyVersioning: want ("%v", "%v"), got ("%v", "%v")`, value, nil, decoded, err)
	}
}

// Benchmarking
var result string

func BenchmarkNoKeyVersioningEncode(b *testing.B) {
	var signed string
	for n := 0; n < b.N; n++ {
		signed = Encode(secret, "key", "value")
	}

	// Always store the result to a package level variable
	// so the compiler cannot eliminate the Benchmark itself.
	result = signed
}

func BenchmarkNoKeyVersioningDecode(b *testing.B) {
	signed := Encode(secret, "key", "value")
	var decoded string
	for n := 0; n < b.N; n++ {
		decoded, _ = Decode(signed, "key", signed, 10)
	}

	// Always store the result to a package level variable
	// so the compiler cannot eliminate the Benchmark itself.
	result = decoded
}
