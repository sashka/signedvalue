// Package signedvalue provides signed and timestamped strings
// compatible with Tornado's create_signed_value and decode_signed_value.
//
// Only v2 format is supported.
package signedvalue

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// ErrInvalidSignature means that the signature could not be verified.
var ErrInvalidSignature = errors.New("invalid signature")

// ErrInvalidKey means that a key with requested version had not been found.
var ErrInvalidKey = errors.New("invalid secret key")

// ErrInvalidName means that the name inside the signed value didn't match with a name passed to the decode function.
var ErrInvalidName = errors.New("invalid name")

// ErrSignatureExpired means that the signature expired, thus the signed value should not be trusted any more.
var ErrSignatureExpired = errors.New("signature expired")

// ErrSignatureInFuture means that the timestamp is in future and cannot be checked properly, thus should not be trusted.
var ErrSignatureInFuture = errors.New("signature in future")

// ErrValueDecodeFailed literally means that value could not be decoded.
var ErrValueDecodeFailed = errors.New("value decode failed")

// ErrMalformedField means that a field is broken and cannot be decoded properly.
var ErrMalformedField = errors.New("malformed field")

// Create creates signed and timestamped string so the string cannot be forged.
// This method doesn't support secret key versioning.
func Create(key string, name string, value string) string {
	return create(key, 0, name, value, timestamp())
}

// Decode decodes and returns the value if it validates.
// This method doesn't support secret key versioning.
func Decode(key string, name string, signed string, ttl int) (string, error) {
	return decode(key, name, signed, timestamp(), ttl)
}

// CreateWithKeyVersioning creates signed and timestamped string using the given secret key version.
func CreateWithKeyVersioning(keys map[int]string, keyVersion int, name string, value string) (string, error) {
	key, found := keys[keyVersion]
	if !found {
		return "", ErrInvalidKey
	}
	return create(key, keyVersion, name, value, timestamp()), nil
}

// DecodeWithKeyVersioning decodes and retures the value if it validates.
func DecodeWithKeyVersioning(keys map[int]string, name string, signed string, ttl int) (decoded string, error error) {
	return decodeWithKeyVersioning(keys, name, signed, timestamp(), ttl)
}

// timestamp returns the current timestamp, in seconds.
func timestamp() int {
	return int(time.Now().UTC().Unix())
}

// As I mentioned before, only v2 format is supported.
const formatVersion string = "2"

// Field separator.
const fieldSep string = "|"

// Length separator
const lenSep string = ":"

// versionPrefix is a pre-calculated mandatory prefix for every valid signed value.
const versionPrefix string = formatVersion + fieldSep

// create signs and timestamps a given string with secret key.
// Secret key version is stored so it may be used upon decodeWithKeyVersioning.
func create(key string, keyVersion int, name string, value string, timestamp int) string {
	/*
		The v2 format consists of a version number and a series of length-prefixed fields "%d:%s",
		the last of which is a signature, all separated by pipes.
		All numbers are in decimal format with no leading zeros.
		The signature is an HMAC-SHA256 of the whole string up to that point, including the final pipe.

		The fields are:
		- format version (i.e. 2; no length prefix)
		- secret key version (integer, default is 0)
		- timestamp (integer seconds since epoch)
		- name (not encoded; assumed to be alphanumeric)
		- value (base64-encoded)
		- signature (hex-encoded; no length prefix)
	*/
	b := strings.Builder{}

	// Preallocate more to reduce a number of underground array re-allocations.
	b.Grow(100 + len(value)*2)

	b.WriteString(versionPrefix)
	formatField(&b, strconv.Itoa(keyVersion))
	formatField(&b, strconv.Itoa(timestamp))
	formatField(&b, name)
	formatField(&b, base64.URLEncoding.EncodeToString([]byte(value)))
	b.WriteString(createSignature(key, b.String()))

	return b.String()
}

func formatField(b *strings.Builder, value string) {
	b.WriteString(strconv.Itoa(len(value)))
	b.WriteString(lenSep)
	b.WriteString(value)
	b.WriteString(fieldSep)
}

func createSignature(key string, s string) string {
	hash := hmac.New(sha256.New, []byte(key))
	hash.Write([]byte(s))
	return hex.EncodeToString(hash.Sum(nil))
}

func decode(key string, name string, signed string, timestamp int, ttl int) (string, error) {
	fields, err := decodeFields(signed)
	if err != nil {
		return "", err
	}

	// This method doesn't expect a versioned key.
	if fields.KeyVersion != 0 {
		return "", ErrInvalidKey
	}

	// Validate a signature.
	err = validate(fields, key, name, signed, timestamp, ttl)
	if err != nil {
		return "", err
	}

	// Decode a value.
	decoded, err := decodeValue(fields.Value)
	if err != nil {
		// base64 decode has failed
		return "", err
	}
	return decoded, nil
}

func decodeWithKeyVersioning(keys map[int]string, name string, signed string, timestamp int, ttl int) (string, error) {
	fields, err := decodeFields(signed)
	if err != nil {
		return "", err
	}

	key, found := keys[fields.KeyVersion]
	if !found {
		return "", ErrInvalidKey
	}

	// Validate a signature.
	err = validate(fields, key, name, signed, timestamp, ttl)
	if err != nil {
		return "", err
	}

	// Decode a value.
	decoded, err := decodeValue(fields.Value)
	if err != nil {
		// base64 decode has failed
		return "", err
	}
	return decoded, nil
}

func validate(fields *decodedFields, key string, name string, signed string, timestamp int, ttl int) error {
	body := signed[:len(signed)-len(fields.Signature)]
	expectedSignature := createSignature(key, body)
	if !hmac.Equal([]byte(fields.Signature), []byte(expectedSignature)) {
		// Signature check failed.
		return ErrInvalidSignature
	}
	if fields.Name != name {
		// Unexpected name.
		return ErrInvalidName
	}
	if fields.Timestamp < (timestamp - ttl) {
		// The signature has expired.
		return ErrSignatureExpired
	}
	if fields.Timestamp > timestamp {
		// The signature is in future.
		return ErrSignatureInFuture
	}
	return nil
}

func decodeValue(s string) (string, error) {
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return "", ErrValueDecodeFailed
	}
	return string(b), nil
}

type decodedFields struct {
	KeyVersion int
	Timestamp  int
	Name       string
	Value      string
	Signature  string
}

func decodeFields(s string) (*decodedFields, error) {
	next, err := checkVersionPrefix(s)
	if err != nil {
		return nil, err
	}

	keyver, next, err := consumeIntField(s, next)
	if err != nil {
		return nil, err
	}

	timestamp, next, err := consumeIntField(s, next)
	if err != nil {
		return nil, err
	}

	name, next, err := consumeField(s, next)
	if err != nil {
		return nil, err
	}

	value, next, err := consumeField(s, next)
	if err != nil {
		return nil, err
	}

	return &decodedFields{
		KeyVersion: keyver,
		Timestamp:  timestamp,
		Name:       name,
		Value:      value,
		Signature:  s[next:],
	}, nil
}

// checkVersionPrefix validates format version of a given string.
func checkVersionPrefix(s string) (next int, err error) {
	vplen := len(versionPrefix)
	if len(s) < vplen {
		return -1, ErrMalformedField
	}
	if s[:vplen] != versionPrefix {
		return -1, ErrMalformedField
	}
	return vplen, nil
}

// consumeField decodes field at given offset and return decoded field and an offset to the next field.
func consumeField(s string, offset int) (value string, next int, err error) {
	// Field bounds.
	if len(s) < offset {
		return "", -1, ErrMalformedField
	}
	field := s[offset:]

	// Length separator.
	lsep := strings.Index(field, lenSep)

	// Field separator.
	fsep := strings.Index(field, fieldSep)

	// Both length separator and field separator are expected in a valid field.
	if lsep == -1 || fsep == -1 {
		return "", -1, ErrMalformedField
	}

	// Check field length for leading zeros.
	// It means "0" length is valid, but "00" is invalid.
	if lsep > 1 && field[0] == '0' {
		return "", -1, ErrMalformedField
	}

	// Read field length.
	n, err := strconv.ParseUint(field[:lsep], 10, 64)
	if err != nil {
		return "", -1, ErrMalformedField
	}

	// Cast field length to int to make offset maths easier.
	l := int(n)

	// Ensure there's enough bytes left, and the field terminates exactly on a field separator.
	if lsep+1+l != fsep {
		return "", -1, ErrMalformedField
	}

	return field[lsep+1 : lsep+1+l], offset + lsep + l + 2, nil
}

func consumeIntField(s string, offset int) (value int, next int, err error) {
	v, next, err := consumeField(s, offset)
	if err != nil {
		return 0, -1, err
	}

	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, -1, ErrMalformedField
	}

	return n, next, nil
}
