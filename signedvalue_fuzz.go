// +build gofuzz

package signedvalue

const secret = "It's a secret to everybody!111"

var secrets = map[int]string{
	1: "shhhhhhhhhhhhhhhhh!",
}

func Fuzz(data []byte) int {
	s := string(data)

	// Fuzzing unversioned Create -> Decode.
	e1 := Create(secret, "fuzz", s)
	if e1 == "" {
		panic("e1 is empty")
	}
	d1, err := Decode(secret, "fuzz", e1, 600)
	if err != nil {
		panic(err)
	}
	if d1 != s {
		panic("d1 != s")
	}

	// Fuzzing versioned Create -> Decode.
	e2, err := CreateWithKeyVersioning(secrets, 1, "fuzz", s)
	if e2 == "" {
		panic("e2 is empty")
	}
	if err != nil {
		panic("should never fail")
	}
	d2, err := DecodeWithKeyVersioning(secrets, "fuzz", e2, 600)
	if err != nil {
		panic(err)
	}
	if d2 != s {
		panic("d2 != s")
	}

	// Fuzzing both decode functions with s.
	var result int

	if _, err := Decode(secret, "fuzz", s, 600); err != nil {
		result -= 1
	}
	if _, err := DecodeWithKeyVersioning(secrets, "fuzz", s, 600); err != nil {
		result -= 1
	}

	if result < 0 {
		return 0
	}
	return 1
}
