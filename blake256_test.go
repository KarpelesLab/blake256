// Copyright (c) 2019-2023 The Decred developers
// Originally written in 2011-2012 by Dmitry Chestnykh.
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package blake256

import (
	"bytes"
	"encoding"
	"fmt"
	"hash"
	"testing"
)

func Test256C(t *testing.T) {
	// Test as in C program.
	var hashes = [][]byte{
		{
			0x0C, 0xE8, 0xD4, 0xEF, 0x4D, 0xD7, 0xCD, 0x8D,
			0x62, 0xDF, 0xDE, 0xD9, 0xD4, 0xED, 0xB0, 0xA7,
			0x74, 0xAE, 0x6A, 0x41, 0x92, 0x9A, 0x74, 0xDA,
			0x23, 0x10, 0x9E, 0x8F, 0x11, 0x13, 0x9C, 0x87,
		},
		{
			0xD4, 0x19, 0xBA, 0xD3, 0x2D, 0x50, 0x4F, 0xB7,
			0xD4, 0x4D, 0x46, 0x0C, 0x42, 0xC5, 0x59, 0x3F,
			0xE5, 0x44, 0xFA, 0x4C, 0x13, 0x5D, 0xEC, 0x31,
			0xE2, 0x1B, 0xD9, 0xAB, 0xDC, 0xC2, 0x2D, 0x41,
		},
	}
	data := make([]byte, 72)

	h := New()
	h.Write(data[:1])
	sum := h.Sum(nil)
	if !bytes.Equal(hashes[0], sum) {
		t.Errorf("0: expected %X, got %X", hashes[0], sum)
	}

	// Try to continue hashing.
	h.Write(data[1:])
	sum = h.Sum(nil)
	if !bytes.Equal(hashes[1], sum) {
		t.Errorf("1(1): expected %X, got %X", hashes[1], sum)
	}

	// Try with reset.
	h.Reset()
	h.Write(data)
	sum = h.Sum(nil)
	if !bytes.Equal(hashes[1], sum) {
		t.Errorf("1(2): expected %X, got %X", hashes[1], sum)
	}
}

type blakeVector struct {
	out, in string
}

//nolint:misspell
var vectors256 = []blakeVector{
	{"7576698ee9cad30173080678e5965916adbb11cb5245d386bf1ffda1cb26c9d7",
		"The quick brown fox jumps over the lazy dog"},
	{"07663e00cf96fbc136cf7b1ee099c95346ba3920893d18cc8851f22ee2e36aa6",
		"BLAKE"},
	{"716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a",
		""},
	{"18a393b4e62b1887a2edf79a5c5a5464daf5bbb976f4007bea16a73e4c1e198e",
		"'BLAKE wins SHA-3! Hooray!!!' (I have time machine)"},
	{"fd7282ecc105ef201bb94663fc413db1b7696414682090015f17e309b835f1c2",
		"Go"},
	{"1e75db2a709081f853c2229b65fd1558540aa5e7bd17b04b9a4b31989effa711",
		"HELP! I'm trapped in hash!"},
	{"4181475cb0c22d58ae847e368e91b4669ea2d84bcd55dbf01fe24bae6571dd08",
		`Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congue ligula ac quam viverra nec consectetur ante hendrerit. Donec et mollis dolor. Praesent et diam eget libero egestas mattis sit amet vitae augue. Nam tincidunt congue enim, ut porta lorem lacinia consectetur. Donec ut libero sed arcu vehicula ultricies a non tortor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ut gravida lorem. Ut turpis felis, pulvinar a semper sed, adipiscing id dolor. Pellentesque auctor nisi id magna consequat sagittis. Curabitur dapibus enim sit amet elit pharetra tincidunt feugiat nisl imperdiet. Ut convallis libero in urna ultrices accumsan. Donec sed odio eros. Donec viverra mi quis quam pulvinar at malesuada arcu rhoncus. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. In rutrum accumsan ultricies. Mauris vitae nisi at sem facilisis semper ac in est.`,
	},
	{"af95fffc7768821b1e08866a2f9f66916762bfc9d71c4acb5fd515f31fd6785a", // test with one padding byte
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congu",
	},
}

// nolint: dupword
var vectors224 = []blakeVector{
	{"c8e92d7088ef87c1530aee2ad44dc720cc10589cc2ec58f95a15e51b",
		"The quick brown fox jumps over the lazy dog"},
	{"cfb6848add73e1cb47994c4765df33b8f973702705a30a71fe4747a3",
		"BLAKE"},
	{"7dc5313b1c04512a174bd6503b89607aecbee0903d40a8a569c94eed",
		""},
	{"dde9e442003c24495db607b17e07ec1f67396cc1907642a09a96594e",
		"Go"},
	{"9f655b0a92d4155754fa35e055ce7c5e18eb56347081ea1e5158e751",
		"Buffalo buffalo Buffalo buffalo buffalo buffalo Buffalo buffalo"},
}

func newTestVectors(t *testing.T, hashfunc func() hash.Hash, vectors []blakeVector) {
	for i, v := range vectors {
		h := hashfunc()
		h.Write([]byte(v.in))
		res := fmt.Sprintf("%x", h.Sum(nil))
		if res != v.out {
			t.Errorf("%d: expected %q, got %q", i, v.out, res)
		}
	}
}

func TestNew256(t *testing.T) {
	newTestVectors(t, New, vectors256)
}

func TestNew224(t *testing.T) {
	newTestVectors(t, New224, vectors224)
}

func TestSum256(t *testing.T) {
	for i, v := range vectors256 {
		res := fmt.Sprintf("%x", Sum256([]byte(v.in)))
		if res != v.out {
			t.Errorf("%d: expected %q, got %q", i, v.out, res)
		}
	}
}

func TestSum224(t *testing.T) {
	for i, v := range vectors224 {
		res := fmt.Sprintf("%x", Sum224([]byte(v.in)))
		if res != v.out {
			t.Errorf("%d: expected %q, got %q", i, v.out, res)
		}
	}
}

var vectors256salt = []struct{ out, in, salt string }{
	{"561d6d0cfa3d31d5eedaf2d575f3942539b03522befc2a1196ba0e51af8992a8",
		"",
		"1234567890123456"},
	{"88cc11889bbbee42095337fe2153c591971f94fbf8fe540d3c7e9f1700ab2d0c",
		"It's so salty out there!",
		"SALTsaltSaltSALT"},
}

func TestSalt(t *testing.T) {
	for i, v := range vectors256salt {
		h, err := NewSalt([]byte(v.salt))
		if err != nil {
			t.Fatalf("%d: NewSalt: %v", i, err)
		}
		h.Write([]byte(v.in))
		res := fmt.Sprintf("%x", h.Sum(nil))
		if res != v.out {
			t.Errorf("%d: expected %q, got %q", i, v.out, res)
		}
	}
}

func TestSaltErrors(t *testing.T) {
	badSalts := [][]byte{
		nil,
		{1, 2, 3},
		make([]byte, 8),
		make([]byte, 15),
		make([]byte, 17),
		make([]byte, 32),
	}
	for _, salt := range badSalts {
		if _, err := NewSalt(salt); err == nil {
			t.Errorf("NewSalt(len=%d): expected error, got nil", len(salt))
		}
		if _, err := New224Salt(salt); err == nil {
			t.Errorf("New224Salt(len=%d): expected error, got nil", len(salt))
		}
	}

	goodSalt := make([]byte, 16)
	if _, err := NewSalt(goodSalt); err != nil {
		t.Errorf("NewSalt(len=16): unexpected error: %v", err)
	}
	if _, err := New224Salt(goodSalt); err != nil {
		t.Errorf("New224Salt(len=16): unexpected error: %v", err)
	}
}

func TestTwoWrites(t *testing.T) {
	b := make([]byte, 65)
	for i := range b {
		b[i] = byte(i)
	}
	h1 := New()
	h1.Write(b[:1])
	h1.Write(b[1:])
	sum1 := h1.Sum(nil)

	h2 := New()
	h2.Write(b)
	sum2 := h2.Sum(nil)

	if !bytes.Equal(sum1, sum2) {
		t.Errorf("Result of two writes differs from a single write with the same bytes")
	}
}

// TestTwoCompressionPadding tests messages of 56-63 bytes, which exercise the
// two-compression finalization path (nx >= 56 in checkSum).
func TestTwoCompressionPadding(t *testing.T) {
	for msgLen := 56; msgLen <= 63; msgLen++ {
		msg := make([]byte, msgLen)
		for i := range msg {
			msg[i] = byte(i * 3)
		}

		// Compute via Sum256.
		expected := Sum256(msg)

		// Compute via New + Write + Sum and verify consistency.
		h := New()
		h.Write(msg)
		got := h.Sum(nil)
		if !bytes.Equal(expected[:], got) {
			t.Errorf("len=%d: Sum256 vs New+Write+Sum mismatch", msgLen)
		}

		// Compute via split writes at every possible boundary.
		for split := 0; split <= msgLen; split++ {
			h2 := New()
			h2.Write(msg[:split])
			h2.Write(msg[split:])
			got2 := h2.Sum(nil)
			if !bytes.Equal(expected[:], got2) {
				t.Errorf("len=%d split=%d: mismatch", msgLen, split)
			}
		}
	}

	// Also test 120 bytes (64+56): one full block consumed by Write, then
	// the remaining 56 bytes trigger the two-compression padding path.
	msg := make([]byte, 120)
	for i := range msg {
		msg[i] = byte(i)
	}
	expected := Sum256(msg)
	h := New()
	h.Write(msg)
	got := h.Sum(nil)
	if !bytes.Equal(expected[:], got) {
		t.Errorf("len=120: Sum256 vs New+Write+Sum mismatch")
	}
}

// TestTwoCompressionPadding224 tests the two-compression path for BLAKE-224.
func TestTwoCompressionPadding224(t *testing.T) {
	for msgLen := 56; msgLen <= 63; msgLen++ {
		msg := make([]byte, msgLen)
		for i := range msg {
			msg[i] = byte(i * 7)
		}

		expected := Sum224(msg)

		h := New224()
		h.Write(msg)
		got := h.Sum(nil)
		if !bytes.Equal(expected[:], got) {
			t.Errorf("len=%d: Sum224 vs New224+Write+Sum mismatch", msgLen)
		}
	}
}

// TestSumMidStream verifies that calling Sum does not affect subsequent writes.
func TestSumMidStream(t *testing.T) {
	data := []byte("The quick brown fox jumps over the lazy dog and then some more text for good measure!!!")

	for split := 0; split <= len(data); split++ {
		// Incremental with mid-stream Sum.
		h1 := New()
		h1.Write(data[:split])
		_ = h1.Sum(nil) // should not affect state
		h1.Write(data[split:])
		sum1 := h1.Sum(nil)

		// Single write for reference.
		h2 := New()
		h2.Write(data)
		sum2 := h2.Sum(nil)

		if !bytes.Equal(sum1, sum2) {
			t.Errorf("split=%d: mid-stream Sum affected result", split)
		}
	}
}

// TestMarshalBinary tests encoding.BinaryMarshaler / BinaryUnmarshaler.
func TestMarshalBinary(t *testing.T) {
	// Verify interface compliance.
	h := New()
	if _, ok := h.(encoding.BinaryMarshaler); !ok {
		t.Fatal("New() does not implement encoding.BinaryMarshaler")
	}
	if _, ok := h.(encoding.BinaryUnmarshaler); !ok {
		t.Fatal("New() does not implement encoding.BinaryUnmarshaler")
	}

	testCases := []struct {
		name    string
		newHash func() hash.Hash
	}{
		{"BLAKE-256", New},
		{"BLAKE-224", New224},
	}

	data := []byte("The quick brown fox jumps over the lazy dog")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for split := 0; split <= len(data); split++ {
				// Write first part and marshal.
				h1 := tc.newHash()
				h1.Write(data[:split])

				marshaled, err := h1.(encoding.BinaryMarshaler).MarshalBinary()
				if err != nil {
					t.Fatalf("split=%d: MarshalBinary: %v", split, err)
				}

				if len(marshaled) != marshalLen {
					t.Fatalf("split=%d: marshaled length = %d, want %d", split, len(marshaled), marshalLen)
				}

				// Unmarshal into a fresh hash and write the rest.
				h2 := tc.newHash()
				if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(marshaled); err != nil {
					t.Fatalf("split=%d: UnmarshalBinary: %v", split, err)
				}
				h2.Write(data[split:])
				sum2 := h2.Sum(nil)

				// Reference: single write.
				h3 := tc.newHash()
				h3.Write(data)
				sum3 := h3.Sum(nil)

				if !bytes.Equal(sum2, sum3) {
					t.Errorf("split=%d: marshal/unmarshal roundtrip produced different hash", split)
				}
			}
		})
	}
}

// TestUnmarshalBinaryErrors tests that invalid data is rejected.
func TestUnmarshalBinaryErrors(t *testing.T) {
	h := New()
	u := h.(encoding.BinaryUnmarshaler)

	// Too short.
	if err := u.UnmarshalBinary([]byte("short")); err == nil {
		t.Error("expected error for short input")
	}

	// Wrong length.
	if err := u.UnmarshalBinary(make([]byte, marshalLen+1)); err == nil {
		t.Error("expected error for wrong length")
	}

	// Correct length but bad magic.
	bad := make([]byte, marshalLen)
	copy(bad, "XXXXXXXX\x01")
	if err := u.UnmarshalBinary(bad); err == nil {
		t.Error("expected error for bad magic")
	}

	// Valid marshal should succeed.
	marshaled, _ := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err := u.UnmarshalBinary(marshaled); err != nil {
		t.Errorf("unexpected error for valid data: %v", err)
	}
}

// TestMarshalBinaryWithSalt verifies marshal/unmarshal preserves salt.
func TestMarshalBinaryWithSalt(t *testing.T) {
	salt := []byte("SALTsaltSaltSALT")
	data := []byte("It's so salty out there!")

	h1, err := NewSalt(salt)
	if err != nil {
		t.Fatal(err)
	}
	h1.Write(data[:10])

	marshaled, err := h1.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	h2 := New()
	if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(marshaled); err != nil {
		t.Fatal(err)
	}
	h2.Write(data[10:])
	sum2 := h2.Sum(nil)

	// Reference: write all at once with salt.
	h3, err := NewSalt(salt)
	if err != nil {
		t.Fatal(err)
	}
	h3.Write(data)
	sum3 := h3.Sum(nil)

	if !bytes.Equal(sum2, sum3) {
		t.Errorf("salt not preserved across marshal/unmarshal: got %x, want %x", sum2, sum3)
	}
}

var bufIn = make([]byte, 8<<10)
var bufOut = make([]byte, 32)

func Benchmark1K(b *testing.B) {
	b.SetBytes(1024)
	for i := 0; i < b.N; i++ {
		var bench = New()
		bench.Write(bufIn[:1024])
		_ = bench.Sum(bufOut[0:0])
	}
}

func Benchmark8K(b *testing.B) {
	b.SetBytes(int64(len(bufIn)))
	for i := 0; i < b.N; i++ {
		var bench = New()
		bench.Write(bufIn)
		_ = bench.Sum(bufOut[0:0])
	}
}

func Benchmark64(b *testing.B) {
	b.SetBytes(64)
	for i := 0; i < b.N; i++ {
		var bench = New()
		bench.Write(bufIn[:64])
		_ = bench.Sum(bufOut[0:0])
	}
}

func Benchmark1KNoAlloc(b *testing.B) {
	b.SetBytes(1024)
	for i := 0; i < b.N; i++ {
		_ = Sum256(bufIn[:1024])
	}
}

func Benchmark8KNoAlloc(b *testing.B) {
	b.SetBytes(int64(len(bufIn)))
	for i := 0; i < b.N; i++ {
		_ = Sum256(bufIn)
	}
}

func Benchmark64NoAlloc(b *testing.B) {
	b.SetBytes(64)
	for i := 0; i < b.N; i++ {
		_ = Sum256(bufIn[:64])
	}
}
