// ported from C++ source at
// https://github.com/weidai11/cryptopp/blob/CRYPTOPP_5_4/md5mac.cpp
// https://github.com/sghiassy/Code-Reading-Book/blob/master/OpenCL/src/md5mac.cpp

package md5mac

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const (
	BLOCKSIZE = 64
	MACLENGTH = 16
	KEYLENGTH = 16
)

type MD5MAC struct {
	m []uint8

	k1 []uint32
	k2 []uint32
	k3 []byte

	buffer []byte
	digest []uint32

	count    uint32
	position uint32
}

func NewMD5MAC() *MD5MAC {
	return &MD5MAC{
		m: make([]uint8, BLOCKSIZE),

		k1: make([]uint32, 4),
		k2: make([]uint32, 4),
		k3: make([]byte, BLOCKSIZE),

		buffer: nil,
		digest: make([]uint32, 4),

		count:    0,
		position: 0,
	}
}

func NewMD5MACWithKey(key []byte) (mac *MD5MAC, err error) {

	mac = NewMD5MAC()
	err = mac.SetKey(key)

	return

}

func (m *MD5MAC) clear() {

	m.m = make([]uint8, BLOCKSIZE)

	m.k1 = make([]uint32, 4)
	m.k2 = make([]uint32, 4)
	m.k3 = make([]byte, BLOCKSIZE)

	m.buffer = nil
	m.digest = make([]uint32, 4)

	m.count = 0
	m.position = 0
}

func (m *MD5MAC) hash(input []byte) {

	var (
		A = m.digest[0]
		B = m.digest[1]
		C = m.digest[2]
		D = m.digest[3]
	)

	for j := 0; j < 16; j++ {
		startIndex := j * 4
		endIndex := startIndex + 4
		patch := []byte{input[4*j+3], input[4*j+2], input[4*j+1], input[4*j+0]}
		copy(m.m[startIndex:endIndex], patch)
	}

	FF := func(A *uint32, B, C, D uint32, msg []uint8, shift, magic uint32) {

		msgValue := binary.BigEndian.Uint32(msg[:])

		*A += (D ^ (B & (C ^ D))) + msgValue + magic + m.k2[0]
		*A = (*A << shift) | (*A >> (32 - shift))
		*A += B
	}

	GG := func(A *uint32, B, C, D uint32, msg []uint8, shift, magic uint32) {

		msgValue := binary.BigEndian.Uint32(msg[:])

		*A += (C ^ ((B ^ C) & D)) + msgValue + magic + m.k2[1]
		*A = (*A << shift) | (*A >> (32 - shift))
		*A += B
	}

	HH := func(A *uint32, B, C, D uint32, msg []uint8, shift, magic uint32) {

		msgValue := binary.BigEndian.Uint32(msg[:])

		*A += (B ^ C ^ D) + msgValue + magic + m.k2[2]
		*A = (*A << shift) | (*A >> (32 - shift))
		*A += B
	}

	II := func(A *uint32, B, C, D uint32, msg []uint8, shift, magic uint32) {

		msgValue := binary.BigEndian.Uint32(msg[:])

		*A += (C ^ (B | ^D)) + msgValue + magic + m.k2[3]
		*A = (*A << shift) | (*A >> (32 - shift))
		*A += B
	}

	FF(&A, B, C, D, m.m[0*4:0*4+4], 7, 0xD76AA478)
	FF(&D, A, B, C, m.m[1*4:1*4+4], 12, 0xE8C7B756)
	FF(&C, D, A, B, m.m[2*4:2*4+4], 17, 0x242070DB)
	FF(&B, C, D, A, m.m[3*4:3*4+4], 22, 0xC1BDCEEE)
	FF(&A, B, C, D, m.m[4*4:4*4+4], 7, 0xF57C0FAF)
	FF(&D, A, B, C, m.m[5*4:5*4+4], 12, 0x4787C62A)
	FF(&C, D, A, B, m.m[6*4:6*4+4], 17, 0xA8304613)
	FF(&B, C, D, A, m.m[7*4:7*4+4], 22, 0xFD469501)
	FF(&A, B, C, D, m.m[8*4:8*4+4], 7, 0x698098D8)
	FF(&D, A, B, C, m.m[9*4:9*4+4], 12, 0x8B44F7AF)
	FF(&C, D, A, B, m.m[10*4:10*4+4], 17, 0xFFFF5BB1)
	FF(&B, C, D, A, m.m[11*4:11*4+4], 22, 0x895CD7BE)
	FF(&A, B, C, D, m.m[12*4:12*4+4], 7, 0x6B901122)
	FF(&D, A, B, C, m.m[13*4:13*4+4], 12, 0xFD987193)
	FF(&C, D, A, B, m.m[14*4:14*4+4], 17, 0xA679438E)
	FF(&B, C, D, A, m.m[15*4:15*4+4], 22, 0x49B40821)

	GG(&A, B, C, D, m.m[1*4:1*4+4], 5, 0xF61E2562)
	GG(&D, A, B, C, m.m[6*4:6*4+4], 9, 0xC040B340)
	GG(&C, D, A, B, m.m[11*4:11*4+4], 14, 0x265E5A51)
	GG(&B, C, D, A, m.m[0*4:0*4+4], 20, 0xE9B6C7AA)
	GG(&A, B, C, D, m.m[5*4:15*4+4], 5, 0xD62F105D)
	GG(&D, A, B, C, m.m[10*4:10*4+4], 9, 0x02441453)
	GG(&C, D, A, B, m.m[15*4:15*4+4], 14, 0xD8A1E681)
	GG(&B, C, D, A, m.m[4*4:4*4+4], 20, 0xE7D3FBC8)
	GG(&A, B, C, D, m.m[9*4:9*4+4], 5, 0x21E1CDE6)
	GG(&D, A, B, C, m.m[14*4:14*4+4], 9, 0xC33707D6)
	GG(&C, D, A, B, m.m[3*4:3*4+4], 14, 0xF4D50D87)
	GG(&B, C, D, A, m.m[8*4:8*4+4], 20, 0x455A14ED)
	GG(&A, B, C, D, m.m[13*4:13*4+4], 5, 0xA9E3E905)
	GG(&D, A, B, C, m.m[2*4:2*4+4], 9, 0xFCEFA3F8)
	GG(&C, D, A, B, m.m[7*4:7*4+4], 14, 0x676F02D9)
	GG(&B, C, D, A, m.m[12*4:12*4+4], 20, 0x8D2A4C8A)

	HH(&A, B, C, D, m.m[5*4:5*4+4], 4, 0xFFFA3942)
	HH(&D, A, B, C, m.m[8*4:8*4+4], 11, 0x8771F681)
	HH(&C, D, A, B, m.m[11*4:11*4+4], 16, 0x6D9D6122)
	HH(&B, C, D, A, m.m[14*4:14*4+4], 23, 0xFDE5380C)
	HH(&A, B, C, D, m.m[1*4:1*4+4], 4, 0xA4BEEA44)
	HH(&D, A, B, C, m.m[4*4:4*4+4], 11, 0x4BDECFA9)
	HH(&C, D, A, B, m.m[7*4:7*4+4], 16, 0xF6BB4B60)
	HH(&B, C, D, A, m.m[10*4:10*4+4], 23, 0xBEBFBC70)
	HH(&A, B, C, D, m.m[13*4:13*4+4], 4, 0x289B7EC6)
	HH(&D, A, B, C, m.m[0*4:0*4+4], 11, 0xEAA127FA)
	HH(&C, D, A, B, m.m[3*4:3*4+4], 16, 0xD4EF3085)
	HH(&B, C, D, A, m.m[6*4:6*4+4], 23, 0x04881D05)
	HH(&A, B, C, D, m.m[9*4:9*4+4], 4, 0xD9D4D039)
	HH(&D, A, B, C, m.m[12*4:12*4+4], 11, 0xE6DB99E5)
	HH(&C, D, A, B, m.m[15*4:15*4+4], 16, 0x1FA27CF8)
	HH(&B, C, D, A, m.m[2*4:2*4+4], 23, 0xC4AC5665)

	II(&A, B, C, D, m.m[0*4:0*4+4], 6, 0xF4292244)
	II(&D, A, B, C, m.m[7*4:7*4+4], 10, 0x432AFF97)
	II(&C, D, A, B, m.m[14*4:14*4+4], 15, 0xAB9423A7)
	II(&B, C, D, A, m.m[5*4:5*4+4], 21, 0xFC93A039)
	II(&A, B, C, D, m.m[12*4:12*4+4], 6, 0x655B59C3)
	II(&D, A, B, C, m.m[3*4:3*4+4], 10, 0x8F0CCC92)
	II(&C, D, A, B, m.m[10*4:10*4+4], 15, 0xFFEFF47D)
	II(&B, C, D, A, m.m[1*4:1*4+4], 21, 0x85845DD1)
	II(&A, B, C, D, m.m[8*4:8*4+4], 6, 0x6FA87E4F)
	II(&D, A, B, C, m.m[15*4:15*4+4], 10, 0xFE2CE6E0)
	II(&C, D, A, B, m.m[6*4:6*4+4], 15, 0xA3014314)
	II(&B, C, D, A, m.m[13*4:13*4+4], 21, 0x4E0811A1)
	II(&A, B, C, D, m.m[4*4:4*4+4], 6, 0xF7537E82)
	II(&D, A, B, C, m.m[11*4:11*4+4], 10, 0xBD3AF235)
	II(&C, D, A, B, m.m[2*4:2*4+4], 15, 0x2AD7D2BB)
	II(&B, C, D, A, m.m[9*4:9*4+4], 21, 0xEB86D391)

	m.digest[0] += A
	m.digest[1] += B
	m.digest[2] += C
	m.digest[3] += D
}

// Update adds more data to the hash.
func (m *MD5MAC) Update(input []byte) {

	var (
		length = uint32(len(input))
	)

	m.count += length

	m.buffer = append(m.buffer[m.position:], input...)

	if m.position+length >= BLOCKSIZE {

		m.hash(m.buffer[:])

		input = input[BLOCKSIZE-m.position:]
		length -= BLOCKSIZE - m.position

		for length >= BLOCKSIZE {

			m.hash(input)

			input = input[BLOCKSIZE:]
			length -= BLOCKSIZE
		}

		m.buffer = input
		m.position = 0
	}

	m.position += length
}

func (m *MD5MAC) Finalize(output []byte) {

	var (
		// we will append 0x80 in a second
		bufferSize int

		bufferPadding []byte
	)

	m.buffer = append(m.buffer, 0x80)

	bufferSize = len(m.buffer)
	bufferPadding = bytes.Repeat([]byte{0x0}, BLOCKSIZE-bufferSize)

	m.buffer = append(m.buffer, bufferPadding...)

	// skip cleaning, we just padded with zeros

	if m.position >= BLOCKSIZE-8 {
		m.hash(m.buffer[:])
		m.clearBuffer()
	}

	for j := BLOCKSIZE - 8; j != BLOCKSIZE; j++ {
		m.buffer[j] = byte((8 * m.count) >> (uint(j%8) * 8))
	}

	m.hash(m.buffer)
	m.hash(m.k3[:])

	for j := 0; j != MACLENGTH; j++ {
		output[j] = byte(m.digest[j/4] >> ((j % 4) * 8))
	}

	m.count = 0
	m.position = 0

	m.digest = m.k1
}

func (m *MD5MAC) UpdateFinalize(input []byte) (output []byte) {

	output = make([]byte, MACLENGTH)

	m.Update(input)
	m.Finalize(output)

	return
}

var (
	T = [3][16]byte{
		{0x97, 0xEF, 0x45, 0xAC, 0x29, 0x0F, 0x43, 0xCD, 0x45, 0x7E, 0x1B, 0x55, 0x1C, 0x80, 0x11, 0x34},
		{0xB1, 0x77, 0xCE, 0x96, 0x2E, 0x72, 0x8E, 0x7C, 0x5F, 0x5A, 0xAB, 0x0A, 0x36, 0x43, 0xBE, 0x18},
		{0x9D, 0x21, 0xB4, 0x21, 0xBC, 0x87, 0xB9, 0x4D, 0xA2, 0x9D, 0x27, 0xBD, 0xC7, 0x5B, 0xD7, 0xC3},
	}
)

func convertUint32Slice(data []uint32) []int8 {

	result := make([]int8, len(data)*4)

	for i, value := range data {

		result[i*4+0] = int8(value >> 24)
		result[i*4+1] = int8(value >> 16)
		result[i*4+2] = int8(value >> 8)
		result[i*4+3] = int8(value)
	}

	return result
}

func (m *MD5MAC) SetKey(key []byte) error {

	if len(key) != KEYLENGTH {
		return errors.New("Invalid key length")
	}

	var (
		EK   = make([]uint32, 12)
		data = make([]byte, 128)
	)

	m.clear()

	// copy key to data
	for i := 0; i < 16; i++ {
		data[i] = key[i%KEYLENGTH]
		data[i+112] = key[i%KEYLENGTH]
	}

	// Perform key schedule
	for j := 0; j < 3; j++ {

		m.digest[0] = 0x67452301
		m.digest[1] = 0xEFCDAB89
		m.digest[2] = 0x98BADCFE
		m.digest[3] = 0x10325476

		for k := 16; k < 112; k++ {
			data[k] = T[(j+(k-16)/16)%3][k%16]
		}

		m.hash(data[:])
		m.hash(data[64:])

		EK[4*j] = m.digest[0]
		EK[4*j+1] = m.digest[1]
		EK[4*j+2] = m.digest[2]
		EK[4*j+3] = m.digest[3]
	}

	copy(m.k1[:], EK[:4])
	copy(m.digest[:], EK[:4])
	copy(m.k2[:], EK[4:8])

	ek := convertUint32Slice(EK)

	for j := uint32(0); j < 16; j++ {
		m.k3[j] = byte(ek[(8+j/4)*4+(3-j%4)])
	}

	for j := uint32(16); j < 64; j++ {
		m.k3[j] = m.k3[j%16] ^ T[(j-16)/16][j%16]
	}

	return nil
}

func (m *MD5MAC) clearBuffer() {

	m.buffer = make([]byte, BLOCKSIZE)
}
