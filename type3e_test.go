package melsec

import (
	"github.com/expgo/factory"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncodeValue(t *testing.T) {
	t3e := factory.New[type3E]()
	// test binary
	b, e := t3e.encodeValue(int8(12))
	assert.NoError(t, e)
	assert.Equal(t, []byte{0x0c}, b)

	b, e = t3e.encodeValue(int16(1234))
	assert.NoError(t, e)
	assert.Equal(t, []byte{0xd2, 0x04}, b)

	b, e = t3e.encodeValue(int32(1234567))
	assert.NoError(t, e)
	assert.Equal(t, []byte{0x87, 0xd6, 0x12, 0x00}, b)

	// test ascii
	t3e.commType = CommTypeAscii
	b, e = t3e.encodeValue(int8(12))
	assert.NoError(t, e)
	assert.Equal(t, []byte("0C"), b)

	b, e = t3e.encodeValue(int16(1234))
	assert.NoError(t, e)
	assert.Equal(t, []byte("04D2"), b)

	b, e = t3e.encodeValue(int32(1234567))
	assert.NoError(t, e)
	assert.Equal(t, []byte("0012D687"), b)
}
