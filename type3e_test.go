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

func TestDecodeValue(t *testing.T) {
	t3e := factory.New[type3E]()
	var int16v int16
	e := t3e.decodeValue([]byte{0xd2, 0x04}, &int16v)
	assert.NoError(t, e)
	assert.Equal(t, int16(1234), int16v)

	var int32v int32
	e = t3e.decodeValue([]byte{0x87, 0xd6, 0x12, 0x00}, &int32v)
	assert.NoError(t, e)
	assert.Equal(t, int32(1234567), int32v)

	t3e.commType = CommTypeAscii
	e = t3e.decodeValue([]byte("04D2"), &int16v)
	assert.NoError(t, e)
	assert.Equal(t, int16(1234), int16v)

	e = t3e.decodeValue([]byte("0012D687"), &int32v)
	assert.NoError(t, e)
	assert.Equal(t, int32(1234567), int32v)
}

func TestMakeDeviceData(t *testing.T) {
	t3e := factory.New[type3E]()
	buf, e := t3e.makeDeviceData(DeviceD, 1000)
	assert.NoError(t, e)
	assert.Equal(t, []byte{0xe8, 0x03, 0x00, 0xa8}, buf)

	buf, e = t3e.makeDeviceData(DeviceX, 17)
	assert.NoError(t, e)
	assert.Equal(t, []byte{0x11, 0x00, 0x00, 0x9c}, buf)

	buf, e = t3e.makeDeviceData(DeviceTs, 1234)
	assert.NoError(t, e)
	assert.Equal(t, []byte{0xd2, 0x04, 0x00, 0xc1}, buf)

	t3e.commType = CommTypeAscii
	buf, e = t3e.makeDeviceData(DeviceD, 1000)
	assert.NoError(t, e)
	assert.Equal(t, []byte("D*001000"), buf)

	buf, e = t3e.makeDeviceData(DeviceX, 17)
	assert.NoError(t, e)
	assert.Equal(t, []byte("X*000017"), buf)

	buf, e = t3e.makeDeviceData(DeviceTs, 1234)
	assert.NoError(t, e)
	assert.Equal(t, []byte("TS001234"), buf)

	t3e = factory.New[type3E]()
	t3e.plcType = PlcTypeIQr
	buf, e = t3e.makeDeviceData(DeviceD, 1000)
	assert.NoError(t, e)
	assert.Equal(t, []byte{0xe8, 0x03, 0x00, 0x00, 0xa8, 0x00}, buf)

	buf, e = t3e.makeDeviceData(DeviceX, 17)
	assert.NoError(t, e)
	assert.Equal(t, []byte{0x11, 0x00, 0x00, 0x00, 0x9c, 0x00}, buf)

	buf, e = t3e.makeDeviceData(DeviceTs, 1234)
	assert.NoError(t, e)
	assert.Equal(t, []byte{0xd2, 0x04, 0x00, 0x00, 0xc1, 0x00}, buf)

	t3e.commType = CommTypeAscii
	buf, e = t3e.makeDeviceData(DeviceD, 1000)
	assert.NoError(t, e)
	assert.Equal(t, []byte("D***00001000"), buf)

	buf, e = t3e.makeDeviceData(DeviceX, 17)
	assert.NoError(t, e)
	assert.Equal(t, []byte("X***00000017"), buf)

	buf, e = t3e.makeDeviceData(DeviceTs, 1234)
	assert.NoError(t, e)
	assert.Equal(t, []byte("TS**00001234"), buf)
}
