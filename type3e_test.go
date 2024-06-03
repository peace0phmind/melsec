package melsec

import (
	"encoding/hex"
	"fmt"
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

func TestMakeSendData(t *testing.T) {
	t3e := factory.New[type3E]()
	buf, e := t3e.makeBatchSendData(CommandBatchReadBits, NewDeviceAddress(DeviceD, 1200), 20)
	assert.NoError(t, e)
	bytes, _ := hex.DecodeString("500000ffff03000c00040001040100b00400a81400")
	assert.Equal(t, bytes, buf)

	buf, e = t3e.makeBatchSendData(CommandBatchReadBits, NewDeviceAddress(DeviceX, 0x123), 16)
	assert.NoError(t, e)
	bytes, _ = hex.DecodeString("500000ffff03000c000400010401002301009c1000")
	assert.Equal(t, bytes, buf)

	buf, e = t3e.makeBatchSendData(CommandBatchReadBits, NewDeviceAddress(DeviceTs, 1234), 8)
	assert.NoError(t, e)
	bytes, _ = hex.DecodeString("500000ffff03000c00040001040100d20400c10800")
	assert.Equal(t, bytes, buf)

	t3e.commType = CommTypeAscii
	buf, e = t3e.makeBatchSendData(CommandBatchReadBits, NewDeviceAddress(DeviceD, 1200), 20)
	assert.NoError(t, e)
	bytes, _ = hex.DecodeString("353030303030464630334646303030303138303030343034303130303031442a30303132303030303134")
	assert.Equal(t, bytes, buf)

	buf, e = t3e.makeBatchSendData(CommandBatchReadBits, NewDeviceAddress(DeviceX, 0x123), 16)
	assert.NoError(t, e)
	bytes, _ = hex.DecodeString("353030303030464630334646303030303138303030343034303130303031582a30303032393130303130")
	assert.Equal(t, bytes, buf)

	buf, e = t3e.makeBatchSendData(CommandBatchReadBits, NewDeviceAddress(DeviceTs, 1234), 8)
	assert.NoError(t, e)
	bytes, _ = hex.DecodeString("353030303030464630334646303030303138303030343034303130303031545330303132333430303038")
	assert.Equal(t, bytes, buf)

	t3e = factory.New[type3E]()
	t3e.plcType = PlcTypeIQr
	buf, e = t3e.makeBatchSendData(CommandBatchReadBits, NewDeviceAddress(DeviceD, 1200), 20)
	assert.NoError(t, e)
	bytes, _ = hex.DecodeString("500000ffff03000e00040001040300b0040000a8001400")
	assert.Equal(t, bytes, buf)

	buf, e = t3e.makeBatchSendData(CommandBatchReadBits, NewDeviceAddress(DeviceX, 0x123), 16)
	assert.NoError(t, e)
	bytes, _ = hex.DecodeString("500000ffff03000e00040001040300230100009c001000")
	assert.Equal(t, bytes, buf)

	buf, e = t3e.makeBatchSendData(CommandBatchReadBits, NewDeviceAddress(DeviceTs, 1234), 8)
	assert.NoError(t, e)
	bytes, _ = hex.DecodeString("500000ffff03000e00040001040300d2040000c1000800")
	assert.Equal(t, bytes, buf)

	t3e.commType = CommTypeAscii
	buf, e = t3e.makeBatchSendData(CommandBatchReadBits, NewDeviceAddress(DeviceD, 1200), 20)
	assert.NoError(t, e)
	bytes, _ = hex.DecodeString("353030303030464630334646303030303143303030343034303130303033442a2a2a303030303132303030303134")
	assert.Equal(t, bytes, buf)

	buf, e = t3e.makeBatchSendData(CommandBatchReadBits, NewDeviceAddress(DeviceX, 0x123), 16)
	assert.NoError(t, e)
	bytes, _ = hex.DecodeString("353030303030464630334646303030303143303030343034303130303033582a2a2a303030303032393130303130")
	assert.Equal(t, bytes, buf)

	buf, e = t3e.makeBatchSendData(CommandBatchReadBits, NewDeviceAddress(DeviceTs, 1234), 8)
	assert.NoError(t, e)
	bytes, _ = hex.DecodeString("35303030303046463033464630303030314330303034303430313030303354532a2a303030303132333430303038")
	assert.Equal(t, bytes, buf)
}

func TestRemote(t *testing.T) {
	transporter := NewTransporter(fmt.Sprintf("%s:%d", "192.168.1.232", 1025))
	_ = transporter.Connect()

	t3e := NewType3E(transporter)
	ret, err := t3e.BatchReadWords(NewDeviceAddress(DeviceD, 0), 1)
	assert.NoError(t, err)
	assert.Equal(t, uint16(23), ret[0])
}
