package melsec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/expgo/factory"
	"github.com/expgo/log"
	"io"
	"reflect"
	"strconv"
)

var (
	AddressesAndValuesMustBeSameLength = errors.New("addresses and values must be same length")
)

type type3E struct {
	log.InnerLog
	transporter   *Transporter
	plcType       PlcType  `value:"QnA"`
	commType      CommType `value:"binary"`
	subheader     uint16   `value:"0x5000"`
	network       byte     `value:"0"`
	pc            byte     `value:"0xFF"`
	destModuleIo  uint16   `value:"0x3FF"`
	destModuleSta byte     `value:"0x0"`
	timer         uint16   `value:"4"`
}

func NewType3E(transporter *Transporter) Type3E {
	ret := factory.New[type3E]()
	ret.transporter = transporter
	ret.transporter.commType = ret.commType
	return ret
}

func (t *type3E) writeValue(w io.Writer, value any) error {
	if buf, err := t.encodeValue(value); err != nil {
		return err
	} else {
		if _, err = w.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func (t *type3E) encodeValue(value any) ([]byte, error) {
	var valueByte []byte

	if t.commType == CommTypeBinary {
		switch v := value.(type) {
		case int8:
			valueByte = make([]byte, 1)
			valueByte[0] = byte(v)
		case uint8:
			valueByte = make([]byte, 1)
			valueByte[0] = v
		case int16:
			valueByte = make([]byte, 2)
			binary.LittleEndian.PutUint16(valueByte, uint16(v))
		case uint16:
			valueByte = make([]byte, 2)
			binary.LittleEndian.PutUint16(valueByte, v)
		case int32:
			valueByte = make([]byte, 4)
			binary.LittleEndian.PutUint32(valueByte, uint32(v))
		case uint32:
			valueByte = make([]byte, 4)
			binary.LittleEndian.PutUint32(valueByte, v)
		default:
			return nil, fmt.Errorf("encode unsupported value type: %v", reflect.TypeOf(value))
		}
	} else {
		switch v := value.(type) {
		case int8, uint8:
			valueByte = []byte(fmt.Sprintf("%02X", v))
		case int16, uint16:
			valueByte = []byte(fmt.Sprintf("%04X", value))
		case int32, uint32:
			valueByte = []byte(fmt.Sprintf("%08X", value))
		default:
			return nil, fmt.Errorf("encode unsupported value type: %v", reflect.TypeOf(value))
		}
	}

	return valueByte, nil
}

func (t *type3E) decodeValue(buf []byte, value any) error {
	if t.commType == CommTypeBinary {
		switch v := value.(type) {
		case *int16:
			*v = int16(binary.LittleEndian.Uint16(buf))
		case *uint16:
			*v = binary.LittleEndian.Uint16(buf)
		case *int32:
			*v = int32(binary.LittleEndian.Uint32(buf))
		case *uint32:
			*v = binary.LittleEndian.Uint32(buf)
		default:
			return fmt.Errorf("decode unsupported value type: %v", reflect.TypeOf(value))
		}
	} else {
		switch v := value.(type) {
		case *int16:
			if ret, err := strconv.ParseInt(string(buf), 16, 16); err != nil {
				return err
			} else {
				*v = int16(ret)
			}
		case *uint16:
			if ret, err := strconv.ParseUint(string(buf), 16, 16); err != nil {
				return err
			} else {
				*v = uint16(ret)
			}
		case *int32:
			if ret, err := strconv.ParseInt(string(buf), 16, 32); err != nil {
				return err
			} else {
				*v = int32(ret)
			}
		case *uint32:
			if ret, err := strconv.ParseUint(string(buf), 16, 32); err != nil {
				return err
			} else {
				*v = uint32(ret)
			}
		default:
			return fmt.Errorf("decode unsupported value type: %v", reflect.TypeOf(value))
		}
	}

	return nil
}

func (t *type3E) writeCommandData(w io.Writer, command, subCommand uint16) error {
	if err := t.writeValue(w, command); err != nil {
		return err
	} else {
		return t.writeValue(w, subCommand)
	}
}

func (t *type3E) makeDeviceData(device Device, address int) ([]byte, error) {
	if t.commType == CommTypeBinary {
		buf, err := t.encodeValue(int32(address))
		if err != nil {
			return nil, err
		}

		if t.plcType != PlcTypeIQr {
			buf = buf[:3]
		}

		buf = append(buf, byte(device.Code()))
		if t.plcType == PlcTypeIQr {
			buf = append(buf, 0x0)
		}

		return buf, nil
	} else {
		buf := device.GetAsciiCode(t.plcType)
		tt := fmt.Sprintf(t.plcType.NumFmt(), address)
		buf = append(buf, []byte(tt)...)

		return buf, nil
	}
}

func (t *type3E) makeSendData(buf []byte) []byte {
	var data bytes.Buffer
	if t.commType == CommTypeBinary {
		_ = binary.Write(&data, binary.BigEndian, t.subheader)
	} else {
		data.Write([]byte(fmt.Sprintf("%x", t.subheader)))
	}

	_ = t.writeValue(&data, t.network)
	_ = t.writeValue(&data, t.pc)
	_ = t.writeValue(&data, t.destModuleIo)
	_ = t.writeValue(&data, t.destModuleSta)
	// add self.timer size
	_ = t.writeValue(&data, t.commType.WordSize()+uint16(len(buf)))
	_ = t.writeValue(&data, t.timer)

	data.Write(buf)

	return data.Bytes()
}

func (t *type3E) makeCommandData(cmd Command, deviceAddress *DeviceAddress, readSize int16) ([]byte, error) {
	var requestData bytes.Buffer
	if err := t.writeCommandData(&requestData, cmd.Command(), cmd.SubCommand(t.plcType)); err != nil {
		return nil, err
	}

	if buf, err := t.makeDeviceData(deviceAddress.device, deviceAddress.address); err != nil {
		return nil, err
	} else {
		if _, err = requestData.Write(buf); err != nil {
			return nil, err
		}
	}

	// write read size
	if err := t.writeValue(&requestData, readSize); err != nil {
		return nil, err
	}

	return requestData.Bytes(), nil
}

var UnsupportedCommand = errors.New("unsupported command")

func (t *type3E) BatchReadBits(deviceAddress *DeviceAddress, readSize int16) ([]byte, error) {
	req, err := t.makeCommandData(CommandBatchReadBits, deviceAddress, readSize)
	if err != nil {
		t.L.Warn(err)
		return nil, err
	}

	req = t.makeSendData(req)

	dataSize := (int(readSize) + 1) / 2
	if t.commType == CommTypeAscii {
		dataSize = int(readSize)
	}

	resp, err := t.transporter.Send(req, dataSize)
	if err != nil {
		t.L.Warn(err)
		return nil, err
	}

	bitValues := make([]byte, 0)
	answerDataIndex := int(t.commType.AnswerData())
	if t.commType == CommTypeBinary {
		for i := 0; i < int(readSize); i++ {
			dataIndex := i/2 + answerDataIndex
			value := resp[dataIndex]

			var bitValue byte
			if i%2 == 0 {
				if (value & (1 << 4)) != 0 {
					bitValue = 1
				} else {
					bitValue = 0
				}
			} else {
				if (value & (1 << 0)) != 0 {
					bitValue = 1
				} else {
					bitValue = 0
				}
			}
			bitValues = append(bitValues, bitValue)
		}
	} else {
		dataIndex := answerDataIndex
		byteRange := 1
		for i := 0; i < int(readSize); i++ {
			bitValue, _ := strconv.Atoi(string(resp[dataIndex : dataIndex+byteRange]))
			bitValues = append(bitValues, byte(bitValue))
			dataIndex += byteRange
		}
	}

	return bitValues, nil
}

func (t *type3E) BatchReadWords(deviceAddress *DeviceAddress, readSize int16) ([]uint16, error) {
	req, err := t.makeCommandData(CommandBatchReadWords, deviceAddress, readSize)
	if err != nil {
		t.L.Warn(err)
		return nil, err
	}

	req = t.makeSendData(req)

	resp, err := t.transporter.Send(req, int(t.commType.WordSize())*int(readSize))
	if err != nil {
		t.L.Warn(err)
		return nil, err
	}

	wordValues := make([]uint16, 0)
	dataIndex := t.commType.AnswerData()
	for i := 0; i < int(readSize); i++ {
		var wordValue uint16
		if err = t.decodeValue(resp[dataIndex:dataIndex+t.commType.WordSize()], &wordValue); err != nil {
			t.L.Warn(err)
			return nil, err
		}
		wordValues = append(wordValues, wordValue)
		dataIndex += t.commType.WordSize()
	}

	return wordValues, nil
}

func (t *type3E) writeDeviceData(w io.Writer, deviceAddress *DeviceAddress) error {
	buf, err := t.makeDeviceData(deviceAddress.device, deviceAddress.address)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

func (t *type3E) RandomRead(wordDevices, dwordDevices []*DeviceAddress) ([]uint16, []uint32, error) {
	var requestData bytes.Buffer
	if err := t.writeCommandData(&requestData, CommandRandomRead.Command(), CommandRandomRead.SubCommand(t.plcType)); err != nil {
		return nil, nil, err
	}

	wordLen := len(wordDevices)
	dwordLen := len(dwordDevices)
	_ = t.writeValue(&requestData, byte(wordLen))
	_ = t.writeValue(&requestData, byte(dwordLen))
	for _, wordDevice := range wordDevices {
		if err := t.writeDeviceData(&requestData, wordDevice); err != nil {
			return nil, nil, err
		}
	}
	for _, dwordDevice := range dwordDevices {
		if err := t.writeDeviceData(&requestData, dwordDevice); err != nil {
			return nil, nil, err
		}
	}

	req := t.makeSendData(requestData.Bytes())

	resp, err := t.transporter.Send(req, (wordLen+2*dwordLen)*int(t.commType.WordSize()))
	if err != nil {
		t.L.Warn(err)
		return nil, nil, err
	}

	dataIndex := t.commType.AnswerData()
	wordSize := t.commType.WordSize()

	wordValues := []uint16{}
	dwordValues := []uint32{}

	for range wordDevices {
		var wordValue uint16
		if err = t.decodeValue(resp[dataIndex:dataIndex+wordSize], &wordValue); err != nil {
			return nil, nil, err
		}
		wordValues = append(wordValues, wordValue)
		dataIndex += wordSize
	}
	for range dwordDevices {
		var dwordValue uint32
		if err = t.decodeValue(resp[dataIndex:dataIndex+wordSize*2], &dwordValue); err != nil {
			return nil, nil, err
		}
		dwordValues = append(dwordValues, dwordValue)
		dataIndex += wordSize * 2
	}

	return wordValues, dwordValues, nil
}

func (t *type3E) BatchWriteBits(deviceAddress *DeviceAddress, values []byte) error {
	req, err := t.makeCommandData(CommandBatchWriteBits, deviceAddress, int16(len(values)))
	if err != nil {
		t.L.Warn(err)
		return err
	}

	if t.commType == CommTypeBinary {
		bitData := make([]byte, (len(values)+1)/2)
		for idx, value := range values {
			valueIndex := idx / 2
			var bitIndex uint
			if idx%2 == 0 {
				bitIndex = 4
			} else {
				bitIndex = 0
			}

			bitValue := value << bitIndex
			bitData[valueIndex] |= bitValue
		}

		req = append(req, bitData...)
	} else {
		for _, value := range values {
			req = append(req, []byte(strconv.Itoa(int(value)))...)
		}
	}

	req = t.makeSendData(req)

	_, err = t.transporter.Send(req, 0)
	if err != nil {
		t.L.Warn(err)
		return err
	}

	return nil
}

func (t *type3E) BatchWriteWords(deviceAddress *DeviceAddress, values []uint16) error {
	req, err := t.makeCommandData(CommandBatchWriteWords, deviceAddress, int16(len(values)))
	if err != nil {
		t.L.Warn(err)
		return err
	}

	for _, value := range values {
		data, err := t.encodeValue(value)
		if err != nil {
			return err
		}
		req = append(req, data...)
	}

	req = t.makeSendData(req)

	_, err = t.transporter.Send(req, 0)
	if err != nil {
		t.L.Warn(err)
		return err
	}

	return nil
}

func (t *type3E) RandomWriteBits(bitDevices []*DeviceAddress, values []byte) error {
	if len(bitDevices) != len(values) {
		return AddressesAndValuesMustBeSameLength
	}

	var requestData bytes.Buffer
	if err := t.writeCommandData(&requestData, CommandRandomWriteBits.Command(), CommandRandomWriteBits.SubCommand(t.plcType)); err != nil {
		return err
	}

	// write value len
	if err := t.writeValue(&requestData, byte(len(values))); err != nil {
		return err
	}

	for i, value := range values {
		bitDevice := bitDevices[i]
		err := t.writeDeviceData(&requestData, bitDevice)
		if err != nil {
			return err
		}

		if t.plcType == PlcTypeIQr {
			err = t.writeValue(&requestData, uint16(value))
		} else {
			err = t.writeValue(&requestData, value)
		}
		if err != nil {
			return err
		}
	}

	req := requestData.Bytes()

	req = t.makeSendData(req)

	_, err := t.transporter.Send(req, 0)
	if err != nil {
		t.L.Warn(err)
		return err
	}

	return nil
}

func (t *type3E) RandomWrite(wordDevices []*DeviceAddress, wordValues []uint16, dwordDevices []*DeviceAddress, dwordValues []uint32) error {
	if len(wordDevices) != len(wordValues) {
		return AddressesAndValuesMustBeSameLength
	}

	if len(dwordDevices) != len(dwordValues) {
		return AddressesAndValuesMustBeSameLength
	}

	wordSize := len(wordDevices)
	dwordSize := len(dwordDevices)

	var requestData bytes.Buffer
	if err := t.writeCommandData(&requestData, CommandRandomWrite.Command(), CommandRandomWrite.SubCommand(t.plcType)); err != nil {
		return err
	}

	err := t.writeValue(&requestData, byte(wordSize))
	if err != nil {
		return err
	}

	err = t.writeValue(&requestData, byte(dwordSize))
	if err != nil {
		return err
	}

	for i, value := range wordValues {
		err = t.writeDeviceData(&requestData, wordDevices[i])
		if err != nil {
			return err
		}

		err = t.writeValue(&requestData, value)
		if err != nil {
			return err
		}
	}

	for i, value := range dwordValues {
		err = t.writeDeviceData(&requestData, dwordDevices[i])
		if err != nil {
			return err
		}

		err = t.writeValue(&requestData, value)
		if err != nil {
			return err
		}
	}

	req := requestData.Bytes()

	req = t.makeSendData(req)

	_, err = t.transporter.Send(req, 0)
	if err != nil {
		t.L.Warn(err)
		return err
	}

	return nil
}
