package melsec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/expgo/log"
	"io"
	"reflect"
	"strconv"
)

type type3E struct {
	log.InnerLog
	handler       *transporter
	plcType       PlcType  `value:"QnA"`
	commType      CommType `value:"binary"`
	subheader     uint16   `value:"0x5000"`
	network       byte     `value:"0"`
	pc            byte     `value:"0xFF"`
	destModuleIo  uint16   `value:"0x3FF"`
	destModuleSta byte     `value:"0x0"`
	timer         uint16   `value:"4"`
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

func (t *type3E) makeSendDataByCmd(cmd Command, device Device, address int, readSize int16) ([]byte, error) {
	var requestData bytes.Buffer
	if err := t.writeCommandData(&requestData, cmd.Command(), cmd.SubCommand(t.plcType)); err != nil {
		return nil, err
	}

	if buf, err := t.makeDeviceData(device, address); err != nil {
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

	data := t.makeSendData(requestData.Bytes())
	return data, nil
}

var UnsupportedCommand = errors.New("unsupported command")

func (t *type3E) checkCmdAnswer(buf []byte) error {
	var status uint16
	err := t.decodeValue(buf[t.commType.AnswerStatus():t.commType.AnswerStatus()+t.commType.WordSize()], &status)
	if err != nil {
		return err
	}

	switch status {
	case 0:
		return nil
	case 0xC059:
		return UnsupportedCommand
	default:
		return fmt.Errorf("mc protocol error: error code 0x%04X", status)
	}
}

func (t *type3E) BatchReadBits(device Device, address int, readSize int16) ([]int, error) {
	buf, err := t.makeSendDataByCmd(CommandBatchReadBits, device, address, readSize)
	if err != nil {
		t.L.Warn(err)
		return nil, err
	}

	if err = t.checkCmdAnswer(buf); err != nil {
		t.L.Warn(err)
		return nil, err
	}

	bitValues := make([]int, 0)
	answerDataIndex := int(t.commType.AnswerData())
	if t.commType == CommTypeBinary {
		for i := 0; i < int(readSize); i++ {
			dataIndex := i/2 + answerDataIndex
			value := binary.LittleEndian.Uint16(buf[dataIndex : dataIndex+1])

			var bitValue int
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
			bitValue, _ := strconv.Atoi(string(buf[dataIndex : dataIndex+byteRange]))
			bitValues = append(bitValues, bitValue)
			dataIndex += byteRange
		}
	}

	return bitValues, nil
}

func (t *type3E) BatchReadWords(device Device, address int, readSize int16) error {
	return nil
}
