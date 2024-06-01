package melsec

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"strconv"
)

type type3E struct {
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

func (t *type3E) writeCommandData(w io.Writer, command, subCommand int16) error {
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

func (t *type3E) BatchReadBits(device Device, address int, readSize int16) error {
	command := int16(0x0401)
	var subCommand int16
	if t.plcType == PlcTypeIQr {
		subCommand = 0x0003
	} else {
		subCommand = 0x0001
	}

	var requestData bytes.Buffer
	if err := t.writeCommandData(&requestData, command, subCommand); err != nil {
		return err
	}

	if buf, err := t.makeDeviceData(device, address); err != nil {
		return err
	} else {
		if _, err = requestData.Write(buf); err != nil {
			return err
		}
	}

	// write read size
	if err := t.writeValue(&requestData, readSize); err != nil {
		return err
	}

	return nil
	//requestData = append(requestData, handler.EncodeValue(readSize)...)
	//sendData := handler.MakeSendData(requestData.Bytes())
	//
	//err := handler.Send(sendData)
	//if err != nil {
	//	return nil, err
	//}
	//
	//recvData, err := handler.Recv()
	//if err != nil {
	//	return nil, err
	//}
	//
	//err = handler.CheckCmdAnswer(recvData)
	//if err != nil {
	//	return nil, err
	//}
	//
	//bitValues := make([]int, 0)
	//if handler.Commtype == commtypeBinary {
	//	for i := 0; i < readSize; i++ {
	//		dataIndex := i/2 + handler.GetAnswerDataIndex()
	//		value := int(binary.LittleEndian.Uint16(recvData[dataIndex : dataIndex+1]))
	//
	//		var bitvalue int
	//		if i%2 == 0 {
	//			if (value & (1 << 4)) != 0 {
	//				bitvalue = 1
	//			} else {
	//				bitvalue = 0
	//			}
	//		} else {
	//			if (value & (1 << 0)) != 0 {
	//				bitvalue = 1
	//			} else {
	//				bitvalue = 0
	//			}
	//		}
	//		bitValues = append(bitValues, bitvalue)
	//	}
	//} else {
	//	dataIndex := handler.GetAnswerDataIndex()
	//	byteRange := 1
	//	for i := 0; i < readSize; i++ {
	//		bitvalue, _ := strconv.Atoi(string(recvData[dataIndex : dataIndex+byteRange]))
	//		bitValues = append(bitValues, bitvalue)
	//		dataIndex += byteRange
	//	}
	//}
	//return bitValues, nil
}

func (t *type3E) BatchReadWords(device Device, address int, readSize int) {

}
