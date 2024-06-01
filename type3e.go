package melsec

import (
	"encoding/binary"
	"fmt"
	"reflect"
)

type type3E struct {
	plcType  PlcType  `value:"QnA"`
	commType CommType `value:"binary"`
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
			return nil, fmt.Errorf("unsupported value type: %v", reflect.TypeOf(value))
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
			return nil, fmt.Errorf("unsupported value type: %v", reflect.TypeOf(value))
		}
	}

	return valueByte, nil
}

func (t *type3E) BatchReadBits(device Device, address int, readSize int) {
	//command := 0x0401
	//var subCommand int
	//if t.plcType == PlcTypeIQr {
	//	subCommand = 0x0003
	//} else {
	//	subCommand = 0x0001
	//}
	//
	//var requestData bytes.Buffer
	//
	//requestData = append(requestData, handler.MakeCommandData(command, subCommand)...)
	//requestData = append(requestData, handler.MakeDeviceData(headDevice)...)
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
