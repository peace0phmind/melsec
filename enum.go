package melsec

import "strings"

// @EnumConfig(Marshal, NoCase)
//go:generate ag

/*
Command : command code

	@Enum(command uint16, defaultSubCommand uint16) {
		ReadCpuType		 (0x0101, 0x0000)
		BatchReadWords   (0x0401, 0x0000)
		BatchReadBits    (0x0401, 0x0001)
		RandomReadWords  (0x0403, 0x0000)
		RandomReadBits   (0x0403, 0x0001)
		RemoteRun   	 (0x1001, 0x0000)
		RemoteStop  	 (0x1002, 0x0000)
		RemotePause 	 (0x1003, 0x0000)
		RemoteLatchClear (0x1005, 0x0000)
		RemoteReset		 (0x1006, 0x0000)
		BatchWriteWords  (0x1401, 0x0000)
		BatchWriteBits   (0x1401, 0x0001)
		RandomWriteWords (0x1402, 0x0000)
		RandomWriteBits  (0x1402, 0x0001)
		RemoteUnlock	 (0x1630, 0x0000)
		RemoteLock		 (0x1631, 0x0000)
		EchoTest		 (0x0619, 0x0000)
	}
*/
type Command int16

func (c Command) SubCommand(plcType PlcType) uint16 {
	if plcType == PlcTypeIQr {
		switch c {
		case CommandBatchReadWords, CommandBatchWriteWords, CommandRandomReadWords, CommandRandomWriteWords:
			return 0x0002
		case CommandBatchReadBits, CommandBatchWriteBits, CommandRandomReadBits, CommandRandomWriteBits:
			return 0x0003
		}
	}

	return c.DefaultSubCommand()
}

/*
PlcType : PLC type. "Q", "L", "QnA", "iQ-L", "iQ-R",

	@Enum(name string, numFmt string){
		Q("Q", "%06d")
		L("L", "%06d")
		QnA("QnA", "%06d")
		iQL("iQ-L", "%06d")
		iQR("iQ-R", "%08d")
	}
*/
type PlcType int

/*
CommType : communication type

	@Enum(wordSize uint16, answerStatus uint16, answerData uint16) {
		BINARY(2, 9, 11)
		ASCII(4, 18, 22)
	}
*/
type CommType string

/*
Device : protocol deveice

	@Enum(code int) {
		SM(0x91)
		SD(0xA9)
		X(0x9C)
		Y(0x9D)
		M(0x90)
		L(0x92)
		F(0x93)
		V(0x94)
		B(0xA0)
		D(0xA8)
		W(0xB4)
		TS(0xC1)
		TC(0xC0)
		TN(0xC2)
		SS(0xC7)
		SC(0xC6)
		SN(0xC8)
		CS(0xC4)
		CC(0xC3)
		CN(0xC5)
		SB(0xA1)
		SW(0xB5)
		DX(0xA2)
		DY(0xA3)
		R(0xAF)
		ZR(0xB0)
	}
*/
type Device int

func (d Device) GetAsciiCode(plcType PlcType) []byte {
	if plcType == PlcTypeIQr {
		return []byte(d.Name() + strings.Repeat("*", 4-len(d.Name())))
	} else {
		return []byte(d.Name() + strings.Repeat("*", 2-len(d.Name())))
	}
}

/*
TcpState : tcp state

	@Enum {
		Unknown
		Connecting
		Connected
		Disconnected
		ConnectClosed
	}
*/
type TcpState int
