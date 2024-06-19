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
		RandomRead       (0x0403, 0x0000)
		RemoteRun   	 (0x1001, 0x0000)
		RemoteStop  	 (0x1002, 0x0000)
		RemotePause 	 (0x1003, 0x0000)
		RemoteLatchClear (0x1005, 0x0000)
		RemoteReset		 (0x1006, 0x0000)
		BatchWriteWords  (0x1401, 0x0000)
		BatchWriteBits   (0x1401, 0x0001)
		RandomWrite      (0x1402, 0x0000)
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
		case CommandBatchReadWords, CommandBatchWriteWords, CommandRandomRead, CommandRandomWrite:
			return 0x0002
		case CommandBatchReadBits, CommandBatchWriteBits, CommandRandomWriteBits:
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

	@Enum(code int, isBit bool) {
		SM(0x91, true)		// 特殊继电器, bit, 10
		SD(0xA9, false)		// 特殊寄存器, word, 10
		X(0x9C, true)		// 输入, bit, 16
		Y(0x9D, true)		// 输出, bit, 16
		M(0x90, true)		// 内部继电器, bit, 10
		L(0x92, true)		// 锁存继电器, bit, 10
		F(0x93, true)		// 报警器, bit, 10
		V(0x94, true)		// 变址继电器, bit, 10
		B(0xA0, true)		// 链接继电器, bit, 16
		D(0xA8, false)		// 数据寄存器, word, 10
		W(0xB4, false)		// 链接寄存器, word, 16
		TS(0xC1, true)		// 定时器, 触点 bit, 10
		TC(0xC0, true)		// 定时器, 线圈 bit, 10
		TN(0xC2, false)		// 定时器当前值 word, 10
		SS(0xC7, true)		// 累计定时器, 触点 bit, 10
		SC(0xC6, true)		// 累计定时器, 线圈 bit, 10
		SN(0xC8, false)		// 累计定时器当前值 word, 10
		CS(0xC4, true)		// 计数器, 触点 bit, 10
		CC(0xC3, true)		// 计数器, 线圈 bit, 10
		CN(0xC5, false)		// 计数器当前值 word, 10
		SB(0xA1, true)		// 链接特殊继电器 bit, 16
		SW(0xB5, false)		// 链接特殊寄存器 word, 16
		DX(0xA2, true)		// 直接访问输入 bit, 16
		DY(0xA3, true)		// 直接访问输出 bit, 16
		R(0xAF, false)		// 文件寄存器, 块切换方式 word, 10
		ZR(0xB0, false)		// 文件寄存器, 连号访问方式 word, 16
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
