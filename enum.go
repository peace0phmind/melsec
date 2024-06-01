package melsec

import "strings"

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

	@Enum(wordSize uint16) {
		BINARY(2)
		ASCII(4)
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
