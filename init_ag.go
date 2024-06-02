// Code generated by https://github.com/expgo/ag DO NOT EDIT.
// Plugins:
//   - github.com/expgo/enum

package melsec

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// CommTypeBinary is a CommType of type BINARY.
	CommTypeBinary CommType = "BINARY"
	// CommTypeAscii is a CommType of type ASCII.
	CommTypeAscii CommType = "ASCII"
)

const (
	// CommandReadCpuType is a Command of type ReadCpuType.
	CommandReadCpuType Command = iota
	// CommandBatchReadWords is a Command of type BatchReadWords.
	CommandBatchReadWords
	// CommandBatchReadBits is a Command of type BatchReadBits.
	CommandBatchReadBits
	// CommandRandomReadWords is a Command of type RandomReadWords.
	CommandRandomReadWords
	// CommandRandomReadBits is a Command of type RandomReadBits.
	CommandRandomReadBits
	// CommandRemoteRun is a Command of type RemoteRun.
	CommandRemoteRun
	// CommandRemoteStop is a Command of type RemoteStop.
	CommandRemoteStop
	// CommandRemotePause is a Command of type RemotePause.
	CommandRemotePause
	// CommandRemoteLatchClear is a Command of type RemoteLatchClear.
	CommandRemoteLatchClear
	// CommandRemoteReset is a Command of type RemoteReset.
	CommandRemoteReset
	// CommandBatchWriteWords is a Command of type BatchWriteWords.
	CommandBatchWriteWords
	// CommandBatchWriteBits is a Command of type BatchWriteBits.
	CommandBatchWriteBits
	// CommandRandomWriteWords is a Command of type RandomWriteWords.
	CommandRandomWriteWords
	// CommandRandomWriteBits is a Command of type RandomWriteBits.
	CommandRandomWriteBits
	// CommandRemoteUnlock is a Command of type RemoteUnlock.
	CommandRemoteUnlock
	// CommandRemoteLock is a Command of type RemoteLock.
	CommandRemoteLock
	// CommandEchoTest is a Command of type EchoTest.
	CommandEchoTest
)

const (
	// DeviceSm is a Device of type SM.
	DeviceSm Device = iota
	// DeviceSd is a Device of type SD.
	DeviceSd
	// DeviceX is a Device of type X.
	DeviceX
	// DeviceY is a Device of type Y.
	DeviceY
	// DeviceM is a Device of type M.
	DeviceM
	// DeviceL is a Device of type L.
	DeviceL
	// DeviceF is a Device of type F.
	DeviceF
	// DeviceV is a Device of type V.
	DeviceV
	// DeviceB is a Device of type B.
	DeviceB
	// DeviceD is a Device of type D.
	DeviceD
	// DeviceW is a Device of type W.
	DeviceW
	// DeviceTs is a Device of type TS.
	DeviceTs
	// DeviceTc is a Device of type TC.
	DeviceTc
	// DeviceTn is a Device of type TN.
	DeviceTn
	// DeviceSs is a Device of type SS.
	DeviceSs
	// DeviceSc is a Device of type SC.
	DeviceSc
	// DeviceSn is a Device of type SN.
	DeviceSn
	// DeviceCs is a Device of type CS.
	DeviceCs
	// DeviceCc is a Device of type CC.
	DeviceCc
	// DeviceCn is a Device of type CN.
	DeviceCn
	// DeviceSb is a Device of type SB.
	DeviceSb
	// DeviceSw is a Device of type SW.
	DeviceSw
	// DeviceDx is a Device of type DX.
	DeviceDx
	// DeviceDy is a Device of type DY.
	DeviceDy
	// DeviceR is a Device of type R.
	DeviceR
	// DeviceZr is a Device of type ZR.
	DeviceZr
)

const (
	// PlcTypeQ is a PlcType of type Q.
	PlcTypeQ PlcType = iota
	// PlcTypeL is a PlcType of type L.
	PlcTypeL
	// PlcTypeQnA is a PlcType of type QnA.
	PlcTypeQnA
	// PlcTypeIQl is a PlcType of type iQ-L.
	PlcTypeIQl
	// PlcTypeIQr is a PlcType of type iQ-R.
	PlcTypeIQr
)

const (
	// TcpStateUnknown is a TcpState of type Unknown.
	TcpStateUnknown TcpState = iota
	// TcpStateConnecting is a TcpState of type Connecting.
	TcpStateConnecting
	// TcpStateConnected is a TcpState of type Connected.
	TcpStateConnected
	// TcpStateDisconnected is a TcpState of type Disconnected.
	TcpStateDisconnected
	// TcpStateConnectClosed is a TcpState of type ConnectClosed.
	TcpStateConnectClosed
)

var ErrInvalidCommType = errors.New("not a valid CommType")

var _CommTypeNameMap = map[string]CommType{
	"BINARY": CommTypeBinary,
	"binary": CommTypeBinary,
	"ASCII":  CommTypeAscii,
	"ascii":  CommTypeAscii,
}

// Name is the attribute of CommType.
func (x CommType) Name() string {
	if v, ok := _CommTypeNameMap[string(x)]; ok {
		return string(v)
	}
	return fmt.Sprintf("CommType(%s).Name", string(x))
}

var _CommTypeMapWordSize = map[CommType]uint16{
	CommTypeBinary: 2,
	CommTypeAscii:  4,
}

// WordSize is the attribute of CommType.
func (x CommType) WordSize() uint16 {
	if v, ok := _CommTypeMapWordSize[x]; ok {
		return v
	}
	return 0
}

// Val is the attribute of CommType.
func (x CommType) Val() string {
	return string(x)
}

// IsValid provides a quick way to determine if the typed value is
// part of the allowed enumerated values
func (x CommType) IsValid() bool {
	_, ok := _CommTypeNameMap[string(x)]
	return ok
}

// String implements the Stringer interface.
func (x CommType) String() string {
	return x.Name()
}

// ParseCommType converts a string to a CommType.
func ParseCommType(value string) (CommType, error) {
	if x, ok := _CommTypeNameMap[value]; ok {
		return x, nil
	}
	if x, ok := _CommTypeNameMap[strings.ToLower(value)]; ok {
		return x, nil
	}
	return "", fmt.Errorf("%s is %w", value, ErrInvalidCommType)
}

// MarshalText implements the text marshaller method.
func (x CommType) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *CommType) UnmarshalText(text []byte) error {
	val, err := ParseCommType(string(text))
	if err != nil {
		return err
	}
	*x = val
	return nil
}

var ErrInvalidCommand = errors.New("not a valid Command")

var _CommandName = "ReadCpuTypeBatchReadWordsBatchReadBitsRandomReadWordsRandomReadBitsRemoteRunRemoteStopRemotePauseRemoteLatchClearRemoteResetBatchWriteWordsBatchWriteBitsRandomWriteWordsRandomWriteBitsRemoteUnlockRemoteLockEchoTest"

var _CommandMapName = map[Command]string{
	CommandReadCpuType:      _CommandName[0:11],
	CommandBatchReadWords:   _CommandName[11:25],
	CommandBatchReadBits:    _CommandName[25:38],
	CommandRandomReadWords:  _CommandName[38:53],
	CommandRandomReadBits:   _CommandName[53:67],
	CommandRemoteRun:        _CommandName[67:76],
	CommandRemoteStop:       _CommandName[76:86],
	CommandRemotePause:      _CommandName[86:97],
	CommandRemoteLatchClear: _CommandName[97:113],
	CommandRemoteReset:      _CommandName[113:124],
	CommandBatchWriteWords:  _CommandName[124:139],
	CommandBatchWriteBits:   _CommandName[139:153],
	CommandRandomWriteWords: _CommandName[153:169],
	CommandRandomWriteBits:  _CommandName[169:184],
	CommandRemoteUnlock:     _CommandName[184:196],
	CommandRemoteLock:       _CommandName[196:206],
	CommandEchoTest:         _CommandName[206:214],
}

// Name is the attribute of Command.
func (x Command) Name() string {
	if v, ok := _CommandMapName[x]; ok {
		return v
	}
	return fmt.Sprintf("Command(%d).Name", x)
}

var _CommandMapCommand = map[Command]int16{
	CommandReadCpuType:      257,
	CommandBatchReadWords:   1025,
	CommandBatchReadBits:    1025,
	CommandRandomReadWords:  1027,
	CommandRandomReadBits:   1027,
	CommandRemoteRun:        4097,
	CommandRemoteStop:       4098,
	CommandRemotePause:      4099,
	CommandRemoteLatchClear: 4101,
	CommandRemoteReset:      4102,
	CommandBatchWriteWords:  5121,
	CommandBatchWriteBits:   5121,
	CommandRandomWriteWords: 5122,
	CommandRandomWriteBits:  5122,
	CommandRemoteUnlock:     5680,
	CommandRemoteLock:       5681,
	CommandEchoTest:         1561,
}

// Command is the attribute of Command.
func (x Command) Command() int16 {
	if v, ok := _CommandMapCommand[x]; ok {
		return v
	}
	return 0
}

var _CommandMapDefaultSubCommand = map[Command]int16{
	CommandReadCpuType:      0,
	CommandBatchReadWords:   0,
	CommandBatchReadBits:    1,
	CommandRandomReadWords:  0,
	CommandRandomReadBits:   1,
	CommandRemoteRun:        0,
	CommandRemoteStop:       0,
	CommandRemotePause:      0,
	CommandRemoteLatchClear: 0,
	CommandRemoteReset:      0,
	CommandBatchWriteWords:  0,
	CommandBatchWriteBits:   1,
	CommandRandomWriteWords: 0,
	CommandRandomWriteBits:  1,
	CommandRemoteUnlock:     0,
	CommandRemoteLock:       0,
	CommandEchoTest:         0,
}

// DefaultSubCommand is the attribute of Command.
func (x Command) DefaultSubCommand() int16 {
	if v, ok := _CommandMapDefaultSubCommand[x]; ok {
		return v
	}
	return 0
}

// Val is the attribute of Command.
func (x Command) Val() int16 {
	return int16(x)
}

// IsValid provides a quick way to determine if the typed value is
// part of the allowed enumerated values
func (x Command) IsValid() bool {
	_, ok := _CommandMapName[x]
	return ok
}

// String implements the Stringer interface.
func (x Command) String() string {
	return x.Name()
}

var _CommandNameMap = map[string]Command{
	_CommandName[0:11]:                     CommandReadCpuType,
	strings.ToLower(_CommandName[0:11]):    CommandReadCpuType,
	_CommandName[11:25]:                    CommandBatchReadWords,
	strings.ToLower(_CommandName[11:25]):   CommandBatchReadWords,
	_CommandName[25:38]:                    CommandBatchReadBits,
	strings.ToLower(_CommandName[25:38]):   CommandBatchReadBits,
	_CommandName[38:53]:                    CommandRandomReadWords,
	strings.ToLower(_CommandName[38:53]):   CommandRandomReadWords,
	_CommandName[53:67]:                    CommandRandomReadBits,
	strings.ToLower(_CommandName[53:67]):   CommandRandomReadBits,
	_CommandName[67:76]:                    CommandRemoteRun,
	strings.ToLower(_CommandName[67:76]):   CommandRemoteRun,
	_CommandName[76:86]:                    CommandRemoteStop,
	strings.ToLower(_CommandName[76:86]):   CommandRemoteStop,
	_CommandName[86:97]:                    CommandRemotePause,
	strings.ToLower(_CommandName[86:97]):   CommandRemotePause,
	_CommandName[97:113]:                   CommandRemoteLatchClear,
	strings.ToLower(_CommandName[97:113]):  CommandRemoteLatchClear,
	_CommandName[113:124]:                  CommandRemoteReset,
	strings.ToLower(_CommandName[113:124]): CommandRemoteReset,
	_CommandName[124:139]:                  CommandBatchWriteWords,
	strings.ToLower(_CommandName[124:139]): CommandBatchWriteWords,
	_CommandName[139:153]:                  CommandBatchWriteBits,
	strings.ToLower(_CommandName[139:153]): CommandBatchWriteBits,
	_CommandName[153:169]:                  CommandRandomWriteWords,
	strings.ToLower(_CommandName[153:169]): CommandRandomWriteWords,
	_CommandName[169:184]:                  CommandRandomWriteBits,
	strings.ToLower(_CommandName[169:184]): CommandRandomWriteBits,
	_CommandName[184:196]:                  CommandRemoteUnlock,
	strings.ToLower(_CommandName[184:196]): CommandRemoteUnlock,
	_CommandName[196:206]:                  CommandRemoteLock,
	strings.ToLower(_CommandName[196:206]): CommandRemoteLock,
	_CommandName[206:214]:                  CommandEchoTest,
	strings.ToLower(_CommandName[206:214]): CommandEchoTest,
}

// ParseCommand converts a string to a Command.
func ParseCommand(value string) (Command, error) {
	if x, ok := _CommandNameMap[value]; ok {
		return x, nil
	}
	if x, ok := _CommandNameMap[strings.ToLower(value)]; ok {
		return x, nil
	}
	return Command(0), fmt.Errorf("%s is %w", value, ErrInvalidCommand)
}

// MarshalText implements the text marshaller method.
func (x Command) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *Command) UnmarshalText(text []byte) error {
	val, err := ParseCommand(string(text))
	if err != nil {
		return err
	}
	*x = val
	return nil
}

var ErrInvalidDevice = errors.New("not a valid Device")

var _DeviceName = "SMSDXYMLFVBDWTSTCTNSSSCSNCSCCCNSBSWDXDYRZR"

var _DeviceMapName = map[Device]string{
	DeviceSm: _DeviceName[0:2],
	DeviceSd: _DeviceName[2:4],
	DeviceX:  _DeviceName[4:5],
	DeviceY:  _DeviceName[5:6],
	DeviceM:  _DeviceName[6:7],
	DeviceL:  _DeviceName[7:8],
	DeviceF:  _DeviceName[8:9],
	DeviceV:  _DeviceName[9:10],
	DeviceB:  _DeviceName[10:11],
	DeviceD:  _DeviceName[11:12],
	DeviceW:  _DeviceName[12:13],
	DeviceTs: _DeviceName[13:15],
	DeviceTc: _DeviceName[15:17],
	DeviceTn: _DeviceName[17:19],
	DeviceSs: _DeviceName[19:21],
	DeviceSc: _DeviceName[21:23],
	DeviceSn: _DeviceName[23:25],
	DeviceCs: _DeviceName[25:27],
	DeviceCc: _DeviceName[27:29],
	DeviceCn: _DeviceName[29:31],
	DeviceSb: _DeviceName[31:33],
	DeviceSw: _DeviceName[33:35],
	DeviceDx: _DeviceName[35:37],
	DeviceDy: _DeviceName[37:39],
	DeviceR:  _DeviceName[39:40],
	DeviceZr: _DeviceName[40:42],
}

// Name is the attribute of Device.
func (x Device) Name() string {
	if v, ok := _DeviceMapName[x]; ok {
		return v
	}
	return fmt.Sprintf("Device(%d).Name", x)
}

var _DeviceMapCode = map[Device]int{
	DeviceSm: 145,
	DeviceSd: 169,
	DeviceX:  156,
	DeviceY:  157,
	DeviceM:  144,
	DeviceL:  146,
	DeviceF:  147,
	DeviceV:  148,
	DeviceB:  160,
	DeviceD:  168,
	DeviceW:  180,
	DeviceTs: 193,
	DeviceTc: 192,
	DeviceTn: 194,
	DeviceSs: 199,
	DeviceSc: 198,
	DeviceSn: 200,
	DeviceCs: 196,
	DeviceCc: 195,
	DeviceCn: 197,
	DeviceSb: 161,
	DeviceSw: 181,
	DeviceDx: 162,
	DeviceDy: 163,
	DeviceR:  175,
	DeviceZr: 176,
}

// Code is the attribute of Device.
func (x Device) Code() int {
	if v, ok := _DeviceMapCode[x]; ok {
		return v
	}
	return 0
}

// Val is the attribute of Device.
func (x Device) Val() int {
	return int(x)
}

// IsValid provides a quick way to determine if the typed value is
// part of the allowed enumerated values
func (x Device) IsValid() bool {
	_, ok := _DeviceMapName[x]
	return ok
}

// String implements the Stringer interface.
func (x Device) String() string {
	return x.Name()
}

var _DeviceNameMap = map[string]Device{
	_DeviceName[0:2]:                    DeviceSm,
	strings.ToLower(_DeviceName[0:2]):   DeviceSm,
	_DeviceName[2:4]:                    DeviceSd,
	strings.ToLower(_DeviceName[2:4]):   DeviceSd,
	_DeviceName[4:5]:                    DeviceX,
	strings.ToLower(_DeviceName[4:5]):   DeviceX,
	_DeviceName[5:6]:                    DeviceY,
	strings.ToLower(_DeviceName[5:6]):   DeviceY,
	_DeviceName[6:7]:                    DeviceM,
	strings.ToLower(_DeviceName[6:7]):   DeviceM,
	_DeviceName[7:8]:                    DeviceL,
	strings.ToLower(_DeviceName[7:8]):   DeviceL,
	_DeviceName[8:9]:                    DeviceF,
	strings.ToLower(_DeviceName[8:9]):   DeviceF,
	_DeviceName[9:10]:                   DeviceV,
	strings.ToLower(_DeviceName[9:10]):  DeviceV,
	_DeviceName[10:11]:                  DeviceB,
	strings.ToLower(_DeviceName[10:11]): DeviceB,
	_DeviceName[11:12]:                  DeviceD,
	strings.ToLower(_DeviceName[11:12]): DeviceD,
	_DeviceName[12:13]:                  DeviceW,
	strings.ToLower(_DeviceName[12:13]): DeviceW,
	_DeviceName[13:15]:                  DeviceTs,
	strings.ToLower(_DeviceName[13:15]): DeviceTs,
	_DeviceName[15:17]:                  DeviceTc,
	strings.ToLower(_DeviceName[15:17]): DeviceTc,
	_DeviceName[17:19]:                  DeviceTn,
	strings.ToLower(_DeviceName[17:19]): DeviceTn,
	_DeviceName[19:21]:                  DeviceSs,
	strings.ToLower(_DeviceName[19:21]): DeviceSs,
	_DeviceName[21:23]:                  DeviceSc,
	strings.ToLower(_DeviceName[21:23]): DeviceSc,
	_DeviceName[23:25]:                  DeviceSn,
	strings.ToLower(_DeviceName[23:25]): DeviceSn,
	_DeviceName[25:27]:                  DeviceCs,
	strings.ToLower(_DeviceName[25:27]): DeviceCs,
	_DeviceName[27:29]:                  DeviceCc,
	strings.ToLower(_DeviceName[27:29]): DeviceCc,
	_DeviceName[29:31]:                  DeviceCn,
	strings.ToLower(_DeviceName[29:31]): DeviceCn,
	_DeviceName[31:33]:                  DeviceSb,
	strings.ToLower(_DeviceName[31:33]): DeviceSb,
	_DeviceName[33:35]:                  DeviceSw,
	strings.ToLower(_DeviceName[33:35]): DeviceSw,
	_DeviceName[35:37]:                  DeviceDx,
	strings.ToLower(_DeviceName[35:37]): DeviceDx,
	_DeviceName[37:39]:                  DeviceDy,
	strings.ToLower(_DeviceName[37:39]): DeviceDy,
	_DeviceName[39:40]:                  DeviceR,
	strings.ToLower(_DeviceName[39:40]): DeviceR,
	_DeviceName[40:42]:                  DeviceZr,
	strings.ToLower(_DeviceName[40:42]): DeviceZr,
}

// ParseDevice converts a string to a Device.
func ParseDevice(value string) (Device, error) {
	if x, ok := _DeviceNameMap[value]; ok {
		return x, nil
	}
	if x, ok := _DeviceNameMap[strings.ToLower(value)]; ok {
		return x, nil
	}
	return Device(0), fmt.Errorf("%s is %w", value, ErrInvalidDevice)
}

// MarshalText implements the text marshaller method.
func (x Device) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *Device) UnmarshalText(text []byte) error {
	val, err := ParseDevice(string(text))
	if err != nil {
		return err
	}
	*x = val
	return nil
}

var ErrInvalidPlcType = errors.New("not a valid PlcType")

var _PlcTypeName = "QLQnAiQ-LiQ-R"

var _PlcTypeMapName = map[PlcType]string{
	PlcTypeQ:   _PlcTypeName[0:1],
	PlcTypeL:   _PlcTypeName[1:2],
	PlcTypeQnA: _PlcTypeName[2:5],
	PlcTypeIQl: _PlcTypeName[5:9],
	PlcTypeIQr: _PlcTypeName[9:13],
}

// Name is the attribute of PlcType.
func (x PlcType) Name() string {
	if v, ok := _PlcTypeMapName[x]; ok {
		return v
	}
	return fmt.Sprintf("PlcType(%d).Name", x)
}

var _PlcTypeMapNumFmt = map[PlcType]string{
	PlcTypeQ:   "%06d",
	PlcTypeL:   "%06d",
	PlcTypeQnA: "%06d",
	PlcTypeIQl: "%06d",
	PlcTypeIQr: "%08d",
}

// NumFmt is the attribute of PlcType.
func (x PlcType) NumFmt() string {
	if v, ok := _PlcTypeMapNumFmt[x]; ok {
		return v
	}
	return fmt.Sprintf("PlcType(%d).NumFmt", x)
}

// Val is the attribute of PlcType.
func (x PlcType) Val() int {
	return int(x)
}

// IsValid provides a quick way to determine if the typed value is
// part of the allowed enumerated values
func (x PlcType) IsValid() bool {
	_, ok := _PlcTypeMapName[x]
	return ok
}

// String implements the Stringer interface.
func (x PlcType) String() string {
	return x.Name()
}

var _PlcTypeNameMap = map[string]PlcType{
	_PlcTypeName[0:1]:                   PlcTypeQ,
	strings.ToLower(_PlcTypeName[0:1]):  PlcTypeQ,
	_PlcTypeName[1:2]:                   PlcTypeL,
	strings.ToLower(_PlcTypeName[1:2]):  PlcTypeL,
	_PlcTypeName[2:5]:                   PlcTypeQnA,
	strings.ToLower(_PlcTypeName[2:5]):  PlcTypeQnA,
	_PlcTypeName[5:9]:                   PlcTypeIQl,
	strings.ToLower(_PlcTypeName[5:9]):  PlcTypeIQl,
	_PlcTypeName[9:13]:                  PlcTypeIQr,
	strings.ToLower(_PlcTypeName[9:13]): PlcTypeIQr,
}

// ParsePlcType converts a string to a PlcType.
func ParsePlcType(value string) (PlcType, error) {
	if x, ok := _PlcTypeNameMap[value]; ok {
		return x, nil
	}
	if x, ok := _PlcTypeNameMap[strings.ToLower(value)]; ok {
		return x, nil
	}
	return PlcType(0), fmt.Errorf("%s is %w", value, ErrInvalidPlcType)
}

// MarshalText implements the text marshaller method.
func (x PlcType) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *PlcType) UnmarshalText(text []byte) error {
	val, err := ParsePlcType(string(text))
	if err != nil {
		return err
	}
	*x = val
	return nil
}

var ErrInvalidTcpState = errors.New("not a valid TcpState")

var _TcpStateName = "UnknownConnectingConnectedDisconnectedConnectClosed"

var _TcpStateMapName = map[TcpState]string{
	TcpStateUnknown:       _TcpStateName[0:7],
	TcpStateConnecting:    _TcpStateName[7:17],
	TcpStateConnected:     _TcpStateName[17:26],
	TcpStateDisconnected:  _TcpStateName[26:38],
	TcpStateConnectClosed: _TcpStateName[38:51],
}

// Name is the attribute of TcpState.
func (x TcpState) Name() string {
	if v, ok := _TcpStateMapName[x]; ok {
		return v
	}
	return fmt.Sprintf("TcpState(%d).Name", x)
}

// Val is the attribute of TcpState.
func (x TcpState) Val() int {
	return int(x)
}

// IsValid provides a quick way to determine if the typed value is
// part of the allowed enumerated values
func (x TcpState) IsValid() bool {
	_, ok := _TcpStateMapName[x]
	return ok
}

// String implements the Stringer interface.
func (x TcpState) String() string {
	return x.Name()
}

var _TcpStateNameMap = map[string]TcpState{
	_TcpStateName[0:7]:                    TcpStateUnknown,
	strings.ToLower(_TcpStateName[0:7]):   TcpStateUnknown,
	_TcpStateName[7:17]:                   TcpStateConnecting,
	strings.ToLower(_TcpStateName[7:17]):  TcpStateConnecting,
	_TcpStateName[17:26]:                  TcpStateConnected,
	strings.ToLower(_TcpStateName[17:26]): TcpStateConnected,
	_TcpStateName[26:38]:                  TcpStateDisconnected,
	strings.ToLower(_TcpStateName[26:38]): TcpStateDisconnected,
	_TcpStateName[38:51]:                  TcpStateConnectClosed,
	strings.ToLower(_TcpStateName[38:51]): TcpStateConnectClosed,
}

// ParseTcpState converts a string to a TcpState.
func ParseTcpState(value string) (TcpState, error) {
	if x, ok := _TcpStateNameMap[value]; ok {
		return x, nil
	}
	if x, ok := _TcpStateNameMap[strings.ToLower(value)]; ok {
		return x, nil
	}
	return TcpState(0), fmt.Errorf("%s is %w", value, ErrInvalidTcpState)
}

// MarshalText implements the text marshaller method.
func (x TcpState) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *TcpState) UnmarshalText(text []byte) error {
	val, err := ParseTcpState(string(text))
	if err != nil {
		return err
	}
	*x = val
	return nil
}
