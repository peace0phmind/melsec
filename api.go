package melsec

type Type3E interface {
	BatchReadBits(deviceAddress *DeviceAddress, readSize int16) ([]byte, error)

	BatchReadWords(deviceAddress *DeviceAddress, readSize int16) ([]uint16, error)

	RandomRead(wordDevices, dwordDevices []*DeviceAddress) ([]uint16, []uint32, error)

	BatchWriteBits(deviceAddress *DeviceAddress, values []byte) error

	BatchWriteWords(deviceAddress *DeviceAddress, values []uint16) error

	RandomWriteBits(bitDevices []*DeviceAddress, values []byte) error

	RandomWrite(wordDevices []*DeviceAddress, wordValues []uint16, dwordDevices []*DeviceAddress, dwordValues []uint32) error
}
