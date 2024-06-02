package melsec

type Type3E interface {
	BatchReadBits(deviceAddress *DeviceAddress, readSize int16) ([]byte, error)

	BatchReadWords(deviceAddress *DeviceAddress, readSize int16) ([]uint16, error)

	RandomRead(wordDevices, dwordDevices []*DeviceAddress) ([]uint16, []uint32, error)
}
