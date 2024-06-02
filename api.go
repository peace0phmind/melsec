package melsec

type Type3E interface {
	BatchReadBits(device Device, address int, readSize int16) error
	BatchReadWords(device Device, address int, readSize int16) error
}
