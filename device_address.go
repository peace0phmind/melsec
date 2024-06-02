package melsec

type DeviceAddress struct {
	device  Device
	address int
}

func NewDeviceAddress(device Device, address int) *DeviceAddress {
	return &DeviceAddress{device, address}
}
