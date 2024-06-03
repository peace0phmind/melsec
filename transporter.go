package melsec

import (
	"encoding/binary"
	"fmt"
	"github.com/expgo/factory"
	"github.com/expgo/log"
	"io"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"
)

// Transporter implements Transporter interface.
type Transporter struct {
	log.InnerLog
	Address              string        // Connect string
	Timeout              time.Duration `value:"10s"` // Connect & Read timeout
	IdleTimeout          time.Duration `value:"60s"` // Idle timeout to close the connection
	ReconnectionInterval time.Duration `value:"10s"` // reconnection interval
	RecvBufSize          int           `value:"4096"`

	StateChangeCallback func(oldState, newState TcpState)

	// TCP connection
	mu             sync.Mutex
	conn           net.Conn
	closeTimer     *time.Timer
	reconnectTimer *time.Timer
	lastActivity   time.Time

	state    TcpState
	commType CommType
}

func NewTransporter(address string) *Transporter {
	ret := factory.New[Transporter]()
	ret.Address = address
	return ret
}

func (t *Transporter) CheckState() error {
	if t.state == TcpStateConnected || t.state == TcpStateConnectClosed {
		return nil
	}

	return fmt.Errorf("check state error: Transporter state is %s", t.state)
}

func (t *Transporter) checkCmdAnswer(buf []byte) error {
	var status uint16
	err := t.decodeValue(buf[t.commType.AnswerStatus():t.commType.AnswerStatus()+t.commType.WordSize()], &status)
	if err != nil {
		return err
	}

	switch status {
	case 0:
		return nil
	case 0xC059:
		return UnsupportedCommand
	default:
		return fmt.Errorf("mc protocol error: error code 0x%04X", status)
	}
}

func (t *Transporter) decodeValue(buf []byte, value any) error {
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

// Send sends data to server and ensures response length is greater than header length.
func (t *Transporter) Send(request []byte, dataSize int) (response []byte, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Establish a new connection if not connected
	if err = t.connect(); err != nil {
		return
	}
	// Set timer to close when idle
	t.lastActivity = time.Now()
	t.startCloseTimer()
	// Set write and read timeout
	var timeout time.Time
	if t.Timeout > 0 {
		timeout = t.lastActivity.Add(t.Timeout)
	}
	if err = t.conn.SetDeadline(timeout); err != nil {
		t.setState(TcpStateDisconnected)
		return
	}
	// Send data
	t.L.Debugf("sending %x", request)
	if _, err = t.conn.Write(request); err != nil {
		t.setState(TcpStateDisconnected)
		t.L.Error(err)
		return
	}

	header := make([]byte, t.commType.AnswerStatus()+t.commType.WordSize())

	if _, err = io.ReadFull(t.conn, header); err != nil {
		t.setState(TcpStateDisconnected)
		t.L.Error(err)
		return
	}

	if err = t.checkCmdAnswer(header); err != nil {
		errBuf := make([]byte, 9)
		if _, err1 := io.ReadFull(t.conn, errBuf); err1 != nil {
			t.setState(TcpStateDisconnected)
			t.L.Error(err1)
			return nil, err1
		}
		// skip 9 byte
		return
	}

	response = make([]byte, dataSize)
	if _, err = io.ReadFull(t.conn, response); err != nil {
		t.setState(TcpStateDisconnected)
		t.L.Error(err)
		return
	}

	response = append(header, response...)

	return
}

// Connect establishes a new connection to the address in Address.
// Connect and Close are exported so that multiple requests can be done with one session
func (t *Transporter) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.connect()
}

func (t *Transporter) setState(state TcpState) {
	if state == TcpStateDisconnected {
		t.close()
		t.startReconnectTimer()
	}

	if t.StateChangeCallback != nil {
		t.StateChangeCallback(t.state, state)
	}

	t.L.Infof("%s state change, old state: %s, new state: %s", t.Address, t.state, state)

	t.state = state
}

func (t *Transporter) connect() error {
	if t.state == TcpStateConnected {
		return nil
	}

	if t.conn == nil {
		t.setState(TcpStateConnecting)

		dialer := net.Dialer{Timeout: t.Timeout}
		conn, err := dialer.Dial("tcp", t.Address)
		if err != nil {
			t.setState(TcpStateDisconnected)
			return err
		}
		t.conn = conn

		t.setState(TcpStateConnected)
	}

	return nil
}

func (t *Transporter) startCloseTimer() {
	if t.IdleTimeout <= 0 {
		return
	}
	if t.closeTimer == nil {
		t.closeTimer = time.AfterFunc(t.IdleTimeout, t.closeIdle)
	} else {
		t.closeTimer.Reset(t.IdleTimeout)
	}
}

func (t *Transporter) startReconnectTimer() {
	if t.ReconnectionInterval <= 0 {
		return
	}

	if t.reconnectTimer == nil {
		t.reconnectTimer = time.AfterFunc(t.ReconnectionInterval, t.reconnect)
	} else {
		t.reconnectTimer.Reset(t.ReconnectionInterval)
	}
}

func (t *Transporter) reconnect() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.L.Info("try to reconnect to device")

	if t.closeTimer != nil {
		t.closeTimer.Stop()
		t.closeTimer = nil
	}

	if t.reconnectTimer != nil {
		t.reconnectTimer.Stop()
		t.reconnectTimer = nil
	}

	t.connect()
}

// Close closes current connection.
func (t *Transporter) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	err := t.close()

	if t.state == TcpStateConnected {
		t.setState(TcpStateConnectClosed)
	} else {
		t.setState(TcpStateDisconnected)
	}

	if t.closeTimer != nil {
		t.closeTimer.Stop()
		t.closeTimer = nil
	}

	if t.reconnectTimer != nil {
		t.reconnectTimer.Stop()
		t.reconnectTimer = nil
	}

	return err
}

// flush flushes pending data in the connection,
// returns io.EOF if connection is closed.
func (t *Transporter) flush(b []byte) (err error) {
	if err = t.conn.SetReadDeadline(time.Now()); err != nil {
		return
	}
	// Timeout setting will be reset when reading
	if _, err = t.conn.Read(b); err != nil {
		// Ignore timeout error
		if netError, ok := err.(net.Error); ok && netError.Timeout() {
			err = nil
		}
	}
	return
}

// closeLocked closes current connection. Caller must hold the mutex before calling this method.
func (t *Transporter) close() (err error) {
	if t.conn != nil {
		err = t.conn.Close()
		t.conn = nil
	}
	return
}

// closeIdle closes the connection if last activity is passed behind IdleTimeout.
func (t *Transporter) closeIdle() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.IdleTimeout <= 0 {
		return
	}

	t.L.Infof("Transporter is idle for %d, connect closed", t.IdleTimeout)

	idle := time.Now().Sub(t.lastActivity)
	if idle >= t.IdleTimeout {
		t.L.Debugf("modbus: closing connection due to idle timeout: %v", idle)
		t.close()
		t.setState(TcpStateConnectClosed)
	}
}
