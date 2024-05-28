package tcp

import (
	"bufio"
	"net"
)

type TCPHost struct {
	Сonn   net.Conn
	reader *bufio.Reader
}

func NewTCPHost(conn net.Conn) (*TCPHost, error) {
	reader := bufio.NewReader(conn)
	return &TCPHost{conn, reader}, nil
}

func (s *TCPHost) Send(data []byte) error {
	err := Send(s.Сonn, data)
	return err
}

func (s *TCPHost) Read() ([]byte, error) {
	bytes, err := Read(s.reader)
	return bytes, err
}

func (s *TCPHost) Close() error {
	if s.Сonn != nil {
		return s.Сonn.Close()
	}
	return nil
}
