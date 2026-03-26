package geoip

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
)

// IPv4Database provides 17mon IPv4 lookups.
type IPv4Database struct {
	buf    []byte
	offset uint32
}

// Open loads a 17mon IP database into memory.
func Open(path string) (*IPv4Database, error) {
	if path == "" {
		return nil, nil
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read geoip db: %w", err)
	}
	if len(buf) < 1028 {
		return nil, fmt.Errorf("geoip db too small")
	}

	return &IPv4Database{
		buf:    buf,
		offset: binary.BigEndian.Uint32(buf[:4]),
	}, nil
}

// Find returns the location string for an IPv4 address.
func (db *IPv4Database) Find(ip string) string {
	if db == nil {
		return ""
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	v4 := parsed.To4()
	if v4 == nil {
		return ""
	}

	first := int(v4[0])
	firstOffset := first*4 + 4
	count := binary.LittleEndian.Uint32(db.buf[firstOffset : firstOffset+4])
	pos := count * 8

	lo := uint32(0)
	hi := (db.offset - (pos + 1028)) / 8
	for lo < hi {
		mid := (lo + hi) / 2
		midOffset := pos + 1028 + 8*mid
		midVal := db.buf[midOffset : midOffset+4]
		if compareBytes(midVal, v4) < 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}

	offset := pos + 1028 + 8*lo
	if offset >= db.offset || int(offset+8) > len(db.buf) {
		return ""
	}

	dataPos := binary.LittleEndian.Uint32(append(db.buf[offset+4:offset+7], 0))
	dataLen := uint32(db.buf[offset+7])
	dataOffset := db.offset + dataPos - 1024
	if int(dataOffset+dataLen) > len(db.buf) {
		return ""
	}

	return string(db.buf[dataOffset : dataOffset+dataLen])
}

func compareBytes(a, b []byte) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
