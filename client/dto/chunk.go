package dto

import (
	"encoding/binary"
	"errors"
	"last-pass-poc/client/encryption"
)

type Item struct {
	Data []byte
}

type Chunk struct {
	Name string
	Len  uint32
	Data []byte
}

func (chunk *Chunk) readLen() (uint32, error) {
	if len(chunk.Data) < 4 {
		return 0, errors.New("chunk data too short for length")
	}
	res := binary.BigEndian.Uint32(chunk.Data[:4])
	chunk.Data = chunk.Data[4:]
	return res, nil
}

func (chunk *Chunk) readData(length uint32) (*Item, error) {
	if length > uint32(len(chunk.Data)) {
		return nil, errors.New("chunk data too short for data")
	}
	item := &Item{
		Data: chunk.Data[:length],
	}
	chunk.Data = chunk.Data[length:]
	return item, nil
}

func (chunk *Chunk) ReadItem() (*Item, error) {
	itemLen, err := chunk.readLen()
	if err != nil {
		return nil, err
	}
	return chunk.readData(itemLen)
}

func (chunk *Chunk) ReadHexString() (string, error) {
	item, err := chunk.ReadItem()
	if err != nil {
		return "", err
	}

	if len(item.Data) == 0 {
		return "", nil // or duplicate an empty string if necessary
	}

	str, err := encryption.HexToBytes(item.Data) // Implement hexToBytes as needed
	if err != nil {
		return "", err
	}

	return string(str), nil
}

func (chunk *Chunk) ReadPlainString() (string, error) {
	item, err := chunk.ReadItem()
	if err != nil {
		return "", err
	}

	if len(item.Data) == 0 {
		return "", nil // or duplicate an empty string if necessary
	}

	return string(item.Data), nil
}

func (chunk *Chunk) ReadCryptString(key []byte) (string, error) {
	item, err := chunk.ReadItem()
	if err != nil {
		return "", err
	}

	ptext, err := encryption.Transform(string(item.Data),
		encryption.WithAESDecrypt(key),
	)

	if err != nil {
		return "", err
	}

	return ptext, nil
}

func (chunk *Chunk) ReadBoolean() (bool, error) {
	item, err := chunk.ReadItem()
	if err != nil {
		return false, err
	}

	if len(item.Data) != 1 {
		return false, nil
	}

	return item.Data[0] == '1', nil
}
func (chunk *Chunk) SkipItem() error {
	item, err := chunk.ReadItem()
	if err != nil {
		return err
	}

	if len(item.Data) != 1 {
		return nil
	}

	return nil
}

func (chunk *Chunk) CheckNextEntryEncrypted() bool {
	return len(chunk.Data) > 4 && chunk.Data[4] == '!'
}
