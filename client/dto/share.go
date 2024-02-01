package dto

import (
	"errors"
	"last-pass/client/encryption"
	"last-pass/client/kdf"
)

type Share struct {
	Key      []byte
	Id       string
	Name     string
	ReadOnly bool
}

func ParseShare(chunk *Chunk, privateKey []byte) (*Share, error) {

	var share Share = Share{}
	var err error

	share.Id, err = chunk.ReadPlainString()
	if err != nil {
		return nil, err
	}

	itemData, err := chunk.ReadItem()
	if err != nil {
		return nil, err
	}

	key, err := encryption.Transform(string(itemData.Data),
		encryption.WithUnHex(),
		encryption.WithRSADecrypt(privateKey),
		encryption.WithUnHex(),
	)
	if err != nil {
		return nil, err
	}

	if len(key) != kdf.KDFHashLen {
		return nil, errors.New("invalid key length")
	}
	share.Key = []byte(key)

	base64Name, err := chunk.ReadPlainString()

	share.Name, err = encryption.Transform(base64Name,
		encryption.WithUnbase64(),
		encryption.WithAESDecrypt(share.Key),
	)

	share.ReadOnly, err = chunk.ReadBoolean()
	if err != nil {
		return nil, err
	}

	return &share, nil
}
