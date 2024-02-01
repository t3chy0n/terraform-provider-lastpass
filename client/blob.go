package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"last-pass/client/dto"
	"last-pass/client/encryption"
	"strconv"
)

type Blob struct {
	Data []byte
}

func (blob *Blob) Parse(session *dto.Session) (map[string]*dto.Account, error) {
	var version uint64

	var accounts = make(map[string]*dto.Account)
	var attachments = make(map[string]*dto.Attachment)
	//var lastAccount *entities.Account

	//var shares []*entities.Share
	var lastShare *dto.Share
	var lastAccount *dto.Account

	var prevOpcode = ""
	for {

		var key []byte
		if lastShare != nil {
			key = lastShare.Key
		} else {
			key = session.KDFDecryptionKey
		}

		chunk, err := blob.readChunk()
		if err != nil {
			if err == io.EOF || chunk == nil { // Assuming io.EOF is used to signal the end of the blob
				break
			}
			return nil, err
		}

		println(chunk.Name, len(chunk.Data))
		switch chunk.Name {
		case "LPAV":
			versionStr := string(chunk.Data)
			var err error
			version, err = strconv.ParseUint(versionStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse version: %v", err)
			}

		case "ACCT":
			// Handle the "ACCT" chunk
			account, err := dto.ParseAccount(chunk, lastShare, key)

			if err != nil {
				return nil, fmt.Errorf("failed to parse account: %v", err)
			}

			accounts[account.Id] = account
			lastAccount = account
			//accounts := append(accounts, lastAccount)
			// ...

		case "ACFL", "ACOF":
			field, err := dto.ParseField(chunk, key)
			if err != nil {
				return nil, fmt.Errorf("failed to parse field: %v", err)
			}
			lastAccount.Fields = append(lastAccount.Fields, field)

			//shares := append(shares, lastShare)

		case "SHAR":
			// Handle the Shared items from other accounts
			share, err := dto.ParseShare(chunk, session.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("failed to parse share: %v", err)
			}
			lastShare = share
			//shares := append(shares, lastShare)

		case "AACT":
			// Handle the "AACT" chunk
			println("Parse app - unsupported ")

		case "TMPL":
			//Here are json formated custom templates
			println("Parsing custom templates - unsupported")

		case "ATTA":
			attachment, err := dto.ParseAttachment(chunk, session.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("failed to parse attachment: %v", err)
			}

			attachments[attachment.AccountId] = attachment

		}
		prevOpcode = chunk.Name
		println("Prev op", prevOpcode)
	}

	//Merge attachements
	for _, attach := range attachments {
		acc := accounts[attach.AccountId]
		if acc != nil {

			fileName, err := encryption.Transform(attach.FileName,
				encryption.WithUnbase64(),
				encryption.WithAESDecrypt(acc.Attachkey),
			)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt attachment filename: %v", err)
			}
			attach.FileName = fileName

			acc.Attachments = append(acc.Attachments, attach)

		}
	}

	println(version)
	return accounts, nil
}

func (blob *Blob) readChunk() (*dto.Chunk, error) {
	if len(blob.Data) == 0 {
		return nil, io.EOF
	}

	if len(blob.Data) < 4 {
		return nil, errors.New("blob data too short for chunk name")
	}

	chunk := &dto.Chunk{
		Name: string(blob.Data[:4]),
	}

	blob.Data = blob.Data[4:]

	if len(blob.Data) < 4 {
		return nil, errors.New("blob data too short for chunk length")
	}

	chunk.Len = binary.BigEndian.Uint32(blob.Data[:4])
	blob.Data = blob.Data[4:]

	if int(chunk.Len) > len(blob.Data) {
		return nil, errors.New("blob data too short for chunk data")
	}

	chunk.Data = blob.Data[:chunk.Len]
	blob.Data = blob.Data[chunk.Len:]

	return chunk, nil
}
