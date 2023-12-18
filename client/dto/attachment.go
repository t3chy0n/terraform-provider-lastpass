package dto

type Attachment struct {
	Id         string
	AccountId  string
	FileName   string
	MimeType   string
	Data       []byte
	StorageKey string
	Size       string
}

func ParseAttachment(chunk *Chunk, key []byte) (*Attachment, error) {
	var attach Attachment = Attachment{}
	var err error

	attach.Id, err = chunk.ReadPlainString()
	if err != nil {
		return nil, err
	}
	attach.AccountId, err = chunk.ReadPlainString()
	if err != nil {
		return nil, err
	}
	attach.MimeType, err = chunk.ReadPlainString()
	if err != nil {
		return nil, err
	}
	attach.StorageKey, err = chunk.ReadPlainString()
	if err != nil {
		return nil, err
	}
	attach.Size, err = chunk.ReadPlainString()
	if err != nil {
		return nil, err
	}
	attach.FileName, err = chunk.ReadPlainString()
	if err != nil {
		return nil, err
	}

	return &attach, nil
}
