package dto

import (
	"fmt"
	"last-pass-poc/client/encryption"
)

type Account struct {
	Application *App
	Share       *Share
	Fields      []*Field
	Attachments []*Attachment

	Id               string
	Name             string
	Group            string
	FullName         string
	Url              string
	Note             string
	NoteType         string
	Username         string
	Password         string
	PwProtect        bool
	LastTouch        string
	Attachkey        []byte
	AttachkeyPresent bool
	LastModifiedGMT  string
}

func (acc *Account) IsShared() bool { return acc.Share != nil }
func (acc *Account) IsApp() bool    { return acc.Application != nil }

type AccountUpsertResponse struct {
	Msg       string `xml:"msg,attr"`
	AccountId string `xml:"aid,attr"`
}

func ParseAccount(chunk *Chunk, share *Share, key []byte) (*Account, error) {
	var acc Account = Account{}
	var err error
	var _ string

	acc.Share = share

	acc.Id, err = chunk.ReadPlainString()
	if err != nil {
		return nil, err
	}
	acc.Name, err = chunk.ReadCryptString(key)
	if err != nil {
		return nil, err
	}
	acc.Group, err = chunk.ReadCryptString(key)
	if err != nil {
		return nil, err
	}

	if chunk.CheckNextEntryEncrypted() {
		acc.Url, err = chunk.ReadCryptString(key)
	} else {
		acc.Url, err = chunk.ReadPlainString()
	}
	acc.Note, err = chunk.ReadCryptString(key)
	if err != nil {
		return nil, err
	}
	chunk.SkipItem() //fav boolean
	chunk.SkipItem() //sharedfromaid

	acc.Username, err = chunk.ReadCryptString(key)
	if err != nil {
		return nil, err
	}
	acc.Password, err = chunk.ReadCryptString(key)
	if err != nil {
		return nil, err
	}

	acc.PwProtect, err = chunk.ReadBoolean()
	if err != nil {
		return nil, err
	}

	chunk.SkipItem() //genpw
	chunk.SkipItem() //skip

	acc.LastTouch, err = chunk.ReadPlainString()
	if err != nil {
		return nil, err
	}

	chunk.SkipItem() //(autologin);
	chunk.SkipItem() //(never_autofill);
	chunk.SkipItem() //(realm_data);
	chunk.SkipItem() //(fiid);
	chunk.SkipItem() //(custom_js);
	chunk.SkipItem() //(submit_id);
	chunk.SkipItem() //(captcha_id);
	chunk.SkipItem() //(urid);
	chunk.SkipItem() //(basic_auth);
	chunk.SkipItem() //(method);
	chunk.SkipItem() //(action);
	chunk.SkipItem() //(groupid);
	chunk.SkipItem() //(deleted);

	attachkeyEncrypted, err := chunk.ReadPlainString()
	if err != nil {
		return nil, err
	}
	if len(attachkeyEncrypted) > 0 {

		attachkey, err := encryption.Transform(attachkeyEncrypted,
			encryption.WithUnbase64(),
			encryption.WithAESDecrypt(key),
			encryption.WithUnHex(),
		)
		acc.Attachkey = []byte(attachkey)
		if err != nil {
			return nil, err
		}

	}

	acc.AttachkeyPresent, err = chunk.ReadBoolean()
	if err != nil {
		return nil, err
	}

	chunk.SkipItem() //skip(individualshare)
	acc.NoteType, err = chunk.ReadPlainString()
	chunk.SkipItem() //skip(noalert)

	acc.LastModifiedGMT, err = chunk.ReadPlainString()
	if err != nil {
		return nil, err
	}

	/* use name as 'fullname' only if there's no assigned group, resolve shared folder name if it exist */
	if len(acc.Group) > 0 && (len(acc.Name) > 0 || acc.IsGroup()) {
		acc.FullName = fmt.Sprintf("%s\\%s", acc.Group, acc.Name)
	} else {

		acc.FullName = acc.Name

	}
	if acc.Share != nil {
		acc.FullName = fmt.Sprintf("%s\\%s", acc.Share.Name, acc.FullName)
	}

	return &acc, nil
}

func (acc *Account) IsGroup() bool {
	return acc.Url == "http://group"
}

type AccountOption func(acc *Account)

func WithServer(data AccountServerFields) AccountOption {
	return func(acc *Account) {
		acc.NoteType = NOTE_TYPE_SERVER
		acc.Url = "http://sn"
		acc.Note = fmt.Sprintf("NoteType:%s\nLanguage:en-US\nHostname:%s\nUsername:%s\nPassword:%s\nNotes:%s",
			NOTE_TYPE_SERVER,
			data.Hostname,
			data.Username,
			data.Password,
			data.Notes,
		)
	}
}

func WithDatabase(data AccountDatabaseFields) AccountOption {
	return func(acc *Account) {
		acc.NoteType = NOTE_TYPE_DATABASE
		acc.Url = "http://sn"
		acc.Note = fmt.Sprintf("NoteType:%s\nLanguage:en-US\nType:%s\nHostname:%s\nPort:%s\nDatabase:%s\nUsername:%s\nPassword:%s\nSID:%s\nAlias:%s\nNotes:%s",
			NOTE_TYPE_SERVER,
			data.Type,
			data.Hostname,
			data.Port,
			data.Database,
			data.Username,
			data.Password,
			data.SID,
			data.Alias,
			data.Notes,
		)
	}
}

func WithSsh(data AccountSshFields) AccountOption {
	return func(acc *Account) {
		acc.NoteType = NOTE_TYPE_SSH_KEY
		acc.Url = "http://sn"
		acc.Note = fmt.Sprintf("NoteType:%s\nLanguage:en-US\nBit Strength:%s\nFormat:%s\nPassphrase:%s\nPrivate Key:%s\nPublic Key:%s\nHostname:%s\nDate:%s\nNotes:%s",
			NOTE_TYPE_SSH_KEY,
			data.BitStrength,
			data.Format,
			data.Passphrase,
			data.PrivateKey,
			data.PublicKey,
			data.Hostname,
			data.Date,
			data.Notes,
		)
	}
}

func WithTextFileAttachment(fileName string, data string) AccountOption {
	return func(acc *Account) {
		attach := Attachment{}
		attach.MimeType = "other:txt"
		attach.FileName = fileName
		attach.Data = []byte(data)

		acc.Attachments = append(acc.Attachments, &attach)
	}
}

func WithSecretNote(data AccountSecretNoteFields) AccountOption {
	return func(acc *Account) {
		acc.NoteType = NOTE_TYPE_GENERIC
		acc.Url = "http://sn"
		acc.Note = data.Notes
	}
}

func AccountBuilder(group string, name string, opts ...AccountOption) Account {

	acc := Account{}
	acc.Name = name
	acc.Group = group

	for _, opt := range opts {
		opt(&acc)
	}

	return acc
}
