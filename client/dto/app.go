package dto

import (
	"fmt"
)

type App struct {
	Account *Account

	Id          string
	AppName     string
	Extra       string
	Name        string
	Group       string
	LastTouch   string
	PwProtect   bool
	Fav         bool
	WinTitle    string
	WinInfo     string
	ExeVersion  string
	WarnVersion string
}

func ParseApp(chunk *Chunk, key []byte) (*Account, error) {
	var acc Account = Account{}
	var err error
	var _ string

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

	attachkey, err := chunk.ReadCryptString(key) //TODO: This might require adjustments, not sure if its decoded same way as rest crypt fields
	acc.Attachkey = []byte(attachkey)

	if err != nil {
		return nil, err
	}

	acc.AttachkeyPresent, err = chunk.ReadBoolean()
	if err != nil {
		return nil, err
	}

	chunk.SkipItem() //skip(individualshare)
	chunk.SkipItem() //skip(notetype)
	chunk.SkipItem() //skip(noalert)

	acc.LastModifiedGMT, err = chunk.ReadPlainString()
	if err != nil {
		return nil, err
	}

	/* use name as 'fullname' only if there's no assigned group */
	if len(acc.Group) > 0 && (len(acc.Name) > 0 || acc.IsGroup()) {
		acc.FullName = fmt.Sprintf("%s/%s", acc.Group, acc.Name)
	} else {
		acc.FullName = acc.Name
	}

	return &acc, nil
}
