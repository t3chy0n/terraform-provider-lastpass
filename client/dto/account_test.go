package dto

import (
	"encoding/hex"
	"last-pass/client/kdf"
	"reflect"
	"testing"
)

func TestParsingAccount(t *testing.T) {
	password := "Thisisinsecurekey1!"
	username := "adrian.jutrowski@techyon.dev"

	key := kdf.DecryptionKey(username, password, 600000)

	accSerialized := "000000123635333039373936323233313137313131310000002121cb5392ab4615f6cbe0be2333fcadc75b1fe419bb194876b99a95bc44f26776dd00000031217b2a6945b1cd855ff9681ea24886955ca673cf0e6b6217bb62a3928e46c4556d874533faefbb15aca60ec4d79262ca620000001236383734373437303361326632663733366500000061213af32175b38d177c30e293427ac4e438f7fd6ae5ce3fffba23d26d946705d299c31794a996e481c48f4fe336fcc4e210b02e9ad116c54388d7da2fc771e464bdc3458fcb6ff155dfd8c7ff64069b0a00481e93dc1ee1e1105f26368799bf7524000000013000000000000000000000002121a940f7a6ce04173b28a377210fab5366ca85f815cd6469012a9d7d1a28882ce800000001300000000130000000013100000001300000000130000000013000000000000000123635333039373936323233313137313131310000000000000000000000000000000130000000013000000000000000000000000130000000013000000086214f326d467476734e3737557346512b6c6f6472474a413d3d7c50684543796c2b482b55716f7456516d2b3977564d673772466a426d4f447236554a636f4930767a4a4c6a414e616d4a76574f48544846656352426d586b5a553354304b6c5762636435544f416d6c7231437072366b6d726f6b557347536430794d7939476937343068513d0000000131000000013000000006536572766572000000000000000a3137303235383236313600000001300000000a313730323532383833310000000a31373032353238383331000000000000000130000000013000000000000000000000000000000000000000022d3100000000"

	accByte, err := hex.DecodeString(accSerialized)
	if err != nil {
		t.Errorf("Couldnt deserialize test subject account payload")
	}
	chunk := Chunk{Data: accByte, Len: uint32(len(accByte) / 2)}

	acc, err := ParseAccount(&chunk, nil, key)
	if err != nil {
		t.Errorf("Couldnt parse test subject account payload: %s", err)
	}
	expectedAccName := "TestApp4"

	if !reflect.DeepEqual(expectedAccName, acc.Name) {
		t.Errorf("Account Name = %v, want %v", expectedAccName, acc.Name)
	}
	expectedAccGroup := "K8sManaged\\RabitMq\\Dev"

	if !reflect.DeepEqual(expectedAccGroup, acc.Group) {
		t.Errorf("Account Group = %v, want %v", expectedAccGroup, acc.Group)
	}
	expectedAccFullName := "K8sManaged\\RabitMq\\Dev\\TestApp4"

	if !reflect.DeepEqual(expectedAccFullName, acc.FullName) {
		t.Errorf("Account Fullname = %v, want %v", expectedAccFullName, acc.FullName)
	}
	expectedAccNote := "NoteType:Server\nLanguage:en-US\nHostname:asd\nUsername:asd\nPassword:asda\nNotes:sd"

	if !reflect.DeepEqual(expectedAccNote, acc.Note) {
		t.Errorf("Account Note = %v, want %v", expectedAccNote, acc.Note)
	}
}
