package dto

import (
	"encoding/hex"
	"last-pass/client/kdf"
	"reflect"
	"testing"
)

func TestParsingTextFields(t *testing.T) {
	password := "Thisisinsecurekey1!"
	username := "adrian.jutrowski@techyon.dev"

	key := kdf.DecryptionKey(username, password, 600000)

	fieldSerialized := "00000009546578744669656c6400000004746578740000000000000000000000000000000130000000013000000000"

	fieldByte, err := hex.DecodeString(fieldSerialized)
	if err != nil {
		t.Errorf("Couldnt deserialize test subject account payload")
	}
	chunk := Chunk{Data: fieldByte, Len: uint32(len(fieldByte) / 2)}

	field, err := ParseField(&chunk, key)

	expectedName := "TextField"

	if !reflect.DeepEqual(expectedName, field.Name) {
		t.Errorf("Field Name = %v, want %v", expectedName, field.Name)
	}
	expectedValue := ""

	if !reflect.DeepEqual(expectedValue, field.Value) {
		t.Errorf("Field Value = %v, want %v", expectedValue, field.Value)
	}
	expectedType := "text"

	if !reflect.DeepEqual(expectedType, field.Type) {
		t.Errorf("Field Type = %v, want %v", expectedType, field.Type)
	}
}

func TestParsingPasswordFields(t *testing.T) {
	password := "Thisisinsecurekey1!"
	username := "adrian.jutrowski@techyon.dev"

	key := kdf.DecryptionKey(username, password, 600000)

	fieldSerialized := "0000000d50617373776f72644669656c640000000870617373776f726400000021216b7ef3126a3ca3466527a52a151182a84f26060b70fc3ba6ab26eda8b83c527e00000000000000000000000130000000013000000000"

	fieldByte, err := hex.DecodeString(fieldSerialized)
	if err != nil {
		t.Errorf("Couldnt deserialize test subject account payload")
	}
	chunk := Chunk{Data: fieldByte, Len: uint32(len(fieldByte) / 2)}

	field, err := ParseField(&chunk, key)

	expectedName := "PasswordField"

	if !reflect.DeepEqual(expectedName, field.Name) {
		t.Errorf("Field Name = %v, want %v", expectedName, field.Name)
	}
	expectedValue := "test"

	if !reflect.DeepEqual(expectedValue, field.Value) {
		t.Errorf("Field Value = %v, want %v", expectedValue, field.Value)
	}
	expectedType := "password"

	if !reflect.DeepEqual(expectedType, field.Type) {
		t.Errorf("Field Type = %v, want %v", expectedType, field.Type)
	}
}
