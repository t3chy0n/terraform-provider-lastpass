package dto

import (
	"encoding/hex"
	"last-pass/client/encryption"
	"reflect"
	"testing"
)

func TestParsingAttachment(t *testing.T) {
	attachmentEnc := "!k1T9FMGQ9l42RuzgOQQxPQ==|cwjFQsxNWdWHcqSYMRQ+61B7igyRBYndiXUnbaIM8e4="
	attachmentKeyHex := "89360ea229a5d035938c443b6ef76c177165084bc3fb8a02ea2eb112ee099110"
	attachmentKey, _ := hex.DecodeString(attachmentKeyHex)

	decoded, err := encryption.Transform(attachmentEnc,
		encryption.WithUnbase64(),
		encryption.WithAESDecrypt(attachmentKey),
		encryption.WithUnbase64(),
	)
	expectedContent := "somedataasdasd"

	if err != nil {

		t.Errorf("Couldn't decode attachment payload %v", err)
	}
	if !reflect.DeepEqual(expectedContent, decoded) {
		t.Errorf("Account Name = %v, want %v", expectedContent, decoded)
	}

}
