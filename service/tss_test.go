package service

import (
	"encoding/base64"
	"testing"

	"github.com/vultisig/vultiserver/common"
)

func TestEncryptionGCM(t *testing.T) {
	encryptionKey := "d6022efdbf1cd27b2feb179341b40a800f4fdda7cdfd91ca630f1f17ee0516f3"
	encryptionResult := "lBVUUrBAYm2R6uiESzrgOaaW0GyiOuf2ki6O18YOEBFnQryTj4s="
	rawResult, err := base64.StdEncoding.DecodeString(encryptionResult)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := common.DecryptGCM(rawResult, encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(encrypted) != "helloworld" {
		t.Fatalf("decrypted: %s, expected: %s", encrypted, "helloworld")
	}
}
