package relay

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/vultisig/vultisigner/config"
)

type MessengerImp struct {
	Server           string
	VerificationServer string
	useVerificationServer bool
	SessionID        string
	HexEncryptionKey string
	logger           *logrus.Logger
	messageCache     sync.Map
	isGCM            bool
	messageID        string
	counter          int
}

func NewMessenger(server, sessionID, hexEncryptionKey string, isGCM bool, messageID string) *MessengerImp {
	return &MessengerImp{
		Server:           server,
		SessionID:        sessionID,
		HexEncryptionKey: hexEncryptionKey,
		messageCache:     sync.Map{},
		logger:           logrus.WithField("service", "messenger").Logger,
		isGCM:            isGCM,
		counter:          0,
	}
}

// NewMessengerFromConfig creates a messenger with both relay and verification servers configured
func NewMessengerFromConfig(cfg config.Config, sessionID, hexEncryptionKey string, isGCM bool, messageID string) *MessengerImp {
	return &MessengerImp{
		Server:              cfg.Relay.Server,
		VerificationServer:  cfg.VerificationServer.URL,
		useVerificationServer: false,
		SessionID:           sessionID,
		HexEncryptionKey:    hexEncryptionKey,
		messageCache:        sync.Map{},
		logger:              logrus.WithField("service", "messenger").Logger,
		isGCM:               isGCM,
		counter:             0,
	}
}

// UseVerificationServer tells the messenger to use the verification server for subsequent operations
func (m *MessengerImp) UseVerificationServer() {
	m.useVerificationServer = true
}

// UseRelayServer tells the messenger to use the relay server for subsequent operations
func (m *MessengerImp) UseRelayServer() {
	m.useVerificationServer = false
}

// GetServerURL returns the appropriate server URL based on the current context
func (m *MessengerImp) GetServerURL() string {
	if m.useVerificationServer && m.VerificationServer != "" {
		return m.VerificationServer
	}
	return m.Server
}

func (m *MessengerImp) Send(from, to, body string) error {
	if m.HexEncryptionKey != "" {
		encryptedBody, err := encryptWrapper(body, m.HexEncryptionKey, m.isGCM)
		if err != nil {
			return fmt.Errorf("failed to encrypt body: %w", err)
		}
		body = base64.StdEncoding.EncodeToString([]byte(encryptedBody))
	}

	hash := md5.New()
	hash.Write([]byte(body))
	hashStr := hex.EncodeToString(hash.Sum(nil))

	if hashStr == "" {
		return fmt.Errorf("hash is empty")
	}

	buf, err := json.MarshalIndent(struct {
		SessionID  string   `json:"session_id,omitempty"`
		From       string   `json:"from,omitempty"`
		To         []string `json:"to,omitempty"`
		Body       string   `json:"body,omitempty"`
		Hash       string   `json:"hash,omitempty"`
		SequenceNo int      `json:"sequence_no,omitempty"`
	}{
		SessionID:  m.SessionID,
		From:       from,
		To:         []string{to},
		Body:       body,
		Hash:       hashStr,
		SequenceNo: m.counter,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("fail to marshal message: %w", err)
	}
	m.counter++

	url := fmt.Sprintf("%s/message/%s", m.GetServerURL(), m.SessionID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if body == "" {
		return fmt.Errorf("body is empty")
	}

	req.Header.Set("Content-Type", "application/json")
	if m.messageID != "" {
		req.Header.Set("message_id", m.messageID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			m.logger.Error("Failed to close response body")
		}
	}()

	if resp.Status != "202 Accepted" {
		return fmt.Errorf("fail to send message, response code is not 202 Accepted: %s", resp.Status)
	}

	m.logger.WithFields(logrus.Fields{
		"from": from,
		"to":   to,
		"hash": hashStr,
	}).Info("Message sent")

	return nil
}

func encryptWrapper(plainText, hexKey string, isGCM bool) (string, error) {
	if isGCM {
		return encryptGCM(plainText, hexKey)
	}
	return encrypt(plainText, hexKey)
}

func encrypt(plainText, hexKey string) (string, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", err
	}
	plainByte := []byte(plainText)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	plainByte = pad(plainByte, aes.BlockSize)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plainByte))
	mode.CryptBlocks(ciphertext, plainByte)
	ciphertext = append(iv, ciphertext...)
	return string(ciphertext), nil
}

func encryptGCM(plainText, hexKey string) (string, error) {
	passwd, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(passwd)
	key := hash[:]

	// Create a new AES cipher using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Use GCM (Galois/Counter Mode)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create a nonce. Nonce size is specified by GCM
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Seal encrypts and authenticates plaintext
	ciphertext := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return string(ciphertext), nil
}

// pad applies PKCS7 padding to the plaintext
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}
