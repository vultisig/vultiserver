package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vultisig/mobile-tss-lib/tss"

	"github.com/vultisig/vultiserver/common"
)

type Client struct {
	relayServer string
	client      http.Client
	logger      *logrus.Logger
}

func NewRelayClient(relayServer string) *Client {
	return &Client{
		relayServer: relayServer,
		client: http.Client{
			Timeout: 5 * time.Second,
		},
		logger: logrus.WithField("service", "relay-client").Logger,
	}
}
func (c *Client) bodyCloser(body io.ReadCloser) {
	if body != nil {
		if err := body.Close(); err != nil {
			c.logger.Error("Failed to close body,err:", err)
		}
	}
}

func (c *Client) StartSession(sessionID string, parties []string) error {
	sessionURL := c.relayServer + "/start/" + sessionID
	body, err := json.Marshal(parties)
	if err != nil {
		return fmt.Errorf("fail to start session: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, sessionURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("fail to start session: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("fail to start session: %w", err)
	}
	defer c.bodyCloser(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fail to start session: %s", resp.Status)
	}
	return nil
}

func (c *Client) RegisterSessionWithRetry(sessionID string, key string) error {
	for i := 0; i < 3; i++ {
		if err := c.RegisterSession(sessionID, key); err != nil {
			c.logger.WithFields(logrus.Fields{
				"session": sessionID,
				"key":     key,
				"error":   err,
				"attempt": i,
			}).Error("Failed to register session")
			time.Sleep(100 * time.Millisecond)
		} else {
			return nil
		}
	}
	return fmt.Errorf("fail to register session after 3 retries")
}

func (c *Client) RegisterSession(sessionID string, key string) error {
	sessionURL := c.relayServer + "/" + sessionID
	body := []byte("[\"" + key + "\"]")
	c.logger.WithFields(logrus.Fields{
		"session": sessionID,
		"key":     key,
		"body":    string(body),
	}).Info("Registering session")

	resp, err := c.client.Post(sessionURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("fail to register session: %w", err)
	}
	defer c.bodyCloser(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("fail to register session: %s", resp.Status)
	}

	return nil
}

func (c *Client) WaitForSessionStart(ctx context.Context, sessionID string) ([]string, error) {
	sessionURL := c.relayServer + "/start/" + sessionID
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			resp, err := c.client.Get(sessionURL)
			if err != nil {
				return nil, fmt.Errorf("fail to get session: %w", err)
			}
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("fail to get session: %s", resp.Status)
			}
			var parties []string
			buff, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("fail to read session body: %w", err)
			}
			c.bodyCloser(resp.Body)
			if err := json.Unmarshal(buff, &parties); err != nil {
				return nil, fmt.Errorf("fail to unmarshal session body: %w", err)
			}
			// We need to hold expected parties to start session
			if len(parties) > 1 {
				c.logger.WithFields(logrus.Fields{
					"session": sessionID,
					"parties": parties,
				}).Info("All parties joined")
				return parties, nil
			}

			c.logger.WithFields(logrus.Fields{
				"session": sessionID,
			}).Info("Waiting for someone to start session")

			// backoff
			time.Sleep(1 * time.Second)
		}
	}
}

func (c *Client) GetSession(sessionID string) ([]string, error) {
	sessionURL := c.relayServer + "/" + sessionID

	resp, err := c.client.Get(sessionURL)
	if err != nil {
		return nil, fmt.Errorf("fail to get session: %w", err)
	}
	defer c.bodyCloser(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fail to get session: %s", resp.Status)
	}
	var parties []string
	if err := json.NewDecoder(resp.Body).Decode(&parties); err != nil {
		return nil, fmt.Errorf("fail to unmarshal session body: %w", err)
	}

	return parties, nil
}

func (c *Client) CompleteSession(sessionID, localPartyID string) error {
	sessionURL := c.relayServer + "/complete/" + sessionID
	parties := []string{localPartyID}
	body, err := json.Marshal(parties)
	if err != nil {
		return fmt.Errorf("fail to complete session: %w", err)
	}
	bodyReader := bytes.NewReader(body)
	req, err := http.NewRequest(http.MethodPost, sessionURL, bodyReader)
	if err != nil {
		return fmt.Errorf("fail to complete session: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("fail to complete session: %w", err)
	}
	defer c.bodyCloser(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fail to complete session: %s", resp.Status)
	}
	return nil
}

func (c *Client) CheckCompletedParties(sessionID string, partiesJoined []string) (bool, error) {
	sessionURL := c.relayServer + "/complete/" + sessionID
	start := time.Now()
	timeout := time.Minute

	for {
		req, err := http.NewRequest(http.MethodGet, sessionURL, nil)
		if err != nil {
			return false, fmt.Errorf("fail to check completed parties: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		resp, err := c.client.Do(req)
		if err != nil {
			return false, fmt.Errorf("fail to check completed parties: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return false, fmt.Errorf("fail to check completed parties: %s", resp.Status)
		}

		result, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, fmt.Errorf("fail to fetch request: %w", err)
		}
		c.bodyCloser(resp.Body)

		if len(result) > 0 {
			var peers []string
			err := json.Unmarshal(result, &peers)
			if err != nil {
				c.logger.WithFields(logrus.Fields{
					"error": err,
				}).Error("Failed to decode response to JSON")
				continue
			}

			if common.IsSubset(partiesJoined, peers) {
				c.logger.Info("All parties have completed keygen successfully")
				return true, nil
			}
		}

		time.Sleep(time.Second)
		if time.Since(start) >= timeout {
			break
		}
	}

	return false, nil
}

func (c *Client) MarkKeysignComplete(sessionID string, messageID string, sig tss.KeysignResponse) error {
	sessionURL := c.relayServer + "/complete/" + sessionID + "/keysign"
	body, err := json.Marshal(sig)
	if err != nil {
		return fmt.Errorf("fail to marshal keysign to json: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, sessionURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("fail to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("message_id", messageID)
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("fail to mark keysign complete: %w", err)
	}
	defer c.bodyCloser(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fail to mark keysign complete: %s", resp.Status)
	}
	return nil
}
func (c *Client) CheckKeysignComplete(sessionID string, messageID string) (*tss.KeysignResponse, error) {
	sessionURL := c.relayServer + "/complete/" + sessionID + "/keysign"
	req, err := http.NewRequest(http.MethodGet, sessionURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fail to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("message_id", messageID)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fail to check keysign complete: %w", err)
	}
	defer c.bodyCloser(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fail to check keysign complete: %s", resp.Status)
	}
	var sig tss.KeysignResponse
	if err := json.NewDecoder(resp.Body).Decode(&sig); err != nil {
		return nil, fmt.Errorf("fail to unmarshal keysign response: %w", err)
	}
	return &sig, nil
}
func (c *Client) EndSession(sessionID string) error {
	sessionURL := c.relayServer + "/" + sessionID
	req, err := http.NewRequest(http.MethodDelete, sessionURL, nil)
	if err != nil {
		return fmt.Errorf("fail to end session: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("fail to end session: %w", err)
	}
	defer c.bodyCloser(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fail to end session: %s", resp.Status)
	}
	return nil
}
func (c *Client) UploadSetupMessage(sessionID string, payload string) error {
	sessionUrl := c.relayServer + "/setup-message/" + sessionID
	body := []byte(payload)
	bodyReader := bytes.NewReader(body)
	resp, err := http.Post(sessionUrl, "application/json", bodyReader)
	if err != nil {
		return fmt.Errorf("fail to upload setup message: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("fail to upload setup message: %s", resp.Status)
	}
	return nil
}

func (c *Client) WaitForSetupMessage(ctx context.Context, sessionID, messageID string) (string, error) {
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
			payload, err := c.GetSetupMessage(sessionID, messageID)
			if err == nil && payload != "" {
				return payload, err
			}
			c.logger.Errorf("payload is not ready: %v", err)
			time.Sleep(time.Second) // backoff for 1 sec
		}
	}
}

func (c *Client) GetSetupMessage(sessionID, messageID string) (string, error) {
	sessionUrl := c.relayServer + "/setup-message/" + sessionID
	req, err := http.NewRequest(http.MethodGet, sessionUrl, nil)
	if err != nil {
		return "", fmt.Errorf("fail to get setup message: %w", err)
	}
	if messageID != "" {
		req.Header.Add("message_id", messageID)
	}
	c.logger.Infof("getting setup message, sessionID: %s,message_id: %s", sessionID, messageID)
	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fail to get setup message: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fail to get setup message: %s", resp.Status)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Println("fail to close response body", err)
		}
	}()
	result, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("fail to read setup message: %w", err)
	}

	return string(result), nil
}

func (c *Client) DeleteMessageFromServer(sessionID, localPartyID, hash, messageID string) error {
	req, err := http.NewRequest(http.MethodDelete, c.relayServer+"/message/"+sessionID+"/"+localPartyID+"/"+hash, nil)
	if err != nil {
		return fmt.Errorf("fail to delete message: %w", err)
	}
	if messageID != "" {
		req.Header.Add("message_id", messageID)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("fail to delete message: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fail to delete message: status %s", resp.Status)
	}
	return nil
}

func (c *Client) DownloadMessages(sessionID string, localPartyID string, messageID string) ([]Message, error) {
	req, err := http.NewRequest(http.MethodGet, c.relayServer+"/message/"+sessionID+"/"+localPartyID, nil)
	if err != nil {
		return nil, fmt.Errorf("fail to create request: %w", err)
	}
	if messageID != "" {
		req.Header.Add("message_id", messageID)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.Error("fail to get data from server", "error", err)
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		c.logger.Debug("fail to get data from server", "status", resp.Status)
		return nil, fmt.Errorf("fail to get data from server: %s", resp.Status)
	}
	decoder := json.NewDecoder(resp.Body)
	var messages []Message
	if err := decoder.Decode(&messages); err != nil {
		if err != io.EOF {
			c.logger.Error("fail to decode messages", "error", err)
		}
		return nil, err
	}
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].SequenceNo < messages[j].SequenceNo
	})
	return messages, nil
}
