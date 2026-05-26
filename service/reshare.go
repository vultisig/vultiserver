package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	keygenType "github.com/vultisig/commondata/go/vultisig/keygen/v1"
	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"
	mtss "github.com/vultisig/mobile-tss-lib/tss"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/vultisig/vultiserver/common"
	"github.com/vultisig/vultiserver/internal/tasks"
	"github.com/vultisig/vultiserver/internal/types"
	"github.com/vultisig/vultiserver/relay"
)

func (s *WorkerService) Reshare(vault *vaultType.Vault,
	sessionID,
	hexEncryptionKey,
	serverURL string,
	encryptionPassword string, email string) error {
	if vault.Name == "" {
		return fmt.Errorf("vault name is empty")
	}
	if vault.LocalPartyId == "" {
		return fmt.Errorf("local party id is empty")
	}
	if vault.HexChainCode == "" {
		return fmt.Errorf("hex chain code is empty")
	}
	if serverURL == "" {
		return fmt.Errorf("serverURL is empty")
	}
	client := relay.NewRelayClient(serverURL)
	// Let's register session here
	if err := client.RegisterSessionWithRetry(sessionID, vault.LocalPartyId); err != nil {
		return fmt.Errorf("failed to register session: %w", err)
	}
	// wait longer for keygen start
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	partiesJoined, err := client.WaitForSessionStart(ctx, sessionID)
	s.logger.WithFields(logrus.Fields{
		"session":        sessionID,
		"parties_joined": partiesJoined,
	}).Info("Session started")
	if err != nil {
		return fmt.Errorf("failed to wait for session start: %w", err)
	}
	localStateAccessor, err := relay.NewLocalStateAccessorImp(s.cfg.Server.VaultsFilePath, vault.PublicKeyEcdsa, encryptionPassword, s.blockStorage)
	if err != nil {
		return fmt.Errorf("failed to create localStateAccessor: %w", err)
	}

	tssServerImp, err := s.createTSSService(serverURL, sessionID, hexEncryptionKey, localStateAccessor, true, "")
	if err != nil {
		return fmt.Errorf("failed to create TSS service: %w", err)
	}
	localPartyID := vault.LocalPartyId
	endCh, wg := s.startMessageDownload(serverURL, sessionID, localPartyID, hexEncryptionKey, tssServerImp, "")
	ecdsaPubkey, eddsaPubkey, newResharePrefix := "", "", ""
	for attempt := 0; attempt < 3; attempt++ {
		ecdsaPubkey, newResharePrefix, err = s.reshare(
			tssServerImp,
			vault,
			partiesJoined,
			true,
			"",
		)
		if err == nil {
			break
		}
		s.logger.WithFields(logrus.Fields{
			"session":  sessionID,
			"key_type": "ecdsa",
			"attempt":  attempt,
		}).Error(err)
	}
	if err != nil {
		close(endCh)
		wg.Wait()
		return err
	}
	time.Sleep(500 * time.Millisecond)
	for attempt := 0; attempt < 3; attempt++ {
		eddsaPubkey, _, err = s.reshare(
			tssServerImp,
			vault,
			partiesJoined,
			false,
			newResharePrefix,
		)
		if err == nil {
			break
		}
		s.logger.WithFields(logrus.Fields{
			"session":  sessionID,
			"key_type": "eddsa",
			"attempt":  attempt,
		}).Error(err)
	}
	close(endCh)
	wg.Wait()
	if err != nil {
		return err
	}

	if err := client.CompleteSession(sessionID, localPartyID); err != nil {
		s.logger.WithFields(logrus.Fields{
			"session": sessionID,
			"error":   err,
		}).Error("Failed to complete session")
	}

	if isCompleted, err := client.CheckCompletedParties(sessionID, partiesJoined); err != nil || !isCompleted {
		s.logger.WithFields(logrus.Fields{
			"session":     sessionID,
			"isCompleted": isCompleted,
			"error":       err,
		}).Error("Failed to check completed parties")
		return fmt.Errorf("failed to check completed parties: %w", err)
	}

	ecdsaKeyShare, err := localStateAccessor.GetLocalCacheState(ecdsaPubkey)
	if err != nil {
		return fmt.Errorf("failed to get local sate: %w", err)
	}
	if ecdsaKeyShare == "" {
		return fmt.Errorf("ecdsaKeyShare is empty")
	}
	eddsaKeyShare, err := localStateAccessor.GetLocalCacheState(eddsaPubkey)
	if err != nil {
		return fmt.Errorf("failed to get local sate: %w", err)
	}
	if eddsaKeyShare == "" {
		return fmt.Errorf("eddsaKeyShare is empty")
	}

	newVault := &vaultType.Vault{
		Name:           vault.Name,
		PublicKeyEcdsa: ecdsaPubkey,
		PublicKeyEddsa: eddsaPubkey,
		Signers:        partiesJoined,
		CreatedAt:      timestamppb.Now(),
		HexChainCode:   vault.HexChainCode,
		KeyShares: []*vaultType.Vault_KeyShare{
			{
				PublicKey: ecdsaPubkey,
				Keyshare:  ecdsaKeyShare,
			},
			{
				PublicKey: eddsaPubkey,
				Keyshare:  eddsaKeyShare,
			},
		},
		LocalPartyId:  vault.LocalPartyId,
		LibType:       keygenType.LibType_LIB_TYPE_GG20,
		ResharePrefix: newResharePrefix,
	}
	// GG20 reshare always overwrites — same reasoning as the DKLS reshare path.
	return s.SaveVaultAndScheduleEmail(newVault, encryptionPassword, email, true)
}
func (s *WorkerService) createVerificationCode(publicKeyECDSA string) (string, error) {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	code := rnd.Intn(9000) + 1000
	verificationCode := strconv.Itoa(code)
	key := fmt.Sprintf("verification_code_%s", publicKeyECDSA)
	// verification code will be valid for 1 hour
	if err := s.redis.Set(context.Background(), key, verificationCode, time.Hour); err != nil {
		return "", fmt.Errorf("failed to set cache: %w", err)
	}
	return verificationCode, nil
}
func (s *WorkerService) SaveVaultAndScheduleEmail(vault *vaultType.Vault,
	encryptionPassword string,
	email string,
	forceOverwrite bool) error {
	// Collision guard (spike item C): if a vault already exists for this ECDSA
	// pubkey and its metadata differs, reject the overwrite unless the caller
	// explicitly requests force. This prevents the server from silently
	// replacing a live share while devices that hold the prior share still
	// rely on it for signing.
	//
	// The check compares EdDSA pubkey, chain code, and local_party_id — the
	// three fields that, if they drift, cause the share-mismatch pathology.
	// An identical re-write (same metadata, same password) is always allowed.
	//
	// NOTE: we use the INCOMING encryption password to try to decrypt the
	// existing file. If the password has changed (the user re-imported with a
	// different password), decryption will fail and we conservatively allow
	// the overwrite (we can't verify the existing metadata, so we can't block
	// it). This mirrors the current permissive behaviour for password changes
	// and avoids locking users out of a legitimate re-import.
	if !forceOverwrite {
		if err := s.checkVaultCollision(vault, encryptionPassword); err != nil {
			return err
		}
	}

	vaultData, err := proto.Marshal(vault)
	if err != nil {
		return fmt.Errorf("failed to Marshal vault: %w", err)
	}

	vaultData, err = common.EncryptVault(encryptionPassword, vaultData)
	if err != nil {
		return fmt.Errorf("common.EncryptVault failed: %w", err)
	}

	vaultBackup := &vaultType.VaultContainer{
		Version:     1,
		Vault:       base64.StdEncoding.EncodeToString(vaultData),
		IsEncrypted: true,
	}
	filePathName := vault.PublicKeyEcdsa + ".bak"

	vaultBackupData, err := proto.Marshal(vaultBackup)
	if err != nil {
		return fmt.Errorf("failed to Marshal vaultBackup: %w", err)
	}

	base64VaultContent := base64.StdEncoding.EncodeToString(vaultBackupData)
	if err := s.blockStorage.UploadFileWithRetry([]byte(base64VaultContent), filePathName, 5); err != nil {
		if err := os.WriteFile(s.cfg.Server.VaultsFilePath+"/"+filePathName, []byte(base64VaultContent), 0644); err != nil {
			s.logger.Errorf("fail to write file: %s", err)
		}
		return fmt.Errorf("fail to write file, err: %w", err)
	}
	code, err := s.createVerificationCode(vault.PublicKeyEcdsa)
	if err != nil {
		return fmt.Errorf("failed to create verification code: %w", err)
	}
	emailRequest := types.EmailRequest{
		Email:       email,
		FileName:    common.GetVaultName(vault),
		FileContent: base64VaultContent,
		VaultName:   vault.Name,
		Code:        code,
	}
	buf, err := json.Marshal(emailRequest)
	if err != nil {
		return fmt.Errorf("json.Marshal failed: %w", err)
	}
	taskInfo, err := s.queueClient.Enqueue(asynq.NewTask(tasks.TypeEmailVaultBackup, buf),
		asynq.Retention(10*time.Minute),
		asynq.Queue(tasks.EMAIL_QUEUE_NAME))
	if err != nil {
		s.logger.Errorf("fail to enqueue email task: %v", err)
	}
	s.logger.Info("Email task enqueued: ", taskInfo.ID)
	return nil
}
// checkVaultCollision reads the existing vault file for the given ECDSA pubkey
// (if any) and returns ErrVaultCollision when the existing vault has different
// EdDSA pubkey, chain code, or local_party_id than the incoming vault.
//
// Returns nil when:
//   - no existing vault (new registration — always allowed)
//   - existing vault is identical to the incoming one (idempotent re-write)
//   - existing vault file cannot be decrypted with the provided password (e.g.
//     password changed — we conservatively allow the overwrite since we can't
//     verify the existing metadata)
func (s *WorkerService) checkVaultCollision(incoming *vaultType.Vault, password string) error {
	filePathName := incoming.PublicKeyEcdsa + ".bak"
	existing, err := s.blockStorage.GetFile(filePathName)
	if err != nil {
		// File does not exist — first registration, no collision possible.
		return nil
	}
	return detectVaultCollision(incoming, password, existing, s.logger)
}

// detectVaultCollision is the pure core of checkVaultCollision, extracted so
// it can be tested without a real BlockStorage.
func detectVaultCollision(incoming *vaultType.Vault, password string, existingFileData []byte, logger *logrus.Logger) error {
	if len(existingFileData) == 0 {
		// No existing file data — first registration, no collision possible.
		return nil
	}
	existingVault, err := common.DecryptVaultFromBackup(password, existingFileData)
	if err != nil {
		// Can't decrypt — different password or corrupt file.
		// Conservatively allow: we can't verify whether it collides.
		if logger != nil {
			logger.WithField("pubkey", incoming.PublicKeyEcdsa).
				Warn("checkVaultCollision: failed to decrypt existing vault; allowing overwrite")
		}
		return nil
	}

	// Exact same metadata → idempotent re-write, always allow.
	if existingVault.PublicKeyEddsa == incoming.PublicKeyEddsa &&
		existingVault.HexChainCode == incoming.HexChainCode &&
		existingVault.LocalPartyId == incoming.LocalPartyId {
		return nil
	}

	if logger != nil {
		logger.WithFields(logrus.Fields{
			"pubkey":             incoming.PublicKeyEcdsa,
			"existing_eddsa":     existingVault.PublicKeyEddsa,
			"incoming_eddsa":     incoming.PublicKeyEddsa,
			"existing_chaincode": existingVault.HexChainCode,
			"incoming_chaincode": incoming.HexChainCode,
			"existing_partyid":   existingVault.LocalPartyId,
			"incoming_partyid":   incoming.LocalPartyId,
		}).Warn("checkVaultCollision: vault metadata mismatch, rejecting overwrite (use ?force=true to override)")
	}

	return fmt.Errorf("%w (existing_eddsa=%s incoming_eddsa=%s)",
		ErrVaultCollision,
		existingVault.PublicKeyEddsa,
		incoming.PublicKeyEddsa,
	)
}

func getOldParties(newParties []string, oldSignerCommittee []string) []string {
	oldParties := make([]string, 0)
	for _, party := range oldSignerCommittee {
		if slices.Contains(newParties, party) {
			oldParties = append(oldParties, party)
		}
	}
	return oldParties
}

func (s *WorkerService) reshare(tssService *mtss.ServiceImpl,
	vault *vaultType.Vault,
	newParties []string,
	isEcdsa bool,
	newResharePrefix string,
) (string, string, error) {
	oldParties := getOldParties(newParties, vault.Signers)
	if isEcdsa {
		resp, err := s.reshareECDSAKey(tssService, vault.PublicKeyEcdsa, vault.LocalPartyId, vault.HexChainCode, vault.ResharePrefix,
			newParties, oldParties)
		if err != nil {
			return "", "", fmt.Errorf("failed to reshare ECDSA key: %w", err)
		}
		return resp.PubKey, resp.ResharePrefix, nil
	} else {
		resp, err := s.reshareEDDSAKey(tssService, vault.PublicKeyEddsa, vault.LocalPartyId, vault.HexChainCode, vault.ResharePrefix,
			newParties, oldParties, newResharePrefix)
		if err != nil {
			return "", "", fmt.Errorf("failed to reshare EDDSA key: %w", err)
		}
		return resp.PubKey, resp.ResharePrefix, nil
	}
}

func (s *WorkerService) reshareECDSAKey(tssService *mtss.ServiceImpl,
	publicKey string,
	localPartyID, hexChainCode string,
	resharePrefix string,
	partiesJoined []string,
	oldParties []string) (*mtss.ReshareResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"public_key":         publicKey,
		"localPartyID":       localPartyID,
		"chain_code":         hexChainCode,
		"reshare_prefix":     resharePrefix,
		"parties_joined":     partiesJoined,
		"old_parties":        oldParties,
		"new_reshare_prefix": "",
	}).Info("Start ECDSA reshare...")

	resp, err := tssService.ReshareECDSA(&mtss.ReshareRequest{
		PubKey:           publicKey,
		LocalPartyID:     localPartyID,
		NewParties:       strings.Join(partiesJoined, ","),
		OldParties:       strings.Join(oldParties, ","),
		ChainCodeHex:     hexChainCode,
		ResharePrefix:    resharePrefix,
		NewResharePrefix: "",
	})
	if err != nil {
		return nil, fmt.Errorf("fail to reshare ECDSA key: %w", err)
	}
	s.logger.WithFields(logrus.Fields{
		"key":     localPartyID,
		"pub_key": resp.PubKey,
	}).Info("ECDSA keygen response")

	return resp, nil
}

func (s *WorkerService) reshareEDDSAKey(tssService *mtss.ServiceImpl,
	publicKey string,
	localPartyID, hexChainCode string,
	resharePrefix string,
	partiesJoined []string,
	oldParties []string,
	newResharePrefix string) (*mtss.ReshareResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"public_key":         publicKey,
		"localPartyID":       localPartyID,
		"chain_code":         hexChainCode,
		"reshare_prefix":     resharePrefix,
		"parties_joined":     partiesJoined,
		"old_parties":        oldParties,
		"new_reshare_prefix": newResharePrefix,
	}).Info("Start EdDSA keygen...")
	resp, err := tssService.ResharingEdDSA(&mtss.ReshareRequest{
		PubKey:           publicKey,
		LocalPartyID:     localPartyID,
		NewParties:       strings.Join(partiesJoined, ","),
		ChainCodeHex:     hexChainCode,
		OldParties:       strings.Join(oldParties, ","),
		ResharePrefix:    resharePrefix,
		NewResharePrefix: newResharePrefix,
	})
	if err != nil {
		return nil, fmt.Errorf("fail to reshare EdDSA key: %w", err)
	}
	s.logger.WithFields(logrus.Fields{
		"localPartyID": localPartyID,
		"pub_key":      resp.PubKey,
	}).Info("EdDSA reshare response")
	return resp, nil
}
