package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"

	"github.com/vultisig/vultiserver/contexthelper"
	"github.com/vultisig/vultiserver/internal/types"
	"github.com/vultisig/vultiserver/relay"
)

func (s *WorkerService) HandleKeyGenerationDKLS(ctx context.Context, t *asynq.Task) error {
	if err := contexthelper.CheckCancellation(ctx); err != nil {
		return err
	}
	defer s.measureTime("worker.vault.create.latency", time.Now(), []string{})
	var req types.VaultCreateRequest
	if err := json.Unmarshal(t.Payload(), &req); err != nil {
		return fmt.Errorf("json.Unmarshal failed: %v: %w", err, asynq.SkipRetry)
	}
	if req.LibType != types.DKLS {
		return fmt.Errorf("invalid lib type: %d: %w", req.LibType, asynq.SkipRetry)
	}
	s.logger.WithFields(logrus.Fields{
		"name":           req.Name,
		"session":        req.SessionID,
		"local_party_id": req.LocalPartyId,
		"email":          req.Email,
	}).Info("Joining keygen")
	s.incCounter("worker.vault.create.dkls", []string{})
	if err := req.IsValid(); err != nil {
		return fmt.Errorf("invalid vault create request: %s: %w", err, asynq.SkipRetry)
	}
	localStateAccessor, err := relay.NewLocalStateAccessorImp(s.cfg.Server.VaultsFilePath, "", "", s.blockStorage)
	if err != nil {
		return fmt.Errorf("relay.NewLocalStateAccessorImp failed: %s: %w", err, asynq.SkipRetry)
	}
	dklsService, err := NewDKLSTssService(s.cfg, s.blockStorage, localStateAccessor, s)
	if err != nil {
		return fmt.Errorf("NewDKLSTssService failed: %s: %w", err, asynq.SkipRetry)
	}
	keyECDSA, keyEDDSA, err := dklsService.ProceeDKLSKeygen(req)
	if err != nil {
		_ = s.sdClient.Count("worker.vault.create.dkls.error", 1, nil, 1)
		s.logger.Errorf("keygen.JoinKeyGeneration failed: %v", err)
		return fmt.Errorf("keygen.JoinKeyGeneration failed: %v: %w", err, asynq.SkipRetry)
	}

	s.logger.WithFields(logrus.Fields{
		"keyECDSA": keyECDSA,
		"keyEDDSA": keyEDDSA,
	}).Info("localPartyID generation completed")

	result := KeyGenerationTaskResult{
		EDDSAPublicKey: keyEDDSA,
		ECDSAPublicKey: keyECDSA,
	}

	resultBytes, err := json.Marshal(result)
	if err != nil {
		s.logger.Errorf("json.Marshal failed: %v", err)
		return fmt.Errorf("json.Marshal failed: %v: %w", err, asynq.SkipRetry)
	}

	if _, err := t.ResultWriter().Write(resultBytes); err != nil {
		s.logger.Errorf("t.ResultWriter.Write failed: %v", err)
		return fmt.Errorf("t.ResultWriter.Write failed: %v: %w", err, asynq.SkipRetry)
	}

	return nil
}

func (s *WorkerService) HandleKeySignDKLS(ctx context.Context, t *asynq.Task) error {
	if err := contexthelper.CheckCancellation(ctx); err != nil {
		return err
	}
	var p types.KeysignRequest
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		s.logger.Errorf("json.Unmarshal failed: %v", err)
		return fmt.Errorf("json.Unmarshal failed: %v: %w", err, asynq.SkipRetry)
	}
	defer s.measureTime("worker.vault.sign.latency", time.Now(), []string{})
	s.incCounter("worker.vault.sign", []string{})
	s.logger.WithFields(logrus.Fields{
		"PublicKey":  p.PublicKey,
		"session":    p.SessionID,
		"Messages":   p.Messages,
		"DerivePath": p.DerivePath,
		"IsECDSA":    p.IsECDSA,
	}).Info("joining keysign")

	localStateAccessor, err := relay.NewLocalStateAccessorImp(s.cfg.Server.VaultsFilePath, "", "", s.blockStorage)
	if err != nil {
		return fmt.Errorf("relay.NewLocalStateAccessorImp failed: %s: %w", err, asynq.SkipRetry)
	}
	dklsService, err := NewDKLSTssService(s.cfg, s.blockStorage, localStateAccessor, s)
	if err != nil {
		return fmt.Errorf("NewDKLSTssService failed: %s: %w", err, asynq.SkipRetry)
	}

	signatures, err := dklsService.ProcessDKLSKeysign(p)
	if err != nil {
		s.logger.Errorf("join keysign failed: %v", err)
		return fmt.Errorf("join keysign failed: %v: %w", err, asynq.SkipRetry)
	}

	s.logger.WithFields(logrus.Fields{
		"Signatures": signatures,
	}).Info("localPartyID sign completed")

	resultBytes, err := json.Marshal(signatures)
	if err != nil {
		s.logger.Errorf("json.Marshal failed: %v", err)
		return fmt.Errorf("json.Marshal failed: %v: %w", err, asynq.SkipRetry)
	}

	if _, err := t.ResultWriter().Write(resultBytes); err != nil {
		s.logger.Errorf("t.ResultWriter.Write failed: %v", err)
		return fmt.Errorf("t.ResultWriter.Write failed: %v: %w", err, asynq.SkipRetry)
	}

	return nil
}

func (s *WorkerService) HandleImport(ctx context.Context, t *asynq.Task) error {
	if err := contexthelper.CheckCancellation(ctx); err != nil {
		return err
	}
	defer s.measureTime("worker.vault.import.latency", time.Now(), []string{})
	var req types.VaultCreateRequest
	if err := json.Unmarshal(t.Payload(), &req); err != nil {
		return fmt.Errorf("json.Unmarshal failed: %v: %w", err, asynq.SkipRetry)
	}
	if req.LibType != types.KeyImport {
		return fmt.Errorf("invalid lib type: %d: %w", req.LibType, asynq.SkipRetry)
	}
	s.logger.WithFields(logrus.Fields{
		"name":           req.Name,
		"session":        req.SessionID,
		"local_party_id": req.LocalPartyId,
		"email":          req.Email,
	}).Info("Joining KeyImport")
	s.incCounter("worker.vault.import.dkls", []string{})
	if err := req.IsValid(); err != nil {
		return fmt.Errorf("invalid vault import request: %s: %w", err, asynq.SkipRetry)
	}
	localStateAccessor, err := relay.NewLocalStateAccessorImp(s.cfg.Server.VaultsFilePath, "", "", s.blockStorage)
	if err != nil {
		return fmt.Errorf("relay.NewLocalStateAccessorImp failed: %s: %w", err, asynq.SkipRetry)
	}
	dklsService, err := NewDKLSTssService(s.cfg, s.blockStorage, localStateAccessor, s)
	if err != nil {
		return fmt.Errorf("NewDKLSTssService failed: %s: %w", err, asynq.SkipRetry)
	}
	keyECDSA, keyEDDSA, err := dklsService.ProcessDKLSKeyImport(req)
	if err != nil {
		_ = s.sdClient.Count("worker.vault.import.dkls.error", 1, nil, 1)
		s.logger.Errorf("keygen.KeyImport failed: %v", err)
		return fmt.Errorf("keygen.KeyImport failed: %v: %w", err, asynq.SkipRetry)
	}

	s.logger.WithFields(logrus.Fields{
		"keyECDSA": keyECDSA,
		"keyEDDSA": keyEDDSA,
	}).Info("localPartyID generation completed")

	result := KeyGenerationTaskResult{
		EDDSAPublicKey: keyEDDSA,
		ECDSAPublicKey: keyECDSA,
	}

	resultBytes, err := json.Marshal(result)
	if err != nil {
		s.logger.Errorf("json.Marshal failed: %v", err)
		return fmt.Errorf("json.Marshal failed: %v: %w", err, asynq.SkipRetry)
	}

	if _, err := t.ResultWriter().Write(resultBytes); err != nil {
		s.logger.Errorf("t.ResultWriter.Write failed: %v", err)
		return fmt.Errorf("t.ResultWriter.Write failed: %v: %w", err, asynq.SkipRetry)
	}

	return nil
}
