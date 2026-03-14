package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"

	"github.com/vultisig/vultiserver/contexthelper"
	"github.com/vultisig/vultiserver/internal/types"
	"github.com/vultisig/vultiserver/relay"
)

func (s *WorkerService) HandleKeySignFrozt(ctx context.Context, t *asynq.Task) error {
	if err := contexthelper.CheckCancellation(ctx); err != nil {
		return err
	}
	var p types.KeysignRequest
	unmarshalErr := json.Unmarshal(t.Payload(), &p)
	if unmarshalErr != nil {
		s.logger.Errorf("json.Unmarshal failed: %v", unmarshalErr)
		return fmt.Errorf("json.Unmarshal failed: %v: %w", unmarshalErr, asynq.SkipRetry)
	}
	defer s.measureTime("worker.vault.sign.frozt.latency", time.Now(), []string{})
	s.incCounter("worker.vault.sign.frozt", []string{})
	s.logger.WithField("session", p.SessionID).Info("joining frozt keysign")

	localStateAccessor, err := relay.NewLocalStateAccessorImp(s.cfg.Server.VaultsFilePath, "", "", s.blockStorage)
	if err != nil {
		return fmt.Errorf("relay.NewLocalStateAccessorImp failed: %s: %w", err, asynq.SkipRetry)
	}
	dklsService, err := NewDKLSTssService(s.cfg, s.blockStorage, localStateAccessor, s)
	if err != nil {
		return fmt.Errorf("NewDKLSTssService failed: %s: %w", err, asynq.SkipRetry)
	}

	signatures, signErr := dklsService.ProcessFroztKeysign(p)
	if signErr != nil {
		s.logger.Errorf("frozt keysign failed: %v", signErr)
		return fmt.Errorf("frozt keysign failed: %v: %w", signErr, asynq.SkipRetry)
	}

	s.logger.Info("frozt keysign completed")

	resultBytes, marshalErr := json.Marshal(signatures)
	if marshalErr != nil {
		return fmt.Errorf("json.Marshal failed: %v: %w", marshalErr, asynq.SkipRetry)
	}
	_, writeErr := t.ResultWriter().Write(resultBytes)
	if writeErr != nil {
		return fmt.Errorf("t.ResultWriter.Write failed: %v: %w", writeErr, asynq.SkipRetry)
	}
	return nil
}

func (s *WorkerService) HandleKeySignFromt(ctx context.Context, t *asynq.Task) error {
	if err := contexthelper.CheckCancellation(ctx); err != nil {
		return err
	}
	var p types.KeysignRequest
	unmarshalErr := json.Unmarshal(t.Payload(), &p)
	if unmarshalErr != nil {
		s.logger.Errorf("json.Unmarshal failed: %v", unmarshalErr)
		return fmt.Errorf("json.Unmarshal failed: %v: %w", unmarshalErr, asynq.SkipRetry)
	}
	defer s.measureTime("worker.vault.sign.fromt.latency", time.Now(), []string{})
	s.incCounter("worker.vault.sign.fromt", []string{})
	s.logger.WithField("session", p.SessionID).Info("joining fromt keysign")

	localStateAccessor, err := relay.NewLocalStateAccessorImp(s.cfg.Server.VaultsFilePath, "", "", s.blockStorage)
	if err != nil {
		return fmt.Errorf("relay.NewLocalStateAccessorImp failed: %s: %w", err, asynq.SkipRetry)
	}
	dklsService, err := NewDKLSTssService(s.cfg, s.blockStorage, localStateAccessor, s)
	if err != nil {
		return fmt.Errorf("NewDKLSTssService failed: %s: %w", err, asynq.SkipRetry)
	}

	signatures, signErr := dklsService.ProcessFromtKeysign(p)
	if signErr != nil {
		s.logger.Errorf("fromt keysign failed: %v", signErr)
		return fmt.Errorf("fromt keysign failed: %v: %w", signErr, asynq.SkipRetry)
	}

	s.logger.Info("fromt keysign completed")

	resultBytes, marshalErr := json.Marshal(signatures)
	if marshalErr != nil {
		return fmt.Errorf("json.Marshal failed: %v: %w", marshalErr, asynq.SkipRetry)
	}
	_, writeErr := t.ResultWriter().Write(resultBytes)
	if writeErr != nil {
		return fmt.Errorf("t.ResultWriter.Write failed: %v: %w", writeErr, asynq.SkipRetry)
	}
	return nil
}
