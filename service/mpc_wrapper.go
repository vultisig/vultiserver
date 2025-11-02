package service

import (
	"fmt"

	session "github.com/vultisig/go-wrappers/go-dkls/sessions"
	eddsaSession "github.com/vultisig/go-wrappers/go-schnorr/sessions"
)

type Handle int32
type MPCKeygenWrapper interface {
	KeygenSetupMsgNew(threshold int, keyID []byte, ids []byte) ([]byte, error)
	KeygenSessionFromSetup(setup []byte, id []byte) (Handle, error)
	KeyRefreshSessionFromSetup(setup []byte, id []byte, oldKeyshare Handle) (Handle, error)
	KeygenSessionOutputMessage(session Handle) ([]byte, error)
	KeygenSessionInputMessage(session Handle, message []byte) (bool, error)
	KeygenSessionMessageReceiver(session Handle, message []byte, index int) (string, error)
	KeygenSessionFinish(session Handle) (Handle, error)
	KeygenSessionFree(session Handle) error
	MigrateSessionFromSetup(setup []byte, id []byte, publicKey []byte, rootChainCode []byte, secretCoefficient []byte) (Handle, error)
}
type MPCKeysignWrapper interface {
	SignSetupMsgNew(keyID []byte, chainPath []byte, messageHash []byte, ids []byte) ([]byte, error)
	SignSessionFromSetup(setup []byte, id []byte, shareOrPresign Handle) (Handle, error)
	SignSessionOutputMessage(session Handle) ([]byte, error)
	SignSessionMessageReceiver(session Handle, message []byte, index int) ([]byte, error)
	SignSessionInputMessage(session Handle, message []byte) (bool, error)
	SignSessionFinish(session Handle) ([]byte, error)
	SignSessionFree(session Handle) error
}
type MPCQcWrapper interface {
	QcSetupMsgNew(keyshareHandle Handle, threshod int, ids []string, oldParties []int, newParties []int) ([]byte, error)
	QcSessionFromSetup(setupMsg []byte, id string, keyshareHandle Handle) (Handle, error)
	QcSessionOutputMessage(session Handle) ([]byte, error)
	QcSessionMessageReceiver(session Handle, message []byte, index int) (string, error)
	QcSessionInputMessage(session Handle, message []byte) (bool, error)
	QcSessionFinish(session Handle) (Handle, error)
}
type MPCKeyshareWrapper interface {
	KeyshareFromBytes(buf []byte) (Handle, error)
	KeyshareToBytes(share Handle) ([]byte, error)
	KeysharePublicKey(share Handle) ([]byte, error)
	KeyshareKeyID(share Handle) ([]byte, error)
	KeyshareDeriveChildPublicKey(share Handle, derivationPathStr []byte) ([]byte, error)
	KeyshareToRefreshBytes(share Handle) ([]byte, error)
	RefreshShareFromBytes(buf []byte) (Handle, error)
	RefreshShareToBytes(share Handle) ([]byte, error)
	KeyshareFree(share Handle) error
	KeyshareChainCode(share Handle) ([]byte, error)
}
type MPCSetupWrapper interface {
	DecodeKeyID(setup []byte) ([]byte, error)
	DecodeSessionID(setup []byte) ([]byte, error)
	DecodeMessage(setup []byte) ([]byte, error)
	DecodePartyName(setup []byte, index int) ([]byte, error)
}

type MPCKeyImportWrapper interface {
	KeyImportInitiatorNew(privateKey []byte, chainCode []byte, threshold uint8, ids []string) (Handle, []byte, error)
	KeyImporterNew(setup []byte, id string) (Handle, error)
}
type MPCHDWrapper interface {
	HdSetupMsgNew(keyID []byte, chainPath []byte, ids []byte) ([]byte, error)
	HdSessionFromSetup(setup []byte, id []byte, share Handle) (Handle, error)
	HdSessionInputMessage(session Handle, message []byte) (bool, error)
	HdSessionOutputMessage(session Handle) ([]byte, error)
	HdSessionMessageReceiver(session Handle, message []byte, index int) (string, error)
	HdSessionFinish(session Handle) (Handle, error)
	HdSessionFree(session Handle) error
}

var _ MPCKeygenWrapper = &MPCWrapperImp{}
var _ MPCKeysignWrapper = &MPCWrapperImp{}
var _ MPCKeyshareWrapper = &MPCWrapperImp{}
var _ MPCSetupWrapper = &MPCWrapperImp{}
var _ MPCQcWrapper = &MPCWrapperImp{}
var _ MPCKeyImportWrapper = &MPCWrapperImp{}
var _ MPCHDWrapper = &MPCWrapperImp{}

type MPCWrapperImp struct {
	isEdDSA bool
}

func (w *MPCWrapperImp) QcSetupMsgNew(keyshareHandle Handle, threshod int, ids []string, oldParties []int, newParties []int) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrQcSetupMsgNew(eddsaSession.Handle(keyshareHandle), threshod, ids, oldParties, newParties)
	}
	return session.DklsQcSetupMsgNew(session.Handle(keyshareHandle), threshod, ids, oldParties, newParties)
}

func (w *MPCWrapperImp) QcSessionFromSetup(setupMsg []byte, id string, keyshareHandle Handle) (Handle, error) {
	if w.isEdDSA {
		h, err := eddsaSession.SchnorrQcSessionFromSetup(setupMsg, id, eddsaSession.Handle(keyshareHandle))
		return Handle(h), err
	}
	h, err := session.DklsQcSessionFromSetup(setupMsg, id, session.Handle(keyshareHandle))
	return Handle(h), err
}

func (w *MPCWrapperImp) QcSessionOutputMessage(h Handle) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrQcSessionOutputMessage(eddsaSession.Handle(h))
	}
	return session.DklsQcSessionOutputMessage(session.Handle(h))
}

func (w *MPCWrapperImp) QcSessionMessageReceiver(h Handle, message []byte, index int) (string, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrQcSessionMessageReceiver(eddsaSession.Handle(h), message, index)
	}
	return session.DklsQcSessionMessageReceiver(session.Handle(h), message, index)
}

func (w *MPCWrapperImp) QcSessionInputMessage(h Handle, message []byte) (bool, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrQcSessionInputMessage(eddsaSession.Handle(h), message)
	}
	return session.DklsQcSessionInputMessage(session.Handle(h), message)
}

func (w *MPCWrapperImp) QcSessionFinish(h Handle) (Handle, error) {
	if w.isEdDSA {
		h1, err := eddsaSession.SchnorrQcSessionFinish(eddsaSession.Handle(h))
		return Handle(h1), err
	}
	shareHandle, err := session.DklsQcSessionFinish(session.Handle(h))
	return Handle(shareHandle), err
}

func NewMPCWrapperImp(isEdDSA bool) *MPCWrapperImp {
	return &MPCWrapperImp{
		isEdDSA: isEdDSA,
	}
}
func (w *MPCWrapperImp) KeygenSetupMsgNew(threshold int, keyID []byte, ids []byte) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrKeygenSetupMsgNew(int32(threshold), keyID, ids)
	}
	return session.DklsKeygenSetupMsgNew(threshold, keyID, ids)
}

func (w *MPCWrapperImp) KeygenSessionFromSetup(setup []byte, id []byte) (Handle, error) {
	if w.isEdDSA {
		h, err := eddsaSession.SchnorrKeygenSessionFromSetup(setup, id)
		return Handle(h), err
	}
	h, err := session.DklsKeygenSessionFromSetup(setup, id)
	return Handle(h), err
}
func (w *MPCWrapperImp) KeyRefreshSessionFromSetup(setup []byte, id []byte, oldKeyshare Handle) (Handle, error) {
	if w.isEdDSA {
		h, err := eddsaSession.SchnorrKeyRefreshSessionFromSetup(setup, id, eddsaSession.Handle(oldKeyshare))
		return Handle(h), err
	}
	h, err := session.DklsKeyRefreshSessionFromSetup(setup, id, session.Handle(oldKeyshare))
	return Handle(h), err
}
func (w *MPCWrapperImp) KeygenSessionOutputMessage(h Handle) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrKeygenSessionOutputMessage(eddsaSession.Handle(h))
	}
	return session.DklsKeygenSessionOutputMessage(session.Handle(h))
}
func (w *MPCWrapperImp) KeygenSessionInputMessage(h Handle, message []byte) (bool, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrKeygenSessionInputMessage(eddsaSession.Handle(h), message)
	}
	return session.DklsKeygenSessionInputMessage(session.Handle(h), message)
}

func (w *MPCWrapperImp) KeygenSessionMessageReceiver(h Handle, message []byte, index int) (string, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrKeygenSessionMessageReceiver(eddsaSession.Handle(h), message, uint32(index))
	}
	return session.DklsKeygenSessionMessageReceiver(session.Handle(h), message, index)
}

func (w *MPCWrapperImp) KeygenSessionFinish(h Handle) (Handle, error) {
	if w.isEdDSA {
		h1, err := eddsaSession.SchnorrKeygenSessionFinish(eddsaSession.Handle(h))
		return Handle(h1), err
	}
	h1, err := session.DklsKeygenSessionFinish(session.Handle(h))
	return Handle(h1), err
}

func (w *MPCWrapperImp) KeygenSessionFree(h Handle) error {
	if w.isEdDSA {
		return eddsaSession.SchnorrKeygenSessionFree(eddsaSession.Handle(h))
	}
	return session.DklsKeygenSessionFree(session.Handle(h))
}

func (w *MPCWrapperImp) MigrateSessionFromSetup(setup []byte, id []byte, publicKey []byte, rootChainCode []byte, secretCoefficient []byte) (Handle, error) {
	if w.isEdDSA {
		h, err := eddsaSession.SchnorrKeyMigrateSessionFromSetup(setup, id, publicKey, rootChainCode, secretCoefficient)
		return Handle(h), err
	}
	h, err := session.DklsKeyMigrateSessionFromSetup(setup, id, publicKey, rootChainCode, secretCoefficient)
	return Handle(h), err
}
func (w *MPCWrapperImp) SignSetupMsgNew(keyID []byte, chainPath []byte, messageHash []byte, ids []byte) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrSignSetupMsgNew(keyID, chainPath, messageHash, ids)
	}
	return session.DklsSignSetupMsgNew(keyID, chainPath, messageHash, ids)
}

func (w *MPCWrapperImp) SignSessionFromSetup(setup []byte, id []byte, shareOrPresign Handle) (Handle, error) {
	if w.isEdDSA {
		h, err := eddsaSession.SchnorrSignSessionFromSetup(setup, id, eddsaSession.Handle(shareOrPresign))
		return Handle(h), err
	}
	h, err := session.DklsSignSessionFromSetup(setup, id, session.Handle(shareOrPresign))
	return Handle(h), err
}
func (w *MPCWrapperImp) SignSessionOutputMessage(h Handle) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrSignSessionOutputMessage(eddsaSession.Handle(h))
	}
	return session.DklsSignSessionOutputMessage(session.Handle(h))
}
func (w *MPCWrapperImp) SignSessionMessageReceiver(h Handle, message []byte, index int) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrSignSessionMessageReceiver(eddsaSession.Handle(h), message, uint32(index))
	}
	return session.DklsSignSessionMessageReceiver(session.Handle(h), message, index)
}
func (w *MPCWrapperImp) SignSessionInputMessage(h Handle, message []byte) (bool, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrSignSessionInputMessage(eddsaSession.Handle(h), message)
	}
	return session.DklsSignSessionInputMessage(session.Handle(h), message)
}
func (w *MPCWrapperImp) SignSessionFinish(h Handle) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrSignSessionFinish(eddsaSession.Handle(h))
	}
	return session.DklsSignSessionFinish(session.Handle(h))
}
func (w *MPCWrapperImp) SignSessionFree(h Handle) error {
	if w.isEdDSA {
		return eddsaSession.SchnorrSignSessionFree(eddsaSession.Handle(h))
	}
	return session.DklsSignSessionFree(session.Handle(h))
}
func (w *MPCWrapperImp) KeyshareFromBytes(buf []byte) (Handle, error) {
	if w.isEdDSA {
		h, err := eddsaSession.SchnorrKeyshareFromBytes(buf)
		return Handle(h), err
	}
	h, err := session.DklsKeyshareFromBytes(buf)
	return Handle(h), err
}
func (w *MPCWrapperImp) KeyshareToBytes(share Handle) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrKeyshareToBytes(eddsaSession.Handle(share))
	}
	return session.DklsKeyshareToBytes(session.Handle(share))
}
func (w *MPCWrapperImp) KeysharePublicKey(share Handle) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrKeysharePublicKey(eddsaSession.Handle(share))
	}
	return session.DklsKeysharePublicKey(session.Handle(share))
}
func (w *MPCWrapperImp) KeyshareKeyID(share Handle) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrKeyshareKeyID(eddsaSession.Handle(share))
	}
	return session.DklsKeyshareKeyID(session.Handle(share))
}
func (w *MPCWrapperImp) KeyshareDeriveChildPublicKey(share Handle, derivationPathStr []byte) ([]byte, error) {
	if w.isEdDSA {
		return nil, fmt.Errorf("Not implemented")
	}
	return session.DklsKeyshareDeriveChildPublicKey(session.Handle(share), derivationPathStr)
}
func (w *MPCWrapperImp) KeyshareToRefreshBytes(share Handle) ([]byte, error) {
	if w.isEdDSA {
		return nil, fmt.Errorf("Not implemented")
	}
	return session.DklsKeyshareToRefreshBytes(session.Handle(share))
}
func (w *MPCWrapperImp) RefreshShareFromBytes(buf []byte) (Handle, error) {
	if w.isEdDSA {
		return Handle(0), fmt.Errorf("Not implemented")
	}
	h, err := session.DklsRefreshShareFromBytes(buf)
	return Handle(h), err
}

func (w *MPCWrapperImp) RefreshShareToBytes(share Handle) ([]byte, error) {
	if w.isEdDSA {
		return nil, fmt.Errorf("Not implemented")
	}
	return session.DklsRefreshShareToBytes(session.Handle(share))
}
func (w *MPCWrapperImp) KeyshareFree(share Handle) error {
	if w.isEdDSA {
		return nil
	}
	return session.DklsKeyshareFree(session.Handle(share))
}
func (w *MPCWrapperImp) KeyshareChainCode(share Handle) ([]byte, error) {
	if w.isEdDSA {
		return nil, nil
	}
	return session.DklsKeyshareChainCode(session.Handle(share))
}
func (w *MPCWrapperImp) DecodeKeyID(setup []byte) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrDecodeKeyID(setup)
	}
	return session.DklsDecodeKeyID(setup)
}

func (w *MPCWrapperImp) DecodeSessionID(setup []byte) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrDecodeSessionID(setup)
	}
	return nil, fmt.Errorf("not implemented")
}
func (w *MPCWrapperImp) DecodeMessage(setup []byte) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrDecodeMessage(setup)
	}
	return session.DklsDecodeMessage(setup)
}
func (w *MPCWrapperImp) DecodePartyName(setup []byte, index int) ([]byte, error) {
	if w.isEdDSA {
		return eddsaSession.SchnorrDecodePartyName(setup, index)
	}
	return session.DklsDecodePartyName(setup, index)
}

func (w *MPCWrapperImp) HdSessionFree(h Handle) error {
	if w.isEdDSA {
		return fmt.Errorf("EdDSA HD not implemented")
	}
	return session.DklsHdSessionFree(session.Handle(h))
}

func (w *MPCWrapperImp) HdSetupMsgNew(keyID []byte, chainPath []byte, ids []byte) ([]byte, error) {
	if w.isEdDSA {
		return nil, fmt.Errorf("EdDSA HD not implemented")
	}
	return session.DklsHdSetupMsgNew(keyID, chainPath, ids)
}

func (w *MPCWrapperImp) HdSessionFromSetup(setup []byte, id []byte, share Handle) (Handle, error) {
	if w.isEdDSA {
		return Handle(0), fmt.Errorf("EdDSA HD not implemented")
	}
	h, err := session.DklsHdSessionFromSetup(setup, id, session.Handle(share))
	return Handle(h), err
}

func (w *MPCWrapperImp) HdSessionInputMessage(h Handle, message []byte) (bool, error) {
	if w.isEdDSA {
		return false, fmt.Errorf("EdDSA HD not implemented")
	}
	return session.DklsHdSessionInputMessage(session.Handle(h), message)
}

func (w *MPCWrapperImp) HdSessionOutputMessage(h Handle) ([]byte, error) {
	if w.isEdDSA {
		return nil, fmt.Errorf("EdDSA HD not implemented")
	}
	return session.DklsHdSessionOutputMessage(session.Handle(h))
}

func (w *MPCWrapperImp) HdSessionMessageReceiver(h Handle, message []byte, index int) (string, error) {
	if w.isEdDSA {
		return "", fmt.Errorf("EdDSA HD not implemented")
	}
	return session.DklsHdSessionMessageReceiver(session.Handle(h), message, index)
}

func (w *MPCWrapperImp) HdSessionFinish(h Handle) (Handle, error) {
	if w.isEdDSA {
		return Handle(0), fmt.Errorf("EdDSA HD not implemented")
	}
	sh, err := session.DklsHdSessionFinish(session.Handle(h))
	return Handle(sh), err
}

func (w *MPCWrapperImp) KeyImportInitiatorNew(privateKey []byte, chainCode []byte, threshold uint8, ids []string) (Handle, []byte, error) {
	if w.isEdDSA {
		handle, setupMsg, err := eddsaSession.SchnorrKeyImportInitiatorNew(privateKey, chainCode, threshold, ids)
		return Handle(handle), setupMsg, err
	}
	handle, setupMsg, err := session.DklsKeyImportInitiatorNew(privateKey, chainCode, threshold, ids)
	return Handle(handle), setupMsg, err
}

func (w *MPCWrapperImp) KeyImporterNew(setup []byte, id string) (Handle, error) {
	if w.isEdDSA {
		handle, err := eddsaSession.SchnorrKeyImporterNew(setup, id)
		return Handle(handle), err
	}
	handle, err := session.DklsKeyImporter(setup, id)
	return Handle(handle), err
}
