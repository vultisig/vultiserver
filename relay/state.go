package relay

import (
	"fmt"
	"os"
	"sync"

	vaultType "github.com/vultisig/commondata/go/vultisig/vault/v1"

	"github.com/vultisig/vultiserver/common"
	"github.com/vultisig/vultiserver/storage"
)

type LocalStateAccessorImp struct {
	Folder       string
	Vault        *vaultType.Vault
	cache        sync.Map
	blockStorage *storage.BlockStorage
}

func NewLocalStateAccessorImp(folder, vaultFileName, vaultPasswd string,
	storage *storage.BlockStorage) (*LocalStateAccessorImp, error) {
	localStateAccessor := &LocalStateAccessorImp{
		Folder:       folder,
		Vault:        nil,
		blockStorage: storage,
	}

	var err error
	if localStateAccessor.Folder == "" {
		localStateAccessor.Folder, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current directory: %w", err)
		}
	}

	if vaultFileName != "" {
		buf, err := storage.GetFile(vaultFileName + ".bak")
		if err != nil {
			return nil, fmt.Errorf("fail to get vault file: %w", err)
		}
		localStateAccessor.Vault, err = common.DecryptVaultFromBackup(vaultPasswd, buf)
		if err != nil {
			return nil, fmt.Errorf("fail to decrypt vault from the backup, err: %w", err)
		}
	}

	return localStateAccessor, nil
}

func (l *LocalStateAccessorImp) GetLocalState(pubKey string) (string, error) {
	if l.Vault != nil {
		for _, item := range l.Vault.KeyShares {
			if item.PublicKey == pubKey {
				return item.Keyshare, nil
			}
		}
		return "", fmt.Errorf("%s keyshare does not exist", pubKey)
	}
	val, ok := l.cache.Load(pubKey)
	if !ok {
		return "", nil
	}
	state, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("invalid cached local state type for key %s", pubKey)
	}
	return state, nil
}

func (l *LocalStateAccessorImp) SaveLocalState(pubKey, localState string) error {
	l.cache.Store(pubKey, localState)
	return nil
}

func (l *LocalStateAccessorImp) GetLocalCacheState(pubKey string) (string, error) {
	val, ok := l.cache.Load(pubKey)
	if !ok {
		return "", nil
	}
	state, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("invalid cached state type for key %s", pubKey)
	}
	return state, nil
}
