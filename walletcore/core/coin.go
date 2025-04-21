package core

// #include <TrustWalletCore/TWCoinType.h>
// #include <TrustWalletCore/TWCoinTypeConfiguration.h>
// #include <TrustWalletCore/TWBitcoinScript.h>
import "C"

import "github.com/vultisig/vultiserver/walletcore/types"

type CoinType uint32

const (
	CoinTypeBitcoin     CoinType = C.TWCoinTypeBitcoin
	CoinTypeBitcoinCash CoinType = C.TWCoinTypeBitcoinCash
	CoinTypeLitecoin    CoinType = C.TWCoinTypeLitecoin
	CoinTypeDash        CoinType = C.TWCoinTypeDash
	CoinTypeDogecoin    CoinType = C.TWCoinTypeDogecoin
	CoinTypeZcash       CoinType = C.TWCoinTypeZcash
	CoinTypeKujira      CoinType = C.TWCoinTypeKujira
	CoinTypeBinance     CoinType = C.TWCoinTypeBinance
	CoinTypeEthereum    CoinType = C.TWCoinTypeEthereum
	CoinTypeTron        CoinType = C.TWCoinTypeTron
	CoinTypeTHORChain   CoinType = C.TWCoinTypeTHORChain
	CoinTypeCosmos      CoinType = C.TWCoinTypeCosmos
	CoinTypeDydx        CoinType = C.TWCoinTypeDydx
	CoinTypeSmartChain  CoinType = C.TWCoinTypeSmartChain
	CoinTypeSolana      CoinType = C.TWCoinTypeSolana
	CoinTypePolkadot    CoinType = C.TWCoinTypePolkadot
	CoinTypePolygon     CoinType = C.TWCoinTypePolygon
	CoinTypeSui         CoinType = C.TWCoinTypeSui
	CoinTypeBlast       CoinType = C.TWCoinTypeBlast
	CoinTypeBase        CoinType = C.TWCoinTypeBase
	CoinTypeArbitrum    CoinType = C.TWCoinTypeArbitrum
	CoinTypeOptimism    CoinType = C.TWCoinTypeOptimism
	CoinTypeAvalanche   CoinType = C.TWCoinTypeAvalancheCChain
	CoinTypeCronos      CoinType = C.TWCoinTypeCronosChain
	CoinTypeZKSync      CoinType = C.TWCoinTypeZksync
)

func (c CoinType) GetName() string {
	name := C.TWCoinTypeConfigurationGetName(C.enum_TWCoinType(c))
	defer C.TWStringDelete(name)
	return types.TWStringGoString(name)
}

func (c CoinType) Decimals() int {
	return int(C.TWCoinTypeConfigurationGetDecimals(C.enum_TWCoinType(c)))
}
func (c CoinType) ChainID() string {
	chainID := C.TWCoinTypeChainId(C.enum_TWCoinType(c))
	defer C.TWStringDelete(chainID)
	return types.TWStringGoString(chainID)
}
func (c CoinType) DerivationPath() string {
	derivationPath := C.TWCoinTypeDerivationPath(C.enum_TWCoinType(c))
	defer C.TWStringDelete(derivationPath)
	return types.TWStringGoString(derivationPath)
}
