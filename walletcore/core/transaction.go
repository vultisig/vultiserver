package core

// #include <TrustWalletCore/TWCoinType.h>
// #include <TrustWalletCore/TWAnySigner.h>
import "C"

import (
	"github.com/vultisig/vultiserver/walletcore/types"

	"google.golang.org/protobuf/proto"
)

func CreateSignedTx(inputData proto.Message, ct CoinType, outputData proto.Message) error {
	ibytes, _ := proto.Marshal(inputData)
	idata := types.TWDataCreateWithGoBytes(ibytes)
	defer C.TWDataDelete(idata)

	odata := C.TWAnySignerSign(idata, C.enum_TWCoinType(ct))
	defer C.TWDataDelete(odata)

	err := proto.Unmarshal(types.TWDataGoBytes(odata), outputData)
	if err != nil {
		return err
	}
	return nil
}

func AnySignerPlan(inputData []byte, ct CoinType) ([]byte, error) {
	idata := types.TWDataCreateWithGoBytes(inputData)
	defer C.TWDataDelete(idata)

	odata := C.TWAnySignerPlan(idata, C.enum_TWCoinType(ct))
	defer C.TWDataDelete(odata)

	return types.TWDataGoBytes(odata), nil
}
