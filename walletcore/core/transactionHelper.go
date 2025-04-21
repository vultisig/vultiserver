package core

// #include <TrustWalletCore/TWTransactionCompiler.h>
import "C"
import "github.com/vultisig/vultiserver/walletcore/types"

func PreImageHashes(c CoinType, txInputData []byte) []byte {
	input := types.TWDataCreateWithGoBytes(txInputData)
	defer C.TWDataDelete(input)

	result := C.TWTransactionCompilerPreImageHashes(C.enum_TWCoinType(c), input)
	defer C.TWDataDelete(result)
	return types.TWDataGoBytes(result)
}

func CompileWithSignatures(c CoinType, txInputData []byte, signatures [][]byte, publicKeyHashes [][]byte) []byte {
	input := types.TWDataCreateWithGoBytes(txInputData)
	defer C.TWDataDelete(input)

	sigs := TWDataVectorCreateWithGoBytes(signatures)
	defer C.TWDataVectorDelete(sigs)
	pubkeyhashes := TWDataVectorCreateWithGoBytes(publicKeyHashes)
	defer C.TWDataVectorDelete(pubkeyhashes)

	result := C.TWTransactionCompilerCompileWithSignatures(C.enum_TWCoinType(c), input, sigs, pubkeyhashes)
	defer C.TWDataDelete(result)
	return types.TWDataGoBytes(result)
}
