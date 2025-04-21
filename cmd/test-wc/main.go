package main

import (
	"fmt"

	"github.com/vultisig/vultiserver/walletcore/core"
)

func main() {
	coinType := core.CoinTypeTHORChain
	name := coinType.ChainID()
	fmt.Print(name)
}
