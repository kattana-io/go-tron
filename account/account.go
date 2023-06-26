// Package account provides functionality for managing Tron network accounts.
package account

import (
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/kattana-io/go-tron"
	"github.com/kattana-io/go-tron/address"
)

type Account interface {
	Address() address.Address
	tron.Signer
}

// LocalAccount is a private key address pair.
// TODO(271): Add more functionality to this.
type LocalAccount struct {
	addr address.Address
	priv *ecdsa.PrivateKey
}

// FromPrivateKeyHex derives an account from a hexadecimal private key string.
func FromPrivateKeyHex(hex string) (*LocalAccount, error) {
	priv, err := crypto.HexToECDSA(hex)
	if err != nil {
		return nil, err
	}

	return &LocalAccount{
		addr: address.FromPublicKey(&priv.PublicKey),
		priv: priv,
	}, nil
}

// Address returns the address of the account.
func (a *LocalAccount) Address() address.Address {
	return a.addr
}

// Sign signs a signable object with the account's private key.
func (a *LocalAccount) Sign(signable tron.Signable) error {
	return signable.Sign(a.priv)
}
