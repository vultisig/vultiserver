![Build Status](https://github.com/vultisig/vultiserver/actions/workflows/go.yml/badge.svg?branch=main)
# Vultiserver
`VultiServer`, is a simple TSS server providing Keygen, Keysign, and Reshare services. 

Devs and Users can then use Fast Vaults: Allows creating a 2/2 vault with one mobile device, with VultiServer as the second party. Users can sign transactions with one device. The Server's encrypted vault share is emailed to the user for their full self-custody. 

VultiServer consists of two components:
- API Server: An HTTP server that handles keygen and keysign requests from clients.
- TSS Worker: A service triggered by the API Server to perform the actual TSS operations.

# API Server

## Production Base URL

Cloudflare managed Base URL (this server): https:api.vultisig.com/vault
Relay server (for coordinating MPC): https:api.vultisig.com/router
https://github.com/vultisig/vultisig-relay



## Ping
`/ping` , it provide a simple health check for the Api Server , the return value is `Vultisigner is running`

## Keygen
`POST` `/vault/create`
### Keygen Request
```json
{
  "name": "My Vault",
  "session_id": "session id for key generation",
  "hex_encryption_key": "hex encoded encryption key",
  "hex_chain_code": "hex encoded chain code",
  "local_party_id": "local party id",
  "encryption_password": "password to encryption the generated vault share",
  "email": "email of the user",
  "lib_type": "type of the library"
}
```
- name: Vault name
- session_id: Key generation session ID (random UUID)
- hex_chain_code: 32-byte hex encoded string
- hex_encryption_key: 32-byte hex encoded string for encryption/decryption
- local_party_id: Identifier for VultiServer in the keygen session
- encryption_password: Password to encrypt the vault share
- email: Email to send the encrypted vault share
- lib_type: Type of the library (e.g., 0 for GG20 , 1 for DKLS)
- 
### Response

Status Code: OK

## KeyImport
`POST` `/vault/import`
### KeyImport Request
```json
{
  "name": "My Vault",
  "session_id": "session id for key generation",
  "hex_encryption_key": "hex encoded encryption key",
  "hex_chain_code": "hex encoded chain code",
  "local_party_id": "local party id",
  "encryption_password": "password to encryption the generated vault share",
  "email": "email of the user",
  "lib_type": "type of the library"
}
```
- name: Vault name
- session_id: Key generation session ID (random UUID)
- hex_chain_code: 32-byte hex encoded string
- hex_encryption_key: 32-byte hex encoded string for encryption/decryption
- local_party_id: Identifier for VultiServer in the keygen session
- encryption_password: Password to encrypt the vault share
- email: Email to send the encrypted vault share
- lib_type: Type of the library KeyImport it has to be 2
-
### Response

Status Code: OK

## Keysign
`POST` `/vault/sign` , it is used to sign a transaction

### Keysign Request
```json
{
  "public_key": "ECDSA public key of the vault",
  "messages": [
    "hex encoded message 1",
    "hex encoded message 2",
    "hex encoded message N"
  ], 
  "session": "session id for this key sign", 
  "hex_encryption_key": "hex encoded encryption key",
  "derive_path": "derive path for the key sign",
  "is_ecdsa": "is the key sign ECDSA or not",
  "vault_password": "password to decrypt the vault share"
}
```
- public_key: ECDSA public key of the vault
- messages: Hex encoded messages to be signed
- session: Key sign session ID (random UUID)
- hex_encryption_key: 32-byte hex encoded string for encryption/decryption
- derive_path: Derive path for the key sign (e.g., BITCOIN: m/44'/0'/0'/0/0)
- is_ecdsa: Boolean indicating if the key sign is for ECDSA
- vault_password: Password to decrypt the vault share

## Get Vault
`GET` `/vault/get/{publicKeyECDSA}` , this endpoint allow user to get the vault information

Note: please set `x-password` header with the password to decrypt the vault share , if the password is empty or incorrect, server will return an error
### Response
```json
{
  "name": "vault name",
  "public_key_ecdsa": "ECDSA public key of the vault",
  "public_key_eddsa": "EdDSA public key of the vault",
  "hex_chain_code": "hex encoded chain code",
  "local_party_id": "local party id"
}
```

## Reshare
`POST` `/vault/reshare` , this endpoint allow user to reshare the vault share

### Reshare Request
```json
{
  "name": "My Vault",
  "public_key": "ECDSA public key of the vault",
  "session_id": "session id for key generation",
  "hex_encryption_key": "hex encoded encryption key",
  "hex_chain_code": "hex encoded chain code",
  "local_party_id": "local party id",
  "old_parties": ["old party id 1", "old party id 2"], 
  "encryption_password": "password to encryption the generated vault share",
  "email": "email of the user",
  "old_reshare_prefix":"old reshare prefix",
  "lib_type": "type of the library"
}
```
- name: Vault name
- public_key: ECDSA public key
- session_id: Reshare session ID (random UUID)
- hex_encryption_key: 32-byte hex encoded string for encryption/decryption
- hex_chain_code: 32-byte hex encoded string
- local_party_id: Identifier for VultiServer in the reshare session
- old_parties: List of old party IDs
- encryption_password: Password to encrypt the vault share
- email: Email to send the encrypted vault share
- lib_type: Type of the library (e.g., 0 for GG20 , 1 for DKLS)

## Resend vault share and verification code
`POST` `/vault/resend` , this endpoint allow user to resend the vault share and verification code
Note: user can only request a resend every three minutes

### Resend Request
```json
{
  "public_key_ecdsa": "ECDSA public key of the vault",
  "password": "password to decrypt the vault share",
  "email": "email of the user"
}
```
## Verify code
`GET` `/vault/verify/:public_key_ecdsa/:code` , this endpoint allow user to verify the code
if server return http status code 200, it means the code is valid , other status code means the code is invalid

### Migrate Request
`POST` `/vault/migrate` , this endpoint allow user to migrate the vault share from GG20 to DKLS
```json
{
  "public_key": "ECDSA public key of the vault",
  "session_id": "session id for key generation",
  "hex_encryption_key": "hex encoded encryption key",
  "encryption_password": "password to encryption the generated vault share",
  "email": "email of the user"
}
```
- public_key: ECDSA public key
- session_id: Reshare session ID (random UUID)
- hex_encryption_key: 32-byte hex encoded string for encryption/decryption
- encryption_password: Password to encrypt the vault share
- email: Email to send the encrypted vault share
## How to setup vultisigner to run locally?

### Prerequisites
- Docker
- Golang

### Setup redis using docker

`docker compose up -d --remove-orphans`

### Configuration

see config-example.yaml


