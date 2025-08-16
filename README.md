# VultiServer

![Build Status](https://github.com/vultisig/vultiserver/actions/workflows/go.yml/badge.svg?branch=main)

TSS (Threshold Signature Scheme) server providing distributed cryptographic operations for secure multi-party vaults. Enables 2-of-2 and 2-of-3 vaults where no single party controls complete private keys.

## Users (Vault Developers)

### Health Check
`GET /ping` - Returns `"Vultiserver is running"` for API server health verification

### Core Operations

#### 1. Keygen - Create New Vault
`POST /vault/create`

Creates a new multi-party vault with distributed key shares.

```json
{
  "name": "My Vault",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "hex_encryption_key": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
  "hex_chain_code": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 
  "local_party_id": "server_party_1",
  "encryption_password": "password for vault backup",
  "email": "user@example.com",
  "lib_type": 1
}
```

**Parameters:**
- `name`: Vault name (string)
- `session_id`: Key generation session ID (random UUID, generate with `uuid.v4()`)
- `hex_encryption_key`: 32-byte hex encoded string for encryption/decryption (64-char hex, generate with `crypto.randomBytes(32).toString('hex')`)
- `hex_chain_code`: 32-byte hex encoded string (64-char hex, generate with `crypto.randomBytes(32).toString('hex')`)
- `local_party_id`: Identifier for VultiServer in the keygen session (string, when empty server generates random ID)
- `encryption_password`: Password to encrypt the vault share (string)
- `email`: Email to send the encrypted vault share (valid email format)
- `lib_type`: Type of the library (`1` = DKLS preferred, `0` = GG20 legacy)

**Response:** Status Code: OK

#### 2. Keysign - Sign Transactions  
`POST /vault/sign` - It is used to sign a transaction

Signs transaction messages using distributed key shares.

```json
{
  "public_key": "04a1b2c3d4e5f67890123456789012345678901234567890123456789012345678901234",
  "messages": ["deadbeef1234567890abcdef", "cafebabe9876543210fedcba"],
  "session": "550e8400-e29b-41d4-a716-446655440001", 
  "hex_encryption_key": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
  "derive_path": "m/44'/0'/0'/0/0",
  "is_ecdsa": true,
  "vault_password": "password from keygen"
}
```

**Parameters:**
- `public_key`: ECDSA public key of the vault (66-char hex string starting with '04')
- `messages`: Hex encoded messages to be signed (array of hex strings, no '0x' prefix)
- `session`: Session ID for this key sign (random UUID, generate with `uuid.v4()`)
- `hex_encryption_key`: 32-byte hex encoded string for encryption/decryption (64-char hex, generate with `crypto.randomBytes(32).toString('hex')`)
- `derive_path`: Derive path for the key sign (string, e.g., BITCOIN: `"m/44'/0'/0'/0/0"`, ETHEREUM: `"m/44'/60'/0'/0/0"`)
- `is_ecdsa`: Boolean indicating if the key sign is for ECDSA (`true` for ECDSA, `false` for EdDSA)
- `vault_password`: Password to decrypt the vault share (string)

Returns: `{"messageHash": {"r": "...", "s": "...", "recovery_id": 0}}`

#### 3. Reshare - Rotate Key Shares
`POST /vault/reshare` - This endpoint allows user to reshare the vault share

Redistributes key shares among new parties while preserving public keys.

```json
{
  "name": "My Vault", 
  "public_key": "04a1b2c3d4e5f67890123456789012345678901234567890123456789012345678901234",
  "session_id": "550e8400-e29b-41d4-a716-446655440002",
  "hex_encryption_key": "b2c3d4e5f6789012345678901234567890123456789012345678901234567890a1b2",
  "hex_chain_code": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  "local_party_id": "server_party_2", 
  "old_parties": ["server_party_1", "mobile_device_1"],
  "encryption_password": "new password for backup",
  "email": "user@example.com",
  "old_reshare_prefix": "",
  "lib_type": 1,
  "reshare_type": 0
}
```

**Parameters:**
- `name`: Vault name (string)
- `public_key`: ECDSA public key (66-char hex string starting with '04')
- `session_id`: Reshare session ID (random UUID, generate with `uuid.v4()`)
- `hex_encryption_key`: 32-byte hex encoded string for encryption/decryption (64-char hex, generate with `crypto.randomBytes(32).toString('hex')`)
- `hex_chain_code`: 32-byte hex encoded string (64-char hex from original vault)
- `local_party_id`: Identifier for VultiServer in the reshare session (string)
- `old_parties`: List of old party IDs (string array, must not be empty)
- `encryption_password`: Password to encrypt the vault share (string)
- `email`: Email to send the encrypted vault share (valid email format, required unless reshare_type is Plugin)
- `old_reshare_prefix`: Old reshare prefix (string, empty "" for first reshare)
- `lib_type`: Type of the library (`1` = DKLS preferred, `0` = GG20 legacy)
- `reshare_type`: `0` = Normal, `1` = Plugin (integer)

#### 4. Migration - Upgrade Legacy Vaults
`POST /vault/migrate` - This endpoint allows user to migrate the vault share from GG20 to DKLS

Migrates existing GG20 vaults to DKLS for improved performance.

```json
{
  "public_key": "04a1b2c3d4e5f67890123456789012345678901234567890123456789012345678901234",
  "session_id": "550e8400-e29b-41d4-a716-446655440003",
  "hex_encryption_key": "c3d4e5f6789012345678901234567890123456789012345678901234567890a1b2c3",
  "encryption_password": "new password for migrated vault",
  "email": "user@example.com"
}
```

**Parameters:**
- `public_key`: ECDSA public key of the vault (66-char hex string starting with '04')
- `session_id`: Migration session ID (random UUID, generate with `uuid.v4()`)
- `hex_encryption_key`: 32-byte hex encoded string for encryption/decryption (64-char hex, generate with `crypto.randomBytes(32).toString('hex')`)
- `encryption_password`: Password to encrypt the vault share (string)
- `email`: Email to send the encrypted vault share (valid email format)

### Additional Endpoints

#### Vault Information
`GET /vault/get/{publicKeyECDSA}` - This endpoint allows user to get the vault information

**Note:** Please set `x-password` header with the password to decrypt the vault share. If the password is empty or incorrect, server will return an error.

**Headers:** `x-password: base64(vault_password)` or plain vault password  
**Returns:**
```json
{
  "name": "vault name",
  "public_key_ecdsa": "ECDSA public key of the vault",
  "public_key_eddsa": "EdDSA public key of the vault",
  "hex_chain_code": "hex encoded chain code",
  "local_party_id": "local party id"
}
```
Use to verify vault exists and retrieve chain code for operations.

#### Vault Existence Check  
`GET /vault/exist/{publicKeyECDSA}` - Quick vault existence verification

**Returns:** HTTP 200 (exists) or 400 (not found)  
Use before attempting operations to avoid unnecessary API calls.

#### Resend Vault Share and Verification Code
`POST /vault/resend` - This endpoint allows user to resend the vault share and verification code

**Note:** User can only request a resend every three minutes

```json
{
  "public_key_ecdsa": "ECDSA public key of the vault",
  "password": "password to decrypt the vault share",
  "email": "email of the user"
}
```
Use when users lose their backup email or need vault file resent.

#### Verify Code
`GET /vault/verify/:public_key_ecdsa/:code` - This endpoint allows user to verify the code

If server returns HTTP status code 200, it means the code is valid. Other status codes mean the code is invalid.

**Code format:** 4-digit number (1000-9999) sent in backup email  
Use to confirm user received and can access backup email before vault operations.

### Integration Notes

1. **Session Coordination**: All parties must use the same `session_id` and join within 5 minutes
2. **Encryption**: `hex_encryption_key` encrypts TSS messages between parties
3. **Backups**: Encrypted vault shares automatically emailed after successful operations
4. **Rate Limits**: 5 requests/30 seconds, 30 burst capacity per IP

## Dev (Repository Management)

### Quick Start

```bash
# Start Redis
docker compose up -d

# Copy config
cp config-example.yaml config.yaml

# Run API server
go run cmd/vultisigner/main.go

# Run worker (separate terminal)
go run cmd/worker/main.go
```

### Development

```bash
# Test
go test ./...

# Build
make build

# Docker build
docker build -t vultiserver .
```

### Configuration

Key settings in `config.yaml`:
- `server.port`: API server port (default: 8080)
- `server.vaultsFilePath`: Vault storage directory
- `redis.*`: Redis connection settings
- `email_server.api_key`: Mandrill API key for backups

### Architecture

- **API Server** (`cmd/vultisigner`): HTTP endpoints, request validation, task queuing
- **Worker** (`cmd/worker`): Background TSS operations, email sending
- **Storage**: Redis (sessions/cache) + Block storage (encrypted vaults)
- **Relay**: Message coordination between TSS parties

### Key Files

- `api/server.go`: HTTP handlers and routing
- `service/tss.go`: Core TSS operations (keygen/keysign/reshare)
- `service/worker.go`: Background task processors
- `relay/session.go`: Multi-party session management
- `internal/types/`: Request/response structures


