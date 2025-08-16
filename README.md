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
- `name`: Human-readable vault name (string)
- `session_id`: Random UUID v4 (generate with `uuid.v4()`)
- `hex_encryption_key`: 32-byte hex string (64 chars, generate with `crypto.randomBytes(32).toString('hex')`)
- `hex_chain_code`: 32-byte hex string (64 chars, generate with `crypto.randomBytes(32).toString('hex')`)
- `local_party_id`: Server identifier in TSS session (string, can be any unique identifier)
- `encryption_password`: Password to encrypt vault backup file (string)
- `email`: Email address for encrypted backup delivery (valid email format)
- `lib_type`: `1` = DKLS (preferred), `0` = GG20 (legacy)

#### 2. Keysign - Sign Transactions  
`POST /vault/sign`

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
- `public_key`: ECDSA public key from vault creation (66-char hex string starting with '04')
- `messages`: Array of hex-encoded transaction hashes to sign (hex strings, no '0x' prefix)
- `session`: Random UUID v4 for this signing session (generate with `uuid.v4()`)
- `hex_encryption_key`: 32-byte hex for session encryption (64-char hex, generate with `crypto.randomBytes(32).toString('hex')`)
- `derive_path`: BIP44 derivation path (string, e.g., `"m/44'/0'/0'/0/0"` for Bitcoin, `"m/44'/60'/0'/0/0"` for Ethereum)
- `is_ecdsa`: Signature type boolean (`true` for ECDSA, `false` for EdDSA)
- `vault_password`: Password used during vault creation (string)

Returns: `{"messageHash": {"r": "...", "s": "...", "recovery_id": 0}}`

#### 3. Reshare - Rotate Key Shares
`POST /vault/reshare`

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
- `name`: Human-readable vault name (string, same as original)
- `public_key`: ECDSA public key from vault creation (66-char hex string starting with '04')
- `session_id`: Random UUID v4 for reshare session (generate with `uuid.v4()`)
- `hex_encryption_key`: New 32-byte hex for this session (64-char hex, generate with `crypto.randomBytes(32).toString('hex')`)
- `hex_chain_code`: Original chain code from vault creation (64-char hex string)
- `local_party_id`: New server identifier (string, can be any unique identifier)
- `old_parties`: Array of previous party IDs that participated in vault (string array, must not be empty)
- `encryption_password`: New password for reshared vault backup (string)
- `email`: Email for new backup delivery (valid email format, required unless reshare_type is Plugin)
- `old_reshare_prefix`: Previous reshare prefix (string, empty "" for first reshare)
- `lib_type`: `1` = DKLS (preferred), `0` = GG20 (legacy)
- `reshare_type`: `0` = Normal, `1` = Plugin (integer)

#### 4. Migration - Upgrade Legacy Vaults
`POST /vault/migrate`

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
- `public_key`: ECDSA public key of existing GG20 vault (66-char hex string starting with '04')
- `session_id`: Random UUID v4 for migration session (generate with `uuid.v4()`)
- `hex_encryption_key`: 32-byte hex for migration session (64-char hex, generate with `crypto.randomBytes(32).toString('hex')`)
- `encryption_password`: New password for migrated vault backup (string)
- `email`: Email for migrated backup delivery (valid email format)

### Additional Endpoints

#### Vault Information
`GET /vault/get/{publicKeyECDSA}` - Retrieve vault metadata

**Headers:** `x-password: base64(vault_password)` or plain vault password  
**Returns:**
```json
{
  "name": "My Vault",
  "public_key_ecdsa": "04a1b2...",
  "public_key_eddsa": "a1b2c3...", 
  "hex_chain_code": "1234567890abcdef...",
  "local_party_id": "server_party_1"
}
```
Use to verify vault exists and retrieve chain code for operations.

#### Vault Existence Check  
`GET /vault/exist/{publicKeyECDSA}` - Quick vault existence verification

**Returns:** HTTP 200 (exists) or 400 (not found)  
Use before attempting operations to avoid unnecessary API calls.

#### Backup Management
`POST /vault/resend` - Resend encrypted vault backup email

```json
{
  "public_key_ecdsa": "04a1b2c3d4e5f67890123456789012345678901234567890123456789012345678901234",
  "password": "vault_password_from_creation",
  "email": "user@example.com"
}
```
**Rate limit:** Once per 3 minutes per vault  
Use when users lose their backup email or need vault file resent.

#### Email Verification
`GET /vault/verify/{publicKeyECDSA}/{code}` - Verify 4-digit email code

**Returns:** HTTP 200 (valid) or 400 (invalid/expired)  
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


