package tasks

const QUEUE_NAME = "vultisigner"
const EMAIL_QUEUE_NAME = "vultisigner:email"
const (
	TypeKeyGeneration     = "key:generation"
	TypeKeySign           = "key:sign"
	TypeEmailVaultBackup  = "key:email"
	TypeReshare           = "key:reshare"
	TypeKeyGenerationDKLS = "key:generationDKLS"
	TypeKeySignDKLS       = "key:signDKLS"
	TypeReshareDKLS       = "key:reshareDKLS"
	TypeMigrate           = "key:migrate"
	TypeImport            = "key:import"
)
