package service

const (
	maxInstallRollbackFiles = 128
	maxInstallRollbackBytes = 64 * 1024 * 1024
)

func clearSecretBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
