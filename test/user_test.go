package test

import (
	"github.com/haggj/go-it-crypto/logs"
	"github.com/haggj/go-it-crypto/user"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Generate users and encrypt/decrypt data for single receiver
func TestEncryptSingle(t *testing.T) {
	sender, err := user.GenerateAuthenticatedUser()
	assert.NoError(t, err, "Failed to generate user: %s", err)

	receiver, err := user.GenerateAuthenticatedUser()
	assert.NoError(t, err, "Failed to generate user: %s", err)

	fetchUser := CreateFetchUser([]user.RemoteUser{sender.RemoteUser, receiver.RemoteUser})

	accessLog := logs.GenerateAccessLog()
	accessLog.Owner = receiver.Id
	accessLog.Monitor = sender.Id

	signedLog, err := sender.SignAccessLog(accessLog)
	assert.NoError(t, err, "Failed to sign AccessLog: %s", err)

	cipher, err := sender.Encrypt(signedLog, []user.RemoteUser{receiver.RemoteUser})
	assert.NoError(t, err, "Failed to encrypt log: %s", err)

	receivedSingedLog, err := receiver.Decrypt(cipher, fetchUser)
	assert.NoError(t, err, "Failed to decrypt log: %s", err)

	receivedAccessLog, err := receivedSingedLog.Extract()
	assert.NoError(t, err, "Failed to extract AccessLog: %s", err)

	VerifyAccessLogs(t, accessLog, receivedAccessLog)
}

// Generate users and sent data to multiple receivers.
func TestEncryptMultiple(t *testing.T) {

	// Setup Users
	monitor, err := user.GenerateAuthenticatedUser()
	assert.NoError(t, err, "Failed to generate user: %s", err)
	owner, err := user.GenerateAuthenticatedUser()
	assert.NoError(t, err, "Failed to generate user: %s", err)
	receiver, err := user.GenerateAuthenticatedUser()
	assert.NoError(t, err, "Failed to generate user: %s", err)
	noReceiver, err := user.GenerateAuthenticatedUser()
	assert.NoError(t, err, "Failed to generate user: %s", err)

	fetchUser := CreateFetchUser([]user.RemoteUser{monitor.RemoteUser, owner.RemoteUser, receiver.RemoteUser, noReceiver.RemoteUser})

	accessLog := logs.GenerateAccessLog()
	accessLog.Owner = owner.Id
	accessLog.Monitor = monitor.Id

	// 1. Step: Monitor creates log and encrypts it for owner
	signedLog, err := monitor.SignAccessLog(accessLog)
	assert.NoError(t, err, "Failed to sign AccessLog: %s", err)
	cipher, err := monitor.Encrypt(signedLog, []user.RemoteUser{owner.RemoteUser})
	assert.NoError(t, err, "Failed to encrypt log: %s", err)

	// 2. Step: Owner can decrypt log
	receivedSingedLog1, err := owner.Decrypt(cipher, fetchUser)
	assert.NoError(t, err, "Failed to decrypt log", err)
	receivedAccessLog1, err := receivedSingedLog1.Extract()
	assert.NoError(t, err, "Failed to extract AccessLog: %s", err)

	// 3. Step: Owner shares with receiver
	cipher, err = owner.Encrypt(receivedSingedLog1, []user.RemoteUser{owner.RemoteUser, receiver.RemoteUser})
	assert.NoError(t, err, "Failed to encrypt log: %s", err)

	// 4. Step: Owner and receiver can decrypt
	receivedSingedLog2, err := owner.Decrypt(cipher, fetchUser)
	assert.NoError(t, err, "Failed to decrypt log", err)
	receivedAccessLog2, err := receivedSingedLog2.Extract()
	assert.NoError(t, err, "Failed to extract AccessLog: %s", err)

	receivedSingedLog3, err := receiver.Decrypt(cipher, fetchUser)
	assert.NoError(t, err, "Failed to decrypt log", err)
	receivedAccessLog3, err := receivedSingedLog3.Extract()
	assert.NoError(t, err, "Failed to extract AccessLog: %s", err)

	VerifyAccessLogs(t, accessLog, receivedAccessLog1)
	VerifyAccessLogs(t, receivedAccessLog1, receivedAccessLog2)
	VerifyAccessLogs(t, receivedAccessLog2, receivedAccessLog3)

	// Decrypting data at noReceiver throws error
	_, err = noReceiver.Decrypt(cipher, fetchUser)
	assert.Containsf(t, err.Error(), "Failed to decrypt JWE", "expected error containing %q, got %s", "Failed to decrypt JWE", err)

}

// Import users based on X509 certificates and PCKS8 private keys
func TestImportUser(t *testing.T) {
	sender, err := user.ImportAuthenticatedUser("sender", PubA, PubA, PrivA, PrivA)
	assert.NoError(t, err, "Failed to import user: %s", err)

	receiver, err := user.ImportAuthenticatedUser("receiver", PubB, PubB, PrivB, PrivB)
	assert.NoError(t, err, "Failed to import user: %s", err)

	fetchUser := CreateFetchUser([]user.RemoteUser{sender.RemoteUser, receiver.RemoteUser})

	accessLog := logs.GenerateAccessLog()
	accessLog.Owner = receiver.Id
	accessLog.Monitor = sender.Id

	signedLog, err := sender.SignAccessLog(accessLog)
	assert.NoError(t, err, "Failed to sign AccessLog: %s", err)

	cipher, err := sender.Encrypt(signedLog, []user.RemoteUser{receiver.RemoteUser})
	assert.NoError(t, err, "Failed to encrypt log: %s", err)

	receivedSingedLog, err := receiver.Decrypt(cipher, fetchUser)
	assert.NoError(t, err, "Failed to decrypt log: %s", err)

	receivedAccessLog, err := receivedSingedLog.Extract()
	assert.NoError(t, err, "Failed to extract AccessLog: %s", err)

	VerifyAccessLogs(t, accessLog, receivedAccessLog)
}

// Import users with CA signed keys
func TestImportUserSingedKeys(t *testing.T) {
	sender, err := user.ImportAuthenticatedUser("sender", PubA, PubA, PrivA, PrivA)
	assert.NoError(t, err, "Failed to import user: %s", err)

	receiver, err := user.ImportRemoteUser("receiver", PubB, PubB, PubCa)
	assert.NoError(t, err, "Failed to import user: %s", err)

	accessLog := logs.GenerateAccessLog()
	accessLog.Owner = receiver.Id
	accessLog.Monitor = sender.Id

	signedLog, _ := sender.SignAccessLog(accessLog)

	_, err = sender.Encrypt(signedLog, []user.RemoteUser{receiver})
	assert.NoError(t, err, "Failed to encrypt log: %s", err)
}

// Import users with CA signed keys fails
func TestImportUserSingedKeysFail(t *testing.T) {
	_, err := user.ImportRemoteUser("receiver", PubB, PubB, PubA)
	assert.Containsf(t, err.Error(), "Can not verify encryption certificate", "")
}
