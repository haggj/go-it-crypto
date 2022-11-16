package test

import (
	"github.com/haggj/go-it-crypto/itcrypto"
	"github.com/haggj/go-it-crypto/logs"
	"github.com/haggj/go-it-crypto/user"
	"github.com/stretchr/testify/assert"
	"testing"
)

// No user has logged in. No crypto tasks can be performed.
func TestMissingLogin(t *testing.T) {
	sender, err := user.GenerateAuthenticatedUser()
	assert.NoError(t, err, "Failed to generate user: %s", err)

	receiver, err := user.GenerateAuthenticatedUser()
	assert.NoError(t, err, "Failed to generate user: %s", err)

	//fetchUser := CreateFetchUser([]user.RemoteUser{sender.RemoteUser, receiver.RemoteUser})

	accessLog := logs.GenerateAccessLog()
	accessLog.Owner = receiver.Id
	accessLog.Monitor = sender.Id

	signedLog, err := sender.SignLog(accessLog)
	assert.NoError(t, err, "Failed to sign AccessLog: %s", err)

	itCrypto := itcrypto.ItCrypto{}

	_, err = itCrypto.EncryptLog(signedLog, []user.RemoteUser{receiver.RemoteUser})
	assert.Containsf(t, err.Error(), "Before you can encrypt you need to login a user", "")

	_, err = itCrypto.SignLog(accessLog)
	assert.Containsf(t, err.Error(), "Before you can sign data you need to login a user", "")

	_, err = itCrypto.DecryptLog("signedLog")
	assert.Containsf(t, err.Error(), "Before you can decrypt you need to login a user", "")
}

// User is logged in and can encrypt, decrypt and sign data
func TestValidLogin(t *testing.T) {
	monitor, err := user.ImportAuthenticatedUser("monitor", PubA, PubA, PrivA, PrivA)
	assert.NoError(t, err, "Failed to import user: %s", err)

	owner, err := user.ImportAuthenticatedUser("owner", PubB, PubB, PrivB, PrivB)
	assert.NoError(t, err, "Failed to import user: %s", err)

	receiver, err := user.GenerateAuthenticatedUser()
	assert.NoError(t, err, "Failed to generate user: %s", err)

	fetchUser := CreateFetchUser([]user.RemoteUser{monitor.RemoteUser, owner.RemoteUser, receiver.RemoteUser})

	// Log is signed by a monitor
	accessLog := logs.GenerateAccessLog()
	accessLog.Owner = owner.Id
	accessLog.Monitor = monitor.Id

	signedLog, err := monitor.SignLog(accessLog)
	assert.NoError(t, err, "Failed to sign AccessLog: %s", err)

	// Login as owner and send log to receiver
	itCrypto := itcrypto.ItCrypto{FetchUser: fetchUser}
	itCrypto.Login(owner.Id, PubB, PubB, PrivB, PrivB)
	cipher, err := itCrypto.EncryptLog(signedLog, []user.RemoteUser{owner.RemoteUser, receiver.RemoteUser})
	assert.NoError(t, err, "Failed to encrypt log: %s", err)

	// Owner can decrypt
	receivedSingedLog1, err := itCrypto.DecryptLog(cipher)
	assert.NoError(t, err, "Failed to encrypt log: %s", err)
	receivedAccessLog1, err := receivedSingedLog1.Extract()
	assert.NoError(t, err, "Failed to extract AccessLog: %s", err)

	// Receiver can decrypt
	receivedSingedLog2, err := receiver.DecryptLog(cipher, fetchUser)
	assert.NoError(t, err, "Failed to encrypt log: %s", err)
	receivedAccessLog2, err := receivedSingedLog2.Extract()
	assert.NoError(t, err, "Failed to extract AccessLog: %s", err)

	VerifyAccessLogs(t, accessLog, receivedAccessLog1)
	VerifyAccessLogs(t, receivedAccessLog1, receivedAccessLog2)
}
