package test

import (
	"fmt"
	"github.com/haggj/go-it-crypto/logs"
	"github.com/haggj/go-it-crypto/user"
	"testing"
	"time"
)

// Generate users and encrypt/decrypt data for single receiver
func TestPerformance(t *testing.T) {
	sender, _ := user.GenerateAuthenticatedUser()
	accessLog := logs.GenerateAccessLog()
	signedLog, _ := sender.SignLog(accessLog)

	var receivers []user.RemoteUser

	for i := 0; i < 100; i++ {
		remoteUser, _ := user.GenerateRemoteUser()
		receivers = append(receivers, remoteUser)
	}

	sender.EncryptLog(signedLog, receivers[:1]) // First encryption is slower than others

	iterations := [...]int{1, 2, 3, 5, 10}

	for _, val := range iterations {
		var sum time.Duration = 0
		var rounds = 1000
		for i := 0; i < rounds; i++ {
			start := time.Now()
			sender.EncryptLog(signedLog, receivers[:val])
			elapsed := time.Since(start)
			sum += elapsed
		}
		fmt.Println(float32(sum.Milliseconds()) / float32(rounds))

	}
}
