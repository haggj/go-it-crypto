package test

import (
	"encoding/json"
	"fmt"
	"github.com/haggj/go-it-crypto/logs"
	"github.com/haggj/go-it-crypto/user"
	"github.com/stretchr/testify/assert"
	"testing"
)

var PubCa = `-----BEGIN CERTIFICATE-----
MIIBITCByAIJAJIgM6o1Soz/MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs
b3BtZW50IENBMB4XDTIyMTIwMzEyNTIwNFoXDTIzMTIwMzEyNTIwNFowGTEXMBUG
A1UEAwwORGV2ZWxvcG1lbnQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASz
mmKWEqdfYOcspvWpjyZlzDRj4ueX+VBMIh6PnyTDiF21CD9V/hCeJGMUBwOhA/0K
GBXjuHoEQWolytkNC4IdMAoGCCqGSM49BAMCA0gAMEUCIQCqtjjokBqyMe3h850n
HlXsfCDTLQe+Tq0YGX1s3Ac5zAIgW02bMx6mroNrFONplm6Li0HLIgCfXVOIS3BF
RQUGwhY=
-----END CERTIFICATE-----`

var PubA = `-----BEGIN CERTIFICATE-----
MIIBJzCBzwIJAPi05h3+oZR3MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs
b3BtZW50IENBMB4XDTIyMTIwMzEyNTIwNFoXDTIzMTIwMzEyNTIwNFowIDEeMBwG
A1UEAwwVIm1vaXRvcjJAbW9uaXRvci5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEBshF/Y40TAHRdcLc8CU9iu+ZJz8W69Qrmbttu/i9WAMR8sX+sF/glcOS
5BmltKxfL49B5jBZmVenmyajT6tfITAKBggqhkjOPQQDAgNHADBEAiAXvw+CwR97
ahXX2PPRJq/gQ2gXS/x0pvKNo6521UutlgIgdOknrMA6v+SglkBu8USsKGRgqFa2
RCNGeW9w1K4rnPY=
-----END CERTIFICATE-----`

var PrivA = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNxkH9Z8yVF7KHrLw
KP6IxRk1DYjHS6pYC8tXacYkizyhRANCAAQGyEX9jjRMAdF1wtzwJT2K75knPxbr
1CuZu227+L1YAxHyxf6wX+CVw5LkGaW0rF8vj0HmMFmZV6ebJqNPq18h
-----END PRIVATE KEY-----`

var PubB = `-----BEGIN CERTIFICATE-----
MIIBKTCBzwIJAPi05h3+oZR4MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs
b3BtZW50IENBMB4XDTIyMTIwMzEyNTIwNFoXDTIzMTIwMzEyNTIwNFowIDEeMBwG
A1UEAwwVIm1vaXRvcjJAbW9uaXRvci5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAE2tg3CN9AENSlkL6FONlWDX3wVKIKAZoziWHkZ/U/y0VvcSSke1DMY8Id
jXqmwJtK7OTjv3muQezMaAYdJc73/DAKBggqhkjOPQQDAgNJADBGAiEApED995lG
XEpbpG0nqrnwtXFiZAR9jC6SV9AJP85MF0ECIQC/d3C2oq/q8OLAbcNMagwyEw26
1MnS5F6OMRw1m0IXwA==
-----END CERTIFICATE-----`

var PrivB = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqySZT+PKukQfGQGb
b3F8fZnpY8LYfadaZDaDwteHw1WhRANCAATa2DcI30AQ1KWQvoU42VYNffBUogoB
mjOJYeRn9T/LRW9xJKR7UMxjwh2NeqbAm0rs5OO/ea5B7MxoBh0lzvf8
-----END PRIVATE KEY-----`

func CreateFetchUser(users []user.RemoteUser) user.FetchUser {
	return func(id string) user.RemoteUser {
		for _, user := range users {
			if id == user.Id {
				return user
			}
		}
		panic(fmt.Sprintf("No matching user found (%s)", id))
	}
}

func VerifyAccessLogs(t *testing.T, first logs.AccessLog, second logs.AccessLog) {
	firstRaw, _ := json.Marshal(first)
	secondRaw, _ := json.Marshal(second)
	assert.Equal(t, string(firstRaw), string(secondRaw))
}
