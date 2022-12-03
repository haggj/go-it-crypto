package test

import (
	"fmt"
	"github.com/haggj/go-it-crypto/logs"
	"github.com/haggj/go-it-crypto/user"
	"github.com/stretchr/testify/assert"
	"testing"
)

const goDecryptB = `{"protected":"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIxaWZubjkwRFJxdEhHWEhyeHBhbC13NjZhemtBTERQU3hvNHF5RzRRdGhVIiwieSI6ImZVNGVEVUxmbFJldGQ2Z0MxZzJaTFYxMmFTeVl2dlZZVXgydzk4TjlRTGMifSwib3duZXIiOiJyZWNlaXZlciIsInJlY2lwaWVudHMiOlsicmVjZWl2ZXIiXX0","encrypted_key":"UVgAzNy22Zr47bfxPGLgYmxMtYAIvRt85DWURqiw4wZRzNt8Tup5Ew","iv":"cvz26Qr_Eri1eZ6i","ciphertext":"VylfB2FMOBH-fhceN9-Mv4jcvwRZXV1TapHF4gm9ZrlLVhD4GxQHQbT-KfrMn3SJtx7-Q6MmQIRtwIdJVnvuFHpdfW3VFOy2gPMhoEKhu1NpAZIChl9T4Hj9cZZjNGCvYSaZ8Th8X0JjbzjVVU5MolKm15mCUm_owsBA1MGrQYbK0Pe086YHcxWv1iSm4oEL8Y2mriwFmAIWP3Xu-q2eNnDvuzNrV4hM81pvWCuFAO6QQyO6IWsd5mQ4gt2QIiNu9zIgpOEKpGUlUYL02VQqwEv2GGK3vIyCF6cXo1kRnbNRHVQg6bIW3O6TuCgo4jadmz0Ja7oUNnW2wgWreiBE7uAD55xMbs9B5ModlnbunonLYryV1jS6jd6uB6svyRYnZ8Zd-4OoJl8lx5B6ry2-5HqH_Jtuo2iXwlsurszweBOSNg4gA3lPar4_Zzfljf4oiQS615eq347vXSQB0lkmToqATNZjlywaj7VLF5Lii1fDSMUpI1JI0VTPphOw4mT7a3XSVDs45B5y_pQ5ROn2kCPSjrkpLGRGewMPZQGzCMj_AjOl9pkQmEsvl0a-jJpmLkVGjK1Tm3MaYz3Cr1-XyfP74QId6QMDZzuE6i8lmlOlf6NEe_OuOfA5Abf388u7xLkq3y3hvEetS_FHVbd7qumnGgK7teORtPxM4LsB6CG7HUkWPcX6LbcZuK7kIfsrD2Rsz3jqp8RRlWWNU0uwcdjwZDCaLVl24lq307vHzFtGiNs0xnzfggcUOcG_i-eUsDAdSNTs0yP-jvzwmOmjIDc0_7w2NA6fRa7XyQK-obEM3Dw9BnnyD9jpoH9NtGDqDPbtttFRV7druW-KXg4SZQ557Ch4CA1LcyipXsS7tUAZF3pHFRdHrmHqYB39KiZOqjd6HVnk70VzoTWh5_ZRUEfqmK8W1CCPnQ","tag":"xh2lGFAM-8AK-39B-zaLzw"}`

const goDecryptAB = `{"protected":"eyJlbmMiOiJBMjU2R0NNIiwib3duZXIiOiJyZWNlaXZlciIsInJlY2lwaWVudHMiOlsicmVjZWl2ZXIiLCJzZW5kZXIiXX0","recipients":[{"header":{"alg":"ECDH-ES+A256KW","epk":{"kty":"EC","crv":"P-256","x":"rAEKSPYdJdJ6bHPYrobWCBP1bxgA4uq7rF_xm-5O51U","y":"wLkRfalS1AmaYB29U7nkHzY4kKFhwA6rGO_GMinPwic"}},"encrypted_key":"YT1kMwqtXDg4MRxb9Qgpje1SbkQtCdxJwkfd1BCdKd5jlAlR5dA-Vg"},{"header":{"alg":"ECDH-ES+A256KW","epk":{"kty":"EC","crv":"P-256","x":"aWmlj9hKxT-3oRzsDgqgdk9slceHuoGCt37vdfWM97g","y":"B94CRu3_WGVy2hfVNQFRLyLbdYNTXloqRLoIQIBV-AA"}},"encrypted_key":"BTvPWcvVsmW80x18aW6UPUXIkRAwoKhFu9Ma8IQ7UCeFsQ2OU_50gw"}],"encrypted_key":"YT1kMwqtXDg4MRxb9Qgpje1SbkQtCdxJwkfd1BCdKd5jlAlR5dA-Vg","iv":"aYanSN64oJp-MRN5","ciphertext":"2iXDIW8b8GQ7Et2fO01RpnqV4ALfNBEipdhDrzSvNH98VQmm47RTuWtEclm_-OhtSBhqgHfshbmxlHwyTC4lHI-CGwmuMEuAR4G0586D8QllDenqGMgkaFl4a5oCInHkylxpWcWEr_Sv0uf0br4UpU3sLRLkyZQ5INKflRYkiu-umeN__xxNyKC4e8CD2waqk6u8IlBWX5dUTmEEDWtfDugNaPLZ0xzVWzTwLY5I_P23CFAjTAbBNFwJS6IyJU2HQz-i-pPMgRv2qJ2V6ikJ6KRy0FD_N9kSiHc3gwM3Wu6_PvV3b4nLW7lPeUG6BAOjfwXzvo1T-RwxD8ocqXKk8ctk8H5iKffGlSnugtnY5nBUl69hTPUzhfKL9dOG6QxAhMbkwZh79pofJJ6jx0eFxssDQ-eWFwIfAfMFeDGA9watJAs5VbMKF2jGm6huyxq8cMI3z5N5is9J7qB3R844vLTvHzx-2Qdcrd7x0t_Grk21_nXyCJr8oja4dH6kPVz5PgDPHvVqV4xpAwSQqFoSKlo3T65zkV3AQPGyPO3HFD129ZbNW34OS0plFGUONrL4zfiOqq8YZ7Vgt-1eo0BFnrD9yfjMNwwFr_41-h4_KXI7bAVtzq1kFelx_xmAc9tIEf8rr6yDRhfK6qOzQ-En2LgNl4J1G8WgtglYUUtbDh9dcN6vOwBxC2LB6YNUDebjsJ6c_NK1xcGcPQhObTa3XfIq4qrYZcbdJuNGsENV27NgMd5HrnvJo-G1xsVKCVlnryUeO5MZtmYTKwjjA1-K1wYU4v6cBHaab-aTUPElK7pNfSjPUYTLJVXcyFTzrcvceAkJl-gBlYksH-N0hFMYsQNd55fpbvERjxaSNPu_R4f9VMO_J6TVKKsu7Rn0S2D-W2fPN0KFhBemdyrFtdHrjl4x2LRIPVJa-Tsskc3CThZ6T1bJRCyf-A","tag":"HKUO2q1hTVGnS53s7g7Kcw"}`

const pythonDecryptB = `{"ciphertext":"371dFRlJPJrfTvQO6MBk9L-XLDkerR1sdquw2qxjJblOgJu45RJC7P92iML9z4IcEfoqzIqFQRzLic4tGmhfM4euGswZgvs59t-gNoTN_A_uaVGpJ9oTaBeXF5biQAMTU-CR065ttMGR9_Ii-V9sbwvXfI9cAWbWQowVIyE0V1wOcTDt0eVP22v_vrBbblO6YFKkBQazdohuxRGudFcfUbDrDkV8YvSA7kTDSu5zsehKcxUXFA61PegJI4xVr53a2JZA549DS0dn19ItG-kPtCkfmzDfG3cad6DukF-_-cLetdbpL_NRYhcQHFboXrUqlyEavm6m0gHiawKhNulPec4hWj4Wdu9wqqDtVLizoH6RjsQVJox0zV6InoZfOjnKbi9RGfbIjVwEkGkc1_WSMai3U0TFTGovfZQFTMn5qf2sZZ_j-ovRHb6hnqqaONSsewnYEDha6BvUqi6JcQLfKG5IBOIbS6EfFksmADMr5NiBgmNNju71gUbX_DXd6_0nqXqEDLf26VdKpl-g0P8-4rhaZsl30pJ1rka8YZ76-fPuUrMsj4Ll6_A_kueEd6bMMLjj-Jx9PfImkH67bFisiow-mJ44fj0vyjwvQ4NAUL9WBHJuw4eRVJ-BWKZ66zgv8qxHttDHPDIYW495y7VB1pSo4ljLbMRQpt5J2lbobU2MsmksbNLeT4IMphwL_WOByUQI18kNaJ-jJAQtTGS_81JW5WbxPVEyg_pvjtefqrMEpHetgEjyIT476xjDgIIrPckS82fe27VgL1CrIWZfloQ6Nzhxb2BpzwBq8qCbZKTJxZ9qVdLoc9uJXafDz1lv857QbWIE3K5rCSXM3X9CfyNLiHCyKO1-bM7hi_CBUNEtDXZlTrhorjqcqXw_XlW5OsN5c7DKeFaSPViAkILjpkVYsDLlTMYi","encrypted_key":"-9fIZvCcSgwdashhV1qHed13ut14dHn6skQZKRPW6IEHne9E8BFDMg","header":{"epk":{"crv":"P-256","kty":"EC","x":"feQ-3SCI0kxyqor1vkGxeHJAY8EuFMstnYPBHRyqgcA","y":"69hiWuqUR8xkCrr92gg5tjYFBoxESqnHa5msAR5txuM"}},"iv":"4e6NXEinsBcaxBbl","protected":"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJvd25lciI6InJlY2VpdmVyIiwicmVjaXBpZW50cyI6WyJyZWNlaXZlciJdfQ","tag":"oaBgSEv_cr9pKCDflJ-fgA"}`

const pythonDecryptAB = `{"ciphertext":"2eE4sTRlBDHTmWjXmyW9GZgXvFRHIWiyQdK-jhMs39GDfPBF-HN7R5VaQOGwJZBHn1FW5Codg4ZRS02FcoPDollKKG0QyWtfggzN5_UJyzicpPgU9cYdB691WeA9K31otJo9LEUZJRQrxZQ85ajVt1GMGK809Enk9agGfG3f_F0gKGatCar5ecCMlMEPBHHFZT2Ee2ONJ9H3rWY4ppRrQZl212HBNVC7I3U9yyovmZcJVBaLJAuMRWRn4U0LhcXPb_UMujDqHDsFxEydSGH_vTQjjuLA9lxjhRQRVBjUfZ7x1Kwpg5YBV94SJ62w3wiL_yYAYoGxsuTas48kERr6stGRZ4-qD4I3MyXLyliqURkF8wnzVrEzvIc75DobeMT8hVXUPUyiyRIFi3ON-azyDhAyjQqskdALLbhycN6Ta9S7vWUH1p3qD5OvK8PwbP5R-U8zyx3FdNMIsynPpPub0Q8CVvyClIV2BKmvewpf4iRliIOkmZ_GXuV3nA471hiVU_J60Ok-RXZ1j3cLbtA7yZL5tuks8aHVxzfJACXRhpMPEky16csKa9L6rAFylSsOUzG3HAuSOTSQtiwODMs3gg871QiA4JFNtluBErL4pyFtgZuwgYUwXTGbUsTzt5tQXWkznlOq5Z18rw1KinrwmN64zo3411djh7gmdTYX0zp4N83WedI3g5TGsbe8zwaDGuGaKEPaoAHLifpak_C8Qz_ED2twNl4Z1RtFAqqUYrOeRRuaVlKSFCwTGePv8j8tkPYMXOdzP4YLz--exuQEn7lgLf7CLokYq1UFiuXuqRs38Qc8iQvsaEryuZVpkq5uihB2zffZr6Lz42bo2la9fnIVCr3Haw1kP9Wr91TpLLPrN2t4vSsiCGE2VIci_ffnwpZW6FVVRyslimi2iyQpPT21R-epWqngdLQ2W9o_BJdbfzOXPBs","iv":"kNLM2_lHZtjUFykT","protected":"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJvd25lciI6InJlY2VpdmVyIiwicmVjaXBpZW50cyI6WyJyZWNlaXZlciIsInNlbmRlciJdfQ","recipients":[{"encrypted_key":"eNFK6J8knWYGFBT93zQHDQIYudsIXUbK_K6REh1DwxCxRboCWLIonA","header":{"epk":{"crv":"P-256","kty":"EC","x":"Tko9h05jiz1Wg2xzeXzrBCUy1WopyQraKHdDIP1OsWY","y":"j8fsEtrYRHuC15imEg7xQ3zuvFz-Vls5wswxUmJv1S8"}}},{"encrypted_key":"72sXebGZ_bnsQMh_V-TeAVIelBzklZ9iOOJv1JfGzHIlZUhuYuVCjQ","header":{"epk":{"crv":"P-256","kty":"EC","x":"-jUrekDTk8daLHu7OpA1_E59V2gRE1ksSYSbd1FffZM","y":"0rqGawyBbEsIJ2a8cmaAwLLXxd-Z6MjNcHR6W8_AsSA"}}}],"tag":"PDLbwus5hvFW8jYDHqPNHQ"}`

const jsDecryptB = `{"ciphertext":"bZlgs-8XeAzjHiWbcydItX88Vw8vKDH8z7aSUL1oQRPkTiE12WnehTmpTLIGMtKSKvMvSnF4-NZJ4WErMzRM7u8tMcPkbTHuOsK5ElR-4Y4JlgMt-tpI1CtekL6pHZj4K4rfBQH7kxUHtcbuOxSxPjHgQ4vR7lBNRcFxBdJJ4oCyn4JlCkY5DjZjr57KYCfuhnluau5ThZbvh5LvMYzg9btmJc_xTiLkD2GoxYwdULqt6EGRGkr6wUnkNM_MmK-7OaXOSLPRbGtFpslui7wyxXQhUijSPUhltaBbSzQx9-Ofb5GHNz93gSSVQSu3bFebINDfMrPTMcp7yruq-a08t0NWiHoF-TqHxexhOzZ_RPdzHLnmK_W0LEJxhZvHwcldIdPIc25Pab2QRxr7ypO6IktDVRLj4ac2oJ4AatvwCqAV70Jc_NL5AGurjSLNUMV0GHw7QAqy4eyQBO2HPxnl5n7mGupPAsWfhoxOpRauxU1-PQDqOKZmKfafSm907_nTnHHaeQPrY8OwbJGZl3EHzZJEHE2hBVmQVmZgdK8FLF4nuPxWD2Z2mEOzGcWUtBvuo7gYgUoueNdOI5CAOJMKJXrSihwJMETcHwuTt6PrfTvWinsy3y5S-uQkkxGN5EkCXuzrSGp9Oak2bpurz5ezUKnL1IYmo9m7wC52O7kW0IGJ6B-URr8XHisXXrTrX9SoEOb11Tz5XnGPJP27KJKp1ydrgQLsvUzWz9o1QdJK-lEqigj0CIgmx_UTVuNBRZuz5UAe2mJQ0yhpLGJVyzGJjTwW_5_ZZxXv9S5Qr8oVi7h-dMENqdCuxJPD9dBMR5iFE3kFior98hNRs5C0CokOfmpfLpJXqBjs2a9H5PXSU5UGeUj6_jPjmFldcRga63T4vkV8N3e-Pg5UKEIYzQBQJ22WPbVKlCBuzjh3dmfM","iv":"9hIFX0Nc-WOnz124","recipients":[{"encrypted_key":"747LVKTbu6zRNSgQhAzIVIjwvE-fiUzk5Jvbe6Qg84Hzc87_UlUQaw","header":{"alg":"ECDH-ES+A256KW"}}],"tag":"hmb-Aezjbwuqc8nusvJCgQ","protected":"eyJlbmMiOiJBMjU2R0NNIiwicmVjaXBpZW50cyI6WyJyZWNlaXZlciJdLCJvd25lciI6InJlY2VpdmVyIiwiZXBrIjp7IngiOiJRT2Jpd09OVTZTeTRleUVsWlJXSEtmd2t4U2liSS1rejBLUjhTdVc3N3g0IiwiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsInkiOiIxZmdXM1k5QnFVb1Q5NU9nVkpCM0ktWUFHd1czaDM3N1ZNV0NneVNBaTNBIn19"}`

const jsDecryptAB = `{"ciphertext":"5N8_RLJ-LqeHveNGvgixFi0YNsIwspTaFGRIUOkIqI8fKri1mS3fcXYgDZBvo4KfuueuILFMXsnRzzfWtfkK28wUekzpw33p4OvRneuKI_5xN6k95PP8-iZ8Dj3fwaKooiiWnHAZXZ_9Pyd_Vp1svJli_5MtQL6dAyIFWEGMI23TOHIlv4Y_WIoqzTMr8p8Ngsa1valCipNJXdpi_IcPrj8c8vNCRdxkjli5BiotBAxOPb1dkm4rygRTXe5r48yaQ41I8Sn0lYcUL1f833wHT5dBZcy6dnkVbxXzKjpCRzqzxK3WLbu1buF1MiNVzQfVWi3NPRCF2MkJvW8z6qULTc_cREOQmoRCdORN8X0xv0ySCy7x-b2kqlJXp1cX7oCpPtst8JrEHu6KN2R3glgHXaqazH4EJr3uTXgtqTmL4oaxDoFc0dpHfA4X4tvF3MBdWzib8ExAeUkRGEjaWf98fx6Mnc8NiePRUfdISyaoiUU_Kx5yOkRdKznJugLdc9T3IrAyQlKa0Z4XDuRkjdlDL0B7vf5ijZRccp8iG7ugwBZbYSdSElmzUwjI9r08eSXUYDK2u6RV3yYENwhky-ZRn42ugHrX0DYjNOB1eflrp_JQ-DANExG5cnb9uouKXoIUjbvoRGJVtXde9oKKGMN7XkiNBmn2vgmfuu9z-u59tUCEgMP8rKmUEBWR4AL3pW8V4K6XLpNRFB0flXZy4xbh5VWWfZfQvSOXEkjpDQedBoACPXroY1zkfI2eGegxwwl-gplQk1nHSSd24bMh07yWZWQBOJJBJN1DUQUjfaW75rvmZnDupadS-Hbzbdvd7mu4FopRECuQh3twHvYh7wa6K6UcQG9a6gM71jo8vDASNY48nDJVDU9rCwiyNYdea1LFfBkfvgadsREaIs_WzN7ndz3VCoRNrCCZNtL48ZkAnTWaVhkXb0BjM8LIuWmh","iv":"UhExTANI5WfvWz9Q","recipients":[{"encrypted_key":"bSzBVL-v5gDy_kldRKC4CsdyoTudd-a1jkUOGGd0DWRURI0LKmFuCg","header":{"alg":"ECDH-ES+A256KW","epk":{"x":"lwaGgrNt7j6G7ZYUs62xSxK9GypRdSUWTMGCzeUEHoI","crv":"P-256","kty":"EC","y":"JkYhU-avgsLxNWy2qddcwggph4ImCqNTvXutCHq81cg"}}},{"encrypted_key":"oXLukazxtuxXN5FfvIOtVsH21ul-4RzhEfyPHNchNI5qHKSHjK7-HA","header":{"alg":"ECDH-ES+A256KW","epk":{"x":"dsHx4hcFu7yLJLTJLmTvebnk7nua_oWKAu6LXewVWpo","crv":"P-256","kty":"EC","y":"r3G8A8XCR3bhK5kdoOvqvlCOiGtGQqQlU0gF50St_5M"}}}],"tag":"tO_69F0pamJCuC6EeMq_cg","protected":"eyJlbmMiOiJBMjU2R0NNIiwicmVjaXBpZW50cyI6WyJzZW5kZXIiLCJyZWNlaXZlciJdLCJvd25lciI6InJlY2VpdmVyIn0"}`

func _publicSender() user.AuthenticatedUser {
	sender, _ := user.ImportAuthenticatedUser("sender", PubA, PubA, PrivA, PrivA)
	sender.IsMonitor = true
	return sender
}

var publicSender = _publicSender()
var publicReceiver, _ = user.ImportAuthenticatedUser("receiver", PubB, PubB, PrivB, PrivB)

func TestCompatibilitySingleReceiver(t *testing.T) {
	var tests = []struct {
		name string
		jwe  string
		want string
	}{
		{"Test jwe from go", goDecryptB, "go-it-crypto"},
		{"Test jwe from js", jsDecryptB, "js-it-crypto"},
		{"Test jwe from python", pythonDecryptB, "py-it-crypto"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			singedLog, err := publicReceiver.DecryptLog(tt.jwe, CreateFetchUser([]user.RemoteUser{publicSender.RemoteUser}))
			if err != nil {
				t.Errorf("Failed decryption: %s", err.Error())
			}
			accessLog, err := singedLog.Extract()
			if err != nil {
				t.Errorf("Failed to extract AccessLog: %s", err.Error())
			}
			assert.Equal(t, tt.want, accessLog.Justification)
		})
	}
}

func TestCompatibilityMultiReceiver(t *testing.T) {
	var tests = []struct {
		name string
		jwe  string
		want string
	}{
		{"Test jwe from go", goDecryptAB, "go-it-crypto"},
		{"Test jwe from js", jsDecryptAB, "js-it-crypto"},
		{"Test jwe from python", pythonDecryptAB, "py-it-crypto"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			singedLog, err := publicReceiver.DecryptLog(tt.jwe, CreateFetchUser([]user.RemoteUser{publicSender.RemoteUser, publicReceiver.RemoteUser}))
			if err != nil {
				t.Errorf("Decryption failed: %s", err.Error())
			}
			accessLog, err := singedLog.Extract()
			if err != nil {
				t.Errorf("Failed to extract AccessLog: %s", err.Error())
			}
			assert.Equal(t, tt.want, accessLog.Justification)

			singedLog, err = publicSender.DecryptLog(tt.jwe, CreateFetchUser([]user.RemoteUser{publicSender.RemoteUser, publicReceiver.RemoteUser}))
			if err != nil {
				t.Errorf("Decryption failed: %s", err.Error())
			}
			accessLog, err = singedLog.Extract()
			if err != nil {
				t.Errorf("Failed to extract AccessLog: %s", err.Error())
			}
			assert.Equal(t, tt.want, accessLog.Justification)
		})
	}
}

// Create tokens for compatibility tests
func TestCreateCompatibilityTokens(t *testing.T) {
	sender, err := user.ImportAuthenticatedUser("sender", PubA, PubA, PrivA, PrivA)
	assert.NoError(t, err, "Failed to import user: %s", err)

	receiver, err := user.ImportAuthenticatedUser("receiver", PubB, PubB, PrivB, PrivB)
	assert.NoError(t, err, "Failed to import user: %s", err)

	accessLog := logs.GenerateAccessLog()
	accessLog.Owner = receiver.Id
	accessLog.Monitor = sender.Id
	accessLog.Justification = "go-it-crypto"

	signedLog, err := sender.SignLog(accessLog)
	assert.NoError(t, err, "Failed to sign AccessLog: %s", err)

	goDecryptB, err := sender.EncryptLog(signedLog, []user.RemoteUser{receiver.RemoteUser})
	assert.NoError(t, err, "Failed to encrypt log: %s", err)

	goDecryptAB, err := receiver.EncryptLog(signedLog, []user.RemoteUser{receiver.RemoteUser, sender.RemoteUser})
	assert.NoError(t, err, "Failed to encrypt log: %s", err)

	fmt.Println(goDecryptB)
	fmt.Println(goDecryptAB)

}
