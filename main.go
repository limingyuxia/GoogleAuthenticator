package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/skip2/go-qrcode"
)

var user map[string]string

func main() {
	user = make(map[string]string)
	r := gin.Default()

	r.GET("/googleAuth/get", func(ctx *gin.Context) {
		userName, ok := ctx.GetQuery("userName")
		if !ok {
			ctx.JSON(http.StatusBadRequest, "username not found")
			return
		}

		secret := ""
		if userSecret, ok := user[userName]; ok {
			secret = userSecret
		} else {
			// 生成用户绑定秘钥
			secret = GetSecret()
			user[userName] = secret
		}

		issuer := "hengSheng"     // 机构
		account := "loginConfirm" // 账号
		googleAuth := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s", issuer, account, secret)

		// if err := qrcode.WriteFile(googleAuth, qrcode.Medium, 256, "./qrcode.png"); err != nil {
		// 	fmt.Println(err)
		// }
		qrcodeData, err := qrcode.Encode(googleAuth, qrcode.Medium, 256)
		if err != nil {
			fmt.Println(err)
			ctx.JSON(http.StatusBadRequest, err)
			return
		}

		if _, err := ctx.Writer.Write(qrcodeData); err != nil {
			fmt.Println(err)
		}

		// ctx.JSON(http.StatusOK, qrcodeData)
	})

	r.GET("/googleAuth/auth", func(ctx *gin.Context) {
		userName, ok := ctx.GetQuery("userName")
		if !ok {
			ctx.JSON(http.StatusBadRequest, "username not found")
			return
		}

		code, ok := ctx.GetQuery("code")
		if !ok {
			ctx.JSON(http.StatusBadRequest, "code not found")
			return
		}

		secret := ""
		if userSecret, ok := user[userName]; ok {
			secret = userSecret
		} else {
			ctx.JSON(http.StatusBadRequest, "user is invaild")
			return
		}

		reqCode, _ := strconv.ParseInt(code, 10, 64)
		if ok := VerifyCode(secret, int32(reqCode)); !ok {
			ctx.JSON(http.StatusBadRequest, "verify code is invailed")
			return
		}

		ctx.JSON(http.StatusOK, "confirm success")
	})

	if err := r.Run(":3000"); err != nil {
		fmt.Println(err)
	}
}

func GetSecret() string {
	randomStr := randStr(16)
	return strings.ToUpper(randomStr)
}

func randStr(strSize int) string {
	dictionary := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var bytes = make([]byte, strSize)
	_, _ = rand.Read(bytes)
	for k, v := range bytes {
		bytes[k] = dictionary[v%byte(len(dictionary))]
	}
	return string(bytes)
}

// 为了考虑时间误差，判断前当前时间及前后30秒时间
func VerifyCode(secret string, code int32) bool {

	if getCode(secret, -30) == code || getCode(secret, 0) == code || getCode(secret, 30) == code {
		return true
	}

	return false
}

// 获取Google Code
func getCode(secret string, offset int64) int32 {
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		fmt.Println(err)
		return 0
	}

	// generate a one-time password using the time at 30-second intervals
	epochSeconds := time.Now().Unix() + offset
	return int32(oneTimePassword(key, toBytes(epochSeconds/30)))
}

func toBytes(value int64) []byte {
	var result []byte
	mask := int64(0xFF)
	shifts := [8]uint16{56, 48, 40, 32, 24, 16, 8, 0}
	for _, shift := range shifts {
		result = append(result, byte((value>>shift)&mask))
	}
	return result
}

func toUint32(bytes []byte) uint32 {
	return (uint32(bytes[0]) << 24) + (uint32(bytes[1]) << 16) +
		(uint32(bytes[2]) << 8) + uint32(bytes[3])
}

func oneTimePassword(key []byte, value []byte) uint32 {
	// sign the value using HMAC-SHA1
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(value)
	hash := hmacSha1.Sum(nil)

	// We're going to use a subset of the generated hash.
	// Using the last nibble (half-byte) to choose the index to start from.
	// This number is always appropriate as it's maximum decimal 15, the hash will
	// have the maximum index 19 (20 bytes of SHA1) and we need 4 bytes.
	offset := hash[len(hash)-1] & 0x0F

	// get a 32-bit (4-byte) chunk from the hash starting at offset
	hashParts := hash[offset : offset+4]

	// ignore the most significant bit as per RFC 4226
	hashParts[0] = hashParts[0] & 0x7F

	number := toUint32(hashParts)

	// size to 6 digits
	// one million is the first number with 7 digits so the remainder
	// of the division will always return < 7 digits
	pwd := number % 1000000

	return pwd
}
