package alioss

import (
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

type EscapeError string

func (e EscapeError) Error() string {
	return "invalid URL escape " + strconv.Quote(string(e))
}

func get_gmt_iso8601(expire_end int64) string {
	var tokenExpire = time.Unix(expire_end, 0).UTC().Format("2006-01-02T15:04:05Z")
	return tokenExpire
}

type ConfigStruct struct {
	Expiration string          `json:"expiration"`
	Conditions [][]interface{} `json:"conditions"`
}

type PolicyToken struct {
	Host                string `json:"host"`
	AccessKeyId         string `json:"OSSAccessKeyId"`
	Policy              string `json:"policy"`
	Signature           string `json:"signature"`
	Callback            string `json:"callback"`
	Key                 string `json:"key"`
	SuccessActionStatus int    `json:"success_action_status"`
	Expire              int64  `json:"expire"`
}

type CallbackParam struct {
	CallbackUrl      string `json:"callbackUrl"`
	CallbackBody     string `json:"callbackBody"`
	CallbackBodyType string `json:"callbackBodyType"`
}

type InvalidHostError string

func (e InvalidHostError) Error() string {
	return "invalid character " + strconv.Quote(string(e)) + " in host name"
}

type ExtraCallbackArgc struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type AliossConfig struct {
	AccessKeyId     string `json:"OSSAccessKeyId"`
	AccessKeySecret string `json:"AccessKeySecret"`
	Host            string `json:"Host"`
}

type BodySizeLimit struct {
	MaxBodySize uint `json:"min_body_size"`
	MinBodySize uint `json:"max_body_size"`
}

func LoadConfig() AliossConfig {
	conf_json, err := ioutil.ReadFile("env.json")
	if err != nil {
		panic("读取配置文件失败")
	}

	var conf AliossConfig

	if err = json.Unmarshal(conf_json, &conf); err != nil {
		panic("解析配置文件失败")
	}

	return conf
}

func GetPolicyToken(body_size BodySizeLimit, params []ExtraCallbackArgc, callback_url string, dir string, expire int64) PolicyToken {

	alioss_config := LoadConfig()

	now := time.Now().Unix()
	expire_end := now + expire
	var tokenExpire = get_gmt_iso8601(expire_end)

	var config ConfigStruct
	config.Expiration = tokenExpire
	var condition1 []interface{}
	condition1 = append(condition1, "starts-with")
	condition1 = append(condition1, "$key")
	condition1 = append(condition1, dir)
	config.Conditions = append(config.Conditions, condition1)

	var condition2 []interface{}
	condition2 = append(condition2, "content-length-range")
	condition2 = append(condition2, body_size.MinBodySize)
	condition2 = append(condition2, body_size.MaxBodySize)
	config.Conditions = append(config.Conditions, condition2)

	result, _ := json.Marshal(config)

	debyte := base64.StdEncoding.EncodeToString(result)
	h := hmac.New(func() hash.Hash { return sha1.New() }, []byte(alioss_config.AccessKeySecret))
	io.WriteString(h, debyte)
	signedStr := base64.StdEncoding.EncodeToString(h.Sum(nil))

	var callbackParam CallbackParam

	callbackParam.CallbackBody = "filename=${object}&size=${size}&mimeType=${mimeType}&height=${imageInfo.height}&width=${imageInfo.width}"

	params_len := len(params)
	if params_len > 0 {
		var extra_callback_argc string
		for index, param := range params {
			if index < params_len {
				extra_callback_argc += "&"
			}
			extra_callback_argc += param.Key + "=" + param.Value
		}

		callbackParam.CallbackBody += extra_callback_argc
	}
	callbackParam.CallbackUrl = callback_url

	callbackParam.CallbackBodyType = "application/x-www-form-urlencoded"

	callback_str, _ := json.Marshal(callbackParam)

	callbackBase64 := base64.StdEncoding.EncodeToString(callback_str)

	var policyToken PolicyToken
	policyToken.AccessKeyId = alioss_config.AccessKeyId
	policyToken.Host = alioss_config.Host
	policyToken.Expire = expire_end
	policyToken.Signature = string(signedStr)
	policyToken.SuccessActionStatus = 200
	policyToken.Key = dir
	policyToken.Policy = string(debyte)
	policyToken.Callback = string(callbackBase64)

	return policyToken
}

func Callback(r *http.Request) (bool, error) {
	bytePublicKey, err := getPublicKey(r)
	if err != nil {
		return false, err
	}

	byteAuthorization, err := getAuthorization(r)
	if err != nil {
		return false, err
	}

	byteMD5, err := getMD5FromNewAuthString(r)
	if err != nil {
		return false, err
	}

	if verifySignature(bytePublicKey, byteMD5, byteAuthorization) {
		return true, nil
	} else {
		return false, nil
	}
}

func getPublicKey(r *http.Request) ([]byte, error) {
	var bytePublicKey []byte
	publicKeyURLBase64 := r.Header.Get("x-oss-pub-key-url")
	if publicKeyURLBase64 == "" {
		return bytePublicKey, errors.New("no x-oss-pub-key-url field in Request header ")
	}
	publicKeyURL, _ := base64.StdEncoding.DecodeString(publicKeyURLBase64)

	responsePublicKeyURL, err := http.Get(string(publicKeyURL))
	if err != nil {
		return bytePublicKey, err
	}
	bytePublicKey, err = ioutil.ReadAll(responsePublicKeyURL.Body)
	if err != nil {
		return bytePublicKey, err
	}
	defer responsePublicKeyURL.Body.Close()
	return bytePublicKey, nil
}

func getAuthorization(r *http.Request) ([]byte, error) {
	var byteAuthorization []byte
	strAuthorizationBase64 := r.Header.Get("authorization")
	if strAuthorizationBase64 == "" {
		return byteAuthorization, errors.New("no authorization field in Request header")
	}
	byteAuthorization, _ = base64.StdEncoding.DecodeString(strAuthorizationBase64)
	return byteAuthorization, nil
}

func getMD5FromNewAuthString(r *http.Request) ([]byte, error) {
	var byteMD5 []byte
	bodyContent, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return byteMD5, err
	}
	strCallbackBody := string(bodyContent)
	strURLPathDecode, errUnescape := unescapePath(r.URL.Path, encodePathSegment)
	if errUnescape != nil {
		return byteMD5, errUnescape
	}

	strAuth := ""
	if r.URL.RawQuery == "" {
		strAuth = fmt.Sprintf("%s\n%s", strURLPathDecode, strCallbackBody)
	} else {
		strAuth = fmt.Sprintf("%s?%s\n%s", strURLPathDecode, r.URL.RawQuery, strCallbackBody)
	}
	md5Ctx := md5.New()
	md5Ctx.Write([]byte(strAuth))
	byteMD5 = md5Ctx.Sum(nil)

	return byteMD5, nil
}

func verifySignature(bytePublicKey []byte, byteMd5 []byte, authorization []byte) bool {
	pubBlock, _ := pem.Decode(bytePublicKey)
	if pubBlock == nil {
		return false
	}
	pubInterface, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if (pubInterface == nil) || (err != nil) {
		return false
	}
	pub := pubInterface.(*rsa.PublicKey)

	errorVerifyPKCS1v15 := rsa.VerifyPKCS1v15(pub, crypto.MD5, byteMd5, authorization)

	return errorVerifyPKCS1v15 == nil
}

type encoding int

const (
	encodePath encoding = 1 + iota
	encodePathSegment
	encodeHost
	encodeZone
	encodeUserPassword
	encodeQueryComponent
	encodeFragment
)

func unescapePath(s string, mode encoding) (string, error) {

	n := 0
	hasPlus := false
	for i := 0; i < len(s); {
		switch s[i] {
		case '%':
			n++
			if i+2 >= len(s) || !ishex(s[i+1]) || !ishex(s[i+2]) {
				s = s[i:]
				if len(s) > 3 {
					s = s[:3]
				}
				return "", EscapeError(s)
			}
			if mode == encodeHost && unhex(s[i+1]) < 8 && s[i:i+3] != "%25" {
				return "", EscapeError(s[i : i+3])
			}
			if mode == encodeZone {
				v := unhex(s[i+1])<<4 | unhex(s[i+2])
				if s[i:i+3] != "%25" && v != ' ' && shouldEscape(v, encodeHost) {
					return "", EscapeError(s[i : i+3])
				}
			}
			i += 3
		case '+':
			hasPlus = mode == encodeQueryComponent
			i++
		default:
			if (mode == encodeHost || mode == encodeZone) && s[i] < 0x80 && shouldEscape(s[i], mode) {
				return "", InvalidHostError(s[i : i+1])
			}
			i++
		}
	}

	if n == 0 && !hasPlus {
		return s, nil
	}

	t := make([]byte, len(s)-2*n)
	j := 0
	for i := 0; i < len(s); {
		switch s[i] {
		case '%':
			t[j] = unhex(s[i+1])<<4 | unhex(s[i+2])
			j++
			i += 3
		case '+':
			if mode == encodeQueryComponent {
				t[j] = ' '
			} else {
				t[j] = '+'
			}
			j++
			i++
		default:
			t[j] = s[i]
			j++
			i++
		}
	}
	return string(t), nil
}

func shouldEscape(c byte, mode encoding) bool {
	if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' {
		return false
	}

	if mode == encodeHost || mode == encodeZone {
		switch c {
		case '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '[', ']', '<', '>', '"':
			return false
		}
	}

	switch c {
	case '-', '_', '.', '~':
		return false

	case '$', '&', '+', ',', '/', ':', ';', '=', '?', '@':
		switch mode {
		case encodePath:
			return c == '?'

		case encodePathSegment:
			return c == '/' || c == ';' || c == ',' || c == '?'

		case encodeUserPassword:
			return c == '@' || c == '/' || c == '?' || c == ':'

		case encodeQueryComponent:
			return true

		case encodeFragment:
			return false
		}
	}

	return true
}

func ishex(c byte) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	case 'a' <= c && c <= 'f':
		return true
	case 'A' <= c && c <= 'F':
		return true
	}
	return false
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}
