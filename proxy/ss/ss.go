package ss

import (
	"encoding/base64"
	"net/url"
	"strings"

	"github.com/meoww-bot/glider/pkg/log"
	"github.com/meoww-bot/glider/proxy"
	"github.com/meoww-bot/glider/proxy/ss/cipher"
)

// SS is a base ss struct.
type SS struct {
	dialer proxy.Dialer
	proxy  proxy.Proxy
	addr   string

	cipher.Cipher
}

func init() {
	proxy.RegisterDialer("ss", NewSSDialer)
	proxy.RegisterServer("ss", NewSSServer)
}

func addPaddingIfNeeded(base64String string) string {
	// 计算需要添加的填充字符数量
	padding := strings.Repeat("=", (4-len(base64String)%4)%4)
	return base64String + padding
}

// NewSS returns a ss proxy.
func NewSS(s string, d proxy.Dialer, p proxy.Proxy) (*SS, error) {

	u, err := url.Parse(s)
	if err != nil {
		log.F("[ss] parse err: %s", err)
		return nil, err
	}

	var method, pass string

	addr := u.Host
	if u.User == nil {
		paddedBase64String := addPaddingIfNeeded(addr)
		ss, err := base64.StdEncoding.DecodeString(paddedBase64String)
		if err != nil {
			log.F("[ss] parse err: %s", err)
			return nil, err
		}
		parsedURL, err := url.Parse(string(ss))
		if err != nil {
			log.F("[ss] parse decoded URL err: %s", err)
			return nil, err
		}
		method = parsedURL.Scheme
		pass = strings.Split(parsedURL.Opaque, "@")[0]
		addr = strings.Split(parsedURL.Opaque, "@")[1]

	} else if !strings.Contains(u.User.String(), "-") {

		paddedBase64String := addPaddingIfNeeded(u.User.String())
		ss, err := base64.StdEncoding.DecodeString(paddedBase64String)
		if err != nil {
			log.F("base64 decode err: %s %s", err, u.User.String())
			return nil, err
		}

		method = strings.Split(string(ss), ":")[0]
		pass = strings.Split(string(ss), ":")[1]

	} else {
		method = u.User.Username()
		pass, _ = u.User.Password()
	}

	ciph, err := cipher.PickCipher(method, nil, pass)
	if err != nil {
		log.Fatalf("[ss] PickCipher for '%s', error: %s", method, err)
	}

	ss := &SS{
		dialer: d,
		proxy:  p,
		addr:   addr,
		Cipher: ciph,
	}

	return ss, nil
}

func init() {
	proxy.AddUsage("ss", `
SS scheme:
  ss://method:pass@host:port

  Available methods for ss:
    AEAD Ciphers:
      AEAD_AES_128_GCM AEAD_AES_192_GCM AEAD_AES_256_GCM AEAD_CHACHA20_POLY1305 AEAD_XCHACHA20_POLY1305
    Stream Ciphers:
      AES-128-CFB AES-128-CTR AES-192-CFB AES-192-CTR AES-256-CFB AES-256-CTR CHACHA20-IETF XCHACHA20 CHACHA20 RC4-MD5
    Alias:
	  chacha20-ietf-poly1305 = AEAD_CHACHA20_POLY1305, xchacha20-ietf-poly1305 = AEAD_XCHACHA20_POLY1305
    Plain: NONE
`)
}
