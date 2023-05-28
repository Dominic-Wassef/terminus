package signature

import (
	"encoding/base64"
	"time"
)

type Token struct {
	Payload   []byte
	Timestamp time.Time
}

func (s *Sign) Parse(t []byte) Token {

	tl := len(t)
	el := base64.RawURLEncoding.EncodedLen(s.hash.Size())

	token := Token{}

	if s.timestamp {
		for i := tl - (el + 2); i >= 0; i-- {
			if t[i] == '.' {
				token.Payload = t[0:i]
				token.Timestamp = time.Unix(decodeBase58(t[i+1:tl-(el+1)])+s.epoch, 0)
				break
			}
		}
	} else {
		token.Payload = t[0 : tl-(el+1)]
	}

	return token
}
