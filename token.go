package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	//"log"
	"html"
	"math/rand"
	"strings"
	"time"
	"twiggg/packages/encryption"
)

type Jwthead struct {
	Typ   string `json:"typ"` //JWT
	Alg   string `json:"alg"` // IMPORTANT : if alg=none, JWT needs to be declared unvalid
	KeyId int    `json:"kid"` // key int identifier of the randomly selected key from the keys list
}

type Jwtclaims struct {
	Iss   string `json:"iss"`   //name of issuer
	Iat   int64  `json:"iat"`   //issued at time
	Exp   int64  `json:"exp"`   //expiration time
	Nbf   int64  `json:"nbf"`   //cant be used before this date
	Qsh   string `json:"qsh"`   //query string hash
	Scope string `json:"scope"` //can be used for specifying what a user (sub?) can do
	//Sub jwtcontext `json:"sub"` //subject = user
	Sub interface{} //
	Aud []string    `json:"aud"` //audience of the token
	Jti string      `json:"jti"` //jwt token unique identifier, in order to prevent replay attack. Used for one time use tokens.
}

type jwtcontext struct {
	Username string `json:"username"` //alias of the user
	//Userid         string `json:"userid"`         //user id used for shortcut access to db and user's perso space
	Role           string `json:"role"`           //admin,test,standard,dev
	Private        bool   `json:"private"`        //access level grants access to certain endpoints
	LastConnection int64  `json:"lastconnection"` //time of last connection
	Usertype       string `json:"usertype"`
	Objectkey      string `json:"objectkey"`
	//-> private means access to personal space + public pages. Can modify own info
	//-> public means only access to public pages
	//-> admin means access to everything and permissions to create read update delete
	//-> analytics
	//-> test
}

//encoding
//encodedString := base64.URLEncoding.EncodeToString([]byte(initialString))
//encodedString := base64.StdEncoding.EncodeToString([]byte(initialString))
//decoding
//decodedString, err := base64.URLEncoding.DecodeString(encodedString)
//decodedString, err := base64.StdEncoding.DecodeString(encodedString)

type KeyPicker interface {
	PickKey() (string, int, error)
	valid() bool
	keyValue(keyId int) (string, error)
	len() int
}

type KeySlice []string

var jwtkeys KeySlice = []string{"1K9l89853", "1a9s8n8", "l2a9h0s1s8e8n", "aeiouy"}

func (k KeySlice) PickKey() (string, int, error) {
	if len(k) > 0 {
		n := rand.Intn(len(k))
		key := k[n]
		//return []byte(key), n, nil
		return key, n, nil
	} else {
		return "", 0, errors.New("jwt/keySlice.pickKey : no keys stored in this slice")
	}

}
func (k KeySlice) len() int {
	return len(k)
}

func (k KeySlice) valid() bool {
	if len(k) == 0 {
		return false
	} else {
		for _, v := range k {
			if len(v) == 0 {
				return false
			}
		}
		return true
	}

}

func (k KeySlice) keyValue(keyId int) (string, error) {
	if len(k) < (keyId + 1) {
		return "", errors.New("KeySlice.KeyValue: index out of range.")
	} else {
		return k[keyId], nil
	}

}

//-----------------------------------------------------------------------
func New(keypicker KeyPicker, algorithm string, issuer string, username string, role string, usertype string, objectkey string, private bool, audience []string, tokenId string, nbHours int, scope string) (string, error) {
	if keypicker == nil || !keypicker.valid() {
		return "", errors.New("jwt.Generate: no valid KeyPicker provided")
	}
	// 1) head
	head := Jwthead{}
	head.Typ = "JWT"
	switch strings.ToLower(algorithm) {
	case "bcrypt":
		head.Alg = "bcrypt"
	case "hs256":
		head.Alg = "hs256"
	default:
		head.Alg = "bcrypt"
	}
	//log.Println(head)
	//pick key
	key, keyid, err := keypicker.PickKey()
	if err != nil {
		return "", errors.New("jwt.generate : could not pick a key")
	}
	head.KeyId = keyid
	//2) claims
	claims := Jwtclaims{}
	claims.Iss = issuer
	claims.Iat = time.Now().Unix()
	sdur := fmt.Sprint(nbHours, "h")
	delta, err := time.ParseDuration(sdur)
	if err != nil {
		return "", err
	}
	claims.Exp = time.Unix(claims.Iat, 0).Add(delta).Unix() // 3days of validity
	claims.Qsh = ""
	context := jwtcontext{}
	context.Username = username
	context.Role = role
	context.Private = private
	context.Usertype = usertype
	context.Objectkey = objectkey
	claims.Sub = context
	claims.Aud = audience
	claims.Jti = tokenId
	//3) signature
	signingInput, err := construct(head, claims)
	if err != nil {
		return "", err
	}
	signature, err := sign(signingInput, head.Alg, key)
	if err != nil {
		return "", err
	}
	jwtToken := fmt.Sprint(signingInput, ".", signature)
	return jwtToken, nil
}

//construct the token with any sub
func New2(keypicker KeyPicker, algorithm string, issuer string, audience []string, sub interface{}, tokenId string, nbHours int, querystringhash string, scope string) (string, error) {
	if keypicker == nil || !keypicker.valid() {
		return "", errors.New("jwt.Generate: no valid KeyPicker provided")
	}
	// 1) head
	head := Jwthead{}
	head.Typ = "JWT"
	switch strings.ToLower(algorithm) {
	case "bcrypt":
		head.Alg = "bcrypt"
	case "hs256":
		head.Alg = "hs256"
	default:
		head.Alg = "bcrypt"
	}
	//log.Println(head)
	//pick key
	key, keyid, err := keypicker.PickKey()
	if err != nil {
		return "", errors.New("jwt.generate : could not pick a key")
	}
	head.KeyId = keyid
	//2) claims
	claims := Jwtclaims{}
	claims.Iss = issuer
	claims.Scope = scope
	claims.Iat = time.Now().Unix()
	sdur := fmt.Sprint(nbHours, "h")
	delta, err := time.ParseDuration(sdur)
	if err != nil {
		return "", err
	}
	claims.Exp = time.Unix(claims.Iat, 0).Add(delta).Unix() // 3days of validity
	claims.Qsh = strings.ToLower(html.EscapeString(querystringhash))
	claims.Sub = sub
	claims.Aud = audience
	claims.Jti = tokenId
	//3) signature
	signingInput, err := construct(head, claims)
	if err != nil {
		return "", err
	}
	signature, err := sign(signingInput, head.Alg, key)
	if err != nil {
		return "", err
	}
	jwtToken := fmt.Sprint(signingInput, ".", signature)
	return jwtToken, nil
}

func Update(token string, keys KeyPicker) (string, error) {

	if !Verify(token, keys) {
		return "", errors.New("unvalid token was sent... could not update it")
	}
	head, claims, _, err := Parse(token)
	if err != nil {
		return "", err
	}
	if claims.Exp < time.Now().Unix() {
		return "", errors.New("sorry, the token has already expired. Get a new one.")
	}
	//new, err := New(keys, head.Alg, claims.Iss, claims.Sub.Username, claims.Sub.Role, claims.Sub.AccessLevel, claims.Aud, "", 24*3)
	//new, err := New(keys, head.Alg, claims.Iss, claims.Sub.Username, claims.Sub.Role, claims.Sub.Usertype, claims.Sub.Objectkey, claims.Sub.Private, claims.Aud, "", 24*3)
	new, err := New2(keys, head.Alg, claims.Iss, claims.Aud, claims.Sub, "", 24*3, claims.Qsh, claims.Scope)
	if err != nil {
		return "", err
	}
	return new, nil
}

func Verify(token string, keys KeyPicker) bool {
	head, claims, signature, err := Parse(token)
	if err != nil {
		return false
	}
	if strings.ToLower(head.Alg) != "bcrypt" && strings.ToLower(head.Alg) != "hs256" {
		return false
	}
	if head.KeyId > (keys.len() - 1) {
		return false
	}
	key, err := keys.keyValue(head.KeyId)
	if err != nil {
		return false
	}
	switch strings.ToLower(head.Alg) {
	case "hs256":
		signingInput, err := construct(head, claims)
		if err != nil {
			return false
		}
		verifSignature, err := sign(signingInput, head.Alg, key)
		if err != nil {
			return false
		}
		if verifSignature != signature {
			return false
		}
		return true
	case "bcrypt":
		signingInput, err := construct(head, claims)
		if err != nil {
			return false
		}
		hash, err := base64.URLEncoding.DecodeString(signature)
		if err != nil {
			return false
		}
		erreur := bcrypt.CompareHashAndPassword(hash, []byte(signingInput))
		if erreur != nil {
			return false
		}
		return true
	default:
		signingInput, err := construct(head, claims)
		if err != nil {
			return false
		}
		hash, err := base64.URLEncoding.DecodeString(signature)
		if err != nil {
			return false
		}
		erreur := bcrypt.CompareHashAndPassword(hash, []byte(signingInput))
		if erreur != nil {
			return false
		}
		return true
	}

}

func Parse(token string) (Jwthead, Jwtclaims, string, error) {
	parts := strings.Split(token, ".")
	head := Jwthead{}
	claims := Jwtclaims{}
	if len(parts) != 3 {
		return head, claims, "", errors.New("token has wrong structure")
	}

	// json unmarshal the head
	decoded, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		s := fmt.Sprint("jwt validate base64 decode head:", err)
		return head, claims, "", errors.New(s)
	}
	err = json.Unmarshal(decoded, &head)
	if err != nil {
		s := fmt.Sprint("jwt validate json unmarshall head:", err)
		return head, claims, "", errors.New(s)
	}
	// json unmarshal the claims
	decoded, err = base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		s := fmt.Sprint("jwt validate base64 decode claims:", err)
		return head, claims, "", errors.New(s)
	}
	err = json.Unmarshal(decoded, &claims)
	if err != nil {
		s := fmt.Sprint("jwt validate json unmarshall claims:", err)
		return head, claims, "", errors.New(s)
	}
	return head, claims, parts[2], nil

}

// ------- unexported functions ----------------------------------------------------------

//marshal and encore head and claims + join them
func construct(head Jwthead, claims Jwtclaims) (string, error) {
	//jsonmarshal head
	json_h, err := json.Marshal(head)
	if err != nil {
		s := fmt.Sprint("jwt.generate : could not generate json head, %v", err.Error())
		return "", errors.New(s)
	}
	//encode head
	encodedHead := base64.URLEncoding.EncodeToString([]byte(json_h))
	//json marshal claims
	json_c, err := json.Marshal(claims)
	if err != nil {
		//fmt.Println("error : ", err)
		s := fmt.Sprint("jwt.generate : could not generate json claims, %v", err.Error())
		return "", errors.New(s)
	}
	//encode claims
	encodedClaims := base64.URLEncoding.EncodeToString([]byte(json_c))
	//sign the token (encryption)
	signingInput := fmt.Sprint(encodedHead, ".", encodedClaims)
	return signingInput, nil
}

// sign take the head and claims, marshals, encodes, signs and returns the generated token
func sign(signingInput string, algo string, key string) (string, error) {
	hash := []byte("")
	err := errors.New("")
	switch algo {
	case "bcrypt":
		hash, err = bcrypt.GenerateFromPassword([]byte(signingInput), bcrypt.DefaultCost)
		if err != nil {
			s := fmt.Sprint("jwt.generate : could not sign, %v", err.Error())
			return "", errors.New(s)
		}
	case "hs256":
		hash, err = encryption.HashHS256(signingInput, []byte(key))
		if err != nil {
			s := fmt.Sprint("jwt.generate : could not sign, %v", err.Error())
			return "", errors.New(s)
		}
	default:
		hash, err = encryption.Hashbcrypt(signingInput, []byte(key), 12)
		if err != nil {
			s := fmt.Sprint("jwt.generate : could not sign, %v", err.Error())
			return "", errors.New(s)
		}
	}
	//encode signature
	encodedSignature := base64.URLEncoding.EncodeToString(hash)
	return encodedSignature, nil
}
