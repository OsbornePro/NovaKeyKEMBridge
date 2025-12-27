package novakeykem

import (
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// MUST MATCH YOUR DAEMON derivePairAEADKey info string
// You said: there is no v4; only v3.
const pairHKDFInfo = "NovaKey v3 Pair AEAD"

// ML-KEM-768 ciphertext size (Kyber768 / ML-KEM-768)
const kemCtSize768 = 1088

type pairServerKey struct {
	Op          string `json:"op"`
	V           int    `json:"v"`
	KID         string `json:"kid"`
	KyberPubB64 string `json:"kyber_pub_b64"`
	FP16Hex     string `json:"fp16_hex"`
	ExpiresUnix int64  `json:"expires_unix"`
}

// BuildPairRegisterBundle returns a packed blob:
//
// [u32 frameLen][frameBytes][u16 kemCtLen][kemCt][32 aeadKey]
//
// - frameBytes is exactly what your daemon expects after server_key:
//   ctLen(u16) + ct + nonce(24) + ciphertext
//
// - kemCt is needed as AAD input for ack decrypt ("PAIR"+ct+ackNonce)
// - aeadKey is needed to decrypt ack (XChaCha20-Poly1305)
func BuildPairRegisterBundle(serverKeyJSON string, tokenRawURLB64 string, deviceID string, deviceKeyHex string) ([]byte, error) {
	if deviceID == "" {
		return nil, errors.New("deviceID empty")
	}
	if deviceKeyHex == "" {
		return nil, errors.New("deviceKeyHex empty")
	}
	if len(deviceKeyHex) != 64 {
		return nil, errors.New("deviceKeyHex must be 32 bytes (64 hex chars)")
	}
	if _, err := hex.DecodeString(deviceKeyHex); err != nil {
		return nil, errors.New("deviceKeyHex not valid hex")
	}

	// Parse server key JSON
	var sk pairServerKey
	if err := json.Unmarshal([]byte(serverKeyJSON), &sk); err != nil {
		return nil, err
	}
	if sk.Op != "server_key" || sk.V != 1 || sk.KyberPubB64 == "" {
		return nil, errors.New("bad server_key")
	}

	// Decode token (base64url) and server pub (std base64)
	tokenBytes, err := decodeBase64URL(tokenRawURLB64)
	if err != nil {
		return nil, err
	}
	pubBytes, err := base64.StdEncoding.DecodeString(sk.KyberPubB64)
	if err != nil {
		return nil, err
	}

	// ML-KEM-768 encapsulate using stdlib crypto/mlkem
	ek, err := mlkem.NewEncapsulationKey768(pubBytes)
	if err != nil {
		return nil, err
	}

	// NOTE: stdlib order is (sharedKey, kemCt)
	sharedKey, kemCt := ek.Encapsulate()

	if len(sharedKey) != 32 {
		return nil, errors.New("unexpected sharedKey length")
	}
	if len(kemCt) != kemCtSize768 {
		return nil, errors.New("unexpected kem ciphertext length")
	}

	// HKDF-SHA256: ikm=sharedKey, salt=tokenBytes, info=pairHKDFInfo
	aeadKey := make([]byte, chacha20poly1305.KeySize)
	h := hkdf.New(sha256.New, sharedKey, tokenBytes, []byte(pairHKDFInfo))
	if _, err := io.ReadFull(h, aeadKey); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(aeadKey)
	if err != nil {
		return nil, err
	}

	// register JSON plaintext
	regObj := map[string]any{
		"op":             "register",
		"v":              1,
		"device_id":      deviceID,
		"device_key_hex": deviceKeyHex,
	}
	plain, err := json.Marshal(regObj)
	if err != nil {
		return nil, err
	}

	// nonce 24 bytes
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// aad = "PAIR" + kemCt + nonce
	aad := makePairAAD(kemCt, nonce)

	ciphertext := aead.Seal(nil, nonce, plain, aad)

	// frame: ctLen(u16) + ct + nonce + ciphertext
	if len(kemCt) > 0xFFFF {
		return nil, errors.New("kemCt too large")
	}

	frame := make([]byte, 0, 2+len(kemCt)+len(nonce)+len(ciphertext))
	var ctLen [2]byte
	binary.BigEndian.PutUint16(ctLen[:], uint16(len(kemCt)))
	frame = append(frame, ctLen[:]...)
	frame = append(frame, kemCt...)
	frame = append(frame, nonce...)
	frame = append(frame, ciphertext...)

	// pack bundle: [u32 frameLen][frame][u16 ctLen][ct][32 key]
	out := make([]byte, 0, 4+len(frame)+2+len(kemCt)+32)

	var fl [4]byte
	binary.BigEndian.PutUint32(fl[:], uint32(len(frame)))
	out = append(out, fl[:]...)
	out = append(out, frame...)

	out = append(out, ctLen[:]...)
	out = append(out, kemCt...)

	out = append(out, aeadKey...)
	return out, nil
}

// DecryptPairAck validates and decrypts daemon ack.
// ack is: [24-byte ackNonce][ciphertext]
func DecryptPairAck(ack []byte, registerCT []byte, aeadKey []byte) (string, error) {
	if len(aeadKey) != chacha20poly1305.KeySize {
		return "", errors.New("bad aeadKey length")
	}
	if len(registerCT) != kemCtSize768 {
		return "", errors.New("bad registerCT length")
	}
	if len(ack) < chacha20poly1305.NonceSizeX+16 {
		return "", errors.New("ack too short")
	}

	ackNonce := ack[:chacha20poly1305.NonceSizeX]
	ackCT := ack[chacha20poly1305.NonceSizeX:]

	aead, err := chacha20poly1305.NewX(aeadKey)
	if err != nil {
		return "", err
	}

	// aad = "PAIR" + registerCT + ackNonce
	aad := makePairAAD(registerCT, ackNonce)

	plain, err := aead.Open(nil, ackNonce, ackCT, aad)
	if err != nil {
		return "", err
	}

	// Optional sanity-check JSON includes op:"ok"
	var anyObj map[string]any
	if err := json.Unmarshal(plain, &anyObj); err == nil {
		if op, _ := anyObj["op"].(string); op != "" && op != "ok" {
			return "", errors.New("unexpected ack op")
		}
	}

	return string(plain), nil
}

func makePairAAD(ct []byte, nonce []byte) []byte {
	out := make([]byte, 0, 4+len(ct)+len(nonce))
	out = append(out, 'P', 'A', 'I', 'R')
	out = append(out, ct...)
	out = append(out, nonce...)
	return out
}

func decodeBase64URL(s string) ([]byte, error) {
	b64 := make([]byte, 0, len(s)+4)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '-':
			b64 = append(b64, '+')
		case '_':
			b64 = append(b64, '/')
		default:
			b64 = append(b64, s[i])
		}
	}
	for len(b64)%4 != 0 {
		b64 = append(b64, '=')
	}
	d, err := base64.StdEncoding.DecodeString(string(b64))
	if err != nil {
		return nil, errors.New("bad base64url token")
	}
	return d, nil
}

