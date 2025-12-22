package novakeykem

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"filippo.io/mlkem768"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// BuildV3InjectFrame returns the FULL TCP frame:
//   [u16 length big-endian][payload bytes]
//
// It implements NovaKey Protocol v3 exactly:
// - ML-KEM-768 encapsulation to server pubkey
// - HKDF-SHA256 with deviceKey (32B hex) as salt
// - XChaCha20-Poly1305 with AAD = header through kemCt
// - Plaintext = [u64 timestamp BE][inner frame v1]
//
// outerMsgType is fixed to 1.
// innerMsgType: 1=inject, 2=approve.
//
// serverPubB64: base64 server ML-KEM-768 public key
// deviceKeyHex: 32-byte hex string (64 hex chars)
func BuildV3InjectFrame(serverPubB64 string, deviceID string, deviceKeyHex string, secret string) ([]byte, error) {
	return buildV3Frame(serverPubB64, deviceID, deviceKeyHex, 1, []byte(secret))
}

func BuildV3ApproveFrame(serverPubB64 string, deviceID string, deviceKeyHex string) ([]byte, error) {
	return buildV3Frame(serverPubB64, deviceID, deviceKeyHex, 2, nil)
}

func buildV3Frame(serverPubB64 string, deviceID string, deviceKeyHex string, innerMsgType byte, payloadUTF8 []byte) ([]byte, error) {
	if len(deviceID) == 0 || len(deviceID) > 255 {
		return nil, errors.New("deviceID must be 1..255 bytes")
	}
	if innerMsgType != 1 && innerMsgType != 2 {
		return nil, errors.New("innerMsgType must be 1 (inject) or 2 (approve)")
	}

	// device PSK salt: 32 bytes
	deviceKey, err := hex.DecodeString(deviceKeyHex)
	if err != nil {
		return nil, errors.New("deviceKeyHex must be hex")
	}
	if len(deviceKey) != 32 {
		return nil, errors.New("deviceKeyHex must decode to 32 bytes")
	}

	// server pubkey bytes
	serverPub, err := base64.StdEncoding.DecodeString(serverPubB64)
	if err != nil {
		return nil, errors.New("serverPubB64 must be base64")
	}
	if len(serverPub) != mlkem768.EncapsulationKeySize {
		return nil, errors.New("server pubkey wrong length for ML-KEM-768")
	}

	// KEM
	kemCt, kemShared, err := mlkem768.Encapsulate(serverPub)
	if err != nil {
		return nil, err
	}

	// HKDF -> 32-byte AEAD key
	key := make([]byte, 32)
	h := hkdf.New(sha256.New, kemShared, deviceKey, []byte("NovaKey v3 AEAD key"))
	if _, err := h.Read(key); err != nil {
		return nil, err
	}

	// Outer header (v3)
	// [0]=version(3) [1]=outerMsgType(1) [2]=idLen [3:]=deviceID
	// then [kemCtLen u16][kemCt bytes]
	var header bytes.Buffer
	header.WriteByte(3) // version
	header.WriteByte(1) // outer msgType fixed
	header.WriteByte(byte(len(deviceID)))
	header.WriteString(deviceID)

	kemCtLen := make([]byte, 2)
	binary.BigEndian.PutUint16(kemCtLen, uint16(len(kemCt)))
	header.Write(kemCtLen)
	header.Write(kemCt)

	aad := header.Bytes() // AAD = payload[0:K]

	// Plaintext = [u64 timestamp BE][inner frame v1]
	// inner frame:
	// [0]=innerVersion(1)
	// [1]=innerMsgType (1 inject, 2 approve)
	// [2:4]=deviceIDLen u16 BE
	// [4:8]=payloadLen u32 BE
	// [..]=deviceID bytes
	// [..]=payload bytes (UTF-8)
	ts := uint64(time.Now().Unix())
	plain := &bytes.Buffer{}
	tsb := make([]byte, 8)
	binary.BigEndian.PutUint64(tsb, ts)
	plain.Write(tsb)

	inner := &bytes.Buffer{}
	inner.WriteByte(1)           // innerVersion
	inner.WriteByte(innerMsgType) // innerMsgType

	idLenBE := make([]byte, 2)
	binary.BigEndian.PutUint16(idLenBE, uint16(len(deviceID)))
	inner.Write(idLenBE)

	plLenBE := make([]byte, 4)
	binary.BigEndian.PutUint32(plLenBE, uint32(len(payloadUTF8)))
	inner.Write(plLenBE)

	inner.WriteString(deviceID)
	if len(payloadUTF8) > 0 {
		inner.Write(payloadUTF8)
	}

	plain.Write(inner.Bytes())

	// XChaCha20-Poly1305 (24-byte nonce)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX) // 24
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plain.Bytes(), aad)

	// Final v3 payload bytes:
	// header || nonce || ciphertext
	payload := &bytes.Buffer{}
	payload.Write(aad)
	payload.Write(nonce)
	payload.Write(ciphertext)

	// TCP frame: [u16 length][payload]
	p := payload.Bytes()
	if len(p) > 65535 {
		return nil, errors.New("payload too large")
	}

	out := &bytes.Buffer{}
	lenBE := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBE, uint16(len(p)))
	out.Write(lenBE)
	out.Write(p)

	return out.Bytes(), nil
}

