package novakeykem

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type pairingBlob struct {
	V                 int    `json:"v"`
	DeviceID          string `json:"device_id"`
	DeviceKeyHex      string `json:"device_key_hex"`
	ServerAddr        string `json:"server_addr"`
	ServerKyberPubB64 string `json:"server_kyber768_pub"`
}

const (
	outerVersion  = 3
	outerMsgType  = 1
	innerVersion  = 1
	innerInject   = 1
	innerApprove  = 2
	hkdfInfo      = "NovaKey v3 AEAD key"
)

func BuildInjectFrame(pairingBlobJSON string, secret string) ([]byte, error) {
	return buildFrame(pairingBlobJSON, innerInject, secret)
}

func BuildApproveFrame(pairingBlobJSON string) ([]byte, error) {
	return buildFrame(pairingBlobJSON, innerApprove, "")
}

func buildFrame(pairingBlobJSON string, innerType byte, payload string) ([]byte, error) {
	var pb pairingBlob
	if err := json.Unmarshal([]byte(pairingBlobJSON), &pb); err != nil {
		return nil, err
	}
	if pb.DeviceID == "" || pb.DeviceKeyHex == "" || pb.ServerKyberPubB64 == "" {
		return nil, errors.New("pairing blob missing required fields")
	}
	if innerType != innerInject && innerType != innerApprove {
		return nil, errors.New("invalid inner type")
	}

	deviceKey, err := hex.DecodeString(pb.DeviceKeyHex)
	if err != nil {
		return nil, err
	}
	if len(deviceKey) != 32 {
		return nil, errors.New("device_key_hex must decode to 32 bytes")
	}

	serverPubBytes, err := base64.StdEncoding.DecodeString(pb.ServerKyberPubB64)
	if err != nil {
		return nil, err
	}

	ek, err := mlkem.NewEncapsulationKey768(serverPubBytes)
	if err != nil {
		return nil, err
	}

	// ML-KEM encapsulate (sharedKey, ciphertext)
	sharedKey, kemCt := ek.Encapsulate() // signature per stdlib crypto/mlkem :contentReference[oaicite:1]{index=1}
	if len(sharedKey) != 32 {
		return nil, errors.New("unexpected sharedKey length")
	}
	if len(kemCt) == 0 {
		return nil, errors.New("empty KEM ciphertext")
	}

	// Inner typed frame
	inner := buildInnerFrame(pb.DeviceID, innerType, []byte(payload))

	// Plaintext = timestamp(u64 big endian) || innerFrame
	ts := uint64(time.Now().Unix())
	plain := make([]byte, 8+len(inner))
	binary.BigEndian.PutUint64(plain[0:8], ts)
	copy(plain[8:], inner)

	// HKDF-SHA256: IKM=sharedKey, salt=deviceKey, info="NovaKey v3 AEAD key"
	key := make([]byte, 32)
	h := hkdf.New(sha256.New, sharedKey, deviceKey, []byte(hkdfInfo))
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key) // XChaCha20-Poly1305 (24-byte nonce)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Outer header (AAD covers header through kemCt)
	header, err := buildOuterHeader(pb.DeviceID, kemCt)
	if err != nil {
		return nil, err
	}
	aad := header

	ciphertext := aead.Seal(nil, nonce, plain, aad)

	// Outer payload = header || nonce || ciphertext
	payloadBytes := make([]byte, 0, len(header)+len(nonce)+len(ciphertext))
	payloadBytes = append(payloadBytes, header...)
	payloadBytes = append(payloadBytes, nonce...)
	payloadBytes = append(payloadBytes, ciphertext...)

	if len(payloadBytes) > 0xFFFF {
		return nil, errors.New("payload too large for u16 framing")
	}

	// TCP frame: [u16 length big-endian][payload]
	out := make([]byte, 2+len(payloadBytes))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(payloadBytes)))
	copy(out[2:], payloadBytes)
	return out, nil
}

func buildOuterHeader(deviceID string, kemCt []byte) ([]byte, error) {
	idb := []byte(deviceID)
	if len(idb) == 0 || len(idb) > 255 {
		return nil, errors.New("deviceID must be 1..255 bytes")
	}
	if len(kemCt) > 0xFFFF {
		return nil, errors.New("kemCt too large")
	}

	// layout:
	// [0]=version [1]=outerMsgType [2]=idLen [3..]=deviceID
	// then [kemCtLen u16] [kemCt]
	hlen := 3 + len(idb) + 2 + len(kemCt)
	h := make([]byte, hlen)

	h[0] = outerVersion
	h[1] = outerMsgType
	h[2] = byte(len(idb))
	copy(h[3:3+len(idb)], idb)

	pos := 3 + len(idb)
	binary.BigEndian.PutUint16(h[pos:pos+2], uint16(len(kemCt)))
	pos += 2
	copy(h[pos:], kemCt)

	return h, nil
}

func buildInnerFrame(deviceID string, msgType byte, payload []byte) []byte {
	idb := []byte(deviceID)

	// [0]=innerVersion [1]=innerMsgType [2:4]=deviceIDLen(u16) [4:8]=payloadLen(u32)
	// then deviceID bytes, then payload bytes
	out := make([]byte, 8+len(idb)+len(payload))
	out[0] = innerVersion
	out[1] = msgType
	binary.BigEndian.PutUint16(out[2:4], uint16(len(idb)))
	binary.BigEndian.PutUint32(out[4:8], uint32(len(payload)))
	copy(out[8:8+len(idb)], idb)
	copy(out[8+len(idb):], payload)
	return out
}

// (Optional) tiny helper if we want a deterministic HMAC for “signature” style checks later.
// Keep private unless really need it bound into Swift.
func mac256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

