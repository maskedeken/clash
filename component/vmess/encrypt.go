package vmess

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"time"
)

const (
	KDFSaltConst_AuthIDEncryptionKey = "AES Auth ID Encryption"

	KDFSaltConst_AEADRespHeaderLenKey = "AEAD Resp Header Len Key"

	KDFSaltConst_AEADRespHeaderLenIV = "AEAD Resp Header Len IV"

	KDFSaltConst_AEADRespHeaderPayloadKey = "AEAD Resp Header Key"

	KDFSaltConst_AEADRespHeaderPayloadIV = "AEAD Resp Header IV"

	KDFSaltConst_VMessAEADKDF = "VMess AEAD KDF"

	KDFSaltConst_VMessHeaderPayloadAEADKey = "VMess Header AEAD Key"

	KDFSaltConst_VMessHeaderPayloadAEADIV = "VMess Header AEAD Nonce"

	KDFSaltConst_VMessHeaderPayloadLengthAEADKey = "VMess Header AEAD Key_Length"

	KDFSaltConst_VMessHeaderPayloadLengthAEADIV = "VMess Header AEAD Nonce_Length"
)

func CreateAuthID(cmdKey []byte, time int64) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	binary.Write(buf, binary.BigEndian, time)
	var zero uint32
	io.CopyN(buf, rand.Reader, 4)
	zero = crc32.ChecksumIEEE(buf.Bytes())
	binary.Write(buf, binary.BigEndian, zero)
	aesBlock, err := aes.NewCipher(KDF16(cmdKey, KDFSaltConst_AuthIDEncryptionKey))
	if err != nil {
		return nil, err
	}

	if buf.Len() != 16 {
		return nil, errors.New("Size unexcepted")
	}

	var result [16]byte
	aesBlock.Encrypt(result[:], buf.Bytes())
	return result[:], nil
}

func KDF(key []byte, path ...string) []byte {
	hmacf := hmac.New(func() hash.Hash {
		return sha256.New()
	}, []byte(KDFSaltConst_VMessAEADKDF))

	for _, v := range path {
		hmacf = hmac.New(func() hash.Hash {
			return hmacf
		}, []byte(v))
	}
	hmacf.Write(key)
	return hmacf.Sum(nil)
}

func KDF16(key []byte, path ...string) []byte {
	r := KDF(key, path...)
	return r[:16]
}

func SealVMessAEADHeader(key [16]byte, data []byte) ([]byte, error) {
	generatedAuthID, err := CreateAuthID(key[:], time.Now().Unix())
	if err != nil {
		return nil, err
	}

	connectionNonce := make([]byte, 8)
	io.ReadFull(rand.Reader, connectionNonce)

	aeadPayloadLengthSerializeBuffer := bytes.NewBuffer(nil)

	headerPayloadDataLen := uint16(len(data))

	binary.Write(aeadPayloadLengthSerializeBuffer, binary.BigEndian, headerPayloadDataLen)

	aeadPayloadLengthSerializedByte := aeadPayloadLengthSerializeBuffer.Bytes()
	var payloadHeaderLengthAEADEncrypted []byte

	{
		payloadHeaderLengthAEADKey := KDF16(key[:], KDFSaltConst_VMessHeaderPayloadLengthAEADKey, string(generatedAuthID), string(connectionNonce))

		payloadHeaderLengthAEADNonce := KDF(key[:], KDFSaltConst_VMessHeaderPayloadLengthAEADIV, string(generatedAuthID), string(connectionNonce))[:12]

		payloadHeaderLengthAEADAESBlock, err := aes.NewCipher(payloadHeaderLengthAEADKey)
		if err != nil {
			return nil, err
		}

		payloadHeaderAEAD, err := cipher.NewGCM(payloadHeaderLengthAEADAESBlock)
		if err != nil {
			return nil, err
		}

		payloadHeaderLengthAEADEncrypted = payloadHeaderAEAD.Seal(nil, payloadHeaderLengthAEADNonce, aeadPayloadLengthSerializedByte, generatedAuthID)
	}

	var payloadHeaderAEADEncrypted []byte

	{
		payloadHeaderAEADKey := KDF16(key[:], KDFSaltConst_VMessHeaderPayloadAEADKey, string(generatedAuthID), string(connectionNonce))

		payloadHeaderAEADNonce := KDF(key[:], KDFSaltConst_VMessHeaderPayloadAEADIV, string(generatedAuthID), string(connectionNonce))[:12]

		payloadHeaderAEADAESBlock, err := aes.NewCipher(payloadHeaderAEADKey)
		if err != nil {
			return nil, err
		}

		payloadHeaderAEAD, err := cipher.NewGCM(payloadHeaderAEADAESBlock)
		if err != nil {
			return nil, err
		}

		payloadHeaderAEADEncrypted = payloadHeaderAEAD.Seal(nil, payloadHeaderAEADNonce, data, generatedAuthID)
	}

	var outputBuffer = bytes.NewBuffer(nil)
	outputBuffer.Write(generatedAuthID)                  //16
	outputBuffer.Write(payloadHeaderLengthAEADEncrypted) //2+16
	outputBuffer.Write(connectionNonce)                  //8
	outputBuffer.Write(payloadHeaderAEADEncrypted)
	return outputBuffer.Bytes(), nil
}

func OpenVMessAEADHeader(dst []byte, key []byte, iv []byte, data io.Reader) error {
	aeadResponseHeaderLengthEncryptionKey := KDF16(key, KDFSaltConst_AEADRespHeaderLenKey)
	aeadResponseHeaderLengthEncryptionIV := KDF(iv, KDFSaltConst_AEADRespHeaderLenIV)[:12]

	aeadResponseHeaderLengthEncryptionKeyAESBlock, err := aes.NewCipher(aeadResponseHeaderLengthEncryptionKey)
	if err != nil {
		return err
	}

	aeadResponseHeaderLengthEncryptionAEAD, err := cipher.NewGCM(aeadResponseHeaderLengthEncryptionKeyAESBlock)
	if err != nil {
		return err
	}

	var aeadEncryptedResponseHeaderLength [18]byte
	var decryptedResponseHeaderLength int
	var decryptedResponseHeaderLengthBinaryDeserializeBuffer uint16

	if _, err = io.ReadFull(data, aeadEncryptedResponseHeaderLength[:]); err != nil {
		return err
	}

	if decryptedResponseHeaderLengthBinaryBuffer, err := aeadResponseHeaderLengthEncryptionAEAD.Open(nil, aeadResponseHeaderLengthEncryptionIV, aeadEncryptedResponseHeaderLength[:], nil); err != nil {
		return err
	} else {
		binary.Read(bytes.NewReader(decryptedResponseHeaderLengthBinaryBuffer), binary.BigEndian, &decryptedResponseHeaderLengthBinaryDeserializeBuffer)
		decryptedResponseHeaderLength = int(decryptedResponseHeaderLengthBinaryDeserializeBuffer)
	}

	aeadResponseHeaderPayloadEncryptionKey := KDF16(key, KDFSaltConst_AEADRespHeaderPayloadKey)
	aeadResponseHeaderPayloadEncryptionIV := KDF(iv, KDFSaltConst_AEADRespHeaderPayloadIV)[:12]

	aeadResponseHeaderPayloadEncryptionKeyAESBlock, err := aes.NewCipher(aeadResponseHeaderPayloadEncryptionKey)
	if err != nil {
		return err
	}

	aeadResponseHeaderPayloadEncryptionAEAD, err := cipher.NewGCM(aeadResponseHeaderPayloadEncryptionKeyAESBlock)
	if err != nil {
		return err
	}

	encryptedResponseHeaderBuffer := make([]byte, decryptedResponseHeaderLength+16)

	if _, err := io.ReadFull(data, encryptedResponseHeaderBuffer); err != nil {
		return err
	}

	if decryptedResponseHeaderBuffer, err := aeadResponseHeaderPayloadEncryptionAEAD.Open(nil, aeadResponseHeaderPayloadEncryptionIV, encryptedResponseHeaderBuffer, nil); err != nil {
		return err
	} else {
		copy(dst, decryptedResponseHeaderBuffer)
		return nil
	}

}
