package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
)

// ErrUnsupportedAlgorithm tells you when our quick dev assumptions have failed
var ErrUnsupportedAlgorithm = errors.New("pkcs7: cannot decrypt data: only RSA, RSAES-OAEP, DES, DES-EDE3, AES-256-CBC, AES-128-GCM, AES-256-GCM supported")

// ErrNotEncryptedContent is returned when attempting to Decrypt data that is not encrypted data
var ErrNotEncryptedContent = errors.New("pkcs7: content data is a decryptable data type")

// rsaOAEPAlgParams describes the digest when using RSAES-OAEP. RFC 4055, section 4.1
type rsaOAEPAlgParams struct {
	HashFunc    pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0,default:sha1Identifier"`
	MaskGenFunc pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1,default:mgf1SHA1Identifier"`
	PSourceFunc pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:2,default:pSpecifiedEmptyIdentifier"`
}

func (roap rsaOAEPAlgParams) hash() (hash.Hash, error) {

	oid := roap.HashFunc.Algorithm
	if oid == nil {
		oid = OIDDigestAlgorithmSHA1 // Default
	}

	return getHashFuncForOID(oid)
}

// Decrypt decrypts encrypted content info for recipient cert and private key
func (p7 *PKCS7) Decrypt(cert *x509.Certificate, pkey crypto.PrivateKey) ([]byte, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipient := selectRecipientForCertificate(data.RecipientInfos, cert)
	if recipient.EncryptedKey == nil {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}

	rsaKey, ok := pkey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}

	var (
		contentKey []byte
		err        error
	)

	switch {
	case recipient.KeyEncryptionAlgorithm.Algorithm.Equal(OIDEncryptionAlgorithmRSA):
		if contentKey, err = rsa.DecryptPKCS1v15(rand.Reader, rsaKey, recipient.EncryptedKey); err != nil {
			return nil, err
		}
	case recipient.KeyEncryptionAlgorithm.Algorithm.Equal(OIDEncryptionAlgorithmRSAESOAEP):
		var (
			params rsaOAEPAlgParams
			rest   []byte
			hash   hash.Hash
		)

		if rest, err = asn1.Unmarshal(recipient.KeyEncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
			return nil, err
		}

		if len(rest) > 0 {
			return nil, errors.New("pkcs7: unexpected rest bytes after RSAES-OAEP parameters")
		}

		if hash, err = params.hash(); err != nil {
			return nil, err
		}

		if contentKey, err = rsa.DecryptOAEP(hash, rand.Reader, rsaKey, recipient.EncryptedKey, nil); err != nil {
			return nil, err
		}
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	return data.EncryptedContentInfo.decrypt(contentKey)
}

// DecryptUsingPSK decrypts encrypted data using caller provided
// pre-shared secret
func (p7 *PKCS7) DecryptUsingPSK(key []byte) ([]byte, error) {
	data, ok := p7.raw.(encryptedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	return data.EncryptedContentInfo.decrypt(key)
}

func (eci encryptedContentInfo) decrypt(key []byte) ([]byte, error) {
	alg := eci.ContentEncryptionAlgorithm.Algorithm
	if !alg.Equal(OIDEncryptionAlgorithmDESCBC) &&
		!alg.Equal(OIDEncryptionAlgorithmDESEDE3CBC) &&
		!alg.Equal(OIDEncryptionAlgorithmAES256CBC) &&
		!alg.Equal(OIDEncryptionAlgorithmAES128CBC) &&
		!alg.Equal(OIDEncryptionAlgorithmAES128GCM) &&
		!alg.Equal(OIDEncryptionAlgorithmAES256GCM) {
		fmt.Printf("Unsupported Content Encryption Algorithm: %s\n", alg)
		return nil, ErrUnsupportedAlgorithm
	}

	// EncryptedContent can either be constructed of multple OCTET STRINGs
	// or _be_ a tagged OCTET STRING
	var cyphertext []byte
	if eci.EncryptedContent.IsCompound {
		// Complex case to concat all of the children OCTET STRINGs
		var buf bytes.Buffer
		cypherbytes := eci.EncryptedContent.Bytes
		for {
			var part []byte
			cypherbytes, _ = asn1.Unmarshal(cypherbytes, &part)
			buf.Write(part)
			if cypherbytes == nil {
				break
			}
		}
		cyphertext = buf.Bytes()
	} else {
		// Simple case, the bytes _are_ the cyphertext
		cyphertext = eci.EncryptedContent.Bytes
	}

	var block cipher.Block
	var err error

	switch {
	case alg.Equal(OIDEncryptionAlgorithmDESCBC):
		block, err = des.NewCipher(key)
	case alg.Equal(OIDEncryptionAlgorithmDESEDE3CBC):
		block, err = des.NewTripleDESCipher(key)
	case alg.Equal(OIDEncryptionAlgorithmAES256CBC), alg.Equal(OIDEncryptionAlgorithmAES256GCM):
		fallthrough
	case alg.Equal(OIDEncryptionAlgorithmAES128GCM), alg.Equal(OIDEncryptionAlgorithmAES128CBC):
		block, err = aes.NewCipher(key)
	}

	if err != nil {
		return nil, err
	}

	if alg.Equal(OIDEncryptionAlgorithmAES128GCM) || alg.Equal(OIDEncryptionAlgorithmAES256GCM) {
		params := aesGCMParameters{}
		paramBytes := eci.ContentEncryptionAlgorithm.Parameters.Bytes

		_, err := asn1.Unmarshal(paramBytes, &params)
		if err != nil {

			// Test legacy (and faulty) ASN.1 structure to allow
			// libraries depending on older pkcs7 releases to still
			// function.
			paramsLegacy := struct {
				Nonce  []byte `asn1:"tag:4"`
				ICVLen int
			}{}

			_, err := asn1.Unmarshal(paramBytes, &paramsLegacy)
			if err != nil {
				return nil, err
			}

			params.Nonce = paramsLegacy.Nonce
			params.ICVLen = paramsLegacy.ICVLen
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		if len(params.Nonce) != gcm.NonceSize() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}
		if params.ICVLen != gcm.Overhead() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}

		plaintext, err := gcm.Open(nil, params.Nonce, cyphertext, nil)
		if err != nil {
			return nil, err
		}

		return plaintext, nil
	}

	iv := eci.ContentEncryptionAlgorithm.Parameters.Bytes
	if len(iv) != block.BlockSize() {
		return nil, errors.New("pkcs7: encryption algorithm parameters are malformed")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(cyphertext))
	mode.CryptBlocks(plaintext, cyphertext)
	if plaintext, err = unpad(plaintext, mode.BlockSize()); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}

	// the last byte is the length of padding
	padlen := int(data[len(data)-1])

	// check padding integrity, all bytes should be the same
	pad := data[len(data)-padlen:]
	for _, padbyte := range pad {
		if padbyte != byte(padlen) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}

func selectRecipientForCertificate(recipients []recipientInfo, cert *x509.Certificate) recipientInfo {
	for _, recp := range recipients {
		if isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
			return recp
		}
	}
	return recipientInfo{}
}
