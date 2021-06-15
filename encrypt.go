package pkcs7

import (
	"bytes"
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
)

// EncryptOption is a function on the options for a encryption
type EncryptOption func(*EncryptOptions) error

// EncryptOptions holds encryption options
type EncryptOptions struct {
	Digest     asn1.ObjectIdentifier
	KeyAlg     asn1.ObjectIdentifier
	ContentAlg ContentEncryptionAlgorithm
}

func defaultEncryptOptions() *EncryptOptions {
	return &EncryptOptions{
		Digest:     OIDDigestAlgorithmSHA1,
		KeyAlg:     OIDEncryptionAlgorithmRSA,
		ContentAlg: EncryptionAlgorithmDESCBC,
	}
}

// WithKeyDigestAlgorithmOID configures what hash function to use
// while encrypting the key.
// NOTE: Only applicable when key encryption algorithm is RSAES-OAEP.
func WithKeyDigestAlgorithmOID(d asn1.ObjectIdentifier) EncryptOption {
	return func(o *EncryptOptions) error {
		o.Digest = d
		return nil
	}
}

// WithKeyAlgorithmOID configures what encryption algorithm to
// use for key encryption
func WithKeyAlgorithmOID(d asn1.ObjectIdentifier) EncryptOption {
	return func(o *EncryptOptions) error {
		if !d.Equal(OIDEncryptionAlgorithmRSAESOAEP) &&
			!d.Equal(OIDEncryptionAlgorithmRSA) {
			return errors.New("pkcs7: only RSA and RSAES-OAEP can be used for key encryption")
		}

		o.KeyAlg = d
		return nil
	}
}

// WithContentAlgorithm configures what encryption algorithm to
// use for encrypting the content
func WithContentAlgorithm(a ContentEncryptionAlgorithm) EncryptOption {
	return func(o *EncryptOptions) error {
		o.ContentAlg = a
		return nil
	}
}

type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

// ContentEncryptionAlgorithm is a type that describes a supported
// content symmetric encryption scheme
type ContentEncryptionAlgorithm int

const (
	// EncryptionAlgorithmDESCBC is the DES CBC encryption algorithm
	EncryptionAlgorithmDESCBC ContentEncryptionAlgorithm = iota

	// EncryptionAlgorithmAES128CBC is the AES 128 bits with CBC encryption algorithm
	// Avoid this algorithm unless required for interoperability; use AES GCM instead.
	EncryptionAlgorithmAES128CBC

	// EncryptionAlgorithmAES256CBC is the AES 256 bits with CBC encryption algorithm
	// Avoid this algorithm unless required for interoperability; use AES GCM instead.
	EncryptionAlgorithmAES256CBC

	// EncryptionAlgorithmAES128GCM is the AES 128 bits with GCM encryption algorithm
	EncryptionAlgorithmAES128GCM

	// EncryptionAlgorithmAES256GCM is the AES 256 bits with GCM encryption algorithm
	EncryptionAlgorithmAES256GCM
)

// ErrUnsupportedEncryptionAlgorithm is returned when attempting to encrypt
// content with an unsupported algorithm.
var ErrUnsupportedEncryptionAlgorithm = errors.New("pkcs7: cannot encrypt content: only DES-CBC, AES-CBC, and AES-GCM supported")

// ErrPSKNotProvided is returned when attempting to encrypt
// using a PSK without actually providing the PSK.
var ErrPSKNotProvided = errors.New("pkcs7: cannot encrypt content: PSK not provided")

const nonceSize = 12

type aesGCMParameters struct {
	Nonce  []byte `asn1:"tag:4"`
	ICVLen int
}

func encryptAESGCM(content []byte, key []byte, opts *EncryptOptions) ([]byte, *encryptedContentInfo, error) {
	var keyLen int
	var algID asn1.ObjectIdentifier
	switch opts.ContentAlg {
	case EncryptionAlgorithmAES128GCM:
		keyLen = 16
		algID = OIDEncryptionAlgorithmAES128GCM
	case EncryptionAlgorithmAES256GCM:
		keyLen = 32
		algID = OIDEncryptionAlgorithmAES256GCM
	default:
		return nil, nil, fmt.Errorf("invalid ContentEncryptionAlgorithm in encryptAESGCM: %d", opts.ContentAlg)
	}
	if key == nil {
		// Create AES key
		key = make([]byte, keyLen)

		_, err := rand.Read(key)
		if err != nil {
			return nil, nil, err
		}
	}

	// Create nonce
	nonce := make([]byte, nonceSize)

	_, err := rand.Read(nonce)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt content
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, content, nil)

	// Prepare ASN.1 Encrypted Content Info
	paramSeq := aesGCMParameters{
		Nonce:  nonce,
		ICVLen: gcm.Overhead(),
	}

	paramBytes, err := asn1.Marshal(paramSeq)
	if err != nil {
		return nil, nil, err
	}

	eci := encryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: algID,
			Parameters: asn1.RawValue{
				Tag:   asn1.TagSequence,
				Bytes: paramBytes,
			},
		},
		EncryptedContent: marshalEncryptedContent(ciphertext),
	}

	return key, &eci, nil
}

func encryptDESCBC(content []byte, key []byte) ([]byte, *encryptedContentInfo, error) {
	if key == nil {
		// Create DES key
		key = make([]byte, 8)

		_, err := rand.Read(key)
		if err != nil {
			return nil, nil, err
		}
	}

	// Create CBC IV
	iv := make([]byte, des.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt padded content
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext, err := pad(content, mode.BlockSize())
	if err != nil {
		return nil, nil, err
	}
	cyphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(cyphertext, plaintext)

	// Prepare ASN.1 Encrypted Content Info
	eci := encryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  OIDEncryptionAlgorithmDESCBC,
			Parameters: asn1.RawValue{Tag: 4, Bytes: iv},
		},
		EncryptedContent: marshalEncryptedContent(cyphertext),
	}

	return key, &eci, nil
}

func encryptAESCBC(content []byte, key []byte, opts *EncryptOptions) ([]byte, *encryptedContentInfo, error) {
	var keyLen int
	var algID asn1.ObjectIdentifier
	switch opts.ContentAlg {
	case EncryptionAlgorithmAES128CBC:
		keyLen = 16
		algID = OIDEncryptionAlgorithmAES128CBC
	case EncryptionAlgorithmAES256CBC:
		keyLen = 32
		algID = OIDEncryptionAlgorithmAES256CBC
	default:
		return nil, nil, fmt.Errorf("invalid ContentEncryptionAlgorithm in encryptAESCBC: %d", opts.ContentAlg)
	}

	if key == nil {
		// Create AES key
		key = make([]byte, keyLen)

		_, err := rand.Read(key)
		if err != nil {
			return nil, nil, err
		}
	}

	// Create CBC IV
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt padded content
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext, err := pad(content, mode.BlockSize())
	if err != nil {
		return nil, nil, err
	}
	cyphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(cyphertext, plaintext)

	// Prepare ASN.1 Encrypted Content Info
	eci := encryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  algID,
			Parameters: asn1.RawValue{Tag: 4, Bytes: iv},
		},
		EncryptedContent: marshalEncryptedContent(cyphertext),
	}

	return key, &eci, nil
}

// Encrypt creates and returns an envelope data PKCS7 structure with encrypted
// recipient keys for each recipient public key.
func Encrypt(content []byte, recipients []*x509.Certificate, opts ...EncryptOption) ([]byte, error) {
	var eci *encryptedContentInfo
	var key []byte
	var err error

	options := defaultEncryptOptions()
	for _, o := range opts {
		if err := o(options); err != nil {
			return nil, err
		}
	}

	// Apply chosen symmetric encryption method
	switch options.ContentAlg {
	case EncryptionAlgorithmDESCBC:
		key, eci, err = encryptDESCBC(content, nil)
	case EncryptionAlgorithmAES128CBC:
		fallthrough
	case EncryptionAlgorithmAES256CBC:
		key, eci, err = encryptAESCBC(content, nil, options)
	case EncryptionAlgorithmAES128GCM:
		fallthrough
	case EncryptionAlgorithmAES256GCM:
		key, eci, err = encryptAESGCM(content, nil, options)
	default:
		return nil, ErrUnsupportedEncryptionAlgorithm
	}

	if err != nil {
		return nil, err
	}

	// Prepare each recipient's encrypted cipher key
	recipientInfos := make([]recipientInfo, len(recipients))
	for i, recipient := range recipients {
		encrypted, err := encryptKey(key, recipient, options)
		if err != nil {
			return nil, err
		}
		ias, err := cert2issuerAndSerial(recipient)
		if err != nil {
			return nil, err
		}

		keyAlgParams := asn1.NullRawValue

		if options.KeyAlg.Equal(OIDEncryptionAlgorithmRSAESOAEP) {
			oaepParams := rsaOAEPAlgParams{
				HashFunc: pkix.AlgorithmIdentifier{
					Algorithm:  options.Digest,
					Parameters: asn1.NullRawValue,
				},
				MaskGenFunc: mgf1SHA1Identifier,
				PSourceFunc: pSpecifiedEmptyIdentifier,
			}

			data, err := asn1.Marshal(oaepParams)
			if err != nil {
				return nil, err
			}

			keyAlgParams.FullBytes = data
		}

		info := recipientInfo{
			Version:               0,
			IssuerAndSerialNumber: ias,
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  options.KeyAlg,
				Parameters: keyAlgParams,
			},
			EncryptedKey: encrypted,
		}
		recipientInfos[i] = info
	}

	// Prepare envelope content
	envelope := envelopedData{
		EncryptedContentInfo: *eci,
		Version:              0,
		RecipientInfos:       recipientInfos,
	}
	innerContent, err := asn1.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	// Prepare outer payload structure
	wrapper := contentInfo{
		ContentType: OIDEnvelopedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}

	return asn1.Marshal(wrapper)
}

// EncryptUsingPSK creates and returns an encrypted data PKCS7 structure,
// encrypted using caller provided pre-shared secret.
func EncryptUsingPSK(content []byte, key []byte, opts ...EncryptOption) ([]byte, error) {
	var eci *encryptedContentInfo
	var err error

	if key == nil {
		return nil, ErrPSKNotProvided
	}

	options := defaultEncryptOptions()
	for _, o := range opts {
		if err := o(options); err != nil {
			return nil, err
		}
	}

	// Apply chosen symmetric encryption method
	switch options.ContentAlg {
	case EncryptionAlgorithmDESCBC:
		_, eci, err = encryptDESCBC(content, key)

	case EncryptionAlgorithmAES128GCM:
		fallthrough
	case EncryptionAlgorithmAES256GCM:
		_, eci, err = encryptAESGCM(content, key, options)

	default:
		return nil, ErrUnsupportedEncryptionAlgorithm
	}

	if err != nil {
		return nil, err
	}

	// Prepare encrypted-data content
	ed := encryptedData{
		Version:              0,
		EncryptedContentInfo: *eci,
	}
	innerContent, err := asn1.Marshal(ed)
	if err != nil {
		return nil, err
	}

	// Prepare outer payload structure
	wrapper := contentInfo{
		ContentType: OIDEncryptedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}

	return asn1.Marshal(wrapper)
}

func marshalEncryptedContent(content []byte) asn1.RawValue {
	asn1Content, _ := asn1.Marshal(content)
	return asn1.RawValue{Tag: 0, Class: 2, Bytes: asn1Content, IsCompound: true}
}

func encryptKey(key []byte, recipient *x509.Certificate, opts *EncryptOptions) ([]byte, error) {

	rsaPub, ok := recipient.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}

	if opts.KeyAlg.Equal(OIDEncryptionAlgorithmRSA) {
		return rsa.EncryptPKCS1v15(rand.Reader, rsaPub, key)
	} else {
		hash, err := getHashFuncForOID(opts.Digest)
		if err != nil {
			return nil, err
		}
		return rsa.EncryptOAEP(hash, rand.Reader, rsaPub, key, nil)
	}
}

func pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := blocklen - (len(data) % blocklen)
	if padlen == 0 {
		padlen = blocklen
	}
	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}
