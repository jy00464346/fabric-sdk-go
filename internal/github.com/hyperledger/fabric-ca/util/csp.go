/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/

package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	factory "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkpatch/cryptosuitebridge"
	log "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkpatch/logbridge"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/gm"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite/bccsp/wrapper"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
	gtls "github.com/tjfoc/gmtls"
	"io/ioutil"
	"reflect"
	"strings"
)

// getBCCSPKeyOpts generates a key as specified in the request.
// This supports ECDSA and RSA.
func getBCCSPKeyOpts(kr csr.KeyRequest, ephemeral bool) (opts core.KeyGenOpts, err error) {
	if kr == nil {
		return factory.GetECDSAKeyGenOpts(ephemeral), nil
	}
	log.Debugf("generate key from request: algo=%s, size=%d", kr.Algo(), kr.Size())
	switch kr.Algo() {
	case "rsa":
		switch kr.Size() {
		case 2048:
			return factory.GetRSA2048KeyGenOpts(ephemeral), nil
		case 3072:
			return factory.GetRSA3072KeyGenOpts(ephemeral), nil
		case 4096:
			return factory.GetRSA4096KeyGenOpts(ephemeral), nil
		default:
			// Need to add a way to specify arbitrary RSA key size to bccsp
			return nil, errors.Errorf("Invalid RSA key size: %d", kr.Size())
		}
	case "ecdsa":
		switch kr.Size() {
		case 256:
			return factory.GetECDSAP256KeyGenOpts(ephemeral), nil
		case 384:
			return factory.GetECDSAP384KeyGenOpts(ephemeral), nil
		case 521:
			// Need to add curve P521 to bccsp
			// return &bccsp.ECDSAP512KeyGenOpts{Temporary: false}, nil
			return nil, errors.New("Unsupported ECDSA key size: 521")
		default:
			return nil, errors.Errorf("Invalid ECDSA key size: %d", kr.Size())
		}
	case "gmsm2":
		return factory.GetGMSM2KeyGenOpts(ephemeral), nil
	default:
		return nil, errors.Errorf("Invalid algorithm: %s", kr.Algo())
	}
}

// GetSignerFromCert load private key represented by ski and return bccsp signer that conforms to crypto.Signer
func GetSignerFromCert(cert *x509.Certificate, csp core.CryptoSuite) (core.Key, crypto.Signer, error) {
	if csp == nil {
		return nil, nil, errors.New("CSP was not initialized")
	}
	log.Infof("begin csp.KeyImport,cert.PublicKey is %T   csp:%T", cert.PublicKey, csp)
	switch cert.PublicKey.(type) {
	case sm2.PublicKey:
		log.Infof("cert is sm2 puk")
	default:
		log.Infof("cert is default puk")
	}

	sm2cert := gm.ParseX509Certificate2Sm2(cert)

	// get the public key in the right format
	certPubK, err := csp.KeyImport(sm2cert, factory.GetX509PublicKeyImportOpts(true))
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed to import certificate's public key")
	}
	// Get the key given the SKI value
	ski := certPubK.SKI()
	privateKey, err := csp.GetKey(ski)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Could not find matching private key for SKI")
	}
	// BCCSP returns a public key if the private key for the SKI wasn't found, so
	// we need to return an error in that case.
	if !privateKey.Private() {
		return nil, nil, errors.Errorf("The private key associated with the certificate with SKI '%s' was not found", hex.EncodeToString(ski))
	}
	// Construct and initialize the signer
	signer, err := factory.NewCspSigner(csp, privateKey)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed to load ski from bccsp")
	}
	return privateKey, signer, nil
}

// GetSignerFromSM2Cert load private key represented by ski and return bccsp signer that conforms to crypto.Signer
func GetSignerFromSM2Cert(cert *sm2.Certificate, csp core.CryptoSuite) (core.Key, crypto.Signer, error) {
	if csp == nil {
		return nil, nil, fmt.Errorf("CSP was not initialized")
	}

	log.Infof("begin csp.KeyImport,cert.PublicKey is %T   csp:%T", cert.PublicKey, csp)
	switch cert.PublicKey.(type) {
	case sm2.PublicKey:
		log.Infof("cert is sm2 puk")
	default:
		log.Infof("cert is default puk")
	}

	// sm2cert := gm.ParseX509Certificate2Sm2(cert)
	// pk := cert.PublicKey
	// sm2PublickKey := pk.(sm2.PublicKey)
	// // if !ok {
	// // 	return nil, nil, errors.New("Parse interface []  to sm2 pk error")
	// // }
	// der, err := sm2.MarshalSm2PublicKey(&sm2PublickKey)
	// if err != nil {
	// 	return nil, nil, errors.New("MarshalSm2PublicKey error")
	// }

	// get the public key in the right format
	certPubK, err := csp.KeyImport(cert, factory.GetGMSM2PublicKeyImportOpts(true))
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to import certificate's public key: %s", err.Error())
	}

	kname := hex.EncodeToString(certPubK.SKI())
	log.Infof("begin csp.GetKey kname:%s", kname)

	// Get the key given the SKI value
	privateKey, err := csp.GetKey(certPubK.SKI())
	if err != nil {
		return nil, nil, errors.Errorf("The private key associated with the certificate with SKI '%s' was not found", hex.EncodeToString(certPubK.SKI()))
	}
	// BCCSP returns a public key if the private key for the SKI wasn't found, so
	// we need to return an error in that case.
	if !privateKey.Private() {
		return nil, nil, errors.Errorf("The private key associated with the certificate with SKI '%s' was not found", hex.EncodeToString(certPubK.SKI()))
	}
	// Construct and initialize the signer
	signer, err := factory.NewCspSigner(csp, privateKey)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed to load ski from bccsp")
	}
	log.Info("end GetSignerFromCert successfuul")
	return privateKey, signer, nil
}

// GetSignerFromCertFile load skiFile and load private key represented by ski and return bccsp signer that conforms to crypto.Signer
func GetSignerFromCertFile(certFile string, csp core.CryptoSuite) (core.Key, crypto.Signer, *x509.Certificate, error) {
	// Load cert file
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "Could not read certFile '%s'", certFile)
	}
	// Parse certificate
	parsedCa, err := helpers.ParseCertificatePEM(certBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	// Get the signer from the cert
	key, cspSigner, err := GetSignerFromCert(parsedCa, csp)
	return key, cspSigner, parsedCa, err
}

// BCCSPKeyRequestGenerate generates keys through BCCSP
// somewhat mirroring to cfssl/req.KeyRequest.Generate()
func BCCSPKeyRequestGenerate(req *csr.CertificateRequest, myCSP core.CryptoSuite) (core.Key, crypto.Signer, error) {
	log.Infof("generating key: %+v", req.KeyRequest)
	keyOpts, err := getBCCSPKeyOpts(req.KeyRequest, false)
	if err != nil {
		return nil, nil, err
	}
	key, err := myCSP.KeyGen(keyOpts)
	if err != nil {
		return nil, nil, err
	}
	cspSigner, err := factory.NewCspSigner(myCSP, key)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed initializing CryptoSigner")
	}
	return key, cspSigner, nil
}

// ImportBCCSPKeyFromPEM attempts to create a private BCCSP key from a pem file keyFile
func ImportBCCSPKeyFromPEM(keyFile string, myCSP core.CryptoSuite, temporary bool) (core.Key, error) {
	keyBuff, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	key, err := ImportBCCSPKeyFromPEMBytes(keyBuff, myCSP, temporary)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed parsing private key from key file %s", keyFile))
	}
	return key, nil
}

// ImportBCCSPKeyFromPEMBytes attempts to create a private BCCSP key from a pem byte slice
func ImportBCCSPKeyFromPEMBytes(keyBuff []byte, myCSP core.CryptoSuite, temporary bool) (core.Key, error) {
	keyFile := "pem bytes"

	key, err := factory.PEMtoPrivateKey(keyBuff, nil)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed parsing private key from %s", keyFile))
	}
	switch key.(type) {
	case *sm2.PrivateKey:
		log.Info("[csp] sm2.PrivateKey")
		block, _ := pem.Decode(keyBuff)
		priv, err := myCSP.KeyImport(block.Bytes, factory.GetGMSM2PrivateKeyImportOpts(temporary))
		if err != nil {
			return nil, fmt.Errorf("Failed to convert SM2 private key from %s: %s", keyFile, err.Error())
		}
		return priv, nil
	case *ecdsa.PrivateKey:
		priv, err := factory.PrivateKeyToDER(key.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, errors.WithMessage(err, fmt.Sprintf("Failed to convert ECDSA private key for '%s'", keyFile))
		}
		sk, err := myCSP.KeyImport(priv, factory.GetECDSAPrivateKeyImportOpts(temporary))
		if err != nil {
			return nil, errors.WithMessage(err, fmt.Sprintf("Failed to import ECDSA private key for '%s'", keyFile))
		}
		return sk, nil
	case *rsa.PrivateKey:
		return nil, errors.Errorf("Failed to import RSA key from %s; RSA private key import is not supported", keyFile)
	default:
		return nil, errors.Errorf("Failed to import key from %s: invalid secret key type", keyFile)
	}
}

// LoadX509KeyPair reads and parses a public/private key pair from a pair
// of files. The files must contain PEM encoded data. The certificate file
// may contain intermediate certificates following the leaf certificate to
// form a certificate chain. On successful return, Certificate.Leaf will
// be nil because the parsed form of the certificate is not retained.
//
// This function originated from crypto/tls/tls.go and was adapted to use a
// BCCSP Signer
func LoadX509KeyPair(certFile, keyFile []byte, csp core.CryptoSuite) (*tls.Certificate, error) {

	certPEMBlock := certFile

	cert := &tls.Certificate{}
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return nil, errors.New("Failed to find PEM block in bytes")
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return nil, errors.New("Failed to find certificate PEM data in bytes, but did find a private key; PEM inputs may have been switched")
		}
		return nil, errors.Errorf("Failed to find \"CERTIFICATE\" PEM block in file %s after skipping PEM blocks of the following types: %v", certFile, skippedBlockTypes)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	_, cert.PrivateKey, err = GetSignerFromCert(x509Cert, csp)
	if err != nil {
		if keyFile != nil {
			log.Debugf("Could not load TLS certificate with BCCSP: %s", err)
			log.Debug("Attempting fallback with provided certfile and keyfile")
			fallbackCerts, err := tls.X509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, errors.Wrap(err, "Could not get the private key that matches the provided cert")
			}
			cert = &fallbackCerts
		} else {
			return nil, errors.WithMessage(err, "Could not load TLS certificate with BCCSP")
		}

	}

	return cert, nil
}

func LoadX509KeyPairSM2(certFile, keyFile string, csp core.CryptoSuite) (*gtls.Certificate, error) {

	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	cert := &gtls.Certificate{}
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return nil, errors.Errorf("Failed to find PEM block in file %s", certFile)
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return nil, errors.Errorf("Failed to find certificate PEM data in file %s, but did find a private key; PEM inputs may have been switched", certFile)
		}
		return nil, errors.Errorf("Failed to find \"CERTIFICATE\" PEM block in file %s after skipping PEM blocks of the following types: %v", certFile, skippedBlockTypes)
	}

	sm2Cert, err := sm2.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	x509Cert := gm.ParseSm2Certificate2X509(sm2Cert)
	_, cert.PrivateKey, err = GetSignerFromCert(x509Cert, csp)
	if err != nil {
		if keyFile != "" {
			log.Debugf("Could not load TLS certificate with BCCSP: %s", err)
			log.Debugf("Attempting fallback with certfile %s and keyfile %s", certFile, keyFile)
			fallbackCerts, err := gtls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, errors.Wrapf(err, "Could not get the private key %s that matches %s", keyFile, certFile)
			}
			cert = &fallbackCerts
		} else {
			return nil, errors.WithMessage(err, "Could not load TLS certificate with BCCSP")
		}

	}

	return cert, nil
}

func IsGmBccsp(csp core.CryptoSuite) bool {
	if cs, ok := csp.(*wrapper.CryptoSuite); ok {
		cspType := reflect.TypeOf(cs.BCCSP)
		if cspType.Kind() == reflect.Ptr {
			cspType = cspType.Elem()
			if strings.HasPrefix(cspType.String(), "gm.impl") {
				return true
			}
		}
	}
	return false
}
