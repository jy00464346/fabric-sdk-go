/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/

package gmtls

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"io/ioutil"
	"time"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"
	factory "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkpatch/cryptosuitebridge"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/util"
	"github.com/tjfoc/gmsm/sm2"
	gtls "github.com/tjfoc/gmtls"
)

// ServerTLSConfig defines key material for a TLS server
type ServerTLSConfig struct {
	Enabled    bool   `help:"Enable TLS on the listening port"`
	CertFile   string `def:"tls-cert.pem" help:"PEM-encoded TLS certificate file for server's listening port"`
	KeyFile    string `help:"PEM-encoded TLS key for server's listening port"`
	ClientAuth ClientAuth
}

// ClientAuth defines the key material needed to verify client certificates
type ClientAuth struct {
	Type      string   `def:"noclientcert" help:"Policy the server will follow for TLS Client Authentication."`
	CertFiles []string `help:"A list of comma-separated PEM-encoded trusted certificate files (e.g. root1.pem,root2.pem)"`
}

// ClientTLSConfig defines the key material for a TLS client
type ClientTLSConfig struct {
	Enabled   bool     `skip:"true"`
	CertFiles []string `help:"A list of comma-separated PEM-encoded trusted certificate files (e.g. root1.pem,root2.pem)"`
	Client    KeyCertFiles
}

// KeyCertFiles defines the files need for client on TLS
type KeyCertFiles struct {
	KeyFile  string `help:"PEM-encoded key file when mutual authentication is enabled"`
	CertFile string `help:"PEM-encoded certificate file when mutual authenticate is enabled"`
}

// GetClientTLSConfig creates a tls.Config object from certs and roots
func GetClientTLSConfig(cfg *ClientTLSConfig, csp core.CryptoSuite) (*gtls.Config, error) {
	var certs []gtls.Certificate

	if csp == nil {
		csp = factory.GetDefault()
	}

	log.Debugf("CA Files: %+v\n", cfg.CertFiles)
	log.Debugf("Client Cert File: %s\n", cfg.Client.CertFile)
	log.Debugf("Client Key File: %s\n", cfg.Client.KeyFile)

	if cfg.Client.CertFile != "" {
		err := checkCertDates(cfg.Client.CertFile)
		if err != nil {
			return nil, err
		}

		clientCert, err := util.LoadX509KeyPairSM2(cfg.Client.CertFile, cfg.Client.KeyFile, csp)
		if err != nil {
			return nil, err
		}

		certs = append(certs, *clientCert)
	} else {
		log.Debug("Client TLS certificate and/or key file not provided")
	}
	rootCAPool := sm2.NewCertPool()
	if len(cfg.CertFiles) == 0 {
		return nil, errors.New("No TLS certificate files were provided")
	}

	for _, cacert := range cfg.CertFiles {
		caCert, err := ioutil.ReadFile(cacert)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to read '%s'", cacert)
		}
		ok := rootCAPool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, errors.Errorf("Failed to process certificate from file %s", cacert)
		}
	}

	config := &gtls.Config{
		Certificates: certs,
		RootCAs:      rootCAPool,
	}

	return config, nil
}

// AbsTLSClient makes TLS client files absolute
func AbsTLSClient(cfg *ClientTLSConfig, configDir string) error {
	var err error

	for i := 0; i < len(cfg.CertFiles); i++ {
		cfg.CertFiles[i], err = util.MakeFileAbs(cfg.CertFiles[i], configDir)
		if err != nil {
			return err
		}

	}

	cfg.Client.CertFile, err = util.MakeFileAbs(cfg.Client.CertFile, configDir)
	if err != nil {
		return err
	}

	cfg.Client.KeyFile, err = util.MakeFileAbs(cfg.Client.KeyFile, configDir)
	if err != nil {
		return err
	}

	return nil
}

// AbsTLSServer makes TLS client files absolute
func AbsTLSServer(cfg *ServerTLSConfig, configDir string) error {
	var err error

	for i := 0; i < len(cfg.ClientAuth.CertFiles); i++ {
		cfg.ClientAuth.CertFiles[i], err = util.MakeFileAbs(cfg.ClientAuth.CertFiles[i], configDir)
		if err != nil {
			return err
		}

	}

	cfg.CertFile, err = util.MakeFileAbs(cfg.CertFile, configDir)
	if err != nil {
		return err
	}

	cfg.KeyFile, err = util.MakeFileAbs(cfg.KeyFile, configDir)
	if err != nil {
		return err
	}

	return nil
}

func checkCertDates(certFile string) error {
	log.Debug("Check client TLS certificate for valid dates")
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read file '%s'", certFile)
	}

	cert, err := util.GetX509CertificateFromPEM(certPEM)
	if err != nil {
		return err
	}

	notAfter := cert.NotAfter
	currentTime := time.Now().UTC()

	if currentTime.After(notAfter) {
		return errors.New("Certificate provided has expired")
	}

	notBefore := cert.NotBefore
	if currentTime.Before(notBefore) {
		return errors.New("Certificate provided not valid until later date")
	}

	return nil
}
