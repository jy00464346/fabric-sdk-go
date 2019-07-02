package lib

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/gm"
	"github.com/tjfoc/gmsm/sm2"
	"net"
	"net/mail"
)

//cloudflare 证书请求 转成 国密证书请求
func generate(priv crypto.Signer, req *csr.CertificateRequest, key bccsp.Key) (csr []byte, err error) {
	//log.Info("[gmca] begin generate gm's certificate request")
	sigAlgo := signerAlgo(priv)
	if sigAlgo == sm2.UnknownSignatureAlgorithm {
		return nil, fmt.Errorf("Private key is unavailable ")
	}
	var tpl = sm2.CertificateRequest{
		Subject:            req.Name(),
		SignatureAlgorithm: sigAlgo,
	}
	for i := range req.Hosts {
		if ip := net.ParseIP(req.Hosts[i]); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(req.Hosts[i]); err == nil && email != nil {
			tpl.EmailAddresses = append(tpl.EmailAddresses, email.Address)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, req.Hosts[i])
		}
	}

	if req.CA != nil {
		err = appendCAInfoToCSRSm2(req.CA, &tpl)
		if err != nil {
			err = fmt.Errorf("failed to appendCAInfoToCSRSm2 :%s", err.Error())
			return
		}
	}
	if req.SerialNumber != "" {

	}
	csr, err = gm.CreateSm2CertificateRequestToMem(&tpl, key)
	//log.Info("[gmca] generate gm's certificate request done")
	return
}

func signerAlgo(priv crypto.Signer) sm2.SignatureAlgorithm {
	switch pub := priv.Public().(type) {
	case *sm2.PublicKey:
		switch pub.Curve {
		case sm2.P256Sm2():
			return sm2.SM2WithSM3
		default:
			return sm2.SM2WithSM3
		}
	default:
		return sm2.UnknownSignatureAlgorithm
	}
}

// appendCAInfoToCSR appends CAConfig BasicConstraint extension to a CSR
func appendCAInfoToCSRSm2(reqConf *csr.CAConfig, csreq *sm2.CertificateRequest) error {
	pathlen := reqConf.PathLength
	if pathlen == 0 && !reqConf.PathLenZero {
		pathlen = -1
	}
	val, err := asn1.Marshal(csr.BasicConstraints{true, pathlen})

	if err != nil {
		return err
	}

	csreq.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
			Value:    val,
			Critical: true,
		},
	}

	return nil
}
