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
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	mrand "math/rand"

	factory "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkpatch/cryptosuitebridge"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/tjfoc/gmsm/sm2"

	"net/http"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ocsp"
)

var (
	rnd = mrand.NewSource(time.Now().UnixNano())
	// ErrNotImplemented used to return errors for functions not implemented
	ErrNotImplemented = errors.New("NOT YET IMPLEMENTED")
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// RevocationReasonCodes is a map between string reason codes to integers as defined in RFC 5280
var RevocationReasonCodes = map[string]int{
	"unspecified":          ocsp.Unspecified,
	"keycompromise":        ocsp.KeyCompromise,
	"cacompromise":         ocsp.CACompromise,
	"affiliationchanged":   ocsp.AffiliationChanged,
	"superseded":           ocsp.Superseded,
	"cessationofoperation": ocsp.CessationOfOperation,
	"certificatehold":      ocsp.CertificateHold,
	"removefromcrl":        ocsp.RemoveFromCRL,
	"privilegewithdrawn":   ocsp.PrivilegeWithdrawn,
	"aacompromise":         ocsp.AACompromise,
}

// SecretTag to tag a field as secret as in password, token
const SecretTag = "mask"

// URLRegex is the regular expression to check if a value is an URL
var URLRegex = regexp.MustCompile("(ldap|http)s*://(\\S+):(\\S+)@")

//ECDSASignature forms the structure for R and S value for ECDSA
type ECDSASignature struct {
	R, S *big.Int
}

// ReadFile reads a file
func ReadFile(file string) ([]byte, error) {
	return ioutil.ReadFile(file)
}

// WriteFile writes a file
func WriteFile(file string, buf []byte, perm os.FileMode) error {
	dir := path.Dir(file)
	// Create the directory if it doesn't exist
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return errors.Wrapf(err, "Failed to create directory '%s' for file '%s'", dir, file)
		}
	}
	return ioutil.WriteFile(file, buf, perm)
}

// FileExists checks to see if a file exists
func FileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// Marshal to bytes
func Marshal(from interface{}, what string) ([]byte, error) {
	buf, err := json.Marshal(from)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to marshal %s", what)
	}
	return buf, nil
}

// CreateToken creates a JWT-like token.
// In a normal JWT token, the format of the token created is:
//      <algorithm,claims,signature>
// where each part is base64-encoded string separated by a period.
// In this JWT-like token, there are two differences:
// 1) the claims section is a certificate, so the format is:
//      <certificate,signature>
// 2) the signature uses the private key associated with the certificate,
//    and the signature is across both the certificate and the "body" argument,
//    which is the body of an HTTP request, though could be any arbitrary bytes.
// @param cert The pem-encoded certificate
// @param key The pem-encoded key
// @param method http method of the request
// @param uri URI of the request
// @param body The body of an HTTP request
// @param fabCACompatibilityMode will set auth token signing for Fabric CA 1.3 (true) or Fabric 1.4+ (false)

func CreateToken(csp core.CryptoSuite, cert []byte, key core.Key, method, uri string, body []byte, fabCACompatibilityMode bool) (string, error) {
	x509Cert, err := GetX509CertificateFromPEM(cert)
	if err != nil {
		return "", err
	}
	publicKey := x509Cert.PublicKey

	var token string

	//The RSA Key Gen is commented right now as there is bccsp does
	switch publicKey.(type) {
	/*
		case *rsa.PublicKey:
			token, err = GenRSAToken(csp, cert, key, body)
			if err != nil {
				return "", err
			}
	*/
	case *ecdsa.PublicKey:
		token, err = GenECDSAToken(csp, cert, key, method, uri, body, fabCACompatibilityMode)
		if err != nil {
			return "", err
		}
	case *sm2.PublicKey:
		token, err = GenECDSAToken(csp, cert, key, method, uri, body, fabCACompatibilityMode)
		if err != nil {
			return "", err
		}
	}
	return token, nil
}

//GenRSAToken signs the http body and cert with RSA using RSA private key
// @csp : BCCSP instance
/*
func GenRSAToken(csp core.CryptoSuite, cert []byte, key []byte, body []byte) (string, error) {
	privKey, err := GetRSAPrivateKey(key)
	if err != nil {
		return "", err
	}
	b64body := B64Encode(body)
	b64cert := B64Encode(cert)
	bodyAndcert := b64body + "." + b64cert
	hash := sha512.New384()
	hash.Write([]byte(bodyAndcert))
	h := hash.Sum(nil)
	RSAsignature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA384, h[:])
	if err != nil {
		return "", errors.Wrap(err, "Failed to rsa.SignPKCS1v15")
	}
	b64sig := B64Encode(RSAsignature)
	token := b64cert + "." + b64sig

	return  token, nil
}
*/

//GenECDSAToken signs the http body and cert with ECDSA using EC private key
func GenECDSAToken(csp core.CryptoSuite, cert []byte, key core.Key, method, uri string, body []byte, fabCACompatibilityMode bool) (string, error) {
	b64body := B64Encode(body)
	b64cert := B64Encode(cert)
	b64uri := B64Encode([]byte(uri))
	payload := method + "." + b64uri + "." + b64body + "." + b64cert

	// TODO remove this condition once Fabric CA v1.3 is not supported by the SDK anymore
	if fabCACompatibilityMode {
		payload = b64body + "." + b64cert
	}

	return genECDSAToken(csp, key, b64cert, payload)
}

func genECDSAToken(csp core.CryptoSuite, key core.Key, b64cert, payload string) (string, error) {
	digest, digestError := csp.Hash([]byte(payload), factory.GetSHAOpts())
	if digestError != nil {
		return "", errors.WithMessage(digestError, fmt.Sprintf("Hash failed on '%s'", payload))
	}

	ecSignature, err := csp.Sign(key, digest, nil)
	if err != nil {
		return "", errors.WithMessage(err, "BCCSP signature generation failure")
	}
	if len(ecSignature) == 0 {
		return "", errors.New("BCCSP signature creation failed. Signature must be different than nil")
	}

	b64sig := B64Encode(ecSignature)
	token := b64cert + "." + b64sig

	return token, nil

}

// B64Encode base64 encodes bytes
func B64Encode(buf []byte) string {
	return base64.StdEncoding.EncodeToString(buf)
}

// B64Decode base64 decodes a string
func B64Decode(str string) (buf []byte, err error) {
	return base64.StdEncoding.DecodeString(str)
}

// HTTPRequestToString returns a string for an HTTP request for debuggging
func HTTPRequestToString(req *http.Request) string {
	body, _ := ioutil.ReadAll(req.Body)
	req.Body = ioutil.NopCloser(bytes.NewReader(body))
	return fmt.Sprintf("%s %s\n%s",
		req.Method, req.URL, string(body))
}

// HTTPResponseToString returns a string for an HTTP response for debuggging
func HTTPResponseToString(resp *http.Response) string {
	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body = ioutil.NopCloser(bytes.NewReader(body))
	return fmt.Sprintf("statusCode=%d (%s)\n%s",
		resp.StatusCode, resp.Status, string(body))
}

// GetX509CertificateFromPEM get an X509 certificate from bytes in PEM format
func GetX509CertificateFromPEM(cert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, errors.New("Failed to PEM decode certificate")
	}
	var x509Cert *x509.Certificate
	sm2x509Cert, err := sm2.ParseCertificate(block.Bytes)
	if err == nil {
		x509Cert = ParseSm2Certificate2X509(sm2x509Cert)
	}
	return x509Cert, nil
}

// GetEnrollmentIDFromPEM returns the EnrollmentID from a PEM buffer
func GetEnrollmentIDFromPEM(cert []byte) (string, error) {
	x509Cert, err := GetX509CertificateFromPEM(cert)
	if err != nil {
		return "", err
	}
	return GetEnrollmentIDFromX509Certificate(x509Cert), nil
}

// GetEnrollmentIDFromX509Certificate returns the EnrollmentID from the X509 certificate
func GetEnrollmentIDFromX509Certificate(cert *x509.Certificate) string {
	return cert.Subject.CommonName
}

// MakeFileAbs makes 'file' absolute relative to 'dir' if not already absolute
func MakeFileAbs(file, dir string) (string, error) {
	if file == "" {
		return "", nil
	}
	if filepath.IsAbs(file) {
		return file, nil
	}
	path, err := filepath.Abs(filepath.Join(dir, file))
	if err != nil {
		return "", errors.Wrapf(err, "Failed making '%s' absolute based on '%s'", file, dir)
	}
	return path, nil
}

// GetSerialAsHex returns the serial number from certificate as hex format
func GetSerialAsHex(serial *big.Int) string {
	hex := fmt.Sprintf("%x", serial)
	return hex
}

// StructToString converts a struct to a string. If a field
// has a 'secret' tag, it is masked in the returned string
func StructToString(si interface{}) string {
	rval := reflect.ValueOf(si).Elem()
	tipe := rval.Type()
	var buffer bytes.Buffer
	buffer.WriteString("{ ")
	for i := 0; i < rval.NumField(); i++ {
		tf := tipe.Field(i)
		if !rval.FieldByName(tf.Name).CanSet() {
			continue // skip unexported fields
		}
		var fStr string
		tagv := tf.Tag.Get(SecretTag)
		if tagv == "password" || tagv == "username" {
			fStr = fmt.Sprintf("%s:**** ", tf.Name)
		} else if tagv == "url" {
			val, ok := rval.Field(i).Interface().(string)
			if ok {
				val = GetMaskedURL(val)
				fStr = fmt.Sprintf("%s:%v ", tf.Name, val)
			} else {
				fStr = fmt.Sprintf("%s:%v ", tf.Name, rval.Field(i).Interface())
			}
		} else {
			fStr = fmt.Sprintf("%s:%v ", tf.Name, rval.Field(i).Interface())
		}
		buffer.WriteString(fStr)
	}
	buffer.WriteString(" }")
	return buffer.String()
}

// GetMaskedURL returns masked URL. It masks username and password from the URL
// if present
func GetMaskedURL(url string) string {
	matches := URLRegex.FindStringSubmatch(url)

	// If there is a match, there should be four entries: 1 for
	// the match and 3 for submatches
	if len(matches) == 4 {
		matchIdxs := URLRegex.FindStringSubmatchIndex(url)
		matchStr := url[matchIdxs[0]:matchIdxs[1]]
		for idx := 2; idx < len(matches); idx++ {
			if matches[idx] != "" {
				matchStr = strings.Replace(matchStr, matches[idx], "****", 1)
			}
		}
		url = url[:matchIdxs[0]] + matchStr + url[matchIdxs[1]:len(url)]
	}
	return url
}

//sm2 证书转换 x509 证书
func ParseSm2Certificate2X509(sm2Cert *sm2.Certificate) *x509.Certificate {
	x509cert := &x509.Certificate{
		Raw:                     sm2Cert.Raw,
		RawTBSCertificate:       sm2Cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo: sm2Cert.RawSubjectPublicKeyInfo,
		RawSubject:              sm2Cert.RawSubject,
		RawIssuer:               sm2Cert.RawIssuer,

		Signature:          sm2Cert.Signature,
		SignatureAlgorithm: x509.SignatureAlgorithm(sm2Cert.SignatureAlgorithm),

		PublicKeyAlgorithm: x509.PublicKeyAlgorithm(sm2Cert.PublicKeyAlgorithm),
		PublicKey:          sm2Cert.PublicKey,

		Version:      sm2Cert.Version,
		SerialNumber: sm2Cert.SerialNumber,
		Issuer:       sm2Cert.Issuer,
		Subject:      sm2Cert.Subject,
		NotBefore:    sm2Cert.NotBefore,
		NotAfter:     sm2Cert.NotAfter,
		KeyUsage:     x509.KeyUsage(sm2Cert.KeyUsage),

		Extensions: sm2Cert.Extensions,

		ExtraExtensions: sm2Cert.ExtraExtensions,

		UnhandledCriticalExtensions: sm2Cert.UnhandledCriticalExtensions,

		//ExtKeyUsage:	[]x509.ExtKeyUsage(sm2Cert.ExtKeyUsage) ,
		UnknownExtKeyUsage: sm2Cert.UnknownExtKeyUsage,

		BasicConstraintsValid: sm2Cert.BasicConstraintsValid,
		IsCA:                  sm2Cert.IsCA,
		MaxPathLen:            sm2Cert.MaxPathLen,
		// MaxPathLenZero indicates that BasicConstraintsValid==true and
		// MaxPathLen==0 should be interpreted as an actual maximum path length
		// of zero. Otherwise, that combination is interpreted as MaxPathLen
		// not being set.
		MaxPathLenZero: sm2Cert.MaxPathLenZero,

		SubjectKeyId:   sm2Cert.SubjectKeyId,
		AuthorityKeyId: sm2Cert.AuthorityKeyId,

		// RFC 5280, 4.2.2.1 (Authority Information Access)
		OCSPServer:            sm2Cert.OCSPServer,
		IssuingCertificateURL: sm2Cert.IssuingCertificateURL,

		// Subject Alternate Name values
		DNSNames:       sm2Cert.DNSNames,
		EmailAddresses: sm2Cert.EmailAddresses,
		IPAddresses:    sm2Cert.IPAddresses,

		// Name constraints
		PermittedDNSDomainsCritical: sm2Cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         sm2Cert.PermittedDNSDomains,

		// CRL Distribution Points
		CRLDistributionPoints: sm2Cert.CRLDistributionPoints,

		PolicyIdentifiers: sm2Cert.PolicyIdentifiers,
	}
	for _, val := range sm2Cert.ExtKeyUsage {
		x509cert.ExtKeyUsage = append(x509cert.ExtKeyUsage, x509.ExtKeyUsage(val))
	}

	return x509cert
}

// X509证书格式转换为 SM2证书格式
func ParseX509Certificate2Sm2(x509Cert *x509.Certificate) *sm2.Certificate {
	sm2cert := &sm2.Certificate{
		Raw:                     x509Cert.Raw,
		RawTBSCertificate:       x509Cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo: x509Cert.RawSubjectPublicKeyInfo,
		RawSubject:              x509Cert.RawSubject,
		RawIssuer:               x509Cert.RawIssuer,

		Signature:          x509Cert.Signature,
		SignatureAlgorithm: sm2.SignatureAlgorithm(x509Cert.SignatureAlgorithm),

		PublicKeyAlgorithm: sm2.PublicKeyAlgorithm(x509Cert.PublicKeyAlgorithm),
		PublicKey:          x509Cert.PublicKey,

		Version:      x509Cert.Version,
		SerialNumber: x509Cert.SerialNumber,
		Issuer:       x509Cert.Issuer,
		Subject:      x509Cert.Subject,
		NotBefore:    x509Cert.NotBefore,
		NotAfter:     x509Cert.NotAfter,
		KeyUsage:     sm2.KeyUsage(x509Cert.KeyUsage),

		Extensions: x509Cert.Extensions,

		ExtraExtensions: x509Cert.ExtraExtensions,

		UnhandledCriticalExtensions: x509Cert.UnhandledCriticalExtensions,

		//ExtKeyUsage:	[]x509.ExtKeyUsage(x509Cert.ExtKeyUsage) ,
		UnknownExtKeyUsage: x509Cert.UnknownExtKeyUsage,

		BasicConstraintsValid: x509Cert.BasicConstraintsValid,
		IsCA:                  x509Cert.IsCA,
		MaxPathLen:            x509Cert.MaxPathLen,
		// MaxPathLenZero indicates that BasicConstraintsValid==true and
		// MaxPathLen==0 should be interpreted as an actual maximum path length
		// of zero. Otherwise, that combination is interpreted as MaxPathLen
		// not being set.
		MaxPathLenZero: x509Cert.MaxPathLenZero,

		SubjectKeyId:   x509Cert.SubjectKeyId,
		AuthorityKeyId: x509Cert.AuthorityKeyId,

		// RFC 5280, 4.2.2.1 (Authority Information Access)
		OCSPServer:            x509Cert.OCSPServer,
		IssuingCertificateURL: x509Cert.IssuingCertificateURL,

		// Subject Alternate Name values
		DNSNames:       x509Cert.DNSNames,
		EmailAddresses: x509Cert.EmailAddresses,
		IPAddresses:    x509Cert.IPAddresses,

		// Name constraints
		PermittedDNSDomainsCritical: x509Cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         x509Cert.PermittedDNSDomains,

		// CRL Distribution Points
		CRLDistributionPoints: x509Cert.CRLDistributionPoints,

		PolicyIdentifiers: x509Cert.PolicyIdentifiers,
	}
	for _, val := range x509Cert.ExtKeyUsage {
		sm2cert.ExtKeyUsage = append(sm2cert.ExtKeyUsage, sm2.ExtKeyUsage(val))
	}

	return sm2cert
}
