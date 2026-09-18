// Package nodecert owns the PKI that lets the master (core) talk to remote
// agents over mutually authenticated TLS.
//
// Layout:
//   - one self signed CA per panel installation, persisted encrypted in the
//     settings table
//   - one client certificate for core itself, presented to every agent
//   - one server certificate per node, issued when the node redeems its join
//     token
//
// The agent side already enforces `tls.RequireAndVerifyClientCert` and validates
// incoming client certificates against the CA stored in its `RootCrt` setting,
// so issuing from a single CA is enough to make both directions trust each other.
package nodecert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"

	"github.com/3panel-dev/3panel/core/app/model"
	"github.com/3panel-dev/3panel/core/global"
	"github.com/3panel-dev/3panel/core/utils/encrypt"
	"gorm.io/gorm"
)

const (
	SettingCACrt     = "NodeCACrt"
	SettingCAKey     = "NodeCAKey"
	SettingClientCrt = "NodeClientCrt"
	SettingClientKey = "NodeClientKey"

	caCommonName  = "3Panel Node CA"
	certValidity  = 10 * 365 * 24 * time.Hour
	clientCN      = "3panel-core"
	rsaKeyBits    = 2048
	serialBits    = 128
	backdateHours = 1
	probeTimeout  = 5 * time.Second
)

// CA is the panel's certificate authority, able to issue node certificates.
type CA struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

/* -------------------------------------------------------------- settings */

func loadSecret(key string) (string, error) {
	var item model.Setting
	if err := global.DB.Where("key = ?", key).First(&item).Error; err != nil {
		return "", err
	}
	if item.Value == "" {
		return "", errors.New("empty value")
	}
	return encrypt.StringDecrypt(item.Value)
}

func saveSecret(key, value string) error {
	enc, err := encrypt.StringEncrypt(value)
	if err != nil {
		return err
	}
	var item model.Setting
	err = global.DB.Where("key = ?", key).First(&item).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return global.DB.Create(&model.Setting{Key: key, Value: enc}).Error
		}
		return err
	}
	return global.DB.Model(&model.Setting{}).Where("key = ?", key).Update("value", enc).Error
}

/* ------------------------------------------------------------------- ca */

// EnsureCA loads the panel CA, generating and persisting it on first use.
func EnsureCA() (*CA, error) {
	crtPEM, err := loadSecret(SettingCACrt)
	if err != nil {
		return generateCA()
	}
	keyPEM, err := loadSecret(SettingCAKey)
	if err != nil {
		return generateCA()
	}
	block, _ := pem.Decode([]byte(crtPEM))
	if block == nil {
		return generateCA()
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return generateCA()
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return generateCA()
	}
	return &CA{Cert: cert, Key: key}, nil
}

func generateCA() (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   caCommonName,
			Organization: []string{"3Panel"},
		},
		NotBefore:             time.Now().Add(-backdateHours * time.Hour),
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := encodePrivateKey(key)
	if err := saveSecret(SettingCACrt, string(crtPEM)); err != nil {
		return nil, err
	}
	if err := saveSecret(SettingCAKey, string(keyPEM)); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// CACertPEM returns the PEM encoded CA certificate, handed to agents as their
// `RootCrt` so they can verify the master's client certificate.
func CACertPEM() (string, error) {
	ca, err := EnsureCA()
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})), nil
}

/* -------------------------------------------------------------- issuance */

// IssueServerCert issues a serving certificate for one node. Hosts may contain
// DNS names and/or IP literals; each is placed in the matching SAN list.
func (c *CA) IssueServerCert(commonName string, hosts []string) (crtPEM, keyPEM string, err error) {
	var dnsNames []string
	var ips []net.IP
	for _, host := range hosts {
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dnsNames = append(dnsNames, host)
	}
	tpl := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"3Panel"},
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		BasicConstraintsValid: true,
	}
	return c.issue(tpl)
}

// IssueClientCert issues the certificate core presents when calling an agent.
// ExtKeyUsageClientAuth is mandatory: Go's server side client verification
// requires it.
func (c *CA) IssueClientCert(commonName string) (crtPEM, keyPEM string, err error) {
	tpl := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"3Panel"},
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	return c.issue(tpl)
}

func (c *CA) issue(tpl *x509.Certificate) (string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return "", "", err
	}
	serial, err := newSerial()
	if err != nil {
		return "", "", err
	}
	tpl.SerialNumber = serial
	tpl.NotBefore = time.Now().Add(-backdateHours * time.Hour)
	tpl.NotAfter = time.Now().Add(certValidity)

	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		return "", "", err
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(crtPEM), string(encodePrivateKey(key)), nil
}

// EnsureClientCert returns core's client certificate, issuing one on first use.
func EnsureClientCert() (crtPEM, keyPEM string, err error) {
	crt, err := loadSecret(SettingClientCrt)
	if err == nil {
		key, keyErr := loadSecret(SettingClientKey)
		if keyErr == nil {
			return crt, key, nil
		}
	}
	ca, err := EnsureCA()
	if err != nil {
		return "", "", err
	}
	crt, key, err := ca.IssueClientCert(clientCN)
	if err != nil {
		return "", "", err
	}
	if err := saveSecret(SettingClientCrt, crt); err != nil {
		return "", "", err
	}
	if err := saveSecret(SettingClientKey, key); err != nil {
		return "", "", err
	}
	return crt, key, nil
}

/* ------------------------------------------------------------ health check */

// TLSConfig is the mutually authenticated configuration core uses to talk to a
// node: it presents core's client certificate and accepts only server
// certificates signed by this panel's CA.
func TLSConfig(addr string) (*tls.Config, error) {
	crtPEM, keyPEM, err := EnsureClientCert()
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair([]byte(crtPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}
	caPEM, err := CACertPEM()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errors.New("node CA is not a valid certificate")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   HostOf(addr),
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// Dial probes a node by completing a handshake with it. A successful handshake
// proves three things at once: the host is reachable, it holds a certificate
// this panel issued, and it accepts core's client certificate. That makes it a
// health check and an identity check in one, with no agent side API needed.
func Dial(addr string) error {
	cfg, err := TLSConfig(addr)
	if err != nil {
		return err
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: probeTimeout}, "tcp", addr, cfg)
	if err != nil {
		return err
	}
	return conn.Close()
}

// HostOf strips the port so the remainder can be used as a certificate SAN or
// TLS server name.
func HostOf(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

/* --------------------------------------------------------------- helpers */

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits))
}

func encodePrivateKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func parsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode private key PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return key, nil
}
