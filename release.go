package cacenter

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/tjfoc/gmsm/sm2"
	sm2X509 "github.com/tjfoc/gmsm/x509"
	"math/big"
	"time"
)

type Producer struct {
}

// Rsa rsa证书生成, 传入算法长度, 返回证书生产者和pem格式的私钥
func (c Producer) Rsa(bit int) (*RsaCertProducer, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bit)
	if err != nil {
		return nil, "", err
	}

	return NewRsaCertProducer(privateKey), string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})), nil
}

func (c Producer) Sm2() (*Sm2CertProducer, string, error) {
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}

	keyBytes, err := sm2X509.MarshalSm2PrivateKey(privateKey, nil)
	if err != nil {
		return nil, "", err
	}

	return NewSm2CertProducer(privateKey), string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})), nil
}

type RsaCertProducer struct {
	privateKey any
	publicKey  *rsa.PublicKey
	template   *x509.Certificate
	parentCert *x509.Certificate
}

func (r *RsaCertProducer) SettingCertInfo(fn func(parentCert, templateCert *x509.Certificate)) CertProducerInterface[*x509.Certificate] {
	fn(r.parentCert, r.template)
	return r
}

func (r *RsaCertProducer) WithTLSServer(address ...TLSAddressOption) CertProducerInterface[*x509.Certificate] {
	r.template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	r.template.KeyUsage = x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageKeyAgreement
	for i := range address {
		optionFn := address[i]
		dns, ips := optionFn()
		if dns != nil {
			r.template.DNSNames = append(r.template.DNSNames, dns...)
		}

		if ips != nil {
			r.template.IPAddresses = append(r.template.IPAddresses, ips...)
		}
	}
	return r
}

func (r *RsaCertProducer) WithTLSClient() CertProducerInterface[*x509.Certificate] {
	r.template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	r.template.KeyUsage = x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageKeyAgreement
	return r
}

func (r *RsaCertProducer) WithSubject(subjectInfo pkix.Name) CertProducerInterface[*x509.Certificate] {
	r.template.Subject = subjectInfo
	return r
}

func (r *RsaCertProducer) WithIssuer(issuerInfo pkix.Name) CertProducerInterface[*x509.Certificate] {
	r.template.Issuer = issuerInfo
	return r
}

func (r *RsaCertProducer) WithExpire(start *time.Time, end *time.Time) CertProducerInterface[*x509.Certificate] {
	r.template.NotBefore = *start
	r.template.NotAfter = *end
	return r
}

func (r *RsaCertProducer) WithParent(parentCertTemplate *x509.Certificate, parentPrivateKey any) CertProducerInterface[*x509.Certificate] {
	r.parentCert = parentCertTemplate
	if parentPrivateKey != nil {
		r.privateKey = parentPrivateKey
	}
	return r
}

func (r *RsaCertProducer) WithCaTemplate() CertProducerInterface[*x509.Certificate] {
	r.template.IsCA = true
	r.template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	r.template.BasicConstraintsValid = true
	return r
}

func (r *RsaCertProducer) ToX509Cert() (*x509.Certificate, error) {
	certBytes, err := r.ToCertBytes()
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certBytes)
}

func (r *RsaCertProducer) ToCertBytes() ([]byte, error) {
	if r.parentCert == nil {
		r.parentCert = r.template
	}
	return x509.CreateCertificate(rand.Reader, r.template, r.parentCert, r.publicKey, r.privateKey)
}

func (r *RsaCertProducer) ToCertPem() (string, error) {
	certBytes, err := r.ToCertBytes()
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})), nil
}

// NewRsaCertProducer 创建rsa证书生产者
func NewRsaCertProducer(privateKey *rsa.PrivateKey) *RsaCertProducer {
	return &RsaCertProducer{privateKey: privateKey, publicKey: &privateKey.PublicKey, template: &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
	}}
}

func NewSm2CertProducer(privateKey *sm2.PrivateKey) *Sm2CertProducer {
	return &Sm2CertProducer{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		template: &sm2X509.Certificate{
			SerialNumber:       big.NewInt(time.Now().UnixNano()),
			NotBefore:          time.Now(),
			NotAfter:           time.Now().AddDate(10, 0, 0),
			SignatureAlgorithm: sm2X509.SM2WithSM3,
		},
	}
}

type Sm2CertProducer struct {
	privateKey *sm2.PrivateKey
	publicKey  *sm2.PublicKey
	template   *sm2X509.Certificate
	parentCert *sm2X509.Certificate
}

func (s *Sm2CertProducer) WithParent(parentCertTemplate *sm2X509.Certificate, parentPrivateKey any) CertProducerInterface[*sm2X509.Certificate] {
	s.parentCert = parentCertTemplate
	if key, ok := parentPrivateKey.(*sm2.PrivateKey); !ok {
		return nil
	} else {
		s.privateKey = key
	}
	return s
}

func (s *Sm2CertProducer) WithCaTemplate() CertProducerInterface[*sm2X509.Certificate] {
	s.template.IsCA = true
	s.template.KeyUsage = sm2X509.KeyUsageCertSign | sm2X509.KeyUsageCRLSign
	s.template.BasicConstraintsValid = true
	return s
}

func (s *Sm2CertProducer) WithExpire(start *time.Time, end *time.Time) CertProducerInterface[*sm2X509.Certificate] {
	s.template.NotBefore = *start
	s.template.NotAfter = *end
	return s
}

func (s *Sm2CertProducer) WithSubject(subjectInfo pkix.Name) CertProducerInterface[*sm2X509.Certificate] {
	s.template.Subject = subjectInfo
	return s
}

func (s *Sm2CertProducer) WithIssuer(issuerInfo pkix.Name) CertProducerInterface[*sm2X509.Certificate] {
	s.template.Issuer = issuerInfo
	return s
}

func (s *Sm2CertProducer) WithTLSServer(address ...TLSAddressOption) CertProducerInterface[*sm2X509.Certificate] {
	s.template.ExtKeyUsage = []sm2X509.ExtKeyUsage{sm2X509.ExtKeyUsageServerAuth}
	s.template.KeyUsage = sm2X509.KeyUsageDigitalSignature |
		sm2X509.KeyUsageContentCommitment |
		sm2X509.KeyUsageKeyEncipherment |
		sm2X509.KeyUsageKeyAgreement
	for i := range address {
		optionFn := address[i]
		dns, ips := optionFn()
		if dns != nil {
			s.template.DNSNames = append(s.template.DNSNames, dns...)
		}

		if ips != nil {
			s.template.IPAddresses = append(s.template.IPAddresses, ips...)
		}
	}
	return s
}

func (s *Sm2CertProducer) WithTLSClient() CertProducerInterface[*sm2X509.Certificate] {
	s.template.ExtKeyUsage = []sm2X509.ExtKeyUsage{sm2X509.ExtKeyUsageClientAuth}
	s.template.KeyUsage = sm2X509.KeyUsageDigitalSignature |
		sm2X509.KeyUsageContentCommitment |
		sm2X509.KeyUsageKeyEncipherment |
		sm2X509.KeyUsageKeyAgreement
	return s
}

func (s *Sm2CertProducer) SettingCertInfo(fn func(parentCert *sm2X509.Certificate, templateCert *sm2X509.Certificate)) CertProducerInterface[*sm2X509.Certificate] {
	fn(s.parentCert, s.template)
	return s
}

func (s *Sm2CertProducer) ToCertBytes() ([]byte, error) {
	if s.parentCert == nil {
		s.parentCert = s.template
	}
	return sm2X509.CreateCertificate(s.template, s.parentCert, s.publicKey, s.privateKey)
}

func (s *Sm2CertProducer) ToCertPem() (string, error) {
	pemBytes, err := sm2X509.CreateCertificateToPem(s.template, s.parentCert, s.publicKey, s.privateKey)
	return string(pemBytes), err
}

func (s *Sm2CertProducer) ToX509Cert() (*x509.Certificate, error) {
	bytes, err := s.ToCertBytes()
	if err != nil {
		return nil, err
	}
	return sm2X509.ParseSm2CertifateToX509(bytes)
}
