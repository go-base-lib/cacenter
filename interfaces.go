package cacenter

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"time"
)

type TLSAddressOption func() ([]string, []net.IP)

func TLSAddrWithDNSName(dns ...string) TLSAddressOption {
	return func() ([]string, []net.IP) {
		return dns, nil
	}
}

func TLSAddrWithIp(ip ...net.IP) TLSAddressOption {
	return func() ([]string, []net.IP) {
		return nil, ip
	}
}

type CertProducerInterface[T any] interface {
	// WithParent 传入上级证书
	WithParent(parentCertTemplate T, parentPrivateKey any) CertProducerInterface[T]
	// WithCaTemplate 伴随Ca证书模板信息
	WithCaTemplate() CertProducerInterface[T]
	// WithExpire 传入有效期
	WithExpire(start *time.Time, end *time.Time) CertProducerInterface[T]
	// WithSubject 传入主题信息
	WithSubject(subjectInfo pkix.Name) CertProducerInterface[T]
	// WithIssuer 传入颁发者信息
	WithIssuer(issuerInfo pkix.Name) CertProducerInterface[T]
	// WithTLSServer 伴随TLS模板信息
	WithTLSServer(address ...TLSAddressOption) CertProducerInterface[T]
	// WithTLSClient  伴随TLS客户端模板
	WithTLSClient() CertProducerInterface[T]
	// SettingCertInfo 设置证书信息
	SettingCertInfo(fn func(parentCert, templateCert T)) CertProducerInterface[T]
	// ToCertBytes 转换为证书二进制
	ToCertBytes() ([]byte, error)
	// ToCertPem 转换到证书PEM
	ToCertPem() (string, error)
	// ToX509Cert 转换为x509证书
	ToX509Cert() (*x509.Certificate, error)
}
