package conncheck

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

type Checker struct {
	*tls.Config
	*url.URL
	domain string
	port   string
}

// NewChecker returns a new Checker with the system CA pool, or an error.
func NewChecker(host string) (*Checker, error) {
	u, err := url.Parse(host)
	if err != nil {
		return nil, err
	}

	if u.Port() == "" {
		var port string
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
		u, err = url.Parse(fmt.Sprintf("%s://%s:%s%s", u.Scheme, u.Host, port, u.Path))
		if err != nil {
			return nil, err
		}
	}

	domain, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, err
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	ch := &Checker{Config: &tls.Config{RootCAs: pool},
		URL:    u,
		domain: domain,
		port:   port,
	}

	return ch, nil
}

// AddPool adds a PEM to the CA pool.
func (ch *Checker) AddPool(pem []byte) bool {
	return ch.RootCAs.AppendCertsFromPEM(pem)
}

// CheckConn checks if it's possible to connect at all without TLS.
func (ch *Checker) CheckConn() error {
	addr := net.JoinHostPort(ch.domain, ch.port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}

	defer conn.Close()
	return nil
}

// CheckTLSConn checks if it's possible to connect at all.
func (ch *Checker) CheckTLSConn() error {
	addr := net.JoinHostPort(ch.domain, ch.port)
	conn, err := tls.Dial("tcp", addr, ch.Config)
	if err != nil {
		return err
	}

	defer conn.Close()
	return nil
}

// VerifyName of the certificate.
func (ch *Checker) VerifyName() error {
	conn, err := tls.Dial("tcp", ch.Host, ch.Config)
	if err != nil {
		return err
	}

	defer conn.Close()
	return conn.VerifyHostname(ch.Hostname())
}

// GetHTTP gets the HTTP headers from the URL (whether HTTP or HTTPS) and returns the response.
func (ch *Checker) GetHTTP() (*http.Response, error) {
	if ch.Scheme == "tcp" {
		return nil, fmt.Errorf("tcp scheme not supported")
	}

	req, err := http.NewRequest(http.MethodGet, ch.String(), nil)
	if err != nil {
		return nil, err
	}

	c := &http.Client{Timeout: time.Second * 10}
	return c.Do(req)
}
