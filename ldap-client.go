package ldapclient

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

type LDAPClient struct {
	Scheme string
	Host   string
	Port   string
	BaseDN string
	BindDN string
	BindPW string
	Filter string
}

func NewLDAPClient(scheme, host, port, baseDN, bindDN, bindPW, filter string) *LDAPClient {
	return &LDAPClient{
		Scheme: scheme,
		Host:   host,
		Port:   port,
		BaseDN: baseDN,
		BindDN: bindDN,
		BindPW: bindPW,
		Filter: filter,
	}
}

func (c LDAPClient) DialURL(url string, opt ...ldap.DialOpt) (*ldap.Conn, error) {
	return ldap.DialURL(url, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
}

func (c LDAPClient) UnauthenticatedBind(conn *ldap.Conn) error {
	return conn.UnauthenticatedBind(c.BindDN)
}

func (c LDAPClient) Bind(conn *ldap.Conn) error {
	return conn.Bind(c.BindDN, c.BindPW)
}

func (c LDAPClient) Search(conn *ldap.Conn, username string) (*ldap.SearchResult, error) {
	return conn.Search(&ldap.SearchRequest{
		BaseDN: c.BaseDN,
		Scope:  ldap.ScopeWholeSubtree,
		Filter: fmt.Sprintf(c.Filter, username),
	})
}

func (c LDAPClient) Authenticate(username, password string) (*ldap.SearchResult, error) {
	ldapURL := fmt.Sprintf(`%v://%v:%v`, c.Scheme, c.Host, c.Port)
	l, err := c.DialURL(ldapURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		return nil, err
	}
	defer l.Close()

	if c.BindPW == "" {
		err = c.UnauthenticatedBind(l)
	} else {
		err = c.Bind(l)
	}

	if err != nil {
		return nil, err
	}

	result, err := l.Search(&ldap.SearchRequest{
		BaseDN: c.BaseDN,
		Scope:  ldap.ScopeWholeSubtree,
		Filter: fmt.Sprintf(c.Filter, username),
	})

	if err != nil {
		return nil, err
	}

	if len(result.Entries) != 1 {
		err := errors.New("strategies/ldap: Search user DN does not exist or too many entries returned")
		return nil, err
	}

	err = l.Bind(result.Entries[0].DN, password)

	if err != nil {
		return nil, err
	}

	return result, nil
}
