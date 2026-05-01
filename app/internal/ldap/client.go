package ldap

import (
	"context"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Client provides LDAP lookups needed by the application.
// Connections are opened per-call and closed immediately — appropriate for
// the low-frequency operations performed here (cert binding checks on
// sensitive endpoints).  Add a pool if higher-frequency use is required.
type Client struct {
	url    string // e.g. "ldap://ldap:1389"
	baseDN string
}

// New returns a Client.  No connection is made until the first call.
func New(host, port, baseDN string) *Client {
	return &Client{
		url:    fmt.Sprintf("ldap://%s:%s", host, port),
		baseDN: baseDN,
	}
}

// GetCertThumbprint returns the ssoCertThumbprint LDAP attribute for uid.
// Returns ("", nil) if the user exists but has no enrolled cert.
// Returns an error if the user is not found or LDAP is unreachable.
func (c *Client) GetCertThumbprint(_ context.Context, uid string) (string, error) {
	conn, err := ldap.DialURL(c.url)
	if err != nil {
		return "", fmt.Errorf("LDAP dial %s: %w", c.url, err)
	}
	defer conn.Close()
	conn.SetTimeout(8 * time.Second)

	req := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,     // sizeLimit
		10,    // timeLimit (seconds)
		false, // typesOnly
		fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(uid)),
		[]string{"ssoCertThumbprint"},
		nil,
	)

	result, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("LDAP search for uid=%s: %w", uid, err)
	}

	switch len(result.Entries) {
	case 0:
		return "", fmt.Errorf("no LDAP entry for uid=%s", uid)
	case 1:
		return result.Entries[0].GetAttributeValue("ssoCertThumbprint"), nil
	default:
		return "", fmt.Errorf("ambiguous LDAP result: %d entries for uid=%s", len(result.Entries), uid)
	}
}

// Ping verifies the LDAP server is reachable.
func (c *Client) Ping() error {
	conn, err := ldap.DialURL(c.url)
	if err != nil {
		return fmt.Errorf("LDAP ping: %w", err)
	}
	conn.Close()
	return nil
}
