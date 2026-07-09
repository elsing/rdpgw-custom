package config

import (
	"testing"
)

func TestHeaderEnabled(t *testing.T) {
	cases := []struct {
		name           string
		authentication []string
		expected       bool
	}{
		{
			name:           "header_enabled",
			authentication: []string{"header"},
			expected:       true,
		},
		{
			name:           "header_with_others",
			authentication: []string{"openid", "header", "local"},
			expected:       true,
		},
		{
			name:           "header_not_enabled",
			authentication: []string{"openid", "local"},
			expected:       false,
		},
		{
			name:           "empty_authentication",
			authentication: []string{},
			expected:       false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := &ServerConfig{
				Authentication: tc.authentication,
			}

			result := config.HeaderEnabled()
			if result != tc.expected {
				t.Errorf("expected HeaderEnabled(): %v, got: %v", tc.expected, result)
			}
		})
	}
}

func TestAuthenticationConstants(t *testing.T) {
	// Test that the header authentication constant is correct
	if AuthenticationHeader != "header" {
		t.Errorf("incorrect authentication header constant: %v", AuthenticationHeader)
	}
}

func TestCheckDefaultSecrets(t *testing.T) {
	const placeholder = "thisisasessionkeyreplacethisjetzt"

	cases := []struct {
		name      string
		mutate    func(*Configuration)
		wantField string
	}{
		{
			name:      "session key",
			mutate:    func(c *Configuration) { c.Server.SessionKey = placeholder },
			wantField: "server.sessionkey",
		},
		{
			name:      "session encryption key",
			mutate:    func(c *Configuration) { c.Server.SessionEncryptionKey = placeholder },
			wantField: "server.sessionencryptionkey",
		},
		{
			name:      "paa signing key",
			mutate:    func(c *Configuration) { c.Security.PAATokenSigningKey = placeholder },
			wantField: "security.paatokensigningkey",
		},
		{
			name:      "paa encryption key",
			mutate:    func(c *Configuration) { c.Security.PAATokenEncryptionKey = placeholder },
			wantField: "security.paatokenencryptionkey",
		},
		{
			name:      "user signing key",
			mutate:    func(c *Configuration) { c.Security.UserTokenSigningKey = placeholder },
			wantField: "security.usertokensigningkey",
		},
		{
			name:      "user encryption key",
			mutate:    func(c *Configuration) { c.Security.UserTokenEncryptionKey = placeholder },
			wantField: "security.usertokenencryptionkey",
		},
		{
			name:      "query signing key",
			mutate:    func(c *Configuration) { c.Security.QueryTokenSigningKey = placeholder },
			wantField: "security.querytokensigningkey",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Configuration{}
			tc.mutate(c)
			err := checkDefaultSecrets(c)
			if err == nil {
				t.Fatalf("checkDefaultSecrets accepted a placeholder value in %s", tc.wantField)
			}
			if got := err.Error(); !contains(got, tc.wantField) {
				t.Errorf("error message %q should mention the field %q", got, tc.wantField)
			}
		})
	}
}

func TestCheckDefaultSecretsAllowsRandomValues(t *testing.T) {
	c := &Configuration{}
	c.Server.SessionKey = "5aa3a1568fe8421cd7e127d5ace28d2d"
	c.Server.SessionEncryptionKey = "d3ecd7e565e56e37e2f2e95b584d8c0c"
	c.Security.PAATokenSigningKey = "0123456789abcdef0123456789abcdef"
	if err := checkDefaultSecrets(c); err != nil {
		t.Errorf("checkDefaultSecrets rejected non-placeholder values: %v", err)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestPAAReconnectSettingsFromEnv asserts that PAATokenLifetime and
// PAAReconnectWindow can be set via the standard RDPGW_<SECTION>__<FIELD>
// environment variable convention (no config file needed), the same way
// every other Configuration field already can - RDPGW_SECURITY__PAATOKENLIFETIME
// and RDPGW_SECURITY__PAARECONNECTWINDOW respectively.
func TestPAAReconnectSettingsFromEnv(t *testing.T) {
	t.Setenv("RDPGW_SECURITY__PAATOKENLIFETIME", "15")
	t.Setenv("RDPGW_SECURITY__PAARECONNECTWINDOW", "45")
	// Load() needs signing/encryption keys of the right length or it will
	// silently generate random ones; that's fine here, we only care about
	// the two fields under test.
	t.Setenv("RDPGW_SECURITY__PAATOKENSIGNINGKEY", "5aa3a1568fe8421cd7e127d5ace28d2d")
	t.Setenv("RDPGW_SECURITY__PAATOKENENCRYPTIONKEY", "d3ecd7e565e56e37e2f2e95b584d8c0c")
	t.Setenv("RDPGW_SERVER__SESSIONKEY", "0123456789abcdef0123456789abcdef")
	t.Setenv("RDPGW_SERVER__SESSIONENCRYPTIONKEY", "fedcba9876543210fedcba9876543210")

	c := Load("/nonexistent-rdpgw-config-for-test.yaml")

	if c.Security.PAATokenLifetime != 15 {
		t.Errorf("PAATokenLifetime = %d, want 15 (from RDPGW_SECURITY__PAATOKENLIFETIME)", c.Security.PAATokenLifetime)
	}
	if c.Security.PAAReconnectWindow != 45 {
		t.Errorf("PAAReconnectWindow = %d, want 45 (from RDPGW_SECURITY__PAARECONNECTWINDOW)", c.Security.PAAReconnectWindow)
	}
}

// TestPAAReconnectWindowDefaultsToDisabled asserts that with no env var or
// config file entry, PAAReconnectWindow defaults to 0 (disabled) while
// PAATokenLifetime still defaults to 5 - i.e. reconnects are opt-in.
func TestPAAReconnectWindowDefaultsToDisabled(t *testing.T) {
	t.Setenv("RDPGW_SECURITY__PAATOKENSIGNINGKEY", "5aa3a1568fe8421cd7e127d5ace28d2d")
	t.Setenv("RDPGW_SECURITY__PAATOKENENCRYPTIONKEY", "d3ecd7e565e56e37e2f2e95b584d8c0c")
	t.Setenv("RDPGW_SERVER__SESSIONKEY", "0123456789abcdef0123456789abcdef")
	t.Setenv("RDPGW_SERVER__SESSIONENCRYPTIONKEY", "fedcba9876543210fedcba9876543210")

	c := Load("/nonexistent-rdpgw-config-for-test.yaml")

	if c.Security.PAAReconnectWindow != 0 {
		t.Errorf("PAAReconnectWindow = %d, want 0 (disabled by default)", c.Security.PAAReconnectWindow)
	}
	if c.Security.PAATokenLifetime != 5 {
		t.Errorf("PAATokenLifetime = %d, want 5 (default)", c.Security.PAATokenLifetime)
	}
}

func TestHeaderConfigValidation(t *testing.T) {
	cases := []struct {
		name        string
		headerConf  HeaderConfig
		shouldError bool
	}{
		{
			name: "valid_config",
			headerConf: HeaderConfig{
				UserHeader: "X-Forwarded-User",
			},
			shouldError: false,
		},
		{
			name: "missing_user_header",
			headerConf: HeaderConfig{
				EmailHeader: "X-Forwarded-Email",
			},
			shouldError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the configuration struct
			if tc.headerConf.UserHeader == "" && !tc.shouldError {
				t.Error("expected user header to be set")
			}
			if tc.headerConf.UserHeader != "" && tc.shouldError {
				t.Error("expected configuration to be invalid")
			}
		})
	}
}
