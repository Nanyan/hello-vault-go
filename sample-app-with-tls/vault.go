package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
)

type VaultParameters struct {
	// connection parameters
	address             string
	approleRoleID       string
	approleSecretIDFile string
	caCertFile          string
}

type Vault struct {
	client     *vault.Client
	parameters VaultParameters
}

// NewVaultAppRoleClient logs in to Vault using the AppRole authentication
// method, returning an authenticated client and the auth token itself, which
// can be periodically renewed.
func NewVaultAppRoleClient(ctx context.Context, parameters VaultParameters) (*Vault, *vault.Secret, error) {
	log.Printf("connecting to vault @ %s", parameters.address)

	config := vault.DefaultConfig() // modify for more granular configuration
	config.Address = strings.TrimSpace(parameters.address)
	if strings.HasPrefix(config.Address, "https") {
		config.ConfigureTLS(&vault.TLSConfig{CACert: parameters.caCertFile, Insecure: true})
	}

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to initialize vault client: %w", err)
	}

	vault := &Vault{
		client:     client,
		parameters: parameters,
	}

	token, err := vault.login(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("vault login error: %w", err)
	}

	log.Println("connecting to vault: success!")

	return vault, token, nil
}

// A combination of a RoleID and a SecretID is required to log into Vault
// with AppRole authentication method. The SecretID is a value that needs
// to be protected, so the app having knowledge of the SecretID
// directly is insecure.
//
// For secure practice, reference to:
// ref: https://www.vaultproject.io/docs/concepts/response-wrapping
// ref: https://learn.hashicorp.com/tutorials/vault/secure-introduction?in=vault/app-integration#trusted-orchestrator
// ref: https://learn.hashicorp.com/tutorials/vault/approle-best-practices?in=vault/auth-methods#secretid-delivery-best-practices
func (v *Vault) login(ctx context.Context) (*vault.Secret, error) {
	log.Printf("logging in to vault with approle auth; role id: %s", v.parameters.approleRoleID)

	secretID, err := v.readSecretIDFromJsonFile()
	if err != nil {
		return nil, err
	}

	approleSecretID := &approle.SecretID{
		FromString: secretID,
	}

	appRoleAuth, err := approle.NewAppRoleAuth(
		v.parameters.approleRoleID,
		approleSecretID,
	)
	log.Printf("role_id: %v\tsecret_id: %v\n", v.parameters.approleRoleID, secretID)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize approle authentication method: %w", err)
	}

	authInfo, err := v.client.Auth().Login(ctx, appRoleAuth)
	if err != nil {
		return nil, fmt.Errorf("unable to login using approle auth method: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no approle info was returned after login")
	}

	log.Println("logging in to vault with approle auth: success!")

	return authInfo, nil
}

func (v *Vault) readSecretIDFromJsonFile() (string, error) {
	secretIDFile, err := os.Open(v.parameters.approleSecretIDFile)
	if err != nil {
		return "", fmt.Errorf("unable to open file containing secret ID: %w", err)
	}
	defer secretIDFile.Close()

	limitedReader := io.LimitReader(secretIDFile, 1000)
	secretIDBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", fmt.Errorf("unable to read secret ID: %w", err)
	}

	secret := &vault.Secret{}
	err = json.Unmarshal(secretIDBytes, secret)
	if err != nil {
		return "", fmt.Errorf("unable to unmarshal secret ID: %w", err)
	}

	return secret.Data["secret_id"].(string), nil
}
