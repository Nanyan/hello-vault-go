package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/jessevdk/go-flags"
)

const (
	Kvv1Path = "kv-v1"
	Kvv2Path = "kv-v2"
)

type Environment struct {
	// Vault address, approle login credentials, and secret locations
	VaultAddress             string `env:"VAULT_ADDRESS"                 default:"https://127.0.0.1:8200"              description:"Vault address"                                          long:"vault-address"`
	VaultApproleRoleID       string `env:"VAULT_APPROLE_ROLE_ID"         default:"demo-app"                            description:"AppRole RoleID to log in to Vault"                      long:"vault-approle-role-id"`
	VaultApproleSecretIDFile string `env:"VAULT_APPROLE_SECRET_ID_FILE"  default:"./dev-auto-gen/approle_secret.json"  description:"AppRole SecretID file path to log in to Vault"          long:"vault-approle-secret-id-file"`
	VaultCaCertFile          string `env:"VAULT_CA_CERT_FILE"            default:"./dev-auto-gen/vault-cert.pem"       description:"CACert is the path to a PEM-encoded CA cert file to use to verify the Vault server SSL certificate."          long:"vault-ca-cert-file"`
}

func main() {
	log.Println("hello!")
	defer log.Println("goodbye!")

	var env Environment

	// parse & validate environment variables
	_, err := flags.Parse(&env)
	if err != nil {
		if flags.WroteHelp(err) {
			os.Exit(0)
		}
		log.Fatalf("unable to parse environment variables: %v", err)
	}

	ctx := context.Background()
	// vault. the auth token is not used here
	vault, _, err := NewVaultAppRoleClient(
		ctx,
		VaultParameters{
			address:             env.VaultAddress,
			approleRoleID:       env.VaultApproleRoleID,
			approleSecretIDFile: env.VaultApproleSecretIDFile,
			caCertFile:          env.VaultCaCertFile,
		},
	)
	if err != nil {
		log.Fatalf("unable to initialize vault connection @ %s: %v", env.VaultAddress, err)
	}

	fmt.Println()
	log.Println("secret engine v1:")

	if err := Kvv1ReadWrite(vault); err != nil {
		log.Fatalf("read write Kvv1 err: %v\n", err)
	}

	fmt.Println()
	log.Println("secret engine v2:")
	if err := Kvv2ReadWrite(vault); err != nil {
		log.Fatalf("read write Kvv2 err: %v\n", err)
	}
}

func Kvv1ReadWrite(vault *Vault) error {
	kvv1 := vault.client.KVv1(Kvv1Path)
	ctx := context.TODO()
	keyid := "onetime-key"
	secretData := map[string]interface{}{
		"password": "Hashi123",
	}
	err := kvv1.Put(ctx, keyid, secretData)
	if err != nil {
		return fmt.Errorf("put secret failed: %w", err)
	}
	log.Println("kvv1 put secret ok")

	secret, err := kvv1.Get(ctx, keyid)
	if err != nil {
		return fmt.Errorf("get secret failed: %w", err)
	}
	value, ok := secret.Data["password"].(string)
	if !ok {
		return fmt.Errorf("value type assertion failed: %T %#v", secret.Data["password"], secret.Data["password"])
	}

	if value != "Hashi123" {
		return fmt.Errorf("unexpected password value %q retrieved from vault", value)
	}
	log.Println("kvv1 get secret ok")

	err = kvv1.Delete(ctx, keyid)
	if err != nil {
		return fmt.Errorf("delete secret failed: %w", err)
	}
	log.Println("kvv1 delete secret ok")
	return nil
}

func Kvv2ReadWrite(vault *Vault) error {
	kvv2 := vault.client.KVv2(Kvv2Path)
	ctx := context.TODO()

	keyid := "my-secret-password"

	secretData := map[string]interface{}{
		"password": "Hashi123",
	}

	// Write a secret
	_, err := kvv2.Put(ctx, keyid, secretData)
	if err != nil {
		return fmt.Errorf("unable to write secret: %v", err)
	}

	log.Println("Secret written successfully.")

	// Read a secret
	secret, err := kvv2.Get(ctx, keyid)
	if err != nil {
		log.Fatalf("unable to read secret: %v", err)
	}

	value, ok := secret.Data["password"].(string)
	if !ok {
		log.Fatalf("value type assertion failed: %T %#v", secret.Data["password"], secret.Data["password"])
	}

	if value != "Hashi123" {
		log.Fatalf("unexpected password value %q retrieved from vault", value)
	}

	secretData = map[string]interface{}{
		"password": "Hashi456",
	}

	ctx = context.Background()

	// Write a secret
	_, err = kvv2.Put(ctx, keyid, secretData)
	if err != nil {
		log.Fatalf("unable to write secret: %v", err)
	}

	log.Println("Secret new dataversion written successfully.")

	// Read a secret
	secret, err = kvv2.Get(ctx, keyid)
	if err != nil {
		log.Fatalf("unable to read secret: %v", err)
	}

	value, ok = secret.Data["password"].(string)
	if !ok {
		log.Fatalf("value type assertion failed: %T %#v", secret.Data["password"], secret.Data["password"])
	}

	if value != "Hashi456" {
		log.Fatalf("unexpected password value %q retrieved from vault", value)
	}

	log.Println("Access granted!")
	jsbytes, _ := json.Marshal(secret.VersionMetadata)
	log.Println("current vertion value: ", value)
	log.Printf("VersionMetadata: %s\n", string(jsbytes))

	//get an old version
	verMeta, err := kvv2.GetVersionsAsList(ctx, keyid)
	if err != nil {
		log.Fatalf("unable to GetVersionsAsList: %v", err)
	}
	if len(verMeta) <= 1 {
		log.Fatalf("expect 2 versions, but only get %v", len(verMeta))
	}
	oldVer := verMeta[len(verMeta)-2]
	secret, err = kvv2.GetVersion(ctx, keyid, oldVer.Version)
	if err != nil {
		log.Fatalf("unable to read secret: %v", err)
	}
	log.Println("oldVersion value: ", secret.Data["password"])

	// rollback == get OldVersion and than put it as a new version
	secret, _ = kvv2.Rollback(ctx, keyid, oldVer.Version)
	jsbytes, _ = json.Marshal(secret.VersionMetadata)
	log.Println("rollback return: ", secret.Data["password"], "version meta: ", string(jsbytes))
	secret, _ = kvv2.Get(ctx, keyid)
	log.Println("value after rollback: ", secret.Data["password"])

	verMeta, _ = kvv2.GetVersionsAsList(ctx, keyid)
	log.Println("versions after rollback:")
	for _, v := range verMeta {
		log.Println(v.Version, v.CreatedTime, v.DeletionTime, v.Destroyed)
	}
	return nil
}
