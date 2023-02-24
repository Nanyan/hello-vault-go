#!/bin/sh

###############################################################################################
##               *** WARNING - INSECURE - DO NOT USE IN PRODUCTION ***                       ##
## This script is to simulate operations a Vault operator would perform and, as such,        ##
## is not a representation of best practices in production environments.                     ##
## https://learn.hashicorp.com/tutorials/vault/pattern-approle?in=vault/recommended-patterns ##
###############################################################################################

set -e

rm -f /vault/tls/*
export VAULT_ADDR='https://127.0.0.1:8200'
export VAULT_FORMAT='json'
export VAULT_CACERT='/vault/tls/vault-ca.pem'

# Spawn a new process for the development Vault server and wait for it to come online
# ref: https://www.vaultproject.io/docs/concepts/dev-server
vault server -dev-tls -dev-tls-cert-dir=/vault/tls/ -dev-listen-address="0.0.0.0:8200" &
sleep 2s

# Authenticate container's local Vault CLI
# ref: https://www.vaultproject.io/docs/commands/login
vault login -no-print "${VAULT_DEV_ROOT_TOKEN_ID}"

#####################################
########## ACCESS POLICIES ##########
#####################################

# Add policies for the various roles we'll be using
# ref: https://www.vaultproject.io/docs/concepts/policies
vault policy write dev-policy /vault/config/dev-policy.hcl

#####################################
######## APPROLE AUTH METHDO ########
#####################################

# Enable AppRole auth method utilized by our web application
# ref: https://www.vaultproject.io/docs/auth/approle
vault auth enable approle

# Configure a specific AppRole role with associated parameters
# ref: https://www.vaultproject.io/api/auth/approle#parameters
#
# NOTE: we use artificially low ttl values to demonstrate the credential renewal logic
# by default, the token max ttl is using the system max TTL, which is 32 days but can be changed in Vault's configuration file.
# In this case, we set the token_explicit_max_ttl to a low time to see the effect 
vault write auth/approle/role/dev-role \
    token_policies=dev-policy \
    token_ttl=5s \
    token_max_ttl=10s \
    token_explicit_max_ttl=20s
echo "done write dev-policy"

vault read auth/approle/role/dev-role

# Overwrite our role id with a known value to simplify our demo
vault write auth/approle/role/dev-role/role-id role_id="${APPROLE_ROLE_ID}"
echo "done write role_id"

# Generate a secret id for the "dev-role" to be used in application. INSECURE
vault write -force auth/approle/role/dev-role/secret-id >/vault/tls/approle_secret.json
echo "done generate secret_id"

#####################################
########## SECRETS ENGINE ###########
#####################################

# Enable the kv-v2 secrets engine, passing in the path parameter
# ref: https://www.vaultproject.io/docs/secrets/kv/kv-v2
vault secrets enable -version=1 kv-v1
vault secrets enable -version=2 kv-v2


# This container is now healthy
touch /tmp/healthy

# Keep container alive
tail -f /dev/null & trap 'kill %1' TERM ; wait
