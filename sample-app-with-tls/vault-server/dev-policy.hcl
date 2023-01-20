# This section grants access to "kv-v1", 
# should not grants the "list" capability
path "kv-v1/*" {
  capabilities = ["create", "read", "update", "delete"]
}

# This section grants access to "kv-v2"
path "kv-v2/*" {
  capabilities = ["create", "read", "update", "delete"]
}

