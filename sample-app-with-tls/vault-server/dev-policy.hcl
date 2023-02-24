# This section grants access to "kv-v1", 
# should not grants the "list" capability
path "kv-v1/*" {
  capabilities = ["create", "read", "delete"]
}

# This section grants read/write access to "kv-v2"
path "kv-v2/data/*" {
  capabilities = ["create", "read", "update", "delete"]
}
# allow a policy to view metadata for each version
#path "kv-v2/metadata/*" {
#  capabilities = ["read"]
#}
