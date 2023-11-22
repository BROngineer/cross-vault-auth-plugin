## Cross-Vault authentication plugin

### Why it was created

The idea of this plugin was born, when I was trying to solve quite specific problem. Long story short, there was the 
following architecture: CI/CD solution installed in AWS along with Vault cluster (hereafter, central Vault), 
which stored infrastructural secrets. Aside from them, there was kubernetes cluster, where was deployed dedicated 
Vault cluster (hereafter, k8s Vault), which provided secrets for workloads deployed in k8s. CI/CD instance could 
authenticate in central Vault using AWS auth, so there were no problems to run jobs which apply configuration 
updates to central Vault itself. However, I couldn't find any suitable way how to authenticate CI/CD runner in k8s 
Vault without exposing any kind of information like role IDs, secret IDs, JWT tokens etc.

That's how I come to the idea of cross-vault authentication: 
1. k8s Vault cluster was configured to use central Vault's transit engine for unsealing. It was deployed with vault 
   agent sidecar and had been already authenticated in central Vault using kubernetes auth without exposing any 
   credentials or sensitive information :white_check_mark:
2. CI/CD runner could authenticate in central Vault without exposing any credentials or sensitive information :white_check_mark:

Considering all of the above, I'd decided to prove the concept, that I could use token issued by one Vault cluster 
to authenticate in another Vault cluster. Well, honestly, I can't. The real workflow is the following:
1. Get token/token accessor from the "issuing" Vault;
2. Pass it to the "validating" Vault;
3. "Validating" Vault sends lookup request to "issuing" Vault;
4. "Validating" Vault compares response data with defined parameters (for now it is the entity_id and entity metadata);
5. "Validating" Vault issues token with defined policies, ttl and whatnot;
6. Use issued token to login to "validating" Vault;
7. PROFIT!

### Installation

##### Development mode

Simply run server in dev mode and pass the `-dev-plugin-dir` arg:
```shell
vault server -dev -dev-root-token-id=root -dev-plugin-dir=/path/to/dir/with/plugin
vault login root
vault auth enable -path=some-path cva-plugin
# Success! Enabled cva-plugin auth method at: cva/
```

##### Production mode (it's not ready for production)

1. Add `plugin_directory` entry to vault server configuration
2. Reload config if needed or stop/start the server (keep in mind, in case server will be stopped unsealing will be 
   required)
3. Register plugin
```shell
vault plugin register -sha256=... auth cva-plugin
# Success! Registered plugin: cva-plugin
```

### Endpoints and parameters

- `auth/{mount}/config`  
Available operations: `read`, `write -f`  
`write -f` parameters:
  - `cluster` (string)
  - `ca_cert` (string)
  - `insecure_skip_verify` (bool)


- `auth/{mount}/role`  
Available operations: `list`  


- `auth/{mount}/role/{name}`  
Available operations: `read`, `write`  
`write` parameters:
  - `name` (string)
  - `entity_id` (string)
  - `entity_meta` (comma-separated "key"="value")
  - `strict_meta_verify` (bool)
  - `token_ttl` (go parsable duration: 5s, 10m, 1h etc)
  - `token_policies` (comma-separated strings)


- `auth/{mount}/login`  
Available operations: `write`  
`write` parameters:
  - `role` (string)
  - `secret` (string)
  - `accessor` (bool)

### Usage

Falling back to ["Why it was created"](#why-it-was-created) section, I assume that the Vault cluster, where the 
plugin will be enabled, has already been authenticated in the "upstream" Vault cluster. So the `VAULT_TOKEN` 
environment variable should be already set.

To be able to authenticate in target Vault cluster using __cross-vault-auth__ plugin, it is required to provide the 
following data for plugin and role configuration:
1. __[MANDATORY]__ API endpoint of the "upstream" cluster, which will be the issuer of the initial token;
2. __[OPTIONAL]__ CA certificate to validate server certificate of the endpoint ;
3. __[MANDATORY]__ Entity ID which issued token refers to;

```shell
vault auth enable -path=cva cva-plugin
# Success! Enabled cva-plugin auth method at: cva/
vault write -f auth/cva/config cluster="http://vault.target.example.local" insecure_skip_verify=true
# Success! Data written to: auth/cva/config
vault write auth/cva/role/sample \
  entity_id=11111111-2222-3333-4444-555566667777 \
  strict_meta_verify=false \
  token_ttl=5m
  token_policies=sample-policy
# Success! Data written to: auth/cva/role/sample
vault write auth/cva/login role=sample secret={TOKEN}
# Key                            Value
# ---                            -----
# token                          hvs.CAESIIkOvtZiU70VBDbAG3EDyK3nbGyuiXFMPo1GEKu62ZqnGh4KHGh2cy53VUJ0OUJuMDM4ZU80cWlHN0RTY1N0Tzk
# token_accessor                 4abjOqsQYJv77Az5DZ1ZWacZ
# token_duration                 5m
# token_renewable                true
# token_policies                 ["sample-policy" "default"]
# identity_policies              []
# policies                       ["sample-policy" "default"]
# token_meta_mapped_entity_id    11111111-2222-3333-4444-555566667777
# token_meta_role                sample
```
Now issued token can be used to log in to cluster.

### TODOs: 

1. __TESTS__
2. ~~Login using token accessor (add optional `-accessor` boolean field)~~
3. Login using wrapped token (add optional `-wrapped` boolean field)
