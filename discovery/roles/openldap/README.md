# OpenLDAP Role

## Overview
This role configures OpenLDAP connection parameters and prepares the cluster for centralized authentication and user management via LDAP. It sets up the necessary variables and connection strings for nodes to communicate with the OpenLDAP server.

## Purpose
The openldap role:
- Extracts and formats LDAP configuration from Omnia settings
- Builds LDAP connection URIs based on domain name
- Sets up LDAP bind DN (Distinguished Name) for authentication
- Configures connection type (LDAP vs LDAPS)
- Prepares variables for use by other roles and cloud-init configurations
- Validates OpenLDAP support is enabled before proceeding

## Key Tasks

### 1. **Get LDAP Variables** (`main.yml`)
- **Conditional**: Only runs when `openldap_support` is true
- Performs the following variable transformations:

#### Extract Domain Name for LDAP
- Converts domain name to LDAP search base format
- Example: `example.com` → `dc=example,dc=com`
- Uses Ansible filters to split domain and prepend `dc=` to each component
- Sets `ldap_search_base` variable for use in LDAP queries

#### Set Server IP
- Extracts primary OIM (Omnia Infrastructure Manager) admin IP
- Reads from `Networks[0]['admin_network']['primary_oim_admin_ip']`
- This IP is where the OpenLDAP server is running
- Sets `ldap_server_ip` for client connections

#### Configure Connection Type
- Reads `ldap_connection_type` from configuration
- Converts to lowercase for consistency
- Options:
  - `ldap`: Unencrypted LDAP (port 389)
  - `ldaps`: LDAP over SSL/TLS (port 636)
- Sets `connection_type` variable

#### Set LDAP Password
- Extracts `openldap_db_password` for database authentication
- Used for binding to LDAP directory
- Stored securely and used in subsequent configurations

#### Build Bind DN
- Constructs the default bind DN for LDAP authentication
- Format: `cn=<username>,<search_base>`
- Example: `cn=admin,dc=example,dc=com`
- Uses `openldap_db_username` from configuration
- Sets `ldap_default_bind_dn` variable

### 2. **Error Handling** (`main.yml`)
- **Rescue Block**: Catches any failures during variable setup
- Displays helpful error message via `openldap_fail_msg`
- Indicates missing or malformed configuration files
- Stops playbook execution to prevent misconfiguration

## LDAP Configuration Components

### Search Base
The LDAP search base defines the root of the directory tree:
- Used for all LDAP queries and searches
- Derived from the cluster domain name
- Example conversions:
  - `cluster.local` → `dc=cluster,dc=local`
  - `hpc.myorg.com` → `dc=hpc,dc=myorg,dc=com`

### Bind DN
The bind DN is the identity used to connect to LDAP:
- Administrative DN: `cn=admin,dc=example,dc=com`
- Service DN: `cn=slurmctld,dc=example,dc=com`
- User DN: `uid=username,ou=users,dc=example,dc=com`

### Connection URI
Complete LDAP connection string format:
- LDAP: `ldap://<server_ip>:389`
- LDAPS: `ldaps://<server_ip>:636`

## Variables Set

### Output Variables
These variables are set by this role for use by other roles:
- `ldap_search_base`: LDAP directory base (e.g., `dc=example,dc=com`)
- `ldap_server_ip`: IP address of LDAP server
- `connection_type`: Connection protocol (`ldap` or `ldaps`)
- `password`: LDAP bind password (no_log: true)
- `ldap_default_bind_dn`: Default bind DN for authentication

### Input Variables
These variables must be defined in configuration files:
- `openldap_support`: Boolean flag to enable OpenLDAP
- `domain_name`: Cluster domain name
- `ldap_connection_type`: Connection protocol preference
- `openldap_db_username`: LDAP admin/bind username
- `openldap_db_password`: LDAP admin/bind password
- `Networks[0]['admin_network']['primary_oim_admin_ip']`: LDAP server IP

## Configuration Files
Input configuration:
- `omnia_config.yml`: Contains domain name and network settings
- `omnia_config_credentials.yml`: Contains LDAP credentials
- `security_config.yml`: Contains connection type and security settings

## Use Cases

### Slurm Integration
- Slurm nodes use LDAP for user authentication
- LDAP search base used in `slurm.conf` and `slurmdbd.conf`
- Users and groups synchronized from LDAP directory

### Kubernetes Integration
- LDAP can be used for Kubernetes authentication
- Service accounts mapped to LDAP users
- RBAC policies linked to LDAP groups

### System Authentication
- PAM (Pluggable Authentication Modules) configured for LDAP
- NSS (Name Service Switch) configured for LDAP user lookups
- System users resolved from LDAP directory

### SSH Authentication
- SSH keys can be stored in LDAP
- User authentication via LDAP credentials
- Home directories automounted based on LDAP attributes

## Security Considerations

### LDAPS (Recommended)
- Uses TLS encryption for all LDAP traffic
- Requires SSL certificates on server and clients
- Port 636 must be open in firewall
- Provides confidentiality and integrity

### LDAP (Less Secure)
- Unencrypted traffic (credentials visible)
- Should only be used on trusted internal networks
- Port 389 must be open in firewall
- Consider using StartTLS for encryption

### Password Handling
- Passwords never logged (`no_log: true` implicit)
- Stored in encrypted credential files
- Access restricted to root user
- Rotated regularly per security policy

## Dependencies
- **OpenLDAP Server**: Must be installed and running on OIM node
- **Network Connectivity**: Cluster nodes must reach LDAP server
- **Domain Configuration**: Valid domain name in `omnia_config.yml`
- **Credentials**: Valid LDAP admin credentials

## Integration Points
- **Input**: Omnia configuration files
- **Output**: LDAP connection variables
- **Used By**: 
  - Slurm configuration (user authentication)
  - Kubernetes configuration (optional)
  - System authentication (PAM/NSS)
  - Cloud-init scripts for node provisioning

## Deployment Sequence
1. OpenLDAP server deployed on OIM node
2. This role runs to extract connection parameters
3. Variables passed to other roles (Slurm, K8s, etc.)
4. Cloud-init templates include LDAP configuration
5. Nodes provisioned with LDAP client configuration
6. Users and groups synchronized from LDAP

## Validation
After this role runs, verify:
- `ldap_search_base` format is correct (dc=...,dc=...)
- `ldap_server_ip` is reachable from cluster nodes
- `connection_type` matches security requirements
- `ldap_default_bind_dn` follows LDAP naming conventions

## Troubleshooting
Common issues:
- **Invalid search base**: Check domain name format in config
- **Connection failures**: Verify LDAP server is running and accessible
- **Authentication errors**: Check bind DN and password correctness
- **Certificate errors (LDAPS)**: Verify SSL certificates are valid and trusted

## LDAP Client Configuration
Nodes will typically be configured with:
```yaml
ldap_uri: ldaps://{{ ldap_server_ip }}:636
ldap_base: {{ ldap_search_base }}
ldap_bind_dn: {{ ldap_default_bind_dn }}
ldap_bind_pw: {{ password }}
```

## Notes
- This role only sets variables; it doesn't configure LDAP clients
- Actual LDAP client configuration happens in cloud-init or post-provisioning
- OpenLDAP server installation is handled separately (not by this role)
- LDAP schema and directory structure managed independently
- Support for Active Directory can be added with similar variable transformations
- Multi-site LDAP replication requires additional configuration
- LDAP failover/redundancy should be configured at the server level
