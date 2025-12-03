# Discovery Validations Role

## Overview
This role validates all discovery-related configuration files and inputs before the discovery process begins. It ensures that all required parameters are present, correctly formatted, and logically consistent.

## Purpose
Discovery validations act as a gatekeeper to prevent misconfigured deployments by:
- Validating discovery input files syntax and structure
- Checking software configuration consistency
- Validating mapping files when mapping-based discovery is used
- Ensuring telemetry configuration is correct
- Updating system hosts file with discovered nodes

## Key Tasks

### 1. **Set Facts from Credentials** (`main.yml`)
- Loads sensitive credentials from `omnia_config_credentials.yml`:
  - `provision_password`: Password for node provisioning
  - `bmc_username`: BMC (Baseboard Management Controller) username
  - `bmc_password`: BMC password
- All credential handling uses `no_log: true` for security

### 2. **Include Discovery Inputs** (`include_inputs.yml`)
- Validates syntax of discovery input files
- Loads configuration from multiple discovery input YAML files
- Provides detailed error messages if file syntax is invalid
- Files validated include:
  - Node mapping files
  - Network configuration
  - Discovery mechanism settings

### 3. **Include Software Configuration** (`include_software_config.yml`)
- Validates `software_config.json` file
- Checks for supported software packages (Slurm, Kubernetes, etc.)
- Ensures software dependencies are properly defined

### 4. **Validate Mapping Mechanism** (`validate_mapping_mechanism.yml`)
- Determines if discovery mechanism is set to "mapping" mode
- Sets `mapping_file_status` flag for conditional validation

### 5. **Validate Mapping File** (`validate_mapping_file.yml`)
- **Conditional**: Only runs when `mapping_file_status` is true
- Validates node mapping file structure:
  - MAC address format and uniqueness
  - Hostname format and uniqueness
  - IP address assignments
  - BMC (iDRAC) configuration
  - Service tag and administrative network settings
- Ensures mapping file entries are complete and consistent

### 6. **Update Hosts File** (`update_hosts.yml`)
- Updates `/etc/hosts` with discovered node information
- Ensures hostname resolution for cluster nodes
- Adds admin network IP addresses for all discovered nodes

### 7. **Validate Telemetry Configuration** (`validate_telemetry_config.yml`)
- **Conditional**: Only runs when `idrac_telemetry_support` is enabled
- Validates telemetry-related settings:
  - iDRAC telemetry endpoint configuration
  - LDMS (Lightweight Distributed Metric Service) settings
  - Kafka integration parameters
  - Time-series database configuration

## Validation Scope

### Input Files Validated
- `omnia_config_credentials.yml`: Sensitive credentials
- `discovery_*.yml`: Discovery mechanism configuration
- `software_config.json`: Software packages to deploy
- `mapping_file.csv` (if mapping mode): Node mapping data
- `telemetry_config.yml` (if telemetry enabled): Telemetry settings

### Data Validation Rules
- **MAC Addresses**: Valid format, uniqueness
- **IP Addresses**: Valid CIDR notation, no conflicts
- **Hostnames**: Valid DNS naming, uniqueness
- **Service Tags**: Proper Dell service tag format
- **Passwords**: Minimum complexity requirements
- **File Permissions**: Correct ownership and modes

## Variables
Key variables (defined in `vars/main.yml`):
- `discovery_inputs`: List of discovery input file paths
- `mapping_file_status`: Boolean indicating mapping mode
- `idrac_telemetry_support`: Boolean for telemetry validation
- `input_syntax_fail_msg`: Error message template for syntax failures

## Error Handling
- Syntax errors in input files trigger immediate failure with detailed messages
- Missing required fields are reported with specific file/line references
- Duplicate entries (MAC, IP, hostname) are flagged
- Invalid format entries provide correction guidance

## Dependencies
This role must run:
- **After**: Omnia configuration files are created
- **Before**: Any discovery mechanism starts
- **Before**: Node provisioning begins

## Integration Points
- Reads from: `omnia_config.yml`, `omnia_config_credentials.yml`, `software_config.json`
- Validates for: Discovery mechanism, metadata creation, provisioning
- Updates: System hosts file

## Notes
- This role does not modify configuration files; it only validates them
- All credential operations use `no_log: true` to prevent sensitive data exposure
- Validation failures stop the playbook execution to prevent partial deployments
- Supports multiple discovery mechanisms: mapping, switch-based, MTMS
- Telemetry validation is optional and only runs when telemetry support is enabled
