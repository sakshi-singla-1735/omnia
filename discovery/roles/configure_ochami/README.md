# Configure OpenCHAMI Role

## Overview
This role configures **OpenCHAMI** (Open Composable HPC Architecture Management Interface) for managing HPC cluster nodes. It sets up groups, boot services (BSS), and cloud-init configurations for node provisioning.

## Purpose
OpenCHAMI provides a modern, composable architecture for HPC cluster management. This role:
- Creates and manages SMD (State Management Database) groups for organizing nodes
- Configures BSS (Boot Script Service) boot parameters for node booting
- Sets up cloud-init configurations for automated node initialization
- Manages node metadata and grouping based on functional roles

## Key Tasks

### 1. **Create Groups** (`create_groups.yml`)
- Generates OpenCHAMI group definitions from mapping files
- Creates SMD groups using `ochami smd group` commands
- Manages functional groups for different node types (compute, control plane, login, etc.)
- Updates existing groups when changes are detected

### 2. **Create Common Groups** (`create_groups_common.yml`)
- Creates common cloud-init groups shared across multiple node types
- Handles service cluster and common infrastructure groupings

### 3. **Configure BSS and Cloud-Init** (`configure_bss_cloud_init.yml`)
- **Boot Service Setup**:
  - Deletes existing boot parameters to avoid conflicts
  - Configures boot parameters per functional group
  - Verifies boot parameter configuration
- **Cloud-Init Configuration**:
  - Reads SSH keys for node access
  - Hashes passwords for secure node provisioning
  - Creates cloud-init defaults (timezone, SSH keys, users, etc.)
  - Generates group-specific cloud-init files
  - Sets appropriate SELinux contexts for OpenCHAMI directories

### 4. **Discovery Completion** (`discovery_completion.yml`)
- Finalizes the discovery process
- Validates all configurations are properly set

## Templates
This role uses numerous templates located in the `templates/` directory:
- **Cloud-Init Templates**: Group-specific cloud-init YAML files for different node types (kube control plane, compute, login, etc.)
- **BSS Templates**: Boot parameter configurations
- **Group Templates**: SMD group definitions

## Key Directories
- `{{ nodes_dir }}`: Directory for storing node and group definitions
- `{{ bss_dir }}`: Boot Script Service configuration directory
- `{{ cloud_init_dir }}`: Cloud-init configuration directory

## Dependencies
- OpenCHAMI CLI tool (`ochami` command)
- Valid OpenCHAMI environment variables (set in `hostvars['oim']['ochami_env']`)
- Node mapping file with functional group definitions

## Variables
Key variables used (defined in `vars/main.yml`):
- `functional_groups`: List of functional groups to configure
- `common_cloud_init_groups`: Common cloud-init groups
- `openchami_groups_template`: Template for group definitions
- `ssh_key_path`: Path to SSH public key for node access
- `file_permissions_644`, `dir_permissions_755`: Permission settings

## Integration
This role is typically run after:
- Discovery mechanism completes node discovery
- Metadata creation establishes node records

It prepares nodes for provisioning by setting up all necessary boot and initialization configurations.

## Notes
- The role operates within an OpenCHAMI environment context
- All `ochami` commands require proper authentication and environment setup
- SELinux contexts are set to allow container access to configuration files
- Cloud-init configurations support various node types and architectures (x86_64, aarch64)
