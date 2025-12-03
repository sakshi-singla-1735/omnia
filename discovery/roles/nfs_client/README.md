# NFS Client Role

## Overview
This role configures NFS client mounts on cluster nodes based on their functional roles (Slurm compute/control, Kubernetes service nodes, etc.). It intelligently filters and mounts only the NFS shares relevant to each node's purpose.

## Purpose
The nfs_client role:
- Identifies which NFS shares each node type requires
- Filters NFS mounts based on cluster configuration (Slurm, Kubernetes, etc.)
- Configures NFS client packages and services
- Creates mount points and mounts NFS shares
- Ensures persistent mounts across reboots via `/etc/fstab`
- Supports bolt-on storage additions

## Key Tasks

### 1. **Include Storage Configuration** (`main.yml`)
- Loads `storage_config.yml` containing NFS server details and mount definitions
- Includes NFS server IP addresses, export paths, and mount options

### 2. **Load Software Configuration** (`main.yml`)
- Reads `software_config.json` to determine which software stacks are enabled
- Checks for Slurm support (`slurm` or `slurm_custom`)
- Checks for Kubernetes service cluster support (`service_k8s`)

### 3. **Filter Slurm NFS Mounts** (`main.yml`)
- **Conditional**: Only when Slurm is in `omnia_run_tags` and `slurm_support` is true
- Loads `omnia_config.yml` to get Slurm cluster configuration
- Extracts `nfs_storage_name` from Slurm cluster definitions
- Filters `nfs_client_params` to include only Slurm-relevant shares
- Common Slurm NFS mounts:
  - Shared home directories (`/home`)
  - Slurm state directory (`/var/spool/slurm`)
  - Shared application directories (`/opt/apps`)
  - Scratch/working directories

### 4. **Filter Service K8s NFS Mounts** (`main.yml`)
- **Conditional**: Only when `service_k8s` is in `omnia_run_tags` and `service_k8s_support` is true
- Loads `omnia_config.yml` to get service Kubernetes configuration
- Extracts `nfs_storage_name` from service K8s cluster definitions
- Filters `nfs_client_params` for Kubernetes-relevant shares
- Common K8s NFS mounts:
  - Kubernetes configuration files (`/nfs/k8s_config`)
  - Persistent volume storage
  - Shared logs directory
  - Application data directories

### 5. **Install NFS Client** (`nfs_client.yml`)
- Iterates through filtered `storage_to_be_mounted` list
- For each NFS share:
  - Installs NFS client packages (`nfs-utils`, `nfs-common`)
  - Creates local mount point directory
  - Adds entry to `/etc/fstab` for persistent mounting
  - Mounts the NFS share
  - Verifies mount is successful
  - Sets appropriate permissions on mount point
- Supports bolt-on storage (dynamically added mounts)

## NFS Mount Configuration

### Storage Parameters
Each NFS mount in `storage_to_be_mounted` includes:
- `nfs_name`: Unique identifier for the NFS share
- `nfs_server`: NFS server IP address or hostname
- `nfs_export_path`: Export path on NFS server (e.g., `/export/home`)
- `nfs_mount_point`: Local mount point on client (e.g., `/home`)
- `nfs_mount_options`: Mount options (e.g., `rw,sync,hard,intr,rsize=1048576,wsize=1048576`)
- `nfs_version`: NFS protocol version (typically `nfs4` or `nfs3`)

### Mount Options Explained
- `rw`: Read-write access
- `sync`: Synchronous writes (safer but slower)
- `hard`: Hard mount (retries on failure)
- `intr`: Allows interruption of NFS operations
- `rsize/wsize`: Read/write buffer sizes (1MB for performance)
- `noatime`: Don't update access times (performance optimization)
- `nodiratime`: Don't update directory access times

## Role-Based Filtering

### Slurm Nodes
**Control Nodes (slurmctld)**:
- Mount: Slurm state directory
- Mount: Shared home directories
- Mount: Application directories

**Compute Nodes (slurmd)**:
- Mount: Shared home directories
- Mount: Application directories
- Mount: Scratch directories

**Login Nodes**:
- Mount: Shared home directories
- Mount: Application directories
- Mount: User workspace directories

### Kubernetes Service Nodes
**Control Plane**:
- Mount: Kubernetes configuration share
- Mount: Persistent volume storage
- Mount: Helm chart repository

**Worker Nodes**:
- Mount: Persistent volume storage
- Mount: Shared logs

## Variables
Key variables (defined in `vars/main.yml`):
- `storage_config_vars`: Path to storage configuration file
- `software_config_file`: Path to software configuration JSON
- `omnia_config_vars`: Path to Omnia configuration file
- `nfs_client_params`: Complete list of available NFS mounts
- `storage_to_be_mounted`: Filtered list of mounts for current node
- `slurm_support`: Boolean indicating Slurm is enabled
- `service_k8s_support`: Boolean indicating service K8s is enabled

## Directory Creation
- Mount points are created with appropriate ownership (root:root)
- Permissions set to 755 for directories
- Parent directories created recursively if needed
- Existing directories preserved (no overwrite)

## fstab Management
- Entries added to `/etc/fstab` for persistent mounts
- Format: `<server>:<export> <mount_point> <fs_type> <options> <dump> <pass>`
- Example: `192.168.1.10:/export/home /home nfs4 rw,sync,hard 0 0`
- Duplicate entries are prevented
- Comments added for Omnia-managed mounts

## Error Handling
- Mount failures are logged but don't stop playbook
- Network connectivity to NFS server is checked before mounting
- Mount point permission issues are reported
- NFS service availability is verified

## Dependencies
- **NFS Server**: Must be running and accessible
- **Network**: NFS server must be reachable from client nodes
- **Storage Config**: Valid `storage_config.yml` file
- **Software Config**: Valid `software_config.json` file

## Integration Points
- **Input**: Storage configuration, software configuration, Omnia configuration
- **Output**: Mounted NFS shares on compute/service nodes
- **Used By**: Slurm, Kubernetes, application workloads
- **Triggers**: Node provisioning, bolt-on storage addition

## Mount Verification
After mounting:
1. Check mount command output for errors
2. Verify mount appears in `mount` command
3. Test read access: `ls <mount_point>`
4. Test write access (if rw): `touch <mount_point>/.test && rm <mount_point>/.test`
5. Check mount options: `findmnt <mount_point>`

## Troubleshooting
Common issues and solutions:
- **Mount hangs**: Check NFS server accessibility, firewall rules
- **Permission denied**: Verify NFS export permissions, client IP in exports
- **Stale file handle**: Remount the share, check NFS server logs
- **Mount at boot fails**: Ensure network is up before mounting (use `_netdev` option)

## Performance Tuning
- Adjust `rsize`/`wsize` based on network and workload
- Use `async` for better performance (less safety)
- Consider `actimeo` for attribute caching
- Use NFSv4 for better performance and security
- Enable NFS over RDMA for high-performance networks

## Security
- Use `sec=krb5` for Kerberos authentication (if available)
- Restrict exports on NFS server by IP/subnet
- Use `nosuid` and `nodev` options for security
- Monitor NFS traffic for suspicious activity

## Notes
- Mounts are role-specific; not all nodes mount all shares
- Bolt-on support allows adding storage dynamically
- NFS client automatically reconnects on network issues with `hard` mount
- The role is idempotent; re-running won't duplicate mounts
- Mount failures on non-critical shares are logged but don't fail the role
- Supports multiple NFS servers for different shares
- Compatible with AutoFS for on-demand mounting (if configured separately)
