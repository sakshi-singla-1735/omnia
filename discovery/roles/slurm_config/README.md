# Slurm Config Role

## Overview
This role configures Slurm workload manager settings for the HPC cluster. It reads Slurm node definitions, creates necessary directory structures in NFS, and prepares configuration files for Slurm controller and compute nodes.

## Purpose
The slurm_config role:
- Identifies Slurm nodes from cluster configuration (control, compute, login, compiler)
- Validates Slurm support is enabled in software configuration
- Creates shared Slurm directories on NFS for state management
- Prepares node-specific Slurm configurations
- Sets up directory structures for Slurm logs, spool files, and state information
- Ensures proper permissions and ownership for Slurm directories

## Key Tasks

### 1. **Load Software Configuration** (`main.yml`)
- Reads `software_config.json` to determine available software stacks
- Checks if Slurm is enabled (either `slurm` or `slurm_custom`)
- Sets `slurm_support` boolean flag for conditional execution

### 2. **Get Slurm Hostnames** (`read_slurm_hostnames.yml`)
- Reads node definitions from `omnia_config.yml`
- Identifies nodes by Slurm role:
  - **Control Nodes** (`ctld_list`): Slurm controller daemons (slurmctld)
  - **Compute Nodes** (`cmpt_list`): Slurm compute daemons (slurmd)
  - **Login Nodes** (`login_list`): User login nodes
  - **Compiler/Login Nodes** (`compiler_login_list`): Combined compiler and login nodes
- Extracts hostnames for each category
- Creates lists for configuration generation

### 3. **Create Slurm Directories** (`create_slurm_dir.yml`)
- **Conditional**: Only runs if:
  - At least one control node exists (`ctld_list` not empty), OR
  - At least one compute/login node exists, AND
  - Slurm support is enabled
- Creates the following directory structure on NFS:
  
  #### Primary Directories
  - **`/slurm`**: Root directory for all Slurm data
  - **`/slurm/state`**: Slurm state files (controller state)
  - **`/slurm/spool`**: Spool directory for job scripts and output
  - **`/slurm/log`**: Log files for slurmctld and slurmd
  - **`/slurm/munge`**: Munge authentication keys
  - **`/slurm/config`**: Configuration files (slurm.conf, etc.)

  #### Node-Specific Directories
  - **Control Node**: 
    - `/slurm/state/ctld`: Controller state directory
    - `/slurm/log/ctld`: Controller logs
  - **Compute Nodes**:
    - `/slurm/spool/d`: Compute node spool directories
    - `/slurm/log/d`: Compute node logs
  
  #### Permissions
  - Directories created with mode `755` or `775` depending on purpose
  - Ownership set to `slurm:slurm` (or configured Slurm user/group)
  - State and spool directories require write access for Slurm daemons

## Slurm Architecture

### Node Roles

#### Control Node (slurmctld)
- Runs the Slurm controller daemon
- Manages job scheduling and cluster state
- Maintains job queue and node information
- Communicates with database (slurmdbd)
- Typically 1-2 nodes for high availability

#### Compute Node (slurmd)
- Runs the Slurm compute daemon
- Executes jobs assigned by controller
- Reports node status and resource usage
- Mounts shared directories from NFS
- Can be 10s to 1000s of nodes

#### Login Node
- User access point to the cluster
- Users submit jobs from login nodes
- No compute resources allocated
- Mounts user home directories
- May run compilers and development tools

#### Compiler/Login Node
- Combined role for development and submission
- Includes development tools and compilers
- Users compile code and submit jobs
- May have GPUs for development/testing

### Slurm Directories Explained

#### State Directory (`/slurm/state`)
- Stores controller state information
- Critical for restart and recovery
- Contains job history and node state
- Must be on shared storage for HA setups
- Backed up regularly

#### Spool Directory (`/slurm/spool`)
- Temporary storage for job scripts
- Standard output/error files during execution
- Job batch scripts and prologs/epilogs
- Can be local or shared storage
- Cleaned periodically

#### Log Directory (`/slurm/log`)
- Controller logs (`slurmctld.log`)
- Compute daemon logs (`slurmd.log`)
- Scheduler logs
- Database logs (if co-located)
- Rotated based on size/time

#### Config Directory (`/slurm/config`)
- `slurm.conf`: Main configuration file
- `slurmdbd.conf`: Database configuration
- `cgroup.conf`: Cgroup settings
- `gres.conf`: Generic resource configuration
- Topology files, scripts, etc.

#### Munge Directory (`/slurm/munge`)
- Munge authentication key (`munge.key`)
- Must be identical on all nodes
- Permissions: 400 (read-only for munge user)
- Critical for inter-node authentication

## Configuration Files Generated

### slurm.conf
Main Slurm configuration file containing:
- Cluster name and controller hostname
- Node definitions (CPUs, memory, features)
- Partition definitions
- Scheduler parameters
- Accounting settings
- Resource limits

### slurmdbd.conf
Slurm database daemon configuration:
- Database connection parameters
- Storage backend (MySQL/MariaDB)
- Accounting settings
- Archive settings

### Node Definitions
Example node definition format:
```
NodeName=node[001-100] CPUs=64 RealMemory=256000 Sockets=2 CoresPerSocket=32 ThreadsPerCore=1 State=UNKNOWN
```

### Partition Definitions
Example partition definition:
```
PartitionName=compute Nodes=node[001-100] Default=YES MaxTime=INFINITE State=UP
```

## Variables
Key variables (defined in `vars/main.yml` and `defaults/main.yml`):
- `software_config_file`: Path to software configuration JSON
- `slurm_support`: Boolean indicating Slurm is enabled
- `ctld_list`: List of controller node hostnames
- `cmpt_list`: List of compute node hostnames
- `login_list`: List of login node hostnames
- `compiler_login_list`: List of compiler/login node hostnames
- `slurm_user`: Unix user for Slurm daemons (typically `slurm`)
- `slurm_group`: Unix group for Slurm daemons
- `slurm_nfs_path`: NFS path for Slurm directories

## NFS Requirements
- NFS server must export Slurm directory (e.g., `/export/slurm`)
- All Slurm nodes mount the export (e.g., to `/slurm`)
- NFS must support file locking for state management
- Recommended: NFSv4 for better performance and locking
- Consider dedicated NFS for Slurm if high I/O expected

## Directory Hierarchy
```
/slurm/                          # NFS-mounted root
├── state/                       # Controller state
│   └── ctld/                    # slurmctld state files
├── spool/                       # Job spool
│   └── d/                       # slurmd spool directories
├── log/                         # Log files
│   ├── ctld/                    # Controller logs
│   └── d/                       # Compute daemon logs
├── config/                      # Configuration files
│   ├── slurm.conf
│   ├── slurmdbd.conf
│   ├── cgroup.conf
│   └── gres.conf
└── munge/                       # Authentication
    └── munge.key
```

## Integration Points
- **Input**: Software configuration, Omnia configuration
- **Output**: Slurm directory structure on NFS
- **Used By**: Slurm controller, compute nodes, login nodes
- **Depends On**: NFS server, Slurm packages installed

## Deployment Sequence
1. NFS server sets up and exports Slurm directory
2. This role creates directory structure and sets permissions
3. Slurm configuration files generated (separate role/playbook)
4. Munge key distributed to all nodes
5. Slurm controller started on control node(s)
6. Slurm daemons started on compute nodes
7. Nodes registered with controller
8. Cluster ready for job submission

## High Availability Considerations
For HA Slurm deployments:
- **Primary Controller**: Active slurmctld
- **Backup Controller**: Standby slurmctld
- **Shared State**: Both controllers access same state directory
- **Automatic Failover**: Backup takes over if primary fails
- **Database HA**: Slurmdbd can also be in HA configuration

## Security
- Munge provides authentication between Slurm components
- Munge key must be secret and identical on all nodes
- Slurm directories have restricted permissions
- Communication can be encrypted (requires configuration)
- Accounting database should be access-controlled

## Maintenance
- **Log Rotation**: Configure logrotate for Slurm logs
- **State Cleanup**: Periodically clean old state files
- **Spool Cleanup**: Remove old job scripts and outputs
- **Backup**: Regular backups of state and config directories
- **Monitoring**: Monitor state directory disk usage

## Troubleshooting
Common issues:
- **Controller can't write state**: Check NFS mount and permissions
- **Node registration fails**: Verify hostnames match slurm.conf
- **Munge errors**: Ensure munge.key is identical on all nodes
- **NFS locking issues**: Enable NFS lock services
- **Permission denied**: Check Slurm user/group ownership

## Performance Tuning
- Use local spool directories on compute nodes for better performance
- Keep only state directory on NFS for controller
- Use SSD-backed storage for state directory
- Tune NFS parameters (rsize/wsize) for Slurm workload
- Consider separate NFS for large output files

## Custom Slurm Configuration
The `slurm_custom` option in software config allows:
- Custom-built Slurm versions
- Additional plugins and libraries
- Site-specific modifications
- Integration with custom schedulers

## Notes
- This role only creates directories; Slurm package installation is separate
- Configuration file generation happens in subsequent roles/playbooks
- The role is idempotent; re-running is safe
- Hierarchy shown is standard but can be customized via variables
- Supports both single-controller and HA configurations
- Compatible with Slurm versions 20.x, 21.x, 22.x, 23.x
- Directory structure follows Slurm best practices and recommendations
