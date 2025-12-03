# K8s Config Role

## Overview
This role creates Kubernetes configuration files required for the service Kubernetes cluster and shares them via NFS. It prepares all necessary manifests, Helm charts, and configuration files needed for deploying services on the Kubernetes cluster.

## Purpose
The k8s_config role:
- Generates Kubernetes manifests for cluster services
- Creates Helm chart values files with environment-specific configuration
- Prepares ConfigMaps and Secrets for application deployments
- Stores all configuration in NFS-shared storage for access by service cluster nodes
- Ensures consistent configuration across all service cluster components

## Key Tasks

### 1. **Create K8s Config in NFS** (`create_k8s_config_nfs.yml`)
- **Conditional**: Only runs when `service_k8s_support` is enabled
- Creates directory structure in NFS share for Kubernetes configurations
- Generates Kubernetes resource manifests:
  - **Namespaces**: For logical separation of services
  - **RBAC Resources**: ServiceAccounts, Roles, RoleBindings
  - **ConfigMaps**: Application configuration data
  - **Secrets**: Sensitive data (passwords, tokens, certificates)
  - **Services**: Service endpoints and load balancers
  - **Deployments/StatefulSets**: Application workload definitions
  - **PersistentVolumeClaims**: Storage requests
- Templates Helm chart values files for:
  - Monitoring services (Prometheus, Grafana)
  - Logging infrastructure (ELK stack)
  - Telemetry components (if enabled)
  - Custom applications defined in software_config
- Sets appropriate file permissions and ownership
- Organizes files by service/application for easy management

## Directory Structure
Typical NFS directory layout created:
```
{{ nfs_share_path }}/k8s_config/
├── namespaces/
│   ├── monitoring.yaml
│   ├── telemetry.yaml
│   └── logging.yaml
├── rbac/
│   ├── serviceaccounts.yaml
│   └── roles.yaml
├── configmaps/
│   └── app-config.yaml
├── secrets/
│   └── app-secrets.yaml (encrypted)
├── helm-values/
│   ├── prometheus-values.yaml
│   ├── grafana-values.yaml
│   └── ...
└── manifests/
    ├── deployments/
    ├── services/
    └── pvcs/
```

## Configuration Sources
- **`software_config.json`**: Defines which services to deploy
- **`omnia_config.yml`**: Cluster-wide settings
- **`service_k8s.json`**: Service-specific parameters and image tags
- **`storage_config.yml`**: NFS and storage configuration

## Generated Files

### Namespace Configurations
- Creates isolated namespaces for different service categories
- Applies resource quotas and limits
- Sets network policies if required

### RBAC Configurations
- ServiceAccounts for service identity
- Roles defining permissions
- RoleBindings linking accounts to roles
- ClusterRoles for cluster-wide permissions

### Application Manifests
- Deployment YAMLs with proper resource requests/limits
- Service definitions (ClusterIP, NodePort, LoadBalancer)
- StatefulSets for stateful applications
- DaemonSets for node-level services

### Helm Values
- Customized values.yaml files for Helm charts
- Environment-specific overrides
- Image repository and tag specifications
- Resource allocation settings
- Persistence configuration

## Templates
Located in `templates/`:
- `namespace.yaml.j2`: Namespace definitions
- `rbac.yaml.j2`: RBAC resource templates
- `configmap.yaml.j2`: ConfigMap templates
- `deployment.yaml.j2`: Generic deployment templates
- Helm values templates for specific charts

## Variables
Key variables (defined in `vars/main.yml`):
- `service_k8s_support`: Boolean flag to enable this role
- `nfs_share_path`: Base path for NFS-shared configurations
- `k8s_config_dir`: Directory name for Kubernetes configs
- `file_permissions_644`: File permission mode
- `dir_permissions_755`: Directory permission mode
- Service-specific image tags and registry information

## NFS Integration
- All generated files are stored in NFS-shared storage
- Service cluster nodes mount the NFS share during initialization
- Allows centralized configuration management
- Supports dynamic updates (configurations can be updated and reloaded)
- Provides backup and recovery capability

## Security Considerations
- Secrets are generated with strong passwords
- Sensitive files have restricted permissions (600/640)
- RBAC enforces least-privilege access
- TLS certificates generated for secure communications
- Encryption at rest for sensitive ConfigMaps

## Dependencies
- **NFS Server**: Must be accessible and mounted
- **Software Config**: Valid `software_config.json` file
- **Service K8s Cluster**: Must be deployed or ready for deployment

## Integration Points
- **Input**: Software configuration and cluster parameters
- **Output**: Kubernetes manifests in NFS share
- **Used By**: Service cluster initialization and configuration
- **Accessed From**: Service cluster control plane and worker nodes

## Deployment Workflow
1. Validate `service_k8s_support` flag
2. Create directory structure in NFS share
3. Generate namespace definitions
4. Create RBAC resources
5. Generate ConfigMaps with application configuration
6. Create Secrets with encrypted sensitive data
7. Generate Helm values files
8. Create Deployment/StatefulSet/DaemonSet manifests
9. Generate Service definitions
10. Set appropriate permissions and ownership
11. Verify all files are accessible from NFS

## Usage in Cluster Bootstrap
Service cluster nodes:
1. Mount NFS share during cloud-init
2. Read Kubernetes manifests from NFS
3. Apply configurations using `kubectl apply`
4. Install Helm charts with custom values
5. Verify deployments are running

## Maintenance
- Configuration updates are made by re-running this role
- Changes are automatically picked up by Kubernetes watch mechanisms
- Manual apply may be needed for some resources (`kubectl apply -f`)
- Rolling updates triggered for Deployment changes

## Notes
- This role only creates configuration files; it doesn't apply them to the cluster
- Actual deployment happens during service cluster bootstrap or via separate playbooks
- Supports multiple Kubernetes versions (manifests are version-compatible)
- Helm chart values can be overridden at deployment time
- NFS ensures configuration consistency across all nodes
- File organization allows selective application of configurations
- Compatible with GitOps workflows (files can be version-controlled)
