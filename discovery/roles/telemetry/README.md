# Telemetry Role

## Overview
This role configures telemetry services for HPC cluster monitoring, including iDRAC telemetry streaming and LDMS (Lightweight Distributed Metric Service) data collection. It deploys and configures Kubernetes-based telemetry infrastructure on the service cluster.

## Purpose
The telemetry role enables comprehensive cluster monitoring by:
- Collecting hardware metrics from Dell iDRAC interfaces
- Deploying LDMS agents for system-level metrics collection
- Setting up data aggregation and storage infrastructure
- Configuring Kafka for telemetry data streaming
- Deploying time-series databases for metric storage
- Creating Grafana dashboards for visualization

## Key Tasks

### 1. **Include Telemetry Configuration** (`main.yml`)
- Loads telemetry configuration from `telemetry_config.yml`
- Sets up telemetry-specific variables and parameters

### 2. **Read Software Configuration** (`read_software_config.yml`)
- Extracts telemetry package information from `software_config.json`
- Identifies required telemetry components (LDMS, iDRAC streamers, etc.)

### 3. **Load Service Images** (`load_service_images.yml`)
- Reads container image information from `service_k8s.json`
- Prepares image tags and registry details for telemetry containers

### 4. **Service Cluster Prerequisites** (`telemetry_prereq.yml`)
- **Conditional**: Runs when `idrac_telemetry_support` or `ldms_support` is enabled
- Sets up namespace and common resources in Kubernetes
- Creates ConfigMaps and Secrets for telemetry services
- Installs Helm charts if needed

### 5. **Generate Telemetry Deployments** (`generate_telemetry_deployments.yml`)
- Creates Kubernetes deployment manifests for telemetry services:
  - **LDMS Components**:
    - LDMS samplers (data collectors on compute nodes)
    - LDMS aggregators (first-level aggregation)
    - LDMS storage (time-series data storage)
  - **iDRAC Telemetry**:
    - iDRAC telemetry streamers
    - Kafka topics for iDRAC data
    - Kafka consumers
  - **Storage and Visualization**:
    - TimescaleDB or InfluxDB deployments
    - Grafana dashboards
- Applies appropriate node selectors and resource limits

### 6. **Validate iDRAC Inventory** (`validate_idrac_inventory.yml`)
- **Conditional**: Only for iDRAC telemetry
- Validates iDRAC connection parameters
- Checks iDRAC accessibility from service cluster nodes
- Verifies Redfish API endpoints

### 7. **Generate Service Cluster Metadata** (`generate_service_cluster_metadata.yml`)
- Creates metadata for telemetry service deployment
- Maps iDRAC endpoints to cluster nodes
- Generates configuration files for iDRAC streamers

### 8. **Update LDMS Sampler Configuration** (`update_ldms_sampler.yml`)
- **Conditional**: Runs when `ldms_support` is enabled
- Configures LDMS samplers on compute nodes:
  - Defines metrics to collect (CPU, memory, network, disk, GPU)
  - Sets collection intervals
  - Configures sampler plugins (procstatutil, meminfo, vmstat, etc.)
- Creates sampler configuration files for cloud-init deployment

### 9. **Update LDMS Aggregator Configuration** (`update_ldms_agg_config.yml`)
- **Conditional**: Runs when `ldms_support` is enabled
- Configures LDMS aggregator settings:
  - Sets aggregation rules and intervals
  - Configures storage backends
  - Defines data retention policies
  - Updates Helm values for LDMS aggregator deployment

## Telemetry Components

### iDRAC Telemetry
- **Streamer**: Collects metrics from Dell iDRAC Redfish API
- **Metrics Collected**:
  - Temperature (CPU, GPU, ambient)
  - Power consumption (system, CPU, GPU)
  - Fan speeds
  - Hardware health status
  - Firmware versions
- **Data Flow**: iDRAC → Telemetry Streamer → Kafka → TimescaleDB/InfluxDB → Grafana

### LDMS Telemetry
- **Components**:
  - **Samplers**: Run on compute/login nodes to collect OS-level metrics
  - **Aggregators**: Collect data from multiple samplers, first-level aggregation
  - **Storage**: Final aggregation and storage in time-series database
- **Metrics Collected**:
  - CPU utilization and load
  - Memory usage (physical, swap, cache)
  - Network statistics (packets, bandwidth, errors)
  - Disk I/O (reads, writes, latency)
  - GPU metrics (if available)
  - Process-level statistics
- **Data Flow**: Samplers → L1 Aggregator → L2 Aggregator/Storage → Database → Grafana

## Templates
Located in `templates/telemetry/`:
- **LDMS Templates**:
  - `ldms/sampler_config.j2`: Sampler plugin configuration
  - `ldms/values.yaml.j2`: Helm chart values for LDMS deployment
- **Kafka Templates**:
  - `kafka/kafka.kafkapump_user.yaml.j2`: Kafka user configuration
  - `kafka/topics.j2`: Kafka topic definitions
- **Telemetry Script**: `telemetry.sh.j2`: Initialization script for nodes
- **Dashboard Templates**: Grafana dashboard JSON files

## Files
Located in `files/`:
- Helm charts for LDMS aggregator (`nersc-ldms-aggr/`)
- Pre-built container images or references
- Default configuration files

## Configuration Files
- **Input**: `telemetry_config.yml` - Main telemetry configuration
- **Input**: `software_config.json` - Defines which telemetry components to deploy
- **Input**: `service_k8s.json` - Container image registry and tags
- **Output**: Generated Kubernetes manifests and Helm values

## Variables
Key variables (defined in `vars/main.yml`):
- `idrac_telemetry_support`: Boolean to enable iDRAC telemetry
- `ldms_support`: Boolean to enable LDMS telemetry
- `telemetry_config_file_path`: Path to telemetry configuration file
- `service_cluster_support`: Boolean indicating service K8s cluster availability
- Image tags for various telemetry components

## Dependencies
- **Kubernetes Service Cluster**: Must be deployed and accessible
- **Helm**: Required for chart-based deployments
- **Container Registry**: For pulling telemetry container images
- **Network Access**: 
  - Compute nodes → Aggregators
  - Service cluster → iDRAC interfaces
  - Clients → Grafana dashboards

## Integration Points
- **Compute Nodes**: LDMS samplers installed via cloud-init
- **Service Cluster**: Aggregators, storage, and visualization
- **BMC Network**: iDRAC telemetry streamers access BMC interfaces
- **Admin Network**: Service endpoints exposed for dashboard access

## Deployment Sequence
1. Load configuration and validate inputs
2. Set up Kubernetes prerequisites (namespaces, RBAC)
3. Deploy infrastructure (Kafka, TimescaleDB)
4. Configure and deploy LDMS components
5. Configure and deploy iDRAC streamers
6. Verify deployments and create service endpoints
7. Deploy Grafana and import dashboards

## Monitoring Endpoints
- **Grafana Dashboard**: Typically exposed via MetalLB LoadBalancer or NodePort
- **Kafka**: Internal service for data streaming
- **Database**: Internal service for metric storage
- **LDMS Aggregator**: Listens for sampler connections

## Notes
- Telemetry services run in the Kubernetes service cluster, separate from workload clusters
- Both iDRAC and LDMS telemetry can be enabled independently or together
- LDMS samplers are lightweight and have minimal performance impact
- iDRAC telemetry does not impact compute node performance
- Data retention and collection intervals are configurable
- Supports multiple time-series database backends
- Grafana dashboards are pre-configured for HPC-specific metrics
- SELinux contexts may need adjustment for persistent volume access
