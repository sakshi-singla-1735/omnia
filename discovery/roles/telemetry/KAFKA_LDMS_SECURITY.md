# Kafka LDMS Security Implementation

## Overview

This document describes the security implementation for LDMS (Lightweight Distributed Metric Service) connections to Kafka. LDMS uses the `store_avro_kafka` plugin which does not support TLS or authentication. Instead of using an insecure `ANONYMOUS` superuser configuration, we implement network-level security using Kubernetes NetworkPolicy.

## Security Challenge

### LDMS store_avro_kafka Plugin Limitations

- **No TLS Support**: The `store_avro_kafka` plugin cannot use encrypted connections
- **No Authentication**: The plugin cannot provide credentials
- **Port 9092 Required**: Must use Kafka's plaintext listener (port 9092)

### Previous Insecure Approach (REMOVED)

```yaml
# ❌ INSECURE - Removed in current implementation
authorization:
  type: simple
  superUsers:
    - ANONYMOUS  # Anyone could access Kafka without authentication!
```

**Security Risk**: Any pod or service in the cluster could connect to Kafka port 9092 and perform any operation without authentication.

## Secure Solution: NetworkPolicy

### Implementation

We use Kubernetes NetworkPolicy to restrict access to Kafka's plaintext listener (port 9092) at the network layer.

**File**: `kafka.networkpolicy.yaml.j2`

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kafka-ldms-access
  namespace: telemetry
spec:
  podSelector:
    matchLabels:
      strimzi.io/cluster: kafka
      strimzi.io/kind: Kafka
      strimzi.io/name: kafka-broker
  policyTypes:
    - Ingress
  ingress:
    # Allow all traffic on TLS ports (9093, 9094)
    - ports:
        - protocol: TCP
          port: 9093  # TLS listener (mTLS auth)
        - protocol: TCP
          port: 9094  # External TLS listener (mTLS auth)
    
    # Restrict plaintext port 9092 to authorized pods only
    - from:
        # LDMS store pods
        - podSelector:
            matchLabels:
              app: nersc-ldms-store
        # Kafka internal communication
        - podSelector:
            matchLabels:
              strimzi.io/cluster: kafka
        # Strimzi operators
        - namespaceSelector:
            matchLabels:
              name: telemetry
          podSelector:
            matchLabels:
              name: strimzi-cluster-operator
      ports:
        - protocol: TCP
          port: 9092
```

### Security Benefits

1. **Network-Level Isolation**
   - Only specified pods can reach Kafka port 9092
   - Enforced at the Kubernetes network layer
   - Cannot be bypassed by application-level exploits

2. **Authorized Access Only**
   - **LDMS Store Pods** (`app: nersc-ldms-store`): Can write metrics to Kafka
   - **Kafka Internal Pods**: Required for cluster communication
   - **Strimzi Operators**: Required for topic/user management

3. **Defense in Depth**
   - **Port 9092**: Plaintext, restricted via NetworkPolicy
   - **Port 9093**: TLS with mTLS authentication (iDRAC telemetry, Kafka Bridge)
   - **Port 9094**: External TLS with mTLS authentication

4. **No ANONYMOUS Access**
   - Removed insecure `ANONYMOUS` superuser
   - Empty `superUsers: []` list
   - Access control via NetworkPolicy only

## Architecture

### Kafka Listeners

| Port | Protocol | Authentication | Use Case | Access Control |
|------|----------|---------------|----------|----------------|
| 9092 | Plaintext | None | LDMS store | **NetworkPolicy** |
| 9093 | TLS | mTLS | iDRAC telemetry, Kafka Bridge | mTLS certificates |
| 9094 | TLS (External) | mTLS | External clients | mTLS certificates + LoadBalancer |

### LDMS → Kafka Flow

```
┌──────────────────┐
│  LDMS Store Pod  │
│  (app: nersc-    │
│   ldms-store)    │
└────────┬─────────┘
         │ Port 9092
         │ (Plaintext)
         │ ✅ Allowed by NetworkPolicy
         ▼
┌──────────────────────────────────┐
│  Kafka Broker Pod                │
│  (strimzi.io/cluster: kafka)     │
│                                  │
│  Port 9092: Plaintext            │
│  ├─ NetworkPolicy restricts      │
│  │  ingress to LDMS pods only    │
│  │                               │
│  Port 9093: TLS (mTLS required)  │
│  Port 9094: External TLS         │
└──────────────────────────────────┘
```

## Configuration Files Modified

### 1. Kafka Configuration
**File**: `kafka.kafka.yaml.j2`

```yaml
authorization:
  type: simple
  superUsers: []  # Empty - access via NetworkPolicy
```

**Change**: Removed `ANONYMOUS` from superUsers list

### 2. NetworkPolicy Template
**File**: `kafka.networkpolicy.yaml.j2`

**Added**: New NetworkPolicy restricting port 9092 access

### 3. Ansible Variables
**File**: `vars/main.yml`

```yaml
kafka_templates:
  - src: 'telemetry/kafka/kafka.kafka.yaml.j2'
    dest: 'kafka.kafka.yaml'
  - src: 'telemetry/kafka/kafka.networkpolicy.yaml.j2'  # NEW
    dest: 'kafka.networkpolicy.yaml'
  - src: 'telemetry/kafka/kafka.kafkapump_user.yaml.j2'
    dest: 'kafka.kafkapump_user.yaml'
  # ...
```

**Change**: Added NetworkPolicy template to deployment list

### 4. Kustomization
**File**: `kustomization.yaml.j2`

```yaml
{% if kafka_support %}
  - kafka.kafka.yaml
  - kafka.networkpolicy.yaml  # NEW
  - kafka.kafkapump_user.yaml
  # ...
{% endif %}
```

**Change**: Added NetworkPolicy to Kubernetes resources

### 5. LDMS Configuration Script
**File**: `nersc_ldms_make_ldms_config.py` (lines 539-552)

```python
cfg.extend([
    "# Store in Kafka - port 9092 (plaintext, no TLS, no auth)",
    "# NOTE: store_avro_kafka plugin does not support TLS/authentication",
    "# Security: Access to port 9092 is restricted via NetworkPolicy",
    "#   - NetworkPolicy 'kafka-ldms-access' allows only LDMS store pods",
    "#   - Network-level isolation ensures only authorized pods can connect",
    "#   - TLS ports (9093, 9094) require mTLS for all other clients",
    "load name=store_avro_kafka",
    "config name=store_avro_kafka encoding=json topic=ldms",
    f"strgp_add name=kafka regex=.* plugin=store_avro_kafka "
    f"container=kafka-kafka-bootstrap.{self.namespace}.svc.cluster.local:9092 "
    "decomposition=/ldms_bin/decomp.json",
    "strgp_start name=kafka"
])
```

**Change**: Updated comments to reference NetworkPolicy security

## Deployment

### Files Generated

When `deploy_telemetry.yml` playbook runs:

1. **Kafka Configuration**: `/opt/omnia/k8s_client/telemetry/deployments/kafka.kafka.yaml`
   - Contains Kafka cluster with `superUsers: []`
   
2. **NetworkPolicy**: `/opt/omnia/k8s_client/telemetry/deployments/kafka.networkpolicy.yaml`
   - Contains NetworkPolicy restricting port 9092 access

3. **Kustomization**: `/opt/omnia/k8s_client/telemetry/deployments/kustomization.yaml`
   - References both files for deployment

### Deployment Order

1. Kafka cluster deploys with empty superUsers list
2. NetworkPolicy deploys and restricts port 9092 immediately
3. LDMS store pods deploy with `app: nersc-ldms-store` label
4. NetworkPolicy allows LDMS pods to connect to Kafka port 9092

## Verification

### Check NetworkPolicy Deployment

```bash
kubectl get networkpolicy -n telemetry kafka-ldms-access
```

**Expected Output**:
```
NAME                 POD-SELECTOR                 AGE
kafka-ldms-access    strimzi.io/cluster=kafka     5m
```

### View NetworkPolicy Details

```bash
kubectl describe networkpolicy -n telemetry kafka-ldms-access
```

**Expected Output**:
```
Name:         kafka-ldms-access
Namespace:    telemetry
PodSelector:  strimzi.io/cluster=kafka,strimzi.io/kind=Kafka
Allowing ingress traffic:
  To Port: 9093/TCP
  To Port: 9094/TCP
  To Port: 9092/TCP
    From:
      PodSelector: app=nersc-ldms-store
      PodSelector: strimzi.io/cluster=kafka
      NamespaceSelector: name=telemetry
      PodSelector: name=strimzi-cluster-operator
```

### Verify LDMS Store Connectivity

```bash
# Get LDMS store pod name
LDMS_POD=$(kubectl get pods -n telemetry -l app=nersc-ldms-store -o jsonpath='{.items[0].metadata.name}')

# Check LDMS configuration
kubectl exec -n telemetry $LDMS_POD -c store -- cat /ldms_conf/ldmsd.nersc-ldms-store-*.conf
```

**Expected Output** (should contain):
```
# Store in Kafka - port 9092 (plaintext, no TLS, no auth)
# NOTE: store_avro_kafka plugin does not support TLS/authentication
# Security: Access to port 9092 is restricted via NetworkPolicy
load name=store_avro_kafka
config name=store_avro_kafka encoding=json topic=ldms
strgp_add name=kafka regex=.* plugin=store_avro_kafka container=kafka-kafka-bootstrap.telemetry.svc.cluster.local:9092 decomposition=/ldms_bin/decomp.json
strgp_start name=kafka
```

### Test LDMS → Kafka Connection

```bash
# Check LDMS store logs for successful Kafka connection
kubectl logs -n telemetry $LDMS_POD -c store | grep -i kafka
```

**Expected Output** (no connection errors):
```
[INFO] Connected to Kafka broker: kafka-kafka-bootstrap.telemetry.svc.cluster.local:9092
[INFO] Kafka storage plugin active: store_avro_kafka
```

### Verify Kafka Topics Receiving Data

```bash
# Check if ldms topic has messages
kubectl exec -n telemetry kafka-broker-0 -- bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic ldms \
  --from-beginning \
  --max-messages 5
```

**Expected Output**: JSON-formatted LDMS metrics

### Test NetworkPolicy Enforcement

Try connecting from an unauthorized pod (should fail):

```bash
# Create a test pod without the required label
kubectl run -n telemetry test-pod --image=curlimages/curl:latest --rm -it -- sh

# Inside the pod, try to connect to Kafka (should timeout)
curl -v telnet://kafka-kafka-bootstrap:9092
# Expected: Connection timeout (NetworkPolicy blocks access)
```

## Troubleshooting

### LDMS Cannot Connect to Kafka

**Symptom**: LDMS store pods show Kafka connection errors

**Check**:
1. Verify LDMS store pod has correct label:
   ```bash
   kubectl get pods -n telemetry -l app=nersc-ldms-store --show-labels
   ```
   Expected label: `app=nersc-ldms-store`

2. Check NetworkPolicy exists:
   ```bash
   kubectl get networkpolicy -n telemetry kafka-ldms-access
   ```

3. Verify NetworkPolicy allows LDMS pods:
   ```bash
   kubectl describe networkpolicy -n telemetry kafka-ldms-access | grep -A5 "PodSelector: app=nersc-ldms-store"
   ```

**Solution**: Ensure NetworkPolicy is deployed and LDMS pods have correct labels

### NetworkPolicy Not Enforcing

**Symptom**: Unauthorized pods can still connect to Kafka port 9092

**Check**:
1. Verify NetworkPolicy provider is enabled:
   ```bash
   kubectl get pods -n kube-system | grep -E 'calico|cilium|weave'
   ```

2. Check Kubernetes cluster supports NetworkPolicy:
   ```bash
   kubectl api-resources | grep networkpolicies
   ```

**Solution**: 
- Ensure CNI plugin (Calico, Cilium, Weave) supports NetworkPolicy
- Verify NetworkPolicy is enabled in cluster configuration

### Kafka Operators Cannot Manage Topics

**Symptom**: Kafka topics/users not being created

**Check**:
1. Verify Strimzi operator can access Kafka:
   ```bash
   kubectl logs -n telemetry deployment/strimzi-cluster-operator | grep -i "kafka"
   ```

2. Check NetworkPolicy allows operator:
   ```bash
   kubectl describe networkpolicy -n telemetry kafka-ldms-access | grep -A5 "strimzi-cluster-operator"
   ```

**Solution**: NetworkPolicy should allow Strimzi operators (already configured)

## Security Best Practices

### ✅ Implemented

1. **Network Segmentation**: NetworkPolicy restricts port 9092 to specific pods
2. **Least Privilege**: Only LDMS store pods can access plaintext listener
3. **Defense in Depth**: Multiple layers (NetworkPolicy + TLS on other ports)
4. **No Anonymous Access**: Removed `ANONYMOUS` from superUsers

### 📋 Additional Recommendations

1. **Monitoring**: Set up alerts for NetworkPolicy violations
   ```bash
   # Monitor denied connections (CNI-specific)
   kubectl logs -n kube-system <calico-node-pod> | grep "denied"
   ```

2. **Regular Audits**: Periodically review NetworkPolicy rules
   ```bash
   kubectl get networkpolicies -A
   ```

3. **Pod Security**: Ensure LDMS pods run with minimal privileges
   ```yaml
   securityContext:
     runAsNonRoot: true
     readOnlyRootFilesystem: true
   ```

4. **Network Encryption**: Consider using service mesh (Istio, Linkerd) for mTLS between all pods

## Migration from ANONYMOUS

### Before (Insecure)

```yaml
authorization:
  type: simple
  superUsers:
    - ANONYMOUS  # ❌ Insecure
```

### After (Secure)

```yaml
authorization:
  type: simple
  superUsers: []  # ✅ Secure - NetworkPolicy controls access
```

### Upgrade Path

1. **Deploy NetworkPolicy First**: Ensures no service disruption
2. **Remove ANONYMOUS**: After NetworkPolicy is verified working
3. **Monitor**: Check LDMS connectivity remains functional

## References

- **Kubernetes NetworkPolicy**: https://kubernetes.io/docs/concepts/services-networking/network-policies/
- **Strimzi Kafka**: https://strimzi.io/docs/operators/latest/overview.html
- **LDMS Documentation**: OVIS LDMS documentation
- **store_avro_kafka Plugin**: LDMS Kafka store plugin documentation

## Summary

This implementation replaces insecure `ANONYMOUS` superuser access with network-level security using Kubernetes NetworkPolicy. The solution:

- ✅ Restricts Kafka port 9092 to only LDMS store pods
- ✅ Maintains LDMS functionality (plugin doesn't support TLS)
- ✅ Removes security vulnerabilities (no anonymous access)
- ✅ Provides defense in depth (NetworkPolicy + TLS on other ports)
- ✅ Follows Kubernetes security best practices

**Security Status**: 🔒 **SECURE** - Network-level access control enforced
