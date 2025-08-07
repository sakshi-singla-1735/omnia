=======================================================
Deploy iDRAC telemetry service on the service cluster
=======================================================

To deploy telemetry service on the service cluster and collect iDRAC telemetry data using Prometheus, refer to the following guide.

Prerequisites
===============

1. Ensure that ``discovery_provision.yml`` playbook has been executed successfully and the ``bmc_group_data.csv`` file has been generated.
2. Ensure that the ``service_k8s_cluster`` playbook has been executed successfully and Kubernetes on the service cluster is up and running. For a step-by-step guide, `click here <../OmniaInstallGuide/RHEL_new/OmniaCluster/BuildingCluster/Kubernetes/service_cluster_k8s.html>`_.
3. For federated telemetry collection on service cluster, all BMC (iDRAC) IPs must be reachable from the service cluster nodes.

Steps
======

1. In the ``roles_config.yml`` file, specify the service tag of the ``service_kube_node`` as the parent for the compute groups from which iDRAC telemetry data should be collected.
2. Fill up the ``omnia_config.yml`` and ``telemetry_config.yml``:

    .. csv-table:: omnia_config.yml
        :file: ../Tables/scheduler_k8s_rhel.csv
        :header-rows: 1
        :keepspace: 

    .. csv-table:: telemetry_config.yml
        :file: ../Tables/telemetry_config.csv
        :header-rows: 1
        :keepspace:
3. Execute the ``telemetry.yml`` playbook. ::

    cd telemetry
    ansible-playbook telemetry.yml -i /opt/omnia_inventory/service_cluster_cluster_layout

Result
=======

The iDRAC telemetry pods along with the ``mysqldb``, ``activemq``, ``telemetry_receiver``, and ``prometheus_pump`` containers will get deployed on the ``service_kube_node``.
The number of iDRAC telemetry pods deployed will be number of ``service_kube_nodes`` mentioned as parents in ``roles_config.yml`` plus an extra telemetry pod to collect the metric data of OIM, management layer nodes, and the service cluster.

iDRAC telemetry logs collected by the Prometheus pump
=======================================================

After ``telemetry.yml`` has been executed for the service cluster, the Prometheus pump collects the iDRAC telemetry logs for each pod. To view these logs, do the following:

    1. First, check if all the telemetry pods are running or not using the below command: ::

        kubectl get pods -n telemetry

    2. For each of the ``idrac-telemetry pod``, check the ``idrac_telemetry`` logs collected by the prometheus pump using the below command: ::

        kubectl logs <idrac-telemetry-pod> -n telemetry -c prometheus-pump

.. note:: Metrics visualization using Grafana is not supported for iDRAC telemetry metrics on service cluster.