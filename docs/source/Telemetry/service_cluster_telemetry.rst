=======================================================
Deploy iDRAC telemetry service on the service cluster
=======================================================

To deploy telemetry service on the service cluster and collect iDRAC telemetry data using Prometheus, refer to the following guide.

Prerequisites
===============

1. Ensure that ``discovery_provision.yml`` playbook has been executed successfully and the ``bmc_group_data.csv`` file with the has been generated.
2. Ensure that the ``service_k8s_cluster`` playbook has been executed successfully and Kubernetes on the service cluster is up and running. For a step-by-step guide, `click here <../OmniaInstallGuide/RHEL_new/OmniaCluster/BuildingCluster/service_k8s.html>`_.

Steps
======

1. In the ``roles_config.yml`` file, specify the service tag of the ``service_kube_node`` as the parent for the compute groups from which iDRAC telemetry data should be collected.
2. Execute the ``telemetry.yml`` playbook. ::

    cd telemetry
    ansible-playbook telemetry.yml -i /opt/omnia_inventory/service_cluster_cluster_layout

Result
=======

The iDRAC telemetry pods along with the ``mysqldb``, ``activemq``, ``telemetry_receiver``, and ``prometheus_pump`` containers will get deployed on the ``service_kube_node``.
The number of iDRAC telemetry pods deployed will be number of ``service_kube_nodes`` mentioned as parents in ``roles_config.yml`` plus an extra telemetry pod to collect the metric data of OIM and the entire service cluster.

iDRAC telemetry logs collected by the Prometheus pump
=======================================================

After ``telemetry.yml`` has been executed for the service cluster, the Prometheus pump collects the iDRAC telemetry logs for each pod. To know how view these logs, `click here <../Logging/ControlPlaneLogs.html>`.

.. note:: Metrics visualization using Grafana is not supported for iDRAC telemetry metrics on service cluster.