==================================================
Deploy telemetry service on the service cluster
==================================================

To deploy telemetry service on the service cluster and collect iDRAC and other telemetry data using Prometheus, refer to the following guide.

Prerequisites
===============

1. Ensure that ``discovery_provision.yml`` playbook has been executed successfully and the ``bmc_group_data.csv`` file with the has been generated.
2. Ensure that the ``service_k8s_cluster`` playbook has been executed successfully and Kubernetes on the service cluster is up and running. For a step-by-step guide, `click here <../OmniaInstallGuide/RHEL_new/OmniaCluster/BuildingCluster/service_k8s.html>`_.

Steps
======

1. In the ``roles_config.yml`` file, specify the service tag of the ``service_kube_node`` as the parent for the compute groups from which iDRAC telemetry data should be collected.
2. Execute the ``telemetry.yml`` playbook. ::

    cd telemetry
    ansible-playbook telemetry.yml -i <inventory_filepath>