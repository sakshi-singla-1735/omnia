=======================================================
Deploy iDRAC telemetry service on the service cluster
=======================================================

To deploy telemetry service on the service cluster and collect iDRAC telemetry data using Prometheus, refer to the following guide.

Prerequisites
===============

* Redfish must be enabled in iDRAC.
* All service cluster nodes should have access to the Internet.
* iDRAC firware must be updated to the latest version. 
* Datacenter license must be installed on the nodes.
* Ensure that the correct node service tags are being displayed in the iDRAC interface. Otherwise, telemetry data won't be collected by the ``idrac_telemetry_receiver`` container.
* Ensure that ``discovery_provision.yml`` playbook has been executed successfully and the ``bmc_group_data.csv`` file has been generated.
* Ensure that the ``service_k8s_cluster`` playbook has been executed successfully and Kubernetes on the service cluster is up and running. For a step-by-step guide, `click here <../OmniaInstallGuide/RHEL_new/OmniaCluster/BuildingCluster/Kubernetes/service_cluster_k8s.html>`_.
* For federated telemetry collection on service cluster, all BMC (iDRAC) IPs must be reachable from the service cluster nodes.
* Before running the ``telemetry.yml`` playbook for the service cluster, ensure that all the nodes mentioned in the ``<service_cluster_name>_cluster_layout`` inventory are booted up and reachable.

Steps
======

1. In the ``roles_config.yml`` file, specify the service tag of the ``service_kube_node`` as the parent for the compute groups from which iDRAC telemetry data should be collected.
2. Fill up the ``omnia_config.yml`` and ``telemetry_config.yml``:

    .. csv-table:: omnia_config.yml
        :file: ../Tables/omnia_config_service_cluster.csv
        :header-rows: 1
        :keepspace: 

    .. csv-table:: telemetry_config.yml
        :file: ../Tables/telemetry_config.csv
        :header-rows: 1
        :keepspace:
3. Execute the ``telemetry.yml`` playbook. ::

    cd telemetry
    ansible-playbook telemetry.yml -i /opt/omnia_inventory/<service_cluster_name>_cluster_layout

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

Accessing the ``mysqldb`` database
====================================

After ``telemetry.yml`` has been executed for the service cluster, you can check the mysqldb database inside the ``mysqldb`` container. To view these logs, do the following:

    1. Use the following command to get the names of all the telemetry pods: ::
        
        kubectl get pods -n telemetry -l app=idrac-telemetry

    .. note:: The ``idrac-telemetry-0`` pod will always be responsible for collecting the telemetry data of the management nodes (``oim_ha``, ``service_kube_control_plane``, ``login_node``, ``compiler_node``, etc.).

    2. Execute the following command: ::

        kubectl exec -it -n telemetry <iDRAC_telemetry_pod_name> -c mysqldb -- mysql -u <MYSQL_USER> -p

    3. When prompted, enter the mysql password to log in.