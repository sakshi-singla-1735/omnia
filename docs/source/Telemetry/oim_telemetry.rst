Deploy iDRAC telemetry service on the OIM
===========================================

The telemetry feature in Omnia allows you to set up a telemetry service that collects telemetry data from the eligible iDRACs in the cluster. It also facilitates the installation of `Grafana <https://grafana.com/>`_ and `Loki <https://grafana.com/oss/loki/>`_ as Podman containers.

Prerequisites
---------------

* Redfish must be enabled in iDRAC.

* iDRAC firware must be updated to the latest version. 

* Datacenter license must be installed on the nodes

* The BMC IP address or iDRAC IP address must be reachable from OIM.

* Ensure that the ``discovery_provision.yml`` playbook has been executed successfully. Post execution, an inventory file called ``bmc_group_data.csv`` file is created under the ``/opt/omnia/telemetry/`` directory. This file acts as the default inventory for the ``telemetry.yml`` playbook. 

* To enable telemetry support on the OIM, ensure that ``prepare_oim.yml`` playbook has been executed successfully with ``idrac_telemetry_support`` set to ``true`` and ``idrac_telemetry_collection_type`` set to ``prometheus`` in the ``telemetry_config.yml`` file. This playbook deploys the containers necessary for the telemetry service. For more information, `click here <../OmniaInstallGuide/RHEL_new/prepare_oim.html#telemetry-config-yml>`_.

* To enable federated telemetry support on the service cluster, set ``federated_idrac_telemetry_collection`` to ``true`` in the ``telemetry_config.yml`` file. For more information, `click here <service_cluster_telemetry.html>`_.

    * In a federated setup, telemetry data from the compute nodes is collected by their corresponding parent service cluster node.    
    
    * Additionally, the ``idrac_telemetry_receiver``, ``activemq``, ``mysqldb``, and ``prometheus_pump`` containers are deployed inside the iDRAC telemetry pods to facilitate telemetry data collection. 

.. csv-table:: telemetry_config.yml
   :file: ../Tables/telemetry_config.csv
   :header-rows: 1
   :keepspace:

.. note:: Credentials can be provided using the ``get_config_credential.yml`` utility or can be provided during the execution of the ``prepare_oim.yml`` playbook.          

.. note:: To update the ``bmc_username`` and ``bmc_password`` fields in the ``omnia_config_credentials.yml`` input file for the connected iDRACs, use the command provided below. Do not alter any other fields in the file, as this may lead to unexpected failures. For more information, `click here <../OmniaInstallGuide/RHEL_new/credentials_utility.html>`_.
    ::
        ansible-vault edit omnia_config_credentials.yml --vault-password-file .omnia_config_credentials_key

Playbook execution
-------------------

Once the cluster nodes have been provisioned using the ``discovery_provision.yml`` playbook, you can initiate telemetry service on the cluster using the ``telemetry.yml`` playbook. To invoke the playbooks, use the below command:

::

    ansible-playbook telemetry.yml

.. note:: If you want to add an external node for ``idrac_telemetry`` acquisition, you can do so by editing the ``bmc_group_data.csv`` file manually and then re-running the ``telemetry.yml`` playbook. Sample: 
    ::

        BMC_IP,GROUP_NAME,PARENT
        10.5.0.101,grp0,ABCD123
        10.5.1.102,grp1,EFGH456