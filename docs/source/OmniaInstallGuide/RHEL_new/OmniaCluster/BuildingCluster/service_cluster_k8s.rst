==========================================
Deploy service Kubernetes cluster
==========================================

Omnia deploys a service Kubernetes cluster on the designated service nodes to efficiently distribute workload and manage resources for telemetry data collection. 
This setup reduces the processing load on the OIM node and enhances overall scalability. Each service node is mapped to a specific subset of compute nodes. 
As a result, the service Kubernetes cluster enables a federated approach to telemetry collection where each ``service_kube_node`` is responsible for collecting telemetry data from its assigned subset of compute nodes.

In order to support telemetry collection, first you need to deploy Kubernetes on the service cluster. To do so, use the ``service_k8s_cluster.yml`` playbook.

Prerequisite
==============

To deploy Kubernetes on service cluster, ensure that ``service_k8s`` is added under ``softwares`` in the ``input/software_config.json``. Refer the sample config file below: ::

    {
        "cluster_os_type": "rhel",
        "cluster_os_version": "9.6",
        "iso_file_path": "",
        "repo_config": "always",
        "softwares": [
            {"name": "amdgpu", "version": "6.3.1"},
            {"name": "cuda", "version": "12.8.0"},
            {"name": "ofed", "version": "24.10-1.1.4.0"},
            {"name": "openldap"},
            {"name": "nfs"},
            {"name": "service_k8s","version": "1.31.4"},
            {"name": "slurm"}
        ],
        "amdgpu": [
            {"name": "rocm", "version": "6.3.1" }
        ],
        "slurm": [
            {"name": "slurm_control_node"},
            {"name": "slurm_node"},
            {"name": "login_node"}
        ]
    }

Steps
=======

1. Run ``prepare_oim.yml`` playbook to bring up the required containers on the service cluster nodes.

2. Run ``local_repo.yml`` playbook to download the artifacts required to set up Kubernetes on the service cluster nodes.

3. Fill in the service cluster details in the ``roles_config.yml``.

.. csv-table:: roles_config.yml
   :file: ../../../../Tables/service_k8s_roles.csv
   :header-rows: 1
   :keepspace:

4. Run ``discovery_provision.yml`` playbook to discover and provision OS on the service cluster nodes.

5. Fill up the ``omnia_config.yml`` and ``high_availability_config.yml`` (for `service cluster HA <../../HighAvailability/service_cluster_ha.html>`_) as described in the tables below:

.. csv-table:: omnia_config.yml
   :file: ../../../../Tables/scheduler_k8s_rhel.csv
   :header-rows: 1
   :keepspace:

.. csv-table:: high_availability_config.yml
   :file: ../../../../Tables/service_k8s_high_availability.csv
   :header-rows: 1
   :keepspace:

Playbook execution
====================

Once all the required input files are filled up, use the below commands to set up Kubernetes on the service cluster: ::

    cd scheduler
    ansible-playbook service_k8s_cluster.yml - i <service_cluster_layout_file_path>

In the command above, ``<service_cluster_layout_file_path>`` refers to the inventory generated based on the ``cluster_name`` in ``/opt/omnia/omnia_inventory``. For more details, `click here <../../ViewInventory.html>`_.

Next step
===========

To know how to deploy the telemetry containers on the service cluster, `click here <../../../../https://omniahpc.readthedocs.io/en/staging/Telemetry/service_cluster_telemetry.html>`_.