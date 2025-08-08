==========================================
Set up Kubernetes on the service cluster
==========================================

With Omnia, you can deploy a service Kubernetes cluster on the designated service nodes to efficiently distribute workload and manage resources for telemetry data collection. 
This setup reduces the processing load on the OIM node and enhances overall scalability. Each ``service_kube_node`` is responsible for collecting telemetry data from its assigned subset of compute nodes.
Federated way of telemetry data collection improves efficiency for large-scale clusters.

Prerequisites
==============

* To deploy Kubernetes on service cluster, ensure that ``service_k8s`` is added under ``softwares`` in the ``/opt/omnia/input/project_default/software_config.json``. Refer the sample config file below: ::

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

1. Run ``local_repo.yml`` playbook to download the artifacts required to set up Kubernetes on the service cluster nodes.

2. Fill in the service cluster details in the ``roles_config.yml``.

.. csv-table:: roles_config.yml
   :file: ../../../../../Tables/service_k8s_roles.csv
   :header-rows: 1
   :keepspace:

3. Run ``discovery_provision.yml`` playbook to discover and provision OS on the service cluster nodes.

4. Fill up the ``omnia_config.yml`` and ``high_availability_config.yml`` (for `service cluster HA <../../HighAvailability/service_cluster_ha.html>`_) as described in the tables below:

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

Additional installations
=========================

After deploying Kubernetes, you can install the following additional packages on top of the Kubernetes stack on the service cluster:

1. **nfs-client-provisioner**

    * NFS subdir external provisioner is an automatic provisioner that use your existing and already configured external NFS server to support dynamic provisioning of Kubernetes Persistent Volumes via Persistent Volume Claims.
    * The NFS server utilised here is the one mentioned during ``omnia_core`` container deployment using ``omnia_startup.sh`` script.
    * Use the same NFS server IP provided during ``omnia_startup.sh`` execution. 
    * Path is mentioned in ``/omnia/k8s_pvc_data`` under ``{{ nfs_server_share_path }}``.

    Click `here <https://github.com/kubernetes-sigs/nfs-subdir-external-provisioner>`_ for more information.

2. **whereabouts-cni-plugin**

    Whereabouts is an IP address management (IPAM) CNI plugin that assigns dynamic IP addresses cluster-wide in Kubernetes, ensuring no IP address collisions across nodes.
    It uses a range of IPs and tracks assignments with backends like etcd or Kubernetes Custom Resources.
    Omnia installs the whereabouts plugin as part of ``omnia.yml`` or ``scheduler.yml`` execution. The details of the plugin is present in the ``omnia/input/config/<cluster os>/<os version>/k8s.json`` file.

    Click `here <https://github.com/k8snetworkplumbingwg/whereabouts>`_ for more information.

3. **CSI-driver-for-PowerScale**

    The CSI Driver for Dell PowerScale (formerly known as Isilon) is a Container Storage Interface (CSI) plugin that enables Kubernetes to provision and manage persistent storage using PowerScale.
    It enables Kubernetes clusters to dynamically provision, bind, expand, snapshot, and manage volumes on a PowerScale node.
    Omnia installs the multus plugin as part of ``omnia.yml`` or ``scheduler.yml`` execution.

    Click `here <../../../../../AdvancedConfigurations/PowerScale_CSI.html>`_ for more information.

Next step
===========

To know how to deploy the iDRAC telemetry containers on the service cluster, `click here <../../../../../Telemetry/service_cluster_telemetry.html>`_.