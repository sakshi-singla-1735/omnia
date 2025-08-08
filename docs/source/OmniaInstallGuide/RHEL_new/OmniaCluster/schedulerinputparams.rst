Input parameters for the cluster
===================================

The ``omnia.yml`` playbook is dependent on the inputs provided to the following input files:

* ``/opt/omnia/input/project_default/omnia_config.yml``
* ``/opt/omnia/input/project_default/security_config.yml``
* ``/opt/omnia/input/project_default/storage_config.yml``

.. caution:: Do not remove, edit, or comment any lines in the above mentioned input files.

``/opt/omnia/input/project_default/omnia_config.yml``
-------------------------------------------------------

.. dropdown:: Parameters for kubernetes setup on service Kubernetes cluster

   .. csv-table::
      :file: ../../../Tables/omnia_config_service_cluster.csv
      :header-rows: 1
      :keepspace:

.. dropdown:: Parameters for kubernetes setup on compute Kubernetes cluster

   .. csv-table::
      :file: ../../../Tables/omnia_config_compute_cluster.csv
      :header-rows: 1
      :keepspace:

::

   service_k8s_cluster:
     - cluster_name: service_cluster
       deployment: true
       k8s_cni: "calico"
       pod_external_ip_range: ""
       k8s_service_addresses: "10.233.0.0/18"
       k8s_pod_network_cidr: "10.233.64.0/18"
       opology_manager_policy: "none"
       topology_manager_scope: "container"
       k8s_offline_install: true
 
   compute_k8s_cluster:
     - cluster_name: compute_cluster
       deployment: true
       k8s_cni: "calico"
       pod_external_ip_range: ""
       k8s_service_addresses: "10.233.0.0/18"
       k8s_pod_network_cidr: "10.233.64.0/18"
       topology_manager_policy: "none"
       topology_manager_scope: "container"
       k8s_offline_install: true

.. csv-table:: Parameters for slurm setup
   :file: ../../../Tables/scheduler_slurm.csv
   :header-rows: 1
   :keepspace:

``/opt/omnia/input/project_default/security_config.yml``
----------------------------------------------------------

.. csv-table:: Parameters for Authentication
   :file: ../../../Tables/security_config.csv
   :header-rows: 1
   :keepspace:

.. csv-table:: Parameters for OpenLDAP configuration
   :file: ../../../Tables/security_config_ldap.csv
   :header-rows: 1
   :keepspace:

.. csv-table:: Parameters for FreeIPA configuration
   :file: ../../../Tables/security_config_freeipa.csv
   :header-rows: 1
   :keepspace:


``/opt/omnia/input/project_default/storage_config.yml``
----------------------------------------------------------

.. csv-table:: Parameters for Storage
   :file: ../../../Tables/storage_config.csv
   :header-rows: 1
   :keepspace:


Click here for more information on `OpenLDAP, FreeIPA <BuildingCluster/Authentication.html>`_, `BeeGFS <BuildingCluster/Storage/BeeGFS.html>`_, or `NFS <BuildingCluster/Storage/NFS.html>`_.