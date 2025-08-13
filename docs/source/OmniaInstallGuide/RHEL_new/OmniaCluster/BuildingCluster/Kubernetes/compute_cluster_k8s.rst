==========================================
Set up Kubernetes on the compute cluster
==========================================

Prerequisites
===============

* Ensure that ``k8s`` entry is present in the ``softwares`` list in ``software_config.json``, as mentioned below:
    
    ::

        "softwares": [
                        {"name": "k8s", "version":"1.31.4"},
                     ]

* Ensure to run ``local_repo.yml`` with the ``k8s`` entry present in ``software_config.json``, to download all required Kubernetes packages and images.

* Once all the required parameters in `omnia_config.yml <../schedulerinputparams.html#id12>`_ are filled in, ``omnia.yml`` can be used to set up Kubernetes.

* Ensure that ``k8s_share`` is set to ``true`` in `storage_config.yml <../schedulerinputparams.html#storage-config-yml>`_, for one of the entries in ``nfs_client_params``.

Inventory details
==================

* All the applicable inventory groups are ``kube_control_plane``, ``kube_node``, and ``etcd``.
* The inventory file must contain:

        1. Exactly 1 ``kube_control_plane``.
        2. At least 1 ``kube_node`` [Optional].
        3. Odd number of ``etcd`` nodes.

.. note:: Ensure that the inventory includes an ``[etcd]`` node. etcd is a consistent and highly-available key value store used as Kubernetes' backing store for all cluster data. For more information, `click here. <https://kubernetes.io/docs/tasks/administer-cluster/configure-upgrade-etcd/>`_

Sample inventory
=================

    ::

        [kube_control_plane]

        10.5.1.101

        [kube_node]

        10.5.1.102

        [etcd]

        10.5.1.101


Playbook execution
===================

Run either of the following playbooks, where ``-i <inventory>`` denotes the file path of the user specified inventory:

    1. ::

            cd omnia
            ansible-playbook omnia.yml -i <inventory>

    2. ::

            cd scheduler
            ansible-playbook scheduler.yml -i <inventory>

Additional installations
=========================

.. note:: 
    
    * Additional packages for Kubernetes will be deployed only if ``nfs`` entry is present in the ``/opt/omnia/input/project_default/software_config.json``.
    * If the ``nfs_server_ip`` in ``/opt/omnia/input/project_default/storage_config.yml`` is left blank, you must provide a valid external NFS server IP for the ``nfs_server_ip`` parameter.

After deploying Kubernetes, you can install the following additional packages on top of the Kubernetes stack on the compute cluster:

1.	**nfs-client-provisioner**

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

    Click `here <../../../../AdvancedConfigurations/PowerScale_CSI.html>`_ for more information.