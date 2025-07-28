===================
Set up Kubernetes
===================

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

Omnia installs the following package on top of the Kubernetes stack:

**nfs-client-provisioner**

    * NFS subdir external provisioner is an automatic provisioner that use your existing and already configured NFS server to support dynamic provisioning of Kubernetes Persistent Volumes via Persistent Volume Claims.
    * The NFS server utilised here is the one mentioned in ``storage_config.yml``.
    * Server IP is ``<nfs_client_params.server_ip>`` and path is ``<nfs_client_params>.<server_share_path>`` of the entry where ``k8s_share`` is set to ``true``.

    Click `here <https://github.com/kubernetes-sigs/nfs-subdir-external-provisioner>`_ for more information.

[Optional] Dynamic Kubernetes installation
=============================================

To set up any other Kubernetes version apart from what is present as default in the ``/opt/omnia/input/project_default/software_config.json`` file, `click here <dynamic_k8s.html>`_.

[Optional] Service Kubernetes cluster
==========================================

To set up Kubernetes on the service cluster, `click here <service_k8s.html>`_.