================================
Dynamic Kubernetes installation
================================

Apart from the default Kubernetes version present in the ``/opt/omnia/input/project_default/software_config.json`` (1.31.4) Omnia also lets you choose your own Kubernetes version.
Based on the version that you choose, Omnia will download and configure all Kubernetes related packages required for the cluster.

Compatibility Matrix
==========================

Check the table below for the supported Kubespray and Kubernetes version:

    +-------------------+------------------------------+
    | Kubespray Version | Validated Kubernetes version |
    +===================+==============================+
    | 2.28.0            | 1.31.4, 1.32.5               |
    +-------------------+------------------------------+

Prerequisites
===============

* Build the Kubespray image based on your choice of Kubespray version. Check the table above for the supported versions. ::

    ./build_images.sh kubespray_version=v2.28.0

* Ensure that a compatilable version of ``omnia_kubespray`` image is present based on the version list mentioned above. To know about all the supported versions of Kubernetes for a specific release of Kubespray, check out `Kubespray on github <https://github.com/kubernetes-sigs/kubespray>`_. 
* Ensure that ``discovery_provision.yml`` has been executed and nodes are provisioned with OS.

Input file
============

Update the ``k8s`` version to a supported version of your choice, in the ``/opt/omnia/input/project_default/software_config.json``. For example, update the version to ``1.32.5`` as shown below: ::

    "softwares": [

            {"name":"k8s", "version": "1.32.5"},
    ]

Playbook executions
=====================

1. After filling up the required input in ``/opt/omnia/input/project_default/software_config.json``, run the ``prepare_oim.yml`` playbook. This playbook sets up the Kubespray container required for the updated Kubernetes version. ::

    cd /omnia/prepare_oim
    ansible-playbook prepare_oim.yml

2. Execute ``local_repo.yml`` to download the artifacts required to set up the desired Kubernetes version: ::

    cd /omnia/local_repo
    ansible-playbook local_repo.yml

3. Finally, execute ``scheduler.yml`` or ``omnia.yml`` to deploy the Kubernetes cluster: 

    ::

        cd /omnia/scheduler
        ansible-playbook scheduler.yml -i <inventory_file_path>

    ::

        cd /omnia
        ansible-playbook omnia.yml -i <inventory_file_path>

