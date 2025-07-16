Provisioning the cluster
============================

The ``discovery_provision.yml`` playbook discovers the probable bare-metal cluster nodes and provisions the minimal version of RHEL OS onto those nodes. This playbook is dependent on inputs from the following input files:

* ``/opt/omnia/input/provision_config.yml``
* ``/opt/omnia/input/provision_config_credentials.yml``
* ``/opt/omnia/input/network_spec.yml``

.. note:: The first PXE device on target nodes should be the designated active NIC for PXE booting.

    .. image:: ../../../images/BMC_PXE_Settings.png
        :width: 600px

Configurations made by the ``discovery_provision.yml`` playbook
-----------------------------------------------------------------

* Discovers all target servers.
* PostgreSQL database is set up with all relevant cluster information such as MAC IDs, hostname, admin IP, BMC IPs etc.
* Configures the OIM with NTP services for cluster node synchronization.
* The minimal version of the RHEL operating system is provisioned on the primary disk partition on the nodes. If a BOSS Controller card is available on the target node, the operating system is provisioned on the BOSS card.

[Optional] Additional configurations handled by the provision tool
-------------------------------------------------------------------------

**Disk partitioning**

* Omnia now allows for customization of disk partitions applied to remote servers. The disk partition ``desired_capacity`` has to be provided in MB. Valid ``mount_point`` values accepted for disk partition are  ``/var``, ``/tmp``, ``/usr``, ``swap``. The default partition sizes provided for RHEL are:

  * ``/boot``: 1024MB,
  * ``/boot/efi``: 256MB
  * ``/`` partition: Remaining space.

* Values are accepted in the form of JSON list such as: ::

    disk_partition:
        - { mount_point: "/var", desired_capacity: "102400" }
        - { mount_point: "swap", desired_capacity: "10240" }

**Installation of additional software packages**

Apart from the packages listed in the ``/opt/omnia/input/project_default/software_config.json`` file, additional software can also be installed on the cluster nodes during cluster provisioning. To do so, follow the below steps:

    1. First, fill up the ``additional_software.json`` and ``software_config.json`` input files.
    2. Then, execute the ``local_repo.yml`` playbook in order to download the required packages.
    3. Finally, execute the ``discovery_provision.yml`` playbook in order to provision the cluster nodes along with the new additional software packages.

For more information on how to fill up the input files, `click here <../../../Utils/software_update.html>`_.

**Configure additional NICs and specify Kernel Parameters on the nodes during cluster provisioning**

To do this, you need to add the necessary inputs to the ``/opt/omnia/input/project_default/network_spec.yml`` and ``/opt/omnia/input/project_default/server_spec.yml`` and then run the ``discovery_provision.yml`` playbook with your created `inventory file <../../samplefiles.html#inventory-file-for-additional-nic-and-kernel-parameter-configuration>`_. 
For more information on what inputs are required, `click here <../../AdvancedConfigurations/AdditionalNIC_rhel.html>`_.

.. caution::

    * If you intend to configure additional NICs during provisioning, ensure that you are aware of the network and NIC details of the cluster.
    * Configuring additional NICs and specifying Kernel Parameters is only possible during provisioning of new nodes (first provisioning). Nodes which have already been provisioned and are in booted state can't be modified with a re-run of ``discovery_provision.yml`` playbook.
    * For a node in the "booted" state, configuring additional NICs or kernel parameter changes is not possible with a re-run of the ``discovery_provision.yml`` playbook. Instead, use the ``server_spec_update.yml`` playbook to make any changes to the "booted" node. For more information, `click here <../../AdvancedConfigurations/AdditionalNIC_rhel.html>`_.

Playbook execution
----------------------

To deploy the Omnia provision tool, execute the following commands: ::

    ssh omnia_core
    cd /omnia
    ansible-playbook discovery_provision.yml

.. note::

    * If the ``/opt/omnia/input/project_default/software_config.json`` has AMD ROCm and NVIDIA CUDA drivers mentioned, the AMD and NVIDIA accelerator drivers are installed on the nodes post provisioning.

    * After executing ``discovery_provision.yml`` playbook, you can check the log files available at ``/opt/omnia/log`` for more information.

    * Ansible playbooks by default run concurrently on 5 nodes. To change this, update the ``forks`` value in ``ansible.cfg`` present in the respective playbook directory.

    * While the ``admin_nic`` on cluster nodes is configured by Omnia to be static, the public NIC IP address should be configured by user.

    * If the target nodes were discovered using switch-based or mapping mechanisms, manually PXE boot the target servers after the ``discovery_provision.yml`` playbook is executed and the target node lists as **booted** in the `nodeinfo table <ViewingDB.html>`_.

    * All ports required for xCAT to run will be opened (For a complete list, check out the `Security Configuration Document <../../../SecurityConfigGuide/ProductSubsystemSecurity.html#firewall-settings>`_).

    * After running ``discovery_provision.yml``, the file ``/opt/omnia/input/project_default/omnia_config_credentials.yml`` will be encrypted. To edit the file, use the command: ``ansible-vault edit omnia_config_credentials.yml --vault-password-file .omnia_config_credentials_key``

    * Post execution of ``discovery_provision.yml``, IPs/hostnames cannot be re-assigned by changing the mapping file.

.. caution::

    * To avoid breaking the password-less SSH channel on the OIM, do not run ``ssh-keygen`` commands post execution of ``discovery_provision.yml`` to create a new key.

    * Do not delete the Omnia shared path or the NFS directory.

**Next steps**:

* View generated node inventory in ``/opt/omnia/omnia_inventory``. For more information, `click here <../ViewInventory.html>`_.

* After successfully running ``discovery_provision.yml``, go to `Building Clusters <../OmniaCluster/index.html>`_ to setup Kubernetes, NFS, BeeGFS, and Authentication.