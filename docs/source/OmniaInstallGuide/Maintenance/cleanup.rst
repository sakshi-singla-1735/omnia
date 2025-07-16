===============
OIM cleanup
===============

The ``oim_cleanup.yml`` playbook can be utilized to roll back any configurations made on the OIM. 

Tasks performed by the playbook
================================

The ``oim_cleanup.yml`` playbook performs the following tasks:

* Clean up all containers, log files, and metadata on the OIM node.
* Rollback the firewall ports on the OIM node to its default setting.

Playbook execution
=====================

Use the below command to execute the playbook: ::

    cd utils
    ansible-playbook oim_cleanup.yml

.. note:: If any OIM or service node is not in a booted state, **no action** will be taken on that node during playbook execution.

.. note:: After running the ``oim_cleanup.yml`` playbook, ensure to reboot the OIM node.

.. caution::
    * After a clean-up, when re-provisioning your cluster by re-running the ``discovery_provision.yml`` playbook, ensure to use a different ``admin_nic_subnet`` in ``input/provision_config.yml`` to avoid a conflict with newly assigned servers. Alternatively, disable any OS available in the ``Boot Option Enable/Disable`` section of your BIOS settings (``BIOS Settings`` > ``Boot Settings`` > ``UEFI Boot Settings``) on all target nodes.
    * On subsequent runs of ``discovery_provision.yml``, if users are unable to log into the server, refresh the ssh key manually and retry. ::

        ssh-keygen -R <node IP>