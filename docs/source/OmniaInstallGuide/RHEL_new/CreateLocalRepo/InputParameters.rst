Input parameters for Local Repositories
==========================================

The ``local_repo.yml`` playbook is dependent on the inputs provided to the following input files:

* ``/opt/omnia/input/project_default/software_config.json``
* ``/opt/omnia/input/project_default/local_repo_config.yml``

``/opt/omnia/input/project_default/software_config.json``
----------------------------------------------------------

Based on the inputs provided to the ``/opt/omnia/input/project_default/software_config.json``, the software packages/images are accessed from the Pulp container and the desired software stack is deployed on the cluster nodes.

.. csv-table:: Parameters for Software Configuration
   :file: ../../../Tables/software_config_rhel.csv
   :header-rows: 1
   :keepspace:
   :widths: auto

Here's a sample of the ``software_config.json`` for RHEL clusters:

::

    {
    "cluster_os_type": "rhel",
    "cluster_os_version": "9.6",
    "iso_file_path": "",
    "repo_config": "always",
    "softwares": [
        {"name": "amdgpu", "version": "6.3.1", "arch": ["x86_64"]},
        {"name": "cuda", "version": "12.8.0", "arch": ["x86_64","aarch64"]},
        {"name": "ofed", "version": "24.10-3.2.5.0", "arch": ["x86_64"]},
        {"name": "openldap", "arch": ["x86_64","aarch64"]},
        {"name": "nfs", "arch": ["x86_64","aarch64"]},
        {"name": "k8s", "version":"1.31.4", "arch": ["x86_64"]},
        {"name": "service_k8s","version": "1.31.4", "arch": ["x86_64","aarch64"]},
        {"name": "slurm", "arch": ["x86_64","aarch64"]}
    ],
    "amdgpu": [
        {"name": "rocm", "version": "6.3.1" }
    ],
    "slurm": [
        {"name": "slurm_control_node"},
        {"name": "slurm_node"},
        {"name": "login"}
    ]
}
.. note::
    * To download a software for only x86_64 or aarch64 architecture, the arch key input is not mandatory. It will default to roles_config and the architecture is read accordingly.
    See the following sample:

    {
    "cluster_os_type": "rhel",
    "cluster_os_version": "9.6",
    "iso_file_path": "",
    "repo_config": "always",
    "softwares": [
        {"name": "amdgpu", "version": "6.3.1"},
        {"name": "cuda", "version": "12.8.0"},
        {"name": "ofed", "version": "24.10-3.2.5.0"},
        {"name": "freeipa"},
        {"name": "openldap"},
        {"name": "secure_login_node"},
        {"name": "nfs"},
        {"name": "beegfs", "version": "7.4.5"},
        {"name": "slurm"},
        {"name": "k8s", "version": "1.31.4"},
        {"name": "service_k8s", "version": "1.31.4"},
        {"name": "intel_benchmarks", "version": "2024.1.0"},
        {"name": "amd_benchmarks"},
        {"name": "utils"},
        {"name": "ucx", "version": "1.15.0"},
        {"name": "openmpi", "version": "4.1.6"},
        {"name": "racadm"}
    ],

    "amdgpu": [
        {"name": "rocm", "version": "6.3.1" }
    ],
    "slurm": [
        {"name": "slurm_control_node"},
        {"name": "slurm_node"},
        {"name": "login"}
    ]

}
* To download a software with both x86_64 and aarch64 architectures, the arch key input is mandatory. Ensure that you check if the .json files for all the specified architectures are available in the input or configuration file. Else, update the .json files. See the following sample:
{
    "cluster_os_type": "rhel",
    "cluster_os_version": "9.6",
    "iso_file_path": "",
    "repo_config": "always",
    "softwares": [
        {"name": "amdgpu", "version": "6.3.1", "arch": ["x86_64"]},
        {"name": "cuda", "version": "12.8.0", "arch": ["x86_64","aarch64"]},
        {"name": "ofed", "version": "24.10-3.2.5.0", "arch": ["x86_64"]},
        {"name": "freeipa", "arch": ["x86_64"]},
        {"name": "openldap", "arch": ["x86_64","aarch64"]},
        {"name": "secure_login_node", "arch": ["x86_64","aarch64"]},
        {"name": "nfs", "arch": ["x86_64","aarch64"]},
        {"name": "beegfs", "version": "7.4.5", "arch": ["x86_64"]},
        {"name": "slurm", "arch": ["x86_64","aarch64"]},
        {"name": "k8s", "version": "1.31.4", "arch": ["x86_64"]},
        {"name": "service_k8s", "version": "1.31.4", "arch": ["x86_64","aarch64"]},
        {"name": "intel_benchmarks", "version": "2024.1.0", "arch": ["x86_64","aarch64"]},
        {"name": "amd_benchmarks", "arch": ["x86_64"]},
        {"name": "utils", "arch": ["x86_64"]},
        {"name": "ucx", "version": "1.15.0", "arch": ["x86_64","aarch64"]},
        {"name": "openmpi", "version": "4.1.6", "arch": ["x86_64"]},
        {"name": "racadm", "arch": ["x86_64"]}
    ],

    "amdgpu": [
        {"name": "rocm", "version": "6.3.1" }
    ],
    "slurm": [
        {"name": "slurm_control_node"},
        {"name": "slurm_node"},
        {"name": "login"}
    ]

}

* For additional_software support, update the input/config/{arch}/rhel/9.6/additional_software.json file with the required {arch} data,
where {arch} can either be x86_64 or aarch64, or a combination of both.
.. note::

    * For a list of accepted ``softwares``, go to the ``/opt/omnia/input/project_default/config/<cluster_os_type>/<cluster_os_version>`` and view the list of JSON files available. The filenames present in this location are the list of accepted softwares. For a cluster running RHEL 9.6, go to ``/opt/omnia/input/project_default/config/rhel/9.6/`` and view the file list for accepted softwares.
    * Omnia supports a single version of any software packages in the ``software_config.json`` file. Ensure that multiple versions of the same package is not mentioned.
    * For software packages that do not have a pre-defined json file in ``/opt/omnia/input/project_default/config/<cluster_os_type>/<cluster_os_version>``, you need to create a ``custom.json`` file with the package details. For more information, `click here <../../AdvancedConfigurations/CustomLocalRepo.html>`_.

``/opt/omnia/input/project_default/local_repo_config.yml``
-----------------------------------------------------------

.. csv-table:: Parameters for Local Repository Configuration
   :file: ../../../Tables/local_repo_config_rhel.csv
   :header-rows: 1
   :keepspace:
   :widths: auto