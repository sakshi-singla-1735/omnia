# Copyright 2026 Dell Inc. or its subsidiaries. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# pylint: disable=import-error,no-name-in-module
#!/usr/bin/python

"""
Ansible module to collect RPM packages from default_packages.json and additional_packages.json.
Returns a flat list of package names for base image building.
"""

import os
import json

from ansible.module_utils.basic import AnsibleModule

ROLE_SPECIFIC_KEYS = [
    "slurm_control_node",
    "slurm_node",
    "login_node",
    "login_compiler_node",
    "service_kube_control_plane_first",
    "service_kube_control_plane",
    "service_kube_node"
]


def load_json_file(path, module):
    """
    Load a JSON file safely.

    Args:
        path (str): Path to the JSON file.
        module (AnsibleModule): The Ansible module instance.

    Returns:
        dict or None: Parsed JSON content if successful, otherwise None.
    """
    if not os.path.isfile(path):
        module.log(f"File not found: {path}")
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        module.log(f"Failed to read JSON file {path}: {e}")
        return None


def extract_rpm_package_names(cluster_items):
    """
    Extract RPM package names from a cluster list.

    Args:
        cluster_items (list): List of package items.

    Returns:
        list: List of package names (strings) where type is 'rpm'.
    """
    if not cluster_items or not isinstance(cluster_items, list):
        return []
    return [
        item.get('package') for item in cluster_items
        if item.get('type') == 'rpm' and item.get('package')
    ]


def collect_default_packages(json_path, module):
    """
    Collect RPM package names from default_packages.json.

    Args:
        json_path (str): Path to default_packages.json.
        module (AnsibleModule): The Ansible module instance.

    Returns:
        list: List of package names.
    """
    data = load_json_file(json_path, module)
    if not data:
        return []

    default_packages = data.get('default_packages', {})
    cluster_items = default_packages.get('cluster', [])
    return extract_rpm_package_names(cluster_items)


def collect_additional_global_packages(json_path, module):
    """
    Collect ONLY global RPM package names from additional_packages.json.
    Role-specific packages are handled by image_package_collector.py.

    Args:
        json_path (str): Path to additional_packages.json.
        module (AnsibleModule): The Ansible module instance.

    Returns:
        list: List of global package names.
    """
    data = load_json_file(json_path, module)
    if not data:
        return []

    # Only global RPMs from additional_packages.cluster[]
    additional_packages = data.get('additional_packages', {})
    global_cluster = additional_packages.get('cluster', [])
    return extract_rpm_package_names(global_cluster)


def is_additional_packages_enabled(software_config):
    """
    Check if additional_packages is defined in softwares array of software_config.json.

    Args:
        software_config (dict): Parsed software_config.json content.

    Returns:
        bool: True if additional_packages is in softwares array.
    """
    if not software_config:
        return False
    softwares = software_config.get('softwares', [])
    return any(sw.get('name') == 'additional_packages' for sw in softwares)




def run_module():
    """
    Run the Ansible module.

    Collects RPM packages from default_packages.json and additional_packages.json,
    returns a combined flat list of unique package names.
    """
    module_args = dict(
        default_json_path=dict(type="str", required=True),
        additional_json_path=dict(type="str", required=False, default=""),
        software_config_path=dict(type="str", required=True),
    )

    result = dict(
        changed=False,
        base_image_packages=[],
        default_packages=[],
        additional_packages=[]
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    default_json_path = module.params["default_json_path"]
    additional_json_path = module.params["additional_json_path"]
    software_config_path = module.params["software_config_path"]

    # Load software_config.json
    software_config = load_json_file(software_config_path, module)

    # Collect from default_packages.json
    default_pkgs = collect_default_packages(default_json_path, module)
    result["default_packages"] = default_pkgs

    # Collect ONLY global packages from additional_packages.json if enabled
    # Role-specific packages are handled by image_package_collector.py
    additional_pkgs = []
    if additional_json_path and is_additional_packages_enabled(software_config):
        additional_pkgs = collect_additional_global_packages(additional_json_path, module)
    result["additional_packages"] = additional_pkgs

    # Combine and deduplicate while preserving order
    combined = default_pkgs + additional_pkgs
    seen = set()
    unique_packages = []
    for pkg in combined:
        if pkg not in seen:
            unique_packages.append(pkg)
            seen.add(pkg)

    result["base_image_packages"] = unique_packages
    module.exit_json(**result)


def main():
    """Main entry point."""
    run_module()


if __name__ == "__main__":
    main()
