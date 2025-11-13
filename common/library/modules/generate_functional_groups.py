# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
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

#!/usr/bin/python

"""
Ansible module: Generate or update cluster functional_groups.yaml based on a CSV mapping file.
"""

from ansible.module_utils.basic import AnsibleModule
import csv
import yaml
from collections import OrderedDict
import os

FUNCTIONAL_GROUP_LAYER_MAP = {
    "service_kube_control_plane_first_x86_64": "management",
    "service_kube_control_plane_x86_64": "management",
    "service_kube_node_x86_64": "management",
    "login_node_x86_64": "management",
    "login_node_aarch64": "management",
    "login_compiler_node_x86_64": "management",
    "login_compiler_node_aarch64": "management",
    "slurm_control_node_x86_64": "management",
    "slurm_node_x86_64": "compute",
    "slurm_node_aarch64": "compute",
}

CLUSTER_MAP = {
    "slurm": "slurm_cluster",
    "login": "slurm_cluster",
    "service_kube": "kubernetes_cluster",
}

DESCRIPTION_MAP = {
    "slurm_control_node": "Slurm Head",
    "slurm_node": "Slurm Worker",
    "login_node": "Login Node",
    "login_compiler_node": "Login Compiler Node",
    "service_kube_control_plane_first": "Kubernetes Control Plane (Primary)",
    "service_kube_control_plane": "Kubernetes Control Plane",
    "service_kube_node": "Kubernetes Worker Node",
}


def load_existing_yaml(filepath):
    """Load YAML file safely, or initialize default structure."""
    if not os.path.exists(filepath):
        return OrderedDict({"groups": OrderedDict(), "functional_groups": []})
    with open(filepath) as f:
        data = yaml.safe_load(f)
        if not isinstance(data, dict):
            data = {}
        data.setdefault("groups", OrderedDict())
        data.setdefault("functional_groups", [])
        return data


def parse_csv(filename, module):
    """Parse the CSV and extract groups + functional groups."""
    groups = {}
    functional_groups = {}
    kube_control_seen = False  # Track first kube control plane entry

    try:
        with open(filename, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                func_group = row["FUNCTIONAL_GROUP_NAME"].strip()
                group_name = row["GROUP_NAME"].strip()
                parent = row.get("PARENT_SERVICE_TAG", "").strip() or ""

                # --- Enhancement: rename the first kube control plane entry ---
                if func_group == "service_kube_control_plane_x86_64" and not kube_control_seen:
                    func_group = "service_kube_control_plane_first_x86_64"
                    kube_control_seen = True
                # -------------------------------------------------------------

                if group_name not in groups:
                    groups[group_name] = {"parent": parent}

                if func_group in FUNCTIONAL_GROUP_LAYER_MAP:
                    functional_groups.setdefault(func_group, set()).add(group_name)

        return groups, functional_groups

    except Exception as e:
        module.fail_json(msg=f"Error parsing CSV file: {str(e)}")


def merge_yaml(existing, new_groups, new_func_groups):
    """Merge new data into existing YAML structure."""
    added_groups, added_fgs = [], []

    for grp, details in new_groups.items():
        if grp not in existing["groups"]:
            existing["groups"][grp] = details
            added_groups.append(grp)

    existing_names = {fg["name"] for fg in existing["functional_groups"]}
    for func_group, group_list in new_func_groups.items():
        if func_group not in existing_names:
            layer = FUNCTIONAL_GROUP_LAYER_MAP[func_group]
            cluster_key = next((k for k in CLUSTER_MAP if func_group.startswith(k)), "slurm")
            cluster_name = CLUSTER_MAP.get(cluster_key, "slurm_cluster")
            desc_key = next((k for k in DESCRIPTION_MAP if func_group.startswith(k)), func_group)
            description = DESCRIPTION_MAP.get(desc_key, func_group)

            new_entry = OrderedDict({
                "name": func_group,
                "cluster_name": cluster_name,
                "group": sorted(list(group_list)),
                "_comment": [
                    f"{description} functional_groups: ({func_group.split('_')[-1]})",
                    f"This functional_group is used to configure the nodes for {description}. It belongs to the {layer} layer.",
                    f"The nodes included in this functional_group will have the necessary tools and configurations to run {description}.",
                    f"The nodes in this functional_group can be used to run {description}."
                ]
            })
            existing["functional_groups"].append(new_entry)
            added_fgs.append(func_group)

    return existing, added_groups, added_fgs


def dump_yaml_with_comments(data, filename):
    """Write YAML data to file with comments."""
    with open(filename, "w") as f:
        f.write("# ------------------------------------------------------------------------------------------------\n")
        f.write("# Groups definition\n")
        f.write("# ------------------------------------------------------------------------------------------------\n")
        f.write("groups:\n")
        for g, d in data["groups"].items():
            f.write(f"  {g}:\n")
            f.write(f"    parent: \"{d['parent']}\"\n")
        f.write("\n# ------------------------------------------------------------------------------------------------\n")
        f.write("# Functional Groups definition\n")
        f.write("# ------------------------------------------------------------------------------------------------\n")
        f.write("functional_groups:\n")
        for fg in data["functional_groups"]:
            for c in fg["_comment"]:
                f.write(f"  # {c}\n")
            f.write(f"  - name: \"{fg['name']}\"\n")
            f.write(f"    cluster_name: \"{fg['cluster_name']}\"\n")
            f.write(f"    group:\n")
            for g in fg["group"]:
                f.write(f"      - {g}\n")
            f.write("\n")


def main():
    """Main function for the Ansible module logic."""
    module_args = {
        "mapping_file_path": {"type": "str", "required": True},
        "functional_groups_file_path": {"type": "str", "required": True}
    }

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    mapping_file_path = module.params["mapping_file_path"]
    functional_groups_file_path = module.params["functional_groups_file_path"]

    try:
        if not os.path.exists(mapping_file_path):
            module.fail_json(msg=f"CSV file not found: {mapping_file_path}")

        existing_yaml = load_existing_yaml(functional_groups_file_path)
        new_groups, new_func_groups = parse_csv(mapping_file_path, module)
        merged_yaml, added_groups, added_fgs = merge_yaml(existing_yaml, new_groups, new_func_groups)

        changed = bool(added_groups or added_fgs)

        if changed:
            dump_yaml_with_comments(merged_yaml, functional_groups_file_path)

        module.exit_json(
            changed=changed,
            msg=f"Updated functional_groups_config.yml file: {functional_groups_file_path}",
            added_groups=added_groups,
            added_functional_groups=added_fgs
        )

    except Exception as e:
        module.fail_json(msg=f"Error while generating functional groups YAML: {str(e)}")


if __name__ == "__main__":
    main()
