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
    if not os.path.exists(filepath):
        return OrderedDict({"groups": OrderedDict(), "functional_groups": []})
    with open(filepath) as f:
        data = yaml.safe_load(f)
        if not isinstance(data, dict):
            data = {}
        if not isinstance(data.get("groups"), dict):
            data["groups"] = OrderedDict()
        if not isinstance(data.get("functional_groups"), list):
            data["functional_groups"] = []
        return data


def load_omnia_config(omnia_config_path, module):
    if not os.path.exists(omnia_config_path):
        module.fail_json(msg=f"omnia_config.yml not found: {omnia_config_path}")

    try:
        with open(omnia_config_path) as f:
            config = yaml.safe_load(f) or {}

        kube_name = None
        k8s_clusters = config.get("service_k8s_cluster", [])
        if isinstance(k8s_clusters, list) and k8s_clusters:
            for c in k8s_clusters:
                if c.get("deployment") is True:
                    kube_name = c.get("cluster_name")
                    break
            if kube_name is None:
                kube_name = k8s_clusters[0].get("cluster_name")

        slurm_name = None
        slurm_clusters = config.get("slurm_cluster", [])
        if isinstance(slurm_clusters, list) and slurm_clusters:
            slurm_name = slurm_clusters[0].get("cluster_name")

        return kube_name, slurm_name

    except Exception as e:
        module.fail_json(msg=f"Failed to load omnia_config.yml: {str(e)}")


def parse_csv(filename, module):
    groups = {}
    functional_groups = {}
    kube_control_seen = False

    try:
        with open(filename, newline="") as f:
            cleaned_lines = [line.strip() for line in f if line.strip()]
            header = cleaned_lines[0].split(",")
            expected_columns = len(header)

            # Keep only lines with the correct number of columns
            valid_lines = [line for line in cleaned_lines if len(line.split(",")) == expected_columns]

            reader = csv.DictReader(valid_lines)

            for row in reader:
                func_group = row["FUNCTIONAL_GROUP_NAME"].strip()
                group_name = row["GROUP_NAME"].strip()
                parent = row.get("PARENT_SERVICE_TAG", "").strip() or ""

                if func_group == "service_kube_control_plane_x86_64" and not kube_control_seen:
                    func_group = "service_kube_control_plane_first_x86_64"
                    kube_control_seen = True

                groups[group_name] = {"parent": parent}
                if func_group in FUNCTIONAL_GROUP_LAYER_MAP:
                    functional_groups.setdefault(func_group, set()).add(group_name)

        return groups, functional_groups

    except Exception as e:
        module.fail_json(msg=f"Error parsing CSV file: {str(e)}")


def merge_yaml(existing, new_groups, new_func_groups, kube_cluster_name, slurm_cluster_name):
    added_groups, added_fgs = [], []

    # Add or update groups
    for grp, details in new_groups.items():
        if grp not in existing["groups"]:
            existing["groups"][grp] = details
            added_groups.append(grp)
        else:
            existing_parent = existing["groups"][grp].get("parent", "")
            new_parent = details.get("parent", "")
            if existing_parent != new_parent:
                existing["groups"][grp]["parent"] = new_parent
                added_groups.append(grp + " (parent updated)")

    # Map existing functional groups by name
    existing_fg_map = {fg["name"]: fg for fg in existing["functional_groups"]}

    # Add or update functional groups
    for func_group, group_list in new_func_groups.items():
        layer = FUNCTIONAL_GROUP_LAYER_MAP[func_group]
        fg_lower = func_group.lower()
        cluster_name = kube_cluster_name if "kube" in fg_lower else slurm_cluster_name or "slurm_cluster"
        desc_key = next((k for k in DESCRIPTION_MAP if func_group.startswith(k)), func_group)
        description = DESCRIPTION_MAP.get(desc_key, func_group)

        if func_group in existing_fg_map:
            fg_entry = existing_fg_map[func_group]
            original_groups = set(fg_entry.get("group", []))
            new_groups_to_add = group_list - original_groups
            if new_groups_to_add:
                fg_entry["group"].extend(sorted(new_groups_to_add))
                added_fgs.append(func_group)
        else:
            new_entry = OrderedDict({
                "name": func_group,
                "cluster_name": cluster_name,
                "group": sorted(list(group_list)),
                "_comment": [
                    f"{description} functional_groups:",
                    f"This functional_group is used to configure the nodes for {description}. It belongs to the {layer} layer.",
                    f"The nodes included in this.functional_group will have the necessary tools and configurations to run {description}.",
                    f"The nodes in this functional_group can be used to run {description}."
                ]
            })
            existing["functional_groups"].append(new_entry)
            added_fgs.append(func_group)

    return existing, added_groups, added_fgs


def dump_yaml_with_comments(data, filename):
    with open(filename, "w") as f:
        f.write("# ------------------------------------------------------------------------------------------------\n")
        f.write("# Groups definition\n")
        f.write("# ------------------------------------------------------------------------------------------------\n")
        f.write("groups:\n")
        for g in sorted(data["groups"].keys()):
            d = data["groups"][g]
            f.write(f"  {g}:\n")
            f.write(f"    parent: \"{d['parent']}\"\n")

        f.write("\n# ------------------------------------------------------------------------------------------------\n")
        f.write("# Functional Groups definition\n")
        f.write("# ------------------------------------------------------------------------------------------------\n")
        f.write("functional_groups:\n")
        for fg in data.get("functional_groups") or []:
            for c in fg.get("_comment", []):
                f.write(f"  # {c}\n")
            f.write(f"  - name: \"{fg['name']}\"\n")
            f.write(f"    cluster_name: \"{fg['cluster_name']}\"\n")
            f.write(f"    group:\n")
            for g in sorted(set(fg["group"])):
                f.write(f"      - {g}\n")
            f.write("\n")

def main():
    module_args = {
        "mapping_file_path": {"type": "str", "required": True},
        "functional_groups_file_path": {"type": "str", "required": True},
        "omnia_config_path": {"type": "str", "required": True},
    }

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    mapping_file_path = module.params["mapping_file_path"]
    functional_groups_file_path = module.params["functional_groups_file_path"]
    omnia_config_path = module.params["omnia_config_path"]

    try:
        if not os.path.exists(mapping_file_path):
            module.fail_json(msg=f"CSV file not found: {mapping_file_path}")

        kube_cluster_name, slurm_cluster_name = load_omnia_config(omnia_config_path, module)

        existing_yaml = load_existing_yaml(functional_groups_file_path)
        new_groups, new_func_groups = parse_csv(mapping_file_path, module)

        merged_yaml, added_groups, added_fgs = merge_yaml(
            existing_yaml,
            new_groups,
            new_func_groups,
            kube_cluster_name,
            slurm_cluster_name
        )

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
