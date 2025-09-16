#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
import os
import json
import yaml


def load_yaml_file(path, module):
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        module.fail_json(msg=f"Failed to read YAML file {path}: {e}")


def load_json_file(path, module):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        module.log(f"Failed to read JSON file {path}: {e}")
        return None


def collect_packages_from_json(sw_data, fg_name=None, special_slurm=False):
    """
    Extract rpm package names from JSON structure.
    If special_slurm=True, always include "slurm" section,
    and also include the section for the current fg_name if present.
    """
    packages = []

    if special_slurm:
        # Always collect from top-level "slurm" section
        if "slurm" in sw_data and "cluster" in sw_data["slurm"]:
            for entry in sw_data["slurm"]["cluster"]:
                if entry.get("type") == "rpm" and "package" in entry:
                    packages.append(entry["package"])

        # Collect from matching functional group inside slurm.json
        if fg_name in sw_data and "cluster" in sw_data[fg_name]:
            for entry in sw_data[fg_name]["cluster"]:
                if entry.get("type") == "rpm" and "package" in entry:
                    packages.append(entry["package"])

    else:
        # Case 1: nested sections like "slurm", "login_node", etc.
        for section, section_data in sw_data.items():
            if isinstance(section_data, dict) and "cluster" in section_data:
                for entry in section_data["cluster"]:
                    if entry.get("type") == "rpm" and "package" in entry:
                        packages.append(entry["package"])

        # Case 2: "cluster" directly at the top level
        if "cluster" in sw_data and isinstance(sw_data["cluster"], list):
            for entry in sw_data["cluster"]:
                if entry.get("type") == "rpm" and "package" in entry:
                    packages.append(entry["package"])

    return packages


def process_functional_group(fg_name, base_name, arch, os_version, input_project_dir, software_map, module):
    group_path = os.path.join(input_project_dir, "config", arch, "rhel", os_version)
    if not os.path.isdir(group_path):
        module.log(f"Directory not found: {group_path}")
        return []

    json_files = software_map.get(fg_name, [])
    packages = []

    for json_file in json_files:
        sw_path = os.path.join(group_path, json_file)
        if not os.path.isfile(sw_path):
            module.log(f"File not found: {sw_path}")
            continue

        sw_data = load_json_file(sw_path, module)
        if not sw_data:
            continue

        # Special handling for slurm.json
        if json_file == "slurm.json":
            packages.extend(collect_packages_from_json(sw_data, fg_name=fg_name, special_slurm=True))
        else:
            packages.extend(collect_packages_from_json(sw_data))

    # Deduplicate while preserving order
    seen = set()
    unique_packages = []
    for pkg in packages:
        if pkg not in seen:
            unique_packages.append(pkg)
            seen.add(pkg)

    return unique_packages


def run_module():
    module_args = dict(
        functional_groups_file=dict(type="str", required=True),
        software_config_file=dict(type="str", required=True),
        input_project_dir=dict(type="str", required=True),
    )

    result = dict(changed=False, compute_images_dict={})
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    functional_groups_file = module.params["functional_groups_file"]
    software_config_file = module.params["software_config_file"]
    input_project_dir = module.params["input_project_dir"]

    # Load configs
    functional_groups = load_yaml_file(functional_groups_file, module)
    software_config = load_json_file(software_config_file, module)

    os_version = software_config.get("cluster_os_version") if software_config else None
    if not os_version:
        module.fail_json(msg="cluster_os_version not found in software_config.json")

    # Functional group → json files mapping
    software_map = {
        "default_x86_64": ["ofed.json", "cuda.json", "openldap.json"],
        "service_kube_node_x86_64": ["service_k8s.json", "nfs.json", "openldap.json", "ofed.json"],
        "slurm_control_node_x86_64": ["slurm.json", "nfs.json", "openldap.json", "ofed.json"],
        "slurm_node_x86_64": ["slurm.json", "nfs.json", "openldap.json", "ofed.json", "cuda.json"],
        "login_node_x86_64": ["slurm.json", "nfs.json", "openldap.json", "ofed.json"],
        "login_compiler_node_x86_64": ["slurm.json", "nfs.json", "openldap.json", "ofed.json", "ucx.json", "openmpi.json"],
    }

    compute_images_dict = {}

    for fg in functional_groups.get("functional_groups", []):
        fg_name = fg.get("name") if isinstance(fg, dict) else str(fg)

        # Detect arch + base_name
        if fg_name.endswith("_x86_64"):
            base_name = fg_name.replace("_x86_64", "")
            arch = "x86_64"
        elif fg_name.endswith("_aarch64"):
            base_name = fg_name.replace("_aarch64", "")
            arch = "aarch64"
        else:
            base_name = fg_name
            arch = "x86_64"

        packages = process_functional_group(
            fg_name, base_name, arch, os_version, input_project_dir, software_map, module
        )

        compute_images_dict[fg_name] = {
            "functional_group": fg_name,
            "packages": packages
        }

    result["compute_images_dict"] = compute_images_dict
    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()

