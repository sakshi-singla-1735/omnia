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

# pylint: disable=import-error,no-name-in-module,too-many-positional-arguments,too-many-arguments

from ansible.module_utils.input_validation.common_utils import validation_utils
from ansible.module_utils.input_validation.common_utils import config
from ansible.module_utils.input_validation.common_utils import en_us_validation_msg
from ansible.module_utils.local_repo.software_utils import load_yaml, load_json

create_error_msg = validation_utils.create_error_msg
extract_arch_from_fg = validation_utils.extract_arch_from_fg
key_value_exists = validation_utils.key_value_exists
contains_software = validation_utils.contains_software
create_file_path = validation_utils.create_file_path
load_json = validation_utils.load_json

file_names = config.files

#  Duplicate check for functional groups  
def validate_functional_group_duplicates(functional_groups):
    errors = []
    seen_combinations = set()
    for idx, group in enumerate(functional_groups):
        key = (group.get("name", ""), group.get("cluster_name", ""))
        if key in seen_combinations:
            errors.append(
                create_error_msg(
                    group.get("name", f"group[{idx}]"),
                    str(key),
                    en_us_validation_msg.DUPLICATE_FUNCTIONAL_GROUP_COMBINATION_MSG
                )
            )
        else:
            seen_combinations.add(key)
    return errors

def validate_non_empty_clustername(functional_groups):
    errors = []
    non_empty_clustername = {
        "slurm_control_node_x86_64",
        "slurm_node_x86_64",
        "slurm_node_aarch64",
        "service_kube_node_x86_64",
        "login_node_x86_64",
        "login_compiler_node_x86_64",
        "login_node_aarch64",
        "login_compiler_node_aarch64"
    }
    for group in functional_groups:
        name = group.get("name", "")
        cluster_name = group.get("cluster_name", "")
        if name in non_empty_clustername and not cluster_name:
            errors.append(
                create_error_msg(
                    name,
                    cluster_name,
                    en_us_validation_msg.NON_EMPTY_CLUSTER_NAME_MSG.format(name=name)
                )
            )
    return errors

# Validate if any login functional group is defined, then clustername should match with at least one slurm clustername.
def validate_login_node_clustername(functional_groups):
    errors = []
    login_clusters = set()
    slurm_clusters = set()
    for group in functional_groups:
        name = group.get("name", "")
        cluster_name = group.get("cluster_name", "")
        if "login" in name and cluster_name:
            login_clusters.add(cluster_name)
        if "slurm" in name and cluster_name:
            slurm_clusters.add(cluster_name)
    for cluster in login_clusters:
        if cluster not in slurm_clusters:
            errors.append(
                create_error_msg(
                    "login_node",
                    cluster,
                    en_us_validation_msg.LOGIN_NODE_WITHOUT_SLURM_MSG.format(cluster=cluster)
                )
            )
    return errors

#  SLURM/K8s cluster validations  
def validate_slurm_k8s_clusters(functional_groups):
    errors = []

    slurm_control_clusters = set()
    slurm_node_clusters = set()
    kube_clusters = set()

    for g in functional_groups:
        name = g.get("name", "")
        cluster = g.get("cluster_name", "")
        if "slurm_control_node" in name and cluster:
            slurm_control_clusters.add(cluster)
        elif "slurm_node" in name and cluster:
            slurm_node_clusters.add(cluster)
        elif "kube" in name and cluster:
            kube_clusters.add(cluster)

    # Slurm node requires control node
    for cluster in slurm_node_clusters:
        if cluster not in slurm_control_clusters:
            errors.append(
                create_error_msg(
                    "slurm_node",
                    cluster,
                    en_us_validation_msg.SLURM_NODE_WITHOUT_CONTROL_MSG.format(cluster=cluster)
                )
            )

    # Slurm clusters cannot overlap with kube clusters
    overlap = slurm_control_clusters.union(slurm_node_clusters).intersection(kube_clusters)
    for cluster in overlap:
        errors.append(
            create_error_msg(
                "functional_groups",
                cluster,
                en_us_validation_msg.SLURM_KUBE_CLUSTER_OVERLAP_MSG.format(cluster=cluster)
            )
        )

    return errors

#  Top-level validation  
def validate_top_level(data): 
    errors = []
    if not data or not isinstance(data, dict):
        errors.append(
            create_error_msg(
                "functional_groups_config.yml",
                None,
                en_us_validation_msg.EMPTY_OR_SYNTAX_ERROR_FUNCTIONAL_GROUPS_CONFIG_MSG
            )
        )
        return errors

    if "functional_groups" not in data or data["functional_groups"] is None:
        errors.append(
            create_error_msg(
                "functional_groups",
                None,
                en_us_validation_msg.MISSING_FUNCTIONAL_GROUPS_SECTION_MSG
            )
        )
    return errors

#  Parent validation for slurm_node  

def validate_slurm_node_parent(functional_groups):
    errors = []
    for group in functional_groups:
        name = group.get("name", "")
        parent = group.get("parent", "")
        if "slurm_node" in name and not parent:
            errors.append(
                create_error_msg(
                    name,
                    parent,
                    en_us_validation_msg.SLURM_NODE_PARENT_MISSING_MSG.format(name=name)
                )
            )
    return errors

#  Functional group structure validation  
def validate_functional_groups_structure(functional_groups):
    errors = []
    if not isinstance(functional_groups, list):
        errors.append(
            create_error_msg(
                "functional_groups_config.yml",
                str(functional_groups),
                en_us_validation_msg.FUNCTIONAL_GROUPS_NOT_LIST_MSG
            )
        )
        return errors

    for idx, group in enumerate(functional_groups):
        if not isinstance(group, dict):
            errors.append(
                create_error_msg(
                    f"functional_groups[{idx}]",
                    str(group),
                    en_us_validation_msg.EACH_FUNCTIONAL_GROUP_NOT_DICT_MSG
                )
            )
            continue

        # Required fields``
        for field in ["name", "cluster_name", "parent"]:
            if field not in group:
                errors.append(
                    create_error_msg(
                        group.get("name", f"group[{idx}]"),
                        None,
                        en_us_validation_msg.MISSING_FIELD_FUNCTIONAL_GROUP_MSG.format(field=field)
                    )
                )
                group[field] = ""  # prevent further key errors

    return errors

# Software mapping validation  
def validate_software_section_mappings(functional_groups, software_data):
    """
    Validates the software section mappings for a given list of functional groups and software data.

    Args:
        functional_groups (list): A list of dictionaries, where each dictionary contains information about a functional group.
        software_data (dict): A dictionary containing software data, including a list of softwares.

    Returns:
        list: A list of error messages.
    """
    errors = []

    softwares_list = software_data.get("softwares", [])
    slurm_section = software_data.get("slurm", [])

    SOFTWARE_REQUIREMENTS = {
        "service_kube_node": ["service_k8s", "nfs"],
        "slurm_control_node": ["slurm_custom", "nfs"],
        "slurm_node": ["slurm_custom", "nfs"],
        "login_node": ["slurm_custom", "nfs"],
        "login_compiler_node": ["slurm_custom", "nfs"],
    }

    # Only these softwares are valid for aarch64
    AARCH64_SUPPORTED = {"slurm_custom", "cuda", "nfs"}

    for fg in functional_groups:
        fg_name = fg.get("name", "")
        arch = extract_arch_from_fg(fg_name)
        base_fg_name = fg_name[: -len("_" + arch)] if arch else fg_name

        required_softwares = SOFTWARE_REQUIREMENTS.get(base_fg_name, [])

        # Validate software presence
        for sw in required_softwares:
            # Skip unsupported software for aarch64
            if arch == "aarch64" and sw not in AARCH64_SUPPORTED:
                continue

            # Check if this software exists for the given arch (if arch-aware)
            found = any(
                s.get("name") == sw and (not arch or arch in s.get("arch", []))
                for s in softwares_list
            )
            if not found:
                errors.append(
                    create_error_msg(
                        fg_name,
                        sw,
                        f" For functional group: '{fg_name}', required software '{sw}'{f' with architecture {arch}' if arch else ''} is missing in software_config.json. Please add the missing entry and try again."
                    )
                )

        # Validate SLURM section presence
        expected_slurm_entry = None
        if base_fg_name in ["slurm_control_node", "slurm_node", "login_node", "login_compiler_node"]:
            expected_slurm_entry = "login_node" if "login" in base_fg_name else base_fg_name
        if expected_slurm_entry and not key_value_exists(slurm_section, "name", expected_slurm_entry):
            errors.append(
                create_error_msg(
                    fg_name,
                    expected_slurm_entry,
                    f"For Functional group '{fg_name}', slurm entry: 'slurm': [{{'name': '{expected_slurm_entry}'}}] missing in software_config.json. Please add the missing entry and try again."
                )
            )

    return errors

#  Main validator  
def validate_functional_groups_config(
    input_file_path, data, logger, _module, _omnia_base_dir, _module_utils_base, _project_name
):
    errors = []

    # Top-level checks
    errors.extend(validate_top_level(data))
    if errors:
        return errors

    functional_groups = data.get("functional_groups")

    # Structure checks
    errors.extend(validate_functional_groups_structure(functional_groups))
    if errors:
        return errors

    # Modular validations
    errors.extend(validate_functional_group_duplicates(functional_groups))
    errors.extend(validate_non_empty_clustername(functional_groups))
    errors.extend(validate_slurm_k8s_clusters(functional_groups))
    errors.extend(validate_login_node_clustername(functional_groups))
    errors.extend(validate_slurm_node_parent(functional_groups))
    software_file = create_file_path(input_file_path, "software_config.json")
    software_json = load_json(software_file)
    errors.extend(validate_software_section_mappings(functional_groups, software_json))

    return errors
