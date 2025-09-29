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

import itertools
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

# Top-level validation


def validate_top_level(data):
    """
    Validates the top-level structure of the functional groups config data.

    Parameters:
        data (dict): The functional groups config data to be validated.

    Returns:
        list: A list of validation errors.
    """
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

    if "groups" not in data or not isinstance(data["groups"], dict) or not data["groups"]:
        errors.append(
            create_error_msg(
                "groups",
                None,
                en_us_validation_msg.MISSING_GROUPS_SECTION_MSG
            )
        )

    if "functional_groups" not in data or not isinstance(data["functional_groups"], list):
        errors.append(
            create_error_msg(
                "functional_groups",
                None,
                en_us_validation_msg.MISSING_FUNCTIONAL_GROUPS_SECTION_MSG
            )
        )
    return errors

# Groups structure validation


def validate_groups_structure(groups):
    """
    Validates the structure of groups in the functional groups configuration.

    Parameters:
        groups (dict): A dictionary of groups where each key is the group name
         and the value is the group data.

    Returns:
        list: A list of error messages if the group structure is invalid.
    """
    errors = []
    for gname, gdata in groups.items():
        if not isinstance(gdata, dict):
            errors.append(
                create_error_msg(
                    f"group:{gname}",
                    str(gdata),
                    f"Group '{gname}' should be a dictionary."
                )
            )
            continue
        for field in ["location_id", "parent"]:
            if field not in gdata:
                errors.append(
                    create_error_msg(
                        gname,
                        None,
                        f"Missing field '{field}' in group '{gname}'."
                    )
                )
                gdata[field] = ""
    return errors

# Functional groups structure validation


def validate_functional_groups_structure(functional_groups, groups):
    """
    Validates the structure of functional groups in the functional groups configuration.

    Parameters:
        functional_groups (list): A list of functional group dictionaries.
        groups (dict): A dictionary of groups where each key is the group name
          and the value is the group data.

    Returns:
        list: A list of error messages if the functional group structure is invalid.
    """
    errors = []
    for idx, fg in enumerate(functional_groups):
        if not isinstance(fg, dict):
            errors.append(
                create_error_msg(
                    f"functional_groups[{idx}]",
                    str(fg),
                    en_us_validation_msg.EACH_FUNCTIONAL_GROUP_NOT_DICT_MSG
                )
            )
            continue

        # Required fields
        for field in ["name", "cluster_name", "group"]:
            if field not in fg:
                errors.append(
                    create_error_msg(
                        fg.get("name", f"group[{idx}]"),
                        None,
                        en_us_validation_msg.MISSING_FIELD_FUNCTIONAL_GROUP_MSG.format(field=field)
                    )
                )
                fg[field] = []

        # Validate group references exist
        for gref in fg.get("group", []):
            if gref not in groups:
                errors.append(
                    create_error_msg(
                        fg.get("name", f"group[{idx}]"),
                        gref,
                        f"Referenced group '{gref}' does not exist in 'groups'."
                    )
                )
    return errors

# Duplicate functional group check


def validate_functional_group_duplicates(functional_groups):
    """
    Validates a list of functional groups for duplicate names.

    Parameters:
        functional_groups (list): A list of dictionaries,
          where each dictionary represents a functional group.

    Returns:
        list: A list of error messages if the functional group names are not unique.
    """
    errors = []
    seen = set()
    for idx, fg in enumerate(functional_groups):
        name = fg.get("name", "")
        if name in seen:
            errors.append(
                create_error_msg(
                    name or f"group[{idx}]",
                    name,
                    en_us_validation_msg.DUPLICATE_FUNCTIONAL_GROUP_NAME_MSG
                )
            )
        else:
            seen.add(name)
    return errors

def validate_functional_groups_separation(functional_groups):
    """
    Validates that groups are not shared between functional groups
    """
    errors = []
    fg_groups = {}

    for fg_group in functional_groups:
        fg_group_name = fg_group.get("name", "")
        fg_groups[fg_group_name] = set(fg_group.get("group", []))  # fixed key name

    for fg_group_name1, fg_group_name2 in itertools.combinations(fg_groups.keys(), 2):
        shared = fg_groups[fg_group_name1] & fg_groups[fg_group_name2]  # fixed operator
        if shared:
            group_str = ', '.join(shared)
            msg = f"Group is shared between {fg_group_name1} and {fg_group_name2} functional_groups."
            errors.append(create_error_msg("functional_groups", group_str, msg))

    return errors

# Non-empty cluster name validation
def validate_non_empty_clustername(functional_groups):
    """
    Validates that cluster names are not empty for certain functional groups.

    Args:
        functional_groups (list): A list of dictionaries,
          where each dictionary represents a functional group.

    Returns:
        list: A list of error messages.
    """
    errors = []
    non_empty = {
        "slurm_control_node_x86_64",
        "slurm_node_x86_64",
        "slurm_node_aarch64",
        "service_kube_node_x86_64",
        "login_node_x86_64",
        "login_compiler_node_x86_64",
        "login_node_aarch64",
        "login_compiler_node_aarch64"
    }
    for fg in functional_groups:
        name = fg.get("name", "")
        cluster_name = fg.get("cluster_name", "")
        if name in non_empty and not cluster_name:
            errors.append(
                create_error_msg(
                    name,
                    cluster_name,
                    en_us_validation_msg.NON_EMPTY_CLUSTER_NAME_MSG.format(name=name)
                )
            )
    return errors

# Slurm/K8s cluster validation


def validate_slurm_k8s_clusters(functional_groups, input_file_path):
    """
    Validates that SLURM and Kubernetes clusters do not overlap.
    Ensures that SLURM nodes have corresponding control nodes and
      that SLURM and Kubernetes clusters are distinct.
    Args:
        functional_groups (list): A list of dictionaries,
          where each dictionary represents a functional group.
    Returns:
        list: A list of error messages.
    """
    errors = []

    omnia_config_file = create_file_path(input_file_path, "omnia_config.yml")
    omnia_config = load_yaml(omnia_config_file)
    slurm_cluster = [c.get('cluster_name') for c in omnia_config.get('slurm_cluster')]
    service_k8s_cluster = [c.get('cluster_name') for c in omnia_config.get('service_k8s_cluster')]

    slurm_control_clusters = {fg.get("cluster_name") for fg in functional_groups if (
        fg.get('name').startswith('slurm_control_node') and fg.get("cluster_name"))}

    slurm_node_clusters = {fg.get("cluster_name") for fg in functional_groups
                           if (fg.get('name').startswith('slurm_node') and fg.get("cluster_name"))}

    login_clusters = {fg.get("cluster_name") for fg in functional_groups
                      if (fg.get('name').startswith('login_') and fg.get("cluster_name"))}

    kube_clusters = {fg.get("cluster_name") for fg in functional_groups
                     if (fg.get('name').startswith('service_kube') and fg.get("cluster_name"))}

    slurm_union = (set(slurm_control_clusters) | set(slurm_node_clusters) | set(login_clusters))

    slurm_cluster_not_fg = slurm_union - set(slurm_cluster)
    if slurm_cluster_not_fg:
        errors.append(
            create_error_msg(
                "slurm_cluster",
                slurm_cluster_not_fg,
                f"Slurm cluster mentioned in functional_groups not in omnia_config.yml - {', '.join(slurm_cluster_not_fg)}"))

    k8s_cluster_not_fg = set(kube_clusters) - set(service_k8s_cluster)
    if k8s_cluster_not_fg:
        errors.append(
            create_error_msg(
                "slurm_cluster",
                k8s_cluster_not_fg,
                f"Service_k8s cluster mentioned in functional_groups not in omnia_config.yml - {', '.join(k8s_cluster_not_fg)}"))

    slurm_cluster_not_in_control = set(slurm_node_clusters) - set(slurm_control_clusters)
    if slurm_cluster_not_in_control:
        errors.append(create_error_msg("slurm_cluster", "slurm node not in slurm control",
                                       en_us_validation_msg.SLURM_NODE_WITHOUT_CONTROL_MSG.format(
                                           cluster=", ".join(slurm_cluster_not_in_control))
                                       ))

    login_cluster_not_in_control = set(login_clusters) - set(slurm_control_clusters)
    if login_cluster_not_in_control:
        errors.append(create_error_msg("slurm_cluster", "login not in slurm control",
                                       en_us_validation_msg.LOGIN_NODE_WITHOUT_SLURM_MSG.format(
                                           cluster=', '.join(login_cluster_not_in_control))
                                       ))

    # Slurm clusters cannot overlap with kube clusters
    overlap = slurm_union & kube_clusters
    if overlap:
        errors.append(
            create_error_msg("functional_groups", "Cluster overlap",
                             en_us_validation_msg.SLURM_KUBE_CLUSTER_OVERLAP_MSG.format(
                                 cluster=", ".join(overlap))
                             ))

    return errors

# Slurm node parent validation

def validate_slurm_node_parent(functional_groups, groups):
    """
    Validates the parent field for Slurm nodes in functional groups.

    Parameters:
        functional_groups (list): A list of dictionaries, where each dictionary represents a functional group.
        groups (dict): A dictionary of groups where each key is the group name and the value is the group data.

    Returns:
        list: A list of error messages.
    """
    errors = []

    # Check if "service_kube_node_x86_64" exists
    service_kube_present = any(
        fg.get("name", "") == "service_kube_node_x86_64" for fg in functional_groups
    )
    for fg in functional_groups:
        name = fg.get("name", "")
        if "slurm_node" in name:
            for gref in fg.get("group", []):
                parent = groups.get(gref, {}).get("parent", "")

                # Only require parent if service_kube_node_x86_64 exists
                if service_kube_present and not parent:
                    errors.append(
                        create_error_msg(
                            name,
                            gref,
                            en_us_validation_msg.SLURM_NODE_PARENT_MISSING_MSG.format(name=name)
                        )
                    )
    return errors

# Software mapping validation (unchanged)
def validate_software_section_mappings(functional_groups, software_data):
    """
    Validates the software section mappings for a given list of functional groups and software data.

    Parameters:
        functional_groups (list): A list of dictionaries,
        where each dictionary contains information about a functional group.
        software_data (dict): A dictionary containing software data, including a list of softwares.

    Returns:
        list: A list of error messages.
    """
    errors = []

    softwares_list = software_data.get("softwares", [])
    slurm_section = software_data.get("slurm_custom", [])

    sw_requirements = {
        "service_kube_node": ["service_k8s", "nfs"],
        "slurm_control_node": ["slurm_custom", "nfs"],
        "slurm_node": ["slurm_custom", "nfs"],
        "login_node": ["slurm_custom", "nfs", "openldap"],
        "login_compiler_node": ["slurm_custom", "nfs", "openldap"],
    }

    aarch_supported = {"slurm_custom", "nfs"}

    for fg in functional_groups:
        fg_name = fg.get("name", "")
        arch = extract_arch_from_fg(fg_name)
        base_fg_name = fg_name[: -len("_" + arch)] if arch else fg_name

        required_softwares = sw_requirements.get(base_fg_name, [])

        for sw in required_softwares:
            if arch == "aarch64" and sw not in aarch_supported:
                continue
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

        expected_slurm_entry = None
        if base_fg_name in ["slurm_control_node",
                            "slurm_node", "login_node", "login_compiler_node"]:
            expected_slurm_entry = "login_node" if "login" in base_fg_name else base_fg_name
        if expected_slurm_entry and not key_value_exists(
                slurm_section, "name", expected_slurm_entry):
            errors.append(
                create_error_msg(
                    fg_name,
                    expected_slurm_entry,
                    f"For Functional group '{fg_name}', slurm entry: 'slurm_custom': [{{'name': '{expected_slurm_entry}'}}] missing in software_config.json. Please add the missing entry and try again."
                )
            )

    return errors

# ----------------------------
# Main validator
# ----------------------------


def validate_functional_groups_config(
        input_file_path, data, logger, _module, _omnia_base_dir, _module_utils_base, _project_name):
    errors = []

    # Top-level checks
    errors.extend(validate_top_level(data))
    if errors:
        return errors

    groups = data.get("groups", {})
    functional_groups = data.get("functional_groups", [])

    # Groups structure
    errors.extend(validate_groups_structure(groups))
    if errors:
        return errors

    # Functional groups structure
    errors.extend(validate_functional_groups_structure(functional_groups, groups))
    if errors:
        return errors

    # Modular validations
    errors.extend(validate_functional_group_duplicates(functional_groups))
    errors.extend(validate_functional_groups_separation(functional_groups))s
    errors.extend(validate_non_empty_clustername(functional_groups))
    errors.extend(validate_slurm_k8s_clusters(functional_groups, input_file_path))
    errors.extend(validate_slurm_node_parent(functional_groups, groups))

    # Software validation
    software_file = create_file_path(input_file_path, "software_config.json")
    software_json = load_json(software_file)
    errors.extend(validate_software_section_mappings(functional_groups, software_json))
    return errors
