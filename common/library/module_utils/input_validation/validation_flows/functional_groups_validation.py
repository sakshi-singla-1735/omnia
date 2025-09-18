"""
This module contains functions for validating functional_groups_config.yml
"""

from ansible.module_utils.input_validation.common_utils import validation_utils
from ansible.module_utils.input_validation.common_utils import config
from ansible.module_utils.input_validation.common_utils import en_us_validation_msg

create_error_msg = validation_utils.create_error_msg

# --- Duplicate check for functional groups ---
def validate_functional_group_duplicates(functional_groups):
    errors = []
    seen_combinations = set()
    for idx, group in enumerate(functional_groups):
        key = (group.get("name", ""), group.get("location_id", ""), group.get("cluster_name", ""))
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
        "service_kube_node_x86_64"
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

# --- SLURM/K8s cluster validations ---
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

# --- Top-level validation ---
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

# --- Parent validation for slurm_node ---

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

# --- Functional group structure validation ---
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

        # Required fields
        for field in ["name", "location_id", "cluster_name", "parent"]:
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

# --- Main validator ---
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
    errors.extend(validate_slurm_node_parent(functional_groups))


    return errors
