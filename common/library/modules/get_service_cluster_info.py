# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

# pylint: disable=import-error,no-name-in-module,line-too-long

#!/usr/bin/python

"""Ansible module to check hierarchical provisioning status and service node HA configuration."""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.discovery.omniadb_connection import get_data_from_db # type: ignore

def get_booted_service_nodes_data():
    """
    This function retrieves all service node data from the database
    and ensures they are all in 'booted' state. If not, it raises an error.
    Returns a dictionary of booted service node data.
    """
    query_result = get_data_from_db(
        table_name='cluster.nodeinfo',
        filter_dict = {'role': ['service_kube_node', 'service_etcd', 'service_kube_control_plane']}
    )

    data = {}
    not_booted_nodes = []

    for sn in query_result:
        node = sn['node']
        status = sn.get('status', '')
        admin_ip = sn['admin_ip']
        service_tag = sn['service_tag']
        cluster_name = sn['cluster_name']

        if status != 'booted':
            not_booted_nodes.append(service_tag)
            continue

        data[service_tag] = {
            'admin_ip': admin_ip,
            'service_tag': service_tag,
            'node': node,
            'cluster_name': cluster_name
        }

    if not_booted_nodes:
        raise ValueError(
            f"The following service nodes are not in the 'booted' state: "
            f"{', '.join(not_booted_nodes)}. "
            "For hierarchical provisioning of compute nodes or adding new management layer nodes, "
            "all service nodes initiated for provisioning must be in the 'booted' state. "
            "Please wait until all service nodes are booted, or remove the nodes experiencing "
            "provisioning failures using the utils/delete_node.yml playbook."
        )
    return data

def check_hierarchical_provision(group, parent, booted_service_nodes_data):
    """Check if hierarchical provisioning is required."""

    if not parent:
        return False
    if parent in booted_service_nodes_data:
        return True
    raise ValueError(
            f"Error: The service tag '{parent}' specified in the 'parent' field for group '{group}' "
            "in roles_config.yml may be incorrect, or the node might not have been provisioned. "
            "Please verify the input in roles_config.yml and execute discovery_provision.yml playbook "
            "with the 'management_layer' tag to provision service nodes."
        )

def get_hierarchical_data(groups_roles_info, booted_service_nodes_data):
    """
    Generate hierarchical data from groups_roles_info and booted_service_nodes_data.

    This function checks the hierarchical provisioning status for each group,
    updates the groups_roles_info with the status, and adds child group data
    to booted_service_nodes_data.

    Args:
        groups_roles_info (dict): Dictionary containing group information.
        booted_service_nodes_data (dict): Dictionary containing booted service node information.

    Returns:
        tuple: A tuple containing:
            - updated groups_roles_info (dict)
            - updated booted_service_nodes_data (dict)
            - hierarchical_provision_status (dict)
    """


    hierarchical_provision_status = False

    for group, group_data in groups_roles_info.items():
        parent = group_data.get('parent', '')
        status = check_hierarchical_provision(group, parent, booted_service_nodes_data)
        hierarchical_provision_status = hierarchical_provision_status or status

        if not status:
            groups_roles_info[group]['hierarchical_provision_status'] = False
            continue

        parent_data = booted_service_nodes_data.get(parent, {})
        parent_data.setdefault('child_groups', []).append(group)
        booted_service_nodes_data[parent] = parent_data
        groups_roles_info[group]['hierarchical_provision_status'] = hierarchical_provision_status

    return groups_roles_info, booted_service_nodes_data, hierarchical_provision_status

def main():
    """
        Main function to execute the check_hierarchical_provision custom module.
    """
    module_args = {
        'groups_roles_info': {'type':"dict", 'required':True}
    }

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    try:
        groups_roles_info = module.params["groups_roles_info"]
        booted_service_nodes_data = get_booted_service_nodes_data()
        groups_roles_info, booted_service_nodes_data, hierarchical_provision_status  = \
            get_hierarchical_data(groups_roles_info, booted_service_nodes_data)

        module.exit_json(
            changed=False,
            hierarchical_provision_status = hierarchical_provision_status,
            booted_service_nodes_data = booted_service_nodes_data,
            groups_roles_info = groups_roles_info
        )
    except ValueError as e:
        module.fail_json(msg=str(e).replace('\n', ' '))

if __name__ == "__main__":
    main()
