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

"""Ansible module to check telemetry service cluster node details."""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.discovery.omniadb_connection import get_data_from_db # type: ignore

def get_service_cluster_node_details(host_inventory):
    """
    This function retrieves all service cluster node data from the database.
    Returns a dictionary of service cluster node data.
    """
    query_result = get_data_from_db(
        table_name='cluster.nodeinfo',
        filter_dict = {'role': ['service_kube_node', 'service_etcd', 'service_kube_control_plane']}
    )

    data = {}
    not_available_nodes = {}
    failed_nodes = []

    for sn in query_result:
        node = sn['node']
        status = sn.get('status', '')
        admin_ip = sn['admin_ip']
        service_tag = sn['service_tag']
        cluster_name = sn['cluster_name']
        role = sn['role']

        if status != 'booted':
            not_available_nodes[service_tag] = admin_ip
            continue

        if admin_ip in host_inventory:
            data[service_tag] = {
                'admin_ip': admin_ip,
                'service_tag': service_tag,
                'node': node,
                'cluster_name': cluster_name,
                'role': role
            }

            data[service_tag]['parent_status'] = 'service_kube_control_plane' in role

    for service_tag, ip in not_available_nodes.items():
        if ip in host_inventory:
            failed_nodes.append(service_tag)

    if failed_nodes:
        raise ValueError(
            f"The following service cluster nodes are not in 'booted' state: {', '.join(failed_nodes)}."
            "Please verify the node status and try again."
            "For federated telemetry collection of compute nodes, service cluster nodes must be available and in the 'booted' state."
            "Please wait until all service cluster nodes are booted, or remove the nodes experiencing "
            "provisioning failures using the utils/delete_node.yml playbook."
        )
    return data

def check_service_cluster_node_details(group, parent, service_cluster_node_details):
    """Check if service cluster node details are available."""

    if not parent:
        return False
    if parent in service_cluster_node_details:
        return True
    raise ValueError(
            f"Error: The service tag '{parent}' specified in the 'parent' field for group '{group}' "
            "may be incorrect, or the node might not be available. "
            "Please verify the input and try again."
        )

def get_service_cluster_data(groups_info, service_cluster_node_details, bmc_group_data):
    """
    Generate service cluster node details by analyzing group relationships and BMC group data.

    This function checks the service cluster node details for each group,
    and adds child group data to service_cluster_node_details. It also checks
    if a parent has child groups in the bmc_group_data and adds them to the parent_data.

    Args:
        groups_info (dict): Dictionary containing group information.
        service_cluster_node_details (dict): Dictionary containing service cluster node information.
        bmc_group_data (list): List of dictionaries containing BMC group data.

    Returns:
        dict: Updated service_cluster_node_details.
    """

    for group, group_data in groups_info.items():
        parent = group_data.get('parent', '')
        status = check_service_cluster_node_details(group, parent, service_cluster_node_details)

        if not status:
            continue

        parent_data = service_cluster_node_details.get(parent, {})
        parent_data.setdefault('child_groups', [])

        # Add current group to child_groups
        if group not in parent_data['child_groups']:
            parent_data['child_groups'].append(group)

        # Add child groups from bmc_group_data
        for entry in bmc_group_data:
            if entry.get('PARENT') == parent:
                bmc_group = entry.get('GROUP_NAME')
                if bmc_group and bmc_group not in parent_data['child_groups']:
                    parent_data['child_groups'].append(bmc_group)

        # Set parent_status if there are any child groups
        if parent_data['child_groups']:
            parent_data['parent_status'] = True
        service_cluster_node_details[parent] = parent_data

    return service_cluster_node_details

def main():
    """
        Main function to execute the check_service_cluster_node_details custom module.
    """
    module_args = {
        'groups_info': {'type':"dict", 'required':True},
        'host_inventory': {'type':"list", 'required':True},
        'bmc_group_data': {'type':"list", 'required':True}
    }

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    try:
        groups_info = module.params["groups_info"]
        host_inventory = module.params["host_inventory"]
        bmc_group_data = module.params["bmc_group_data"]
        service_cluster_node_details = get_service_cluster_node_details(host_inventory)
        service_cluster_node_details = get_service_cluster_data(groups_info, service_cluster_node_details, bmc_group_data)

        module.exit_json(
            changed=False,
            service_cluster_node_details = service_cluster_node_details
        )
    except ValueError as e:
        module.fail_json(msg=str(e).replace('\n', ' '))

if __name__ == "__main__":
    main()
