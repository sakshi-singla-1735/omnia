# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
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
Ansible module to find the network interface in a given subnet
and update kube_vip_interface and kube_vip_cidr in the kube_control_plane group
of the inventory file.
"""

import ipaddress
import re
from ansible.module_utils.basic import AnsibleModule


def update_kube_control_plane_block(inventory_path, hostname, matched_iface, prefix_len):
    """Update or append kube_vip_interface and kube_vip_cidr for the given host in the kube_control_plane group."""
    with open(inventory_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    in_control_plane = False
    updated = False

    for i, line in enumerate(lines):
        stripped = line.strip()

        if stripped.startswith('['):
            in_control_plane = stripped == "[kube_control_plane]"

        if in_control_plane and re.match(rf"^{re.escape(hostname)}\b", stripped):
            # Start with the current line
            new_line = stripped

            # Update or append kube_vip_interface
            if 'kube_vip_interface=' in new_line:
                new_line = re.sub(r'kube_vip_interface=\S+', f'kube_vip_interface={matched_iface}', new_line)
            else:
                new_line += f' kube_vip_interface={matched_iface}'

            # Update or append kube_vip_cidr
            if 'kube_vip_cidr=' in new_line:
                new_line = re.sub(r'kube_vip_cidr=\S+', f'kube_vip_cidr={prefix_len}', new_line)
            else:
                new_line += f' kube_vip_cidr={prefix_len}'

            # Update in-memory lines
            lines[i] = new_line + "\n"
            updated = True
            break

    if updated:
        with open(inventory_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)

    return updated


def run_module():
    """Main module logic."""
    module_args = {
        "interfaces": {"type": "dict", "required": True},
        "subnet": {"type": "str", "required": True},
        "hostname": {"type": "str", "required": True},
        "inventory_path": {"type": "str", "required": True}
    }

    result = {
        "changed": False,
        "matched_interface": None,
        "vip_cidr": None,
        "updated_inventory": False,
        "msg": ""
    }

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    interfaces = module.params['interfaces']
    subnet = module.params['subnet']
    hostname = module.params['hostname']
    inventory_path = module.params['inventory_path']

    try:
        network = ipaddress.ip_network(subnet, strict=False)
        prefix_len = network.prefixlen
        matched_iface = None

        for iface_name, iface_data in interfaces.items():
            if 'ipv4' in iface_data and 'address' in iface_data['ipv4']:
                ip = iface_data['ipv4']['address']
                if ipaddress.ip_address(ip) in network:
                    matched_iface = iface_name
                    break

        if matched_iface:
            result["matched_interface"] = matched_iface
            result["vip_cidr"] = prefix_len
            if not module.check_mode:
                updated = update_kube_control_plane_block(inventory_path, hostname, matched_iface, prefix_len)
                result["updated_inventory"] = updated
                result["changed"] = updated
            result["msg"] = f"Matched interface {matched_iface} with CIDR /{prefix_len} and updated kube_control_plane group."
        else:
            result["msg"] = "No matching interface found."

    except Exception as e:
        module.fail_json(msg=f"Failed: {e}")

    module.exit_json(**result)


def main():
    """Entry point."""
    run_module()


if __name__ == '__main__':
    main()
