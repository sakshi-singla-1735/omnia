from ansible.module_utils.basic import AnsibleModule
import yaml
import csv
import os

def main():
    module_args = dict(
        service_cluster_metadata=dict(type="dict", required=True),
        parent_to_bmc_ip_details=dict(type="dict", required=True)
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    service_cluster_metadata = module.params["service_cluster_metadata"]
    module.warn(f"Service Cluster metadata path: {service_cluster_metadata}")
    parent_to_bmc_ip_details = module.params["parent_to_bmc_ip_details"]

    if not service_cluster_metadata:
        module.fail_json(f"Service cluster metadata is required but not provided.")
    if not parent_to_bmc_ip_details:
        module.fail_json(msg="BMC group data list is required but not provided.")

    if not isinstance(service_cluster_metadata, dict):
        module.fail_json(f"service_cluster_metadata should be a dictionary, got {type(service_cluster_metadata)}")
    if not isinstance(parent_to_bmc_ip_details, dict):
        module.fail_json(f"bmc_group_data_list should be a list, got {type(parent_to_bmc_ip_details)}")  
 
    module.warn(f"Loaded service cluster metadata: {service_cluster_metadata}")
    module.warn(f"Loaded BMC group data: {parent_to_bmc_ip_details}")

    # Step 1: Find child_groups for that service tag
    idrac_podname_ips = {}

    for node in service_cluster_metadata.values():
        if node.get("service_tag"): # and node.get("parent_status") == "true":
            idrac_podname = node.get("idrac_podname")
            target_tag = node.get("service_tag")

            if not idrac_podname or not target_tag:
                module.warn(f"Missing idrac_podname or service_tag in service nodes metadata.")
                continue

            if target_tag in parent_to_bmc_ip_details:
                bmc_group_data_list = parent_to_bmc_ip_details.get(target_tag, [])
                if not bmc_group_data_list:
                    module.warn(f"No BMC group data found for service tag {target_tag}.")
                    continue
                else:
                    module.warn(f"Found BMC group data for service tag {target_tag}: {bmc_group_data_list}")
                    idrac_podname_ips[idrac_podname] = bmc_group_data_list

        # elif node.get("parent_status") == "false":
        #     idrac_podname = node.get("idrac_podname")
        #     if idrac_podname:
        #         idrac_podname_ips[idrac_podname] = parent_to_bmc_ip_details.get('oim', [])


    module.exit_json(
        changed=False,
        idrac_podname_ips=idrac_podname_ips
    )

if __name__ == "__main__":
    main()
