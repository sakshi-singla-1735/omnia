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

# pylint: disable=import-error,no-name-in-module
#!/usr/bin/python

import os
from datetime import datetime
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.local_repo.standard_logger import setup_standard_logger
from ansible.module_utils.local_repo.common_functions import(
    get_arch_from_sw_config
)
from ansible.module_utils.local_repo.software_utils  import (
    get_software_names,
    check_csv_existence,
    get_failed_software,
    get_csv_file_path,
    get_csv_software,
    process_software,
    load_json,
    load_yaml,
    get_json_file_path,
    transform_package_dict,
    parse_repo_urls,
    set_version_variables,
    get_subgroup_dict
)

# Import configuration constants individually (excluding fresh_installation_status)
from ansible.module_utils.local_repo.config import (
    CSV_FILE_PATH_DEFAULT,
    USER_JSON_FILE_DEFAULT,
    LOCAL_REPO_CONFIG_PATH_DEFAULT,
    ROLES_CONFIG_PATH_DEFAULT,
    LOG_DIR_DEFAULT,
    SOFTWARE_CSV_FILENAME,
    ARCH_SUFFIXES
)

def main():
    """
    Prepares package lists and processes software based on user and repository configurations.

    This function initializes the module arguments and logger. It loads user data from a JSON file
    and repository configuration from a YAML file, retrieves cluster OS details, and determines the list
    of software. It then computes a boolean flag for fresh installation based on the CSV file's existence.
    For new software, the flag is enforced to True. The software is then processed, and the package tasks
    are aggregated and returned.
    """

    module_args = {
        "csv_file_path": {"type": "list", "elements": "str", "required": False, "default": CSV_FILE_PATH_DEFAULT},
        "user_json_file": {"type": "str", "required": False, "default": USER_JSON_FILE_DEFAULT},
        "local_repo_config_path": {"type": "str", "required": False, "default": LOCAL_REPO_CONFIG_PATH_DEFAULT},
        "roles_config_path": {"type": "str", "required": False, "default": ROLES_CONFIG_PATH_DEFAULT},
        "log_dir": {"type": "str", "required": False, "default": LOG_DIR_DEFAULT},
        "key_path": {"type": "str", "required": True}
    }

    module = AnsibleModule(argument_spec=module_args)
    log_dir = module.params["log_dir"]
    user_json_file = module.params["user_json_file"]
    local_repo_config_path = module.params["local_repo_config_path"]
    roles_config_path = module.params["roles_config_path"]
    csv_file_path = module.params["csv_file_path"]
    vault_key_path = module.params["key_path"]
    logger = setup_standard_logger(log_dir)
    start_time = datetime.now().strftime("%I:%M:%S %p")
    logger.info(f"Start execution time: {start_time}")

    try:
        user_data = load_json(user_json_file)
        repo_config_data = load_yaml(local_repo_config_path)
        roles_config_data = load_yaml(roles_config_path)

        cluster_os_type = user_data['cluster_os_type']
        cluster_os_version = user_data['cluster_os_version']
        repo_config = user_data['repo_config']

        # Append the CSV filename from config (e.g. "software.csv")
        complete_csv_file_path = []       
        for path in csv_file_path:
            for arch in ARCH_SUFFIXES:
                full_path = os.path.join(path, arch, SOFTWARE_CSV_FILENAME)
                complete_csv_file_path.append(full_path)


        software_list = get_software_names(user_json_file)
        logger.info(f"software_list from software_config: {software_list}")

        # Compute fresh_installation as a boolean based on CSV file existence
        # first need to chk all possible arch values
        fresh_installation = True if not check_csv_existence(complete_csv_file_path) else False
        logger.info(f"Fresh install: {fresh_installation}")

        csv_softwares = {}
        new_softwares = {}
        
        if not fresh_installation:
            for arch in ARCH_SUFFIXES:
                arch_csv_paths = [
                    os.path.join(path, arch, SOFTWARE_CSV_FILENAME)
                    for path in csv_file_path
                ]
                arch_csv_software = get_csv_software(arch_csv_paths)
                csv_softwares[arch] = arch_csv_software
                logger.info(f"Software from {arch} CSVs: {arch_csv_software}")

                new_softwares[arch] = [
                    software for software in software_list if software not in arch_csv_software
                ]
                logger.info(f"New software list for {arch}: {new_softwares[arch]}")

            logger.info(f"new software list: {new_softwares}")

        # Build a dictionary mapping software names to subgroup data, if available
        subgroup_dict, software_names = get_subgroup_dict(user_data)
        version_variables = set_version_variables(user_data, software_names, cluster_os_version)
        software_dict = {}
        sw_arch_map = {}

        logger.info("Preparing package lists...")
        for software in software_list:
            logger.info(f"Processing software: {software}")
            logger.info(f"csv_file_path for software: {complete_csv_file_path}")
            
            sw_arch_map.update(get_arch_from_sw_config(software, user_data, roles_config_data))
            logger.info(f"Softwares mapped to architecture: {sw_arch_map}") #Softwares mapped to architecture: {'amdgpu': ['x86_64'], 'k8s': ['aarch64', 'x86_64']}
            sw_architectures = sw_arch_map.get(software, [])
            json_paths = get_json_file_path(software, cluster_os_type, cluster_os_version, user_json_file, sw_architectures)
            csv_paths = get_csv_file_path(software, log_dir, sw_arch_map)
            logger.info(f"csv_path(s): {csv_paths}")
            
            for json_path, csv_path in zip(json_paths, csv_paths):
                if not json_path:
                    logger.warning(f"Skipping {software}: JSON path does not exist.")
                    continue
                
                # Check if software is new in any of its architectures
                if new_softwares:
                    fresh_installation = any(software in new_softwares.get(arch, []) for arch in sw_arch_map)
                else:
                    fresh_installation = True

                logger.info(f"{software} (archs: {sw_arch_map}) - Fresh install: {fresh_installation}")
                logger.info(f"{software}: JSON Path: {json_path}, CSV Path: {csv_path}, Fresh Install: {fresh_installation}")
                logger.info(f"Subgroup Data: {subgroup_dict.get(software, None)}")
                logger.info(f"Whole Subgroup Data: {subgroup_dict}")
                logger.info(f"json_path: {json_path}")
                logger.info(f"csv_path: {csv_path}")

                failed_tasks,new_tasks,status_csv_rows, all_input_packages = process_software(software, fresh_installation, json_path, csv_path, subgroup_dict.get(software, None))
                
                logger.info(f"Processed status_csv_rows : {status_csv_rows}")
                logger.info(f"all_input_packages : {all_input_packages}")
                logger.info(f"Failed_tasks : {failed_tasks}")
                logger.info(f"new_tasks : {new_tasks}")
                
                #Combine all tasks
                if fresh_installation:
                    tasks = all_input_packages
                else:
                    tasks = failed_tasks + new_tasks

                if not tasks:
                    continue

                software_dict[software] = tasks

        software_dict=transform_package_dict(software_dict, sw_arch_map)
        local_config, url_result = parse_repo_urls(repo_config, local_repo_config_path , version_variables, vault_key_path, sw_arch_map)
        if not url_result:
            module.fail_json(f"{local_config} is not reachable or invalid, please check and provide correct URL")

        logger.info(f"Package processing completed: {software_dict}")
        module.exit_json(changed=False, software_dict=software_dict, local_config=local_config)

    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")
        module.fail_json(msg=str(e))

if __name__ == "__main__":
    main()
