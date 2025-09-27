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

# pylint: disable=import-error,no-name-in-module,line-too-long
#!/usr/bin/python

import re
import pandas as pd
import yaml
from ansible.module_utils.basic import AnsibleModule
from string import ascii_lowercase

def generate_alpha_sequence(n, start='b'):
    """Generate alphabetical strings starting from 'b': b, c, ..., z, ba, bb, ..."""
    result = []
    start_index = ascii_lowercase.index(start)
    i = 0
    while len(result) < n:
        s = ''
        temp = i
        while temp >= 0:
            s = ascii_lowercase[temp % 26 + start_index] + s
            temp = temp // 26 - 1
        result.append(s)
        i += 1
    return result


def load_functional_groups_yaml(path, module):
    """Load functional group names from YAML."""
    try:
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        return set(
            fg.get("name") if isinstance(fg, dict) else str(fg)
            for fg in data.get("functional_groups", [])
        )
    except Exception as e:
        module.fail_json(msg=f"Failed to load functional_groups_config.yml: {str(e)}")

def load_groups_yaml(path, module):
    """Load group names from YAML and return as a set."""
    try:
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        return set(data.get("groups", {}).keys())
    except Exception as e:
        module.fail_json(msg=f"Failed to load groups_config.yml: {str(e)}")

def check_functional_groups_in_mapping(csv_file, config_fgs, module):
    """Check that all functional groups in mapping file exist in functional_groups YAML."""
    mapping_fgs = set(csv_file['FUNCTIONAL_GROUP_NAME'].str.strip().unique())
    missing_fgs = mapping_fgs - config_fgs
    if missing_fgs:
        module.fail_json(
            msg=f"The following FUNCTIONAL_GROUP_NAME(s) are missing in functional_groups_config.yml: {', '.join(missing_fgs)}"
        )

def check_groups_in_mapping(csv_file, config_gs, module):
    mapping_gs = set(csv_file['GROUP_NAME'].str.strip().unique())
    missing_gs = mapping_gs - config_gs
    if missing_gs:
        module.fail_json(
            msg=f"The following GROUP_NAME(s) are missing in groups_config.yml: {', '.join(missing_gs)}"
        )


def validate_mapping_file(mapping_file_path, functional_groups_file, module):
    """
    Validate CSV mapping file:
        - Mandatory columns
        - Non-null values
        - MAC addresses format
        - Service tags
        - Functional groups existence in YAML
    """
    try:
        csv_file = pd.read_csv(mapping_file_path)
        if len(csv_file) == 0:
            module.fail_json(msg="Please provide details in mapping file.")

        # Strip whitespace from column values and names
        csv_file = csv_file.apply(lambda x: x.str.strip() if x.dtype == 'object' else x)
        csv_file.columns = csv_file.columns.str.strip()

        # Validate columns
        mandatory_col = ["FUNCTIONAL_GROUP_NAME", "GROUP_NAME", "SERVICE_TAG", "ADMIN_MAC", "HOSTNAME", "ADMIN_IP", "BMC_MAC", "BMC_IP"]
        for col in mandatory_col:
            if col not in csv_file.columns:
                module.fail_json(msg=f"Missing mandatory column: {col} in mapping file.")

        # Validate non-null values
        for col in mandatory_col:
            if csv_file[col].isnull().values.any():
                module.fail_json(msg=f"Null values found in column: {col} in mapping file.")

        # Validate service tags
        for st in csv_file['SERVICE_TAG']:
            if not st.isalnum():
                module.fail_json(msg=f"Invalid service tag: {st} in mapping file.")

        # Validate MAC addresses
        pattern = r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$"
        for mac in csv_file['ADMIN_MAC']:
            if not re.match(pattern, mac):
                module.fail_json(msg=f"Invalid ADMIN_MAC: {mac} in mapping file.")

        for mac in csv_file['BMC_MAC']:
            if not re.match(pattern, mac):
                module.fail_json(msg=f"Invalid BMC_MAC: {mac} in mapping file.")

        # Validate functional groups presence in YAML
        config_fgs = load_functional_groups_yaml(functional_groups_file, module)
        config_gs = load_groups_yaml(functional_groups_file, module)
        check_functional_groups_in_mapping(csv_file, config_fgs, module)
        check_groups_in_mapping(csv_file, config_gs, module)

        # The resulting XNAME values will have the format 'x1000c0s<d><b><d>n0', where <b> is a letter and <d> is a digit
        xname_values = []
        alpha_sequence = generate_alpha_sequence(100)  # 100 groups of 10 = 1000 entries

        for i in range(len(csv_file)):
            group_index = i // 10
            digit = i % 10
            alpha_part = alpha_sequence[group_index]
            num_part = group_index + 1
            xname = f'x1000c0s{num_part}{alpha_part}{digit}n0'
            xname_values.append(xname)

        csv_file['XNAME'] = xname_values

        # Update the mapping file with the new XNAME values
        csv_file.to_csv(mapping_file_path, index=False)

        # If all checks pass
        module.exit_json(changed=False, msg="Mapping file is valid")

    except Exception as e:
        module.fail_json(msg=str(e))

def main():
    """
	Validate a mapping file.

	Parameters:
		mapping_file_path (str): The path to the mapping file.
        functional_groups_file_path (str): The path to the functional_groups file.

	"""
    module_args = {
        'mapping_file_path': {'type': 'path', 'required': True },
        'functional_groups_file_path': {'type': 'path', 'required': True }
    }

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=False)
    mapping_file_path = module.params.get('mapping_file_path')
    functional_groups_file_path = module.params["functional_groups_file_path"]

    validate_mapping_file(mapping_file_path, functional_groups_file_path, module)


if __name__ == "__main__":
    main()
