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

from ansible.module_utils.basic import AnsibleModule

def main():
    """
	Validate a mapping file.

	Parameters:
		mapping_file_path (str): The path to the mapping file.

	"""

    module_args = {
        'mapping_file_path': {'type': 'path', 'required': True }
    }


    module = AnsibleModule(argument_spec=module_args, supports_check_mode=False)


    mapping_file_path = module.params.get('mapping_file_path')

    # Validate the mapping file
    try:
        csv_file = pd.read_csv(mapping_file_path)
        if len(csv_file) == 0:
            module.fail_json(msg="Please provide details in mapping file.")

        # Strip whitespace from column values and names
        csv_file = csv_file.apply(lambda x: x.str.strip() if x.dtype == 'object' else x)
        csv_file.columns = csv_file.columns.str.strip()

        # Validate columns
        mandatory_col = ["FUNCTIONAL_GROUP_NAME", "SERVICE_TAG", "ADMIN_MAC", "HOSTNAME", "ADMIN_IP", "BMC_MAC", "BMC_IP"]
        for col in mandatory_col:
            if col not in csv_file.columns:
                module.fail_json(msg=f"Missing mandatory column: {col}")

        non_null_col = ["FUNCTIONAL_GROUP_NAME", "SERVICE_TAG", "ADMIN_MAC", "HOSTNAME", "ADMIN_IP", "BMC_MAC", "BMC_IP"]
        for col in non_null_col:
            if csv_file[col].isnull().values.any():
                module.fail_json(msg=f"Null values found in column: {col}")

        # Validate service tags
        for st in csv_file['SERVICE_TAG']:
            if not st.isalnum():
                module.fail_json(msg=f"Invalid service tag: {st}")

        # Validate MAC addresses
        pattern = r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$"
        for mac in csv_file['ADMIN_MAC']:
            if not re.match(pattern, mac):
                module.fail_json(msg=f"Invalid ADMIN_MAC: {mac}")

        for mac in csv_file['BMC_MAC']:
            if not re.match(pattern, mac):
                module.fail_json(msg=f"Invalid ADMIN_MAC: {mac}")

        # If all checks pass
        module.exit_json(changed=False, msg="Mapping file is valid")

    except Exception as e:
        module.fail_json(msg=str(e))

if __name__ == '__main__':
    main()
