# Copyright 2026 Dell Inc. or its subsidiaries. All Rights Reserved.
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

#!/usr/bin/python

from collections import OrderedDict
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.input_validation.common_utils.slurm_conf_utils import SlurmParserEnum, all_confs
import os

# NOTE: depends on python3.7+ where dict order is maintained


def read_dict2ini(conf_dict):
    data = []
    for k, v in conf_dict.items():
        if isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    data.append(
                        " ".join(f"{key}={value}" for key, value in item.items()))
                else:
                    data.append(f"{k}={item}")
        else:
            data.append(f"{k}={v}")
    return data


def parse_slurm_conf(file_path, module):
    """Parses the slurm.conf file and returns it as a dictionary."""
    # slurm_dict = {"NodeName": [], "PartitionName": []}
    conf_name = module.params['conf_name']
    current_conf = all_confs.get(conf_name)
    slurm_dict = OrderedDict()

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"{file_path} not found.")

    with open(file_path, 'r') as f:
        for line in f:
            # handles any comment after the data
            line = line.split('#')[0].strip()

            # Skip comments and empty lines
            if not line:
                continue
            # Split the line by one or more spaces
            items = line.split()
            tmp_dict = OrderedDict()
            for item in items:
                # module.warn(f"Item: {item}")
                # Split only on the first '=' to allow '=' inside the value
                key, value = item.split('=', 1)
                tmp_dict[key.strip()] = value.strip()
            skey = list(tmp_dict.keys())[0]
            if skey not in current_conf:
                raise Exception(f"Invalid key while parsing {file_path}: {skey}")
            # if current_conf[skey] == SlurmParserEnum.S_P_ARRAY or len(tmp_dict) > 1:
            if current_conf[skey] == SlurmParserEnum.S_P_ARRAY:
                # TODO hostlist expressions and multiple DEFAULT entries handling
                # if len(tmp_dict) == 1:
                #     first_key = list(tmp_dict.keys())[0]
                #     first_value = list(tmp_dict.values())[0]
                #     slurm_dict[first_key] = list(
                #         slurm_dict.get(first_key, [])) + [first_value]
                # else:
                slurm_dict[list(tmp_dict.keys())[0]] = list(
                        slurm_dict.get(list(tmp_dict.keys())[0], [])) + [tmp_dict]
            else:
                # TODO handle csv values, currently no definite data type for csv values
                slurm_dict.update(tmp_dict)

    return slurm_dict


def slurm_conf_dict_merge(conf_dict_list, module):
    merged_dict = OrderedDict()
    for conf_dict in conf_dict_list:
        for ky, vl in conf_dict.items():
            if isinstance(vl, list):
                for item in vl:
                    if isinstance(item, dict):
                        module.warn(f"DICT Key: {ky}, Value: {vl}")
                        existing_dict = merged_dict.get(ky, {})
                        inner_dict = existing_dict.get(item.get(ky), {})
                        inner_dict.update(item)
                        # TODO Partition node combiner logic
                        existing_dict[item.get(ky)] = inner_dict
                        merged_dict[ky] = existing_dict
                    else:
                        module.warn(f"LIST Key: {ky}, Value: {vl}")
                        existing_list = merged_dict.get(ky, [])
                        module.warn(f"Existing list: {existing_list}")
                        module.warn(f"Item: {item}")
                        if item not in existing_list:
                            # existing_list.append(item)
                            existing_list.update(item)
                        module.warn(f"Updated list: {existing_list}")
                        merged_dict[ky] = existing_list
            else:
                merged_dict[ky] = vl
    # flatten the dict
    merged_dict = {
        k: list(v.values()) if isinstance(v, dict) else v
        for k, v in merged_dict.items()
    }
    return merged_dict


def run_module():
    module_args = {
        "path": {'type': 'str'},
        "op": {'type': 'str', 'required': True, 'choices': ['f2d', 'd2f', 'merge']},
        "conf_map": {'type': 'dict', 'default': {}},
        "conf_sources": {'type': 'list', 'elements': 'raw', 'default': []},
        "conf_name": {'type': 'str', 'default': 'slurm'}
    }

    result = dict(
        changed=False,
        slurm_dict={},
        failed=False
    )

    # Create the AnsibleModule object
    module = AnsibleModule(argument_spec=module_args,
                           required_if=[
                               ('op', 'd2f', ('conf_map',)),
                               ('op', 'merge', ('conf_sources',))
                           ],
                           supports_check_mode=True)
    try:
        # Parse the slurm.conf file
        if module.params['op'] == 'f2d':
            s_dict = parse_slurm_conf(module.params['path'], module)
            result['slurm_dict'] = s_dict
        elif module.params['op'] == 'd2f':
            s_list = read_dict2ini(module.params['conf_map'])
            result['slurm_conf'] = s_list
        elif module.params['op'] == 'merge':
            conf_dict_list = []
            for conf_source in module.params['conf_sources']:
                if isinstance(conf_source, dict):
                    conf_dict_list.append(conf_source)
                elif isinstance(conf_source, str):
                    if not os.path.exists(conf_source):
                        raise Exception(f"File {conf_source} does not exist")
                    s_dict = parse_slurm_conf(conf_source, module)
                    module.warn(f"Conf dict: {s_dict}")
                    conf_dict_list.append(s_dict)
                    # module.warn("After append")
                else:
                    raise Exception(f"Invalid type for conf_source: {type(conf_source)}")
            # module.exit_json(changed=False, conf_dict=conf_dict_list)
            merged_dict = slurm_conf_dict_merge(conf_dict_list, module)
            result['conf_dict'] = merged_dict
            result['ini_lines'] = read_dict2ini(merged_dict)
    except Exception as e:
        result['failed'] = True
        result['msg'] = str(e)
        module.fail_json(msg=str(e))
    module.exit_json(**result)


if __name__ == '__main__':
    run_module()
