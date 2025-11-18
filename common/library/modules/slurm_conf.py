#!/usr/bin/python

from collections import OrderedDict
import json
from ansible.module_utils.basic import AnsibleModule
import os
import configparser

# NOTE: depends on python3.7+ where dict order is maintained

def read_dict2ini(conf_dict):
    data = []
    for k,v in conf_dict.items():
        if isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    data.append(" ".join(f"{key}={value}" for key, value in item.items()))
                else:
                    data.append(f"{k}={item}")
        else:
            data.append(f"{k}={v}")

    return data

def parse_slurm_conf(file_path, module):
    """Parses the slurm.conf file and returns it as a dictionary."""
    # slurm_dict = {"NodeName": [], "PartitionName": []}
    slurm_dict = OrderedDict()

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"{file_path} not found.")
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.split('#')[0].strip() # handles any comment after the data
                
                # Skip comments and empty lines
                if not line:
                    continue
                # Split the line by one or more spaces
                items = line.split()

                if len(items) == 1:
                    key, value = line.split('=')
                    exst_val = slurm_dict.get(key.strip())
                    if exst_val is not None:
                        if isinstance(exst_val, list):
                            exst_val.append(value.strip())
                        else:
                            nlist = [exst_val] + [value.strip()]
                            slurm_dict[key.strip()] = nlist
                    else:
                        slurm_dict[key.strip()] = value.strip()
                else:
                    tmp_dict = {}
                    for item in items:
                        key, value = item.split('=')
                        tmp_dict[key.strip()] = value.strip()
                    if tmp_dict:
                        # module.warn("1")
                        # module.warn(list(tmp_dict.keys())[0])
                        # module.warn("2")
                        # module.warn(json.dumps(slurm_dict))
                        # module.warn("3")
                        # module.warn(json.dumps(slurm_dict.get(list(tmp_dict.keys())[0], [])))
                        slurm_dict[list(tmp_dict.keys())[0]] = list(slurm_dict.get(list(tmp_dict.keys())[0], [])) + [tmp_dict]

    except Exception as e:
        raise Exception(f"Error reading or parsing {file_path}: {str(e)}")

    return slurm_dict

def run_module():
    module_args = dict(
        path=dict(type='str', required=True),
        op=dict(type='str', required=True, choices=['f2d', 'd2f']),
        conf_map=dict(type='dict')
    )

    result = dict(
        changed=False,
        slurm_dict={},
        failed=False
    )

    # Create the AnsibleModule object
    module = AnsibleModule(argument_spec=module_args,
                           required_if=[
                               ('op', 'd2f', ('conf_map',))
                           ],
                           supports_check_mode=True)
    try:
        # Parse the slurm.conf file
        if module.params['op'] == 'f2d':
            s_dict = parse_slurm_conf(module.params['path'], module)
            result['slurm_dict'] = s_dict
        else: #d2f
            s_list = read_dict2ini(module.params['conf_map'])
            result['slurm_conf'] = s_list
        # result['f1'] = s_dict[list(s_dict.keys())[0]]
        # result['node20'] = s_dict['NodeName'][1][list(s_dict['NodeName'][1].keys())[0]]
        # result['config_parsed'] = read_ini_file(module.params['path'])
    except Exception as e:
        result['failed'] = True
        result['msg'] = str(e)

        module.fail_json(msg=str(e))
    
    # Return the result
    module.exit_json(**result)

if __name__ == '__main__':
    run_module()
