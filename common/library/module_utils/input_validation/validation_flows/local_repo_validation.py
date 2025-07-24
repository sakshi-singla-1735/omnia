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
# pylint: disable=import-error,no-name-in-module,too-many-positional-arguments,too-many-arguments,unused-argument
"""
Validates local repository configuration files for Omnia.
"""
import json
import yaml
from ansible.module_utils.input_validation.common_utils import validation_utils
from ansible.module_utils.input_validation.common_utils import config

file_names = config.files
create_error_msg = validation_utils.create_error_msg
create_file_path = validation_utils.create_file_path

# Below is a validation function for each file in the input folder
def validate_local_repo_config(input_file_path, data,
                               logger, module, omnia_base_dir,
                               module_utils_base, project_name):
    """
    Validates local repo configuration by checking cluster_os_type and
    omnia_repo_url_rhel fields are present and accessible.
    """
    # check to make sure associated os info is filled out
    errors = []
    local_repo_yml = create_file_path(input_file_path, file_names["local_repo_config"])
    with open(local_repo_yml, "r", encoding="utf-8") as f:
        local_repo_config = yaml.safe_load(f)

    repo_names = ['baseos', 'appstream']
    url_list = ["omnia_repo_url_rhel", "rhel_os_url", "user_repo_url"]
    for repurl in url_list:
        repos = local_repo_config.get(repurl)
        if repos:
            repo_names = repo_names + [x.get('name') for x in repos]

    if not repo_names: # is this valid scenario?
        errors.append(create_error_msg(local_repo_yml, None, "No repo names found."))

    if len(repo_names) != len(set(repo_names)):
        errors.append(create_error_msg(local_repo_yml, None, "Duplicate repo names found."))
        for c in set(repo_names):
            if repo_names.count(c) > 1:
                errors.append(create_error_msg(local_repo_yml, None,
                                               f"Repo with name {c} found more than once."))

    software_config_file_path = create_file_path(input_file_path, file_names["software_config"])
    with open(software_config_file_path, "r", encoding="utf-8") as f:
        software_config_json = json.load(f)
  
    roles_config_file_path = create_file_path(input_file_path, file_names["roles_config"])
    with open(roles_config_file_path, "r", encoding="utf-8") as f:
        roles_config_dict = yaml.safe_load(f)
    def_archs = list({x["architecture"] for x in roles_config_dict["Groups"].values()})

    os_ver_path = f"/{software_config_json['cluster_os_type']}/{software_config_json['cluster_os_version']}/"
    for software in software_config_json["softwares"]:
        sw = software["name"]
        arch_list = software.get("arch", def_archs)
        for arch in arch_list:
            json_path = create_file_path(
            input_file_path,
            f"config/{arch}{os_ver_path}" + sw +".json")
            curr_json = json.load(open(json_path, "r", encoding="utf-8"))
            pkg_list = curr_json[sw]['cluster']
            if sw in software_config_json:
                for sub_pkg in software_config_json[sw]:
                    sub_sw = sub_pkg.get('name')
                    if sub_sw not in curr_json:
                        errors.append(
                            create_error_msg(sw + '/' + arch,
                                             json_path,
                                             f"Software {sub_sw} not found in {sw}."))
                    else:
                        pkg_list = pkg_list + curr_json[sub_sw]['cluster']
            for pkg in pkg_list:
                if pkg.get("type") in ['rpm', 'rpm_list']:
                    if pkg.get("repo_name") not in repo_names:
                        errors.append(
                            create_error_msg(sw + '/' + arch,
                                             json_path,
                                             f"Repo name {pkg.get('repo_name')} not found."))

            # module.fail_json(msg="local_repo", errors=errors)
    return errors
