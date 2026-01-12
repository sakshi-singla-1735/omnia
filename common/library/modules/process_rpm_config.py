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

#!/usr/bin/python
# pylint: disable=import-error,no-name-in-module
import json
import subprocess
import multiprocessing
import os
from datetime import datetime
from functools import partial

import requests
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.local_repo.standard_logger import setup_standard_logger
from ansible.module_utils.local_repo.config import (
    pulp_rpm_commands,
    STANDARD_LOG_FILE_PATH,
    PULP_SYNC_CONCURRENCY,
    PULP_PUBLISH_CONCURRENCY,
    AGGREGATED_REPO_NAME_TEMPLATE,
    AGGREGATED_REMOTE_NAME_TEMPLATE,
    AGGREGATED_DISTRIBUTION_NAME_TEMPLATE,
    AGGREGATED_BASE_PATH_TEMPLATE
)

def execute_command(cmd_string, log,type_json=None, seconds=None):
    """
    Executes a shell command and returns its output.

    Args:
        cmd_string (str): The shell command to execute.
        log (logging.Logger): Logger instance for logging the process and errors.
        type_json (bool, optional): If set to `True`, the function will attempt to parse the
        command's output as JSON.
        seconds (float, optional): The maximum time allowed for the command to execute. If `None`,
        no timeout is enforced.

    Returns:
        str or bool: Returns the command's output as a string, or `False` if the command failed.
    """

    try:
        log.info("Executing Command: %s", cmd_string)
        cmd = subprocess.run(cmd_string, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=seconds, shell=True)
        log.info(f"execute command return code : {cmd}")
        if cmd.returncode != 0:
            return False
        if type_json:
            return json.loads(cmd.stdout)
        return True
    except Exception as e:
        log.error("Exception while executing command: %s", str(e))
        return False

def check_packages_and_get_url(distribution_name,log):
    """
    Check if packages exist in the distribution and return the base URL.

    Parameters:
        distribution_name (str): The name of the distribution.
        log (logging.Logger): The logger object.

    Returns:
        bool: True if packages exist in the distribution, False otherwise.
    """
    try:
        result = subprocess.run(
            ["pulp", "rpm", "distribution", "list", "--name", distribution_name, "--field", "base_url"],
            capture_output=True, text=True, check=True
        )
        base_urls = json.loads(result.stdout)
        if not base_urls:
            return False

        base_url = base_urls[0]["base_url"]
        response = requests.get(base_url)
        if response.status_code == 200 and "Packages/" in response.text:
            log.info(f"{distribution_name} packages directory exists. Skipping.")
            return True
        else:
            log.info(f"{distribution_name} packages directory does not exist. Proceeding.")
            return False
    except Exception as e:
        log.error(f"Error: {e}")
        return False

def create_rpm_repository(repo,log):
    """
    Create an RPM repository if it doesn't already exist.

    Args:
        repo (dict): A dictionary containing the package information.
        log (logging.Logger): Logger instance for logging the process and errors.

    Returns:
        bool: True if the repository was created successfully or already exists, False if there was an error.
    """
    try:
        repo_name = repo["package"]
        version = repo.get("version")

        if version != "null":
            repo_name = f"{repo_name}_{version}"
        if not show_rpm_repository(repo_name,log):
            command = pulp_rpm_commands["create_repository"] % repo_name
            log.info("Repository '%s' does not exist. Executing command: %s", repo_name, command)
            result = execute_command(command,log)
            log.info("Repository %s created.", repo_name)
            return result, repo_name

        log.info("Repository %s already exists.", repo_name)
        return True, repo_name

    except Exception as e:
        log.error("Unexpected error while creating repository '%s': %s", repo.get('package', 'unknown'), e)
        return False, repo.get("package", "unknown")

def show_rpm_repository(repo_name,log):
    """
    Show details of an RPM repository.

    Args:
        repo_name (str): The name of the repository.
        log (logging.Logger): Logger instance for logging the process and errors.

    Returns:
        bool: True if the repository was found, False otherwise.
    """

    try:
        log.info("Checking existence of RPM repository: '%s'", repo_name)
        command = pulp_rpm_commands["show_repository"] % repo_name
        log.info("Executing command to show repository: %s", command)

        return execute_command(command,log)

    except Exception as e:
        log.error("Unexpected error while checking repository '%s': %s", repo_name, str(e))
        return False

def create_rpm_remote(repo,log):
    """
    Create a remote for the RPM repository if it doesn't already exist.

    Args:
        repo (dict): A dictionary containing the repository information.
        log (logging.Logger): Logger instance for logging the process and errors.

    Returns:
        bool: True if the remote was created or updated successfully, False otherwise.
    """

    try:
        log.info("Starting RPM remote creation/update process")
        remote_url = repo["url"]
        policy_type = repo["policy"]
        version = repo.get("version")
        repo_name = repo["package"]
        result = None

        if version != "null":
            repo_name = f"{repo_name}_{version}"

        remote_name = repo_name
        repo_keys = repo.keys()
        if "ca_cert" in repo_keys and repo["ca_cert"]:
            ca_cert = f"@{repo['ca_cert']}"
            client_cert = f"@{repo['client_cert']}"
            client_key = f"@{repo['client_key']}"
            if not show_rpm_remote(remote_name,log):
                command = pulp_rpm_commands["create_remote_cert"] % (remote_name, remote_url, policy_type, ca_cert, client_cert, client_key)
                log.info("Remote '%s' does not exist. Executing creation command with certs.", remote_name)
                result = execute_command(command,log)
                log.info("Remote %s created.", remote_name)
            else:
                command = pulp_rpm_commands["update_remote_cert"] % (remote_name, remote_url, policy_type, ca_cert, client_cert, client_key)
                log.info("Remote '%s' already exists. Executing update command with certs.", remote_name)
                result = execute_command(command,log)
        else:
            log.info("Repository does not use SSL certificates for remote")
            if not show_rpm_remote(remote_name,log):
                command = pulp_rpm_commands["create_remote"] % (remote_name, remote_url, policy_type)
                log.info("Remote '%s' does not exist. Executing creation command.", remote_name)
                result = execute_command(command,log)
                log.info("Remote %s created.", remote_name)
            else:
                command = pulp_rpm_commands["update_remote"] % (remote_name, remote_url, policy_type)
                log.info("Remote '%s' already exists. Executing update command.", remote_name)
                result = execute_command(command,log)
        return result, repo_name

    except Exception as e:
        log.error("Unexpected error while creating/updating remote '%s': %s", repo.get("package", "unknown"), str(e))
        return False, repo.get("package", "unknown")
    finally:
        log.info("Completed RPM remote creation/update process for '%s'", repo.get("package", "unknown"))

def show_rpm_remote(remote_name,log):
    """
    Show details of an RPM remote.

    Args:
        remote_name (str): The name of the remote.
        log (logging.Logger): Logger instance for logging the process and errors.

    Returns:
        bool: True if the remote was found, False otherwise.
    """
    try:
        log.info("Checking existence of RPM remote: '%s'", remote_name)

        command = pulp_rpm_commands["show_remote"] % remote_name
        log.info("Executing command to show remote: %s", command)

        return execute_command(command,log)

    except Exception as e:
        log.error("Unexpected error while checking remote '%s': %s", remote_name, str(e))
        return False
    finally:
        log.info("Completed check for RPM remote '%s'", remote_name)

def sync_rpm_repository(repo,log):
    """
    Synchronizes the RPM repository with its remote.

    Args:
        repo (dict): A dictionary containing the repository information.
        log (logging.Logger): Logger instance for logging the process and errors.

    Returns:
        bool: True if the repository was synced successfully, False otherwise.
    """

    try:
        log.info("Starting synchronization for RPM repository")
        repo_name = repo["package"]
        version = repo.get("version")

        if version != "null":
            repo_name = f"{repo_name}_{version}"

        log.info("Checking if repository '%s' already has packages and URL", repo_name)
        if check_packages_and_get_url(repo_name,log):
            return True, repo_name
        # else:
        #     remote_name= repo_name
        #     command = pulp_rpm_commands["sync_repository"] % (repo_name, remote_name)
        #     result = execute_command(command,log)
        #     log.info("Repository synced for %s.", repo_name)
        #     return result, repo_name
        remote_name= repo_name
        command = pulp_rpm_commands["sync_repository"] % (repo_name, remote_name)
        log.info("Executing repository synchronization command: %s", command)
        result = execute_command(command, log)

        if isinstance(result, tuple):
            success, _ = result
        elif isinstance(result, subprocess.CompletedProcess):
            success = result.returncode == 0
        else:
            success = bool(result)

        log.info("Repository synced for %s.", repo_name)
        return success, repo_name
    except Exception as e:
        log.error("Unexpected error during synchronization of repository '%s': %s", repo.get("package", "unknown"), str(e))
        return False, repo.get("package", "unknown")

    finally:
        log.info("Completed RPM repository synchronization for '%s'", repo.get("package", "unknown"))

def create_publication(repo,log):
    """
    Create a publication for an RPM repository.

    Args:
        repo (dict): A dictionary containing the package information.
        log (logging.Logger): Logger instance for logging the process and errors.

    Returns:
        bool: True if the publication was created successfully, False otherwise.
    """

    try:
        log.info("Starting publication creation for RPM repository")
        repo_name = repo["package"]
        version = repo.get("version")

        if version != "null":
            repo_name = f"{repo_name}_{version}"

        log.info("Processing repository: '%s'", repo_name)
        command = pulp_rpm_commands["publish_repository"] % repo_name
        log.info("Executing publication command: %s", command)

        result = execute_command(command, log)

        # Initialize
        success = False
        error_message = ""

        # Handle result types
        if isinstance(result, tuple):
            success, _ = result
        elif isinstance(result, subprocess.CompletedProcess):
            success = result.returncode == 0 and "Error:" not in result.stderr
            if not success:
                error_message = result.stderr.strip()
        else:
            # Fallback case
            success = bool(result)

        if success:
            log.info("Publication created for %s.", repo_name)
        else:
            log.error("Failed to create publication for %s. Error: %s", repo_name, error_message or "Unknown error")

        return success, repo_name
    except Exception as e:
        log.error("Unexpected error during publication creation for repository '%s': %s", repo.get("package", "unknown"), str(e))
        return False, repo.get("package", "unknown")

    finally:
        log.info("Completed publication process for repository '%s'", repo.get("package", "unknown"))

def create_distribution(repo, log):
    """
    Create or update a distribution for an RPM repository.

    Args:
        repo (dict): A dictionary containing the repository information.
        log (logging.Logger): Logger instance for logging the process and errors.

    Returns:
        bool: True if the distribution was created or updated successfully, False otherwise.
    """
    try:
        log.info("Starting distribution creation/update for RPM repository")
        package_name = repo["package"]
        repo_name = package_name
        version = repo.get("version")
        sw_arch = repo.get("sw_arch")

        if version != "null":
            base_path = f" opt/omnia/offline_repo/cluster/{sw_arch}/rhel/10.0/rpms/{package_name}/{version}"
            repo_name = f"{repo_name}_{version}"
        else:
            base_path = f"opt/omnia/offline_repo/cluster/{sw_arch}/rhel/10.0/rpms/{package_name}"

        log.info("Repository: '%s', Base path: '%s'", repo_name, base_path)

        show_command = pulp_rpm_commands["check_distribution"] % repo_name
        create_command = pulp_rpm_commands["distribute_repository"] % (repo_name, base_path, repo_name)
        update_command = pulp_rpm_commands["update_distribution"] % (repo_name, base_path, repo_name)

        # Check if distribution already exists
        log.info("Checking if distribution exists for repository '%s'", repo_name)
        if execute_command(show_command, log):
            log.info(f"Distribution for {package_name} exists. Updating it.")
            return execute_command(update_command, log), repo_name
        else:
            log.info(f"Distribution for {package_name} does not exist. Creating it.")
            return execute_command(create_command, log), repo_name

    except Exception as e:
        log.error("Unexpected error during distribution creation/update for repository '%s': %s", repo.get("package", "unknown"), str(e))
        return False, repo.get("package", "unknown")

    finally:
        log.info("Completed distribution creation/update for repository '%s'", repo.get("package", "unknown"))

def get_base_urls(log):
    """
    Fetch all distributions from Pulp RPM distribution.

    Args:
        log (logging.Logger): Logger instance for logging the process and errors.

    Returns:
        list: A list of dictionaries containing the base URLs and names of all distributions.
              Returns an empty list if there is an error.
    """

    command = ['pulp', 'rpm', 'distribution', 'list', '--field', 'base_url,name']
    log.info(f"Executing command: {' '.join(command)}")

    result = subprocess.run(command,stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

    if result.returncode != 0:
        log.info(f"Error fetching distributions: {result.stderr}")
        return []

    # Parse the JSON output to get all distributions
    try:
        distributions = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        log.error(f"Error parsing JSON output: {e}")
        log.error(f"Raw output received:\n{result.stdout}")
        return []

    if not distributions:
        log.info("No distributions found in Pulp response.")
    else:
        log.info(f"Fetched {len(distributions)} distributions successfully.")

    return distributions

def create_yum_repo_file(distributions, log):
    """
    Creates a new 'pulp.repo' file in /etc/yum.repos.d and adds multiple repositories.

    Args:
        distributions (list): A list of dictionaries containing the base URLs and names of all distributions.
        log (logging.Logger): Logger instance for logging the process and errors.

    Returns:
        None
    """
    try:
        repo_file_path = "/etc/yum.repos.d/pulp.repo"
        log.info(f"Target repo file path: {repo_file_path}")

        # Validate input
        if not distributions or not isinstance(distributions, list):
            log.error("Invalid or empty 'distributions' list provided. Skipping repo file creation.")
            return

        log.info(f"Received {len(distributions)} distributions to process")

        # Delete existing file first (only once)
        if os.path.exists(repo_file_path):
            os.remove(repo_file_path)
            log.info(f"Deleted existing {repo_file_path}")

        repo_content = ""

        for distribution in distributions:
            repo_name = distribution["name"]
            base_url = distribution["base_url"]
            repo_entry = f"""
[{repo_name}]
name={repo_name} repo
baseurl={base_url}
enabled=1
gpgcheck=0
"""
            repo_content += repo_entry.strip() + "\n\n"

        # Write all repositories at once
        log.info("Writing all repository entries to pulp.repo file")
        with open(repo_file_path, 'w', encoding='utf-8') as repo_file:
            repo_file.write(repo_content.strip() + "\n")

        log.info(f"Created {repo_file_path} with {len(distributions)} repositories")

    except PermissionError:
        log.error("Permission denied while writing to /etc/yum.repos.d/. Run with elevated privileges.")
    except Exception as e:
        log.error(f"Unexpected error while creating YUM repo file: {e}")


# ============================================================================
# AGGREGATED REPOS FUNCTIONS
# These functions handle the additional_repos_* feature which aggregates
# multiple user-defined repos into a single Pulp repository per architecture.
# ============================================================================

def delete_aggregated_repo(arch, log):
    """
    Delete the aggregated repository, its remotes, and distribution for a given architecture.
    This is called before recreating the aggregated repo to ensure a clean state.

    Args:
        arch (str): Architecture (x86_64 or aarch64).
        log (logging.Logger): Logger instance.

    Returns:
        bool: True if deletion was successful or resources didn't exist, False on error.
    """
    repo_name = AGGREGATED_REPO_NAME_TEMPLATE.format(arch=arch)
    dist_name = AGGREGATED_DISTRIBUTION_NAME_TEMPLATE.format(arch=arch)

    log.info(f"Deleting aggregated resources for arch '{arch}'")

    # Delete distribution first (depends on repo)
    dist_cmd = pulp_rpm_commands["delete_distribution"] % dist_name
    execute_command(dist_cmd, log)  # Ignore errors - may not exist

    # Delete repository (this also removes associated publications)
    repo_cmd = pulp_rpm_commands["delete_repository"] % repo_name
    execute_command(repo_cmd, log)  # Ignore errors - may not exist

    log.info(f"Completed deletion of aggregated resources for arch '{arch}'")
    return True


def create_aggregated_repository(arch, log):
    """
    Create the aggregated repository for a given architecture.

    Args:
        arch (str): Architecture (x86_64 or aarch64).
        log (logging.Logger): Logger instance.

    Returns:
        tuple: (success, repo_name)
    """
    repo_name = AGGREGATED_REPO_NAME_TEMPLATE.format(arch=arch)

    log.info(f"Creating aggregated repository: {repo_name}")

    if not show_rpm_repository(repo_name, log):
        command = pulp_rpm_commands["create_repository"] % repo_name
        result = execute_command(command, log)
        if not result:
            log.error(f"Failed to create aggregated repository: {repo_name}")
            return False, repo_name
        log.info(f"Aggregated repository '{repo_name}' created successfully.")
    else:
        log.info(f"Aggregated repository '{repo_name}' already exists.")

    return True, repo_name


def create_aggregated_remote(repo_entry, arch, log):
    """
    Create or update a remote for an additional repo entry.

    Args:
        repo_entry (dict): Repository entry with name, url, policy, and optional SSL certs.
        arch (str): Architecture (x86_64 or aarch64).
        log (logging.Logger): Logger instance.

    Returns:
        tuple: (success, remote_name)
    """
    name = repo_entry["name"]
    url = repo_entry["url"]
    policy = repo_entry["policy"]
    remote_name = AGGREGATED_REMOTE_NAME_TEMPLATE.format(arch=arch, name=name)

    log.info(f"Creating/updating remote '{remote_name}' for URL: {url}")

    ca_cert = repo_entry.get("ca_cert", "")
    client_key = repo_entry.get("client_key", "")
    client_cert = repo_entry.get("client_cert", "")

    if ca_cert and client_key and client_cert:
        ca_cert_arg = f"@{ca_cert}"
        client_cert_arg = f"@{client_cert}"
        client_key_arg = f"@{client_key}"

        if not show_rpm_remote(remote_name, log):
            command = pulp_rpm_commands["create_remote_cert"] % (
                remote_name, url, policy, ca_cert_arg, client_cert_arg, client_key_arg
            )
        else:
            command = pulp_rpm_commands["update_remote_cert"] % (
                remote_name, url, policy, ca_cert_arg, client_cert_arg, client_key_arg
            )
    else:
        if not show_rpm_remote(remote_name, log):
            command = pulp_rpm_commands["create_remote"] % (remote_name, url, policy)
        else:
            command = pulp_rpm_commands["update_remote"] % (remote_name, url, policy)

    result = execute_command(command, log)
    if not result:
        log.error(f"Failed to create/update remote: {remote_name}")
        return False, remote_name

    log.info(f"Remote '{remote_name}' created/updated successfully.")
    return True, remote_name


def sync_aggregated_repository(repo_name, remote_name, log):
    """
    Sync the aggregated repository with a specific remote.

    Args:
        repo_name (str): Name of the aggregated repository.
        remote_name (str): Name of the remote to sync from.
        log (logging.Logger): Logger instance.

    Returns:
        tuple: (success, remote_name)
    """
    log.info(f"Syncing repository '{repo_name}' with remote '{remote_name}'")

    command = pulp_rpm_commands["sync_repository"] % (repo_name, remote_name)
    result = execute_command(command, log)

    if not result:
        log.error(f"Failed to sync repository '{repo_name}' with remote '{remote_name}'")
        return False, remote_name

    log.info(f"Successfully synced repository '{repo_name}' with remote '{remote_name}'")
    return True, remote_name


def create_aggregated_publication(repo_name, log):
    """
    Create a publication for the aggregated repository.

    Args:
        repo_name (str): Name of the aggregated repository.
        log (logging.Logger): Logger instance.

    Returns:
        tuple: (success, publication_href or None)
    """
    log.info(f"Creating publication for aggregated repository: {repo_name}")

    command = pulp_rpm_commands["publish_repository"] % repo_name

    try:
        cmd = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=3600
        )
        log.info(f"Publication command return code: {cmd.returncode}")

        if cmd.returncode != 0:
            log.error(f"Failed to create publication for {repo_name}: {cmd.stderr}")
            return False, None

        # Parse the output to get publication href
        try:
            pub_data = json.loads(cmd.stdout)
            pub_href = pub_data.get("pulp_href")
            log.info(f"Publication created with href: {pub_href}")
            return True, pub_href
        except json.JSONDecodeError:
            # If output is not JSON, try to get href from list
            log.info("Could not parse publication href from output, fetching from list")
            list_cmd = pulp_rpm_commands["list_publications"] % repo_name
            list_result = subprocess.run(
                list_cmd, shell=True, capture_output=True, text=True
            )
            if list_result.returncode == 0:
                pubs = json.loads(list_result.stdout)
                if pubs:
                    # Get the latest publication
                    pub_href = pubs[-1].get("pulp_href")
                    log.info(f"Got publication href from list: {pub_href}")
                    return True, pub_href
            return True, None

    except Exception as e:
        log.error(f"Exception during publication creation: {e}")
        return False, None


def create_aggregated_distribution(arch, pub_href, log):
    """
    Create or update the distribution for the aggregated repository.

    Args:
        arch (str): Architecture (x86_64 or aarch64).
        pub_href (str): Publication href to associate with distribution.
        log (logging.Logger): Logger instance.

    Returns:
        tuple: (success, distribution_name)
    """
    repo_name = AGGREGATED_REPO_NAME_TEMPLATE.format(arch=arch)
    dist_name = AGGREGATED_DISTRIBUTION_NAME_TEMPLATE.format(arch=arch)
    base_path = AGGREGATED_BASE_PATH_TEMPLATE.format(arch=arch)

    log.info(f"Creating/updating distribution '{dist_name}' with base_path '{base_path}'")

    # Check if distribution exists
    show_cmd = pulp_rpm_commands["check_distribution"] % dist_name

    if execute_command(show_cmd, log):
        # Distribution exists - update with new publication
        if pub_href:
            update_cmd = pulp_rpm_commands["update_distribution_publication"] % (dist_name, pub_href)
            result = execute_command(update_cmd, log)
        else:
            # Update with repository reference
            update_cmd = pulp_rpm_commands["update_distribution"] % (dist_name, base_path, repo_name)
            result = execute_command(update_cmd, log)

        if not result:
            log.error(f"Failed to update distribution: {dist_name}")
            return False, dist_name
        log.info(f"Distribution '{dist_name}' updated successfully.")
    else:
        # Create new distribution
        create_cmd = pulp_rpm_commands["distribute_repository"] % (dist_name, base_path, repo_name)
        result = execute_command(create_cmd, log)

        if not result:
            log.error(f"Failed to create distribution: {dist_name}")
            return False, dist_name
        log.info(f"Distribution '{dist_name}' created successfully.")

    return True, dist_name


def manage_aggregated_repos(additional_repos_config, log):
    """
    Manage aggregated repositories for additional_repos_* entries.
    This function handles the complete workflow:
    1. Delete existing aggregated repo (always recreate for clean state)
    2. Create new aggregated repository
    3. Create remotes for each repo entry
    4. Sync each remote to the aggregated repository
    5. Create publication
    6. Create/update distribution

    Args:
        additional_repos_config (dict): Dictionary with arch as key and list of repo configs as value.
        log (logging.Logger): Logger instance.

    Returns:
        tuple: (success, error_message)
    """
    log.info("Starting management of aggregated repositories")

    for arch in ["x86_64", "aarch64"]:
        repos = additional_repos_config.get(arch, [])
        repo_name = AGGREGATED_REPO_NAME_TEMPLATE.format(arch=arch)

        log.info(f"Processing aggregated repos for arch '{arch}': {len(repos)} repos")

        # Step 1: Delete existing aggregated repo for clean state
        log.info(f"Step 1: Deleting existing aggregated repo for {arch}")
        delete_aggregated_repo(arch, log)

        # Step 2: Create aggregated repository
        log.info(f"Step 2: Creating aggregated repository for {arch}")
        success, _ = create_aggregated_repository(arch, log)
        if not success:
            return False, f"Failed to create aggregated repository for {arch}"

        # Step 3 & 4: Create remotes and sync (only if there are repos)
        if repos:
            sync_failures = []

            for repo_entry in repos:
                # Create remote
                log.info(f"Step 3: Creating remote for '{repo_entry['name']}'")
                success, remote_name = create_aggregated_remote(repo_entry, arch, log)
                if not success:
                    return False, f"Failed to create remote for {repo_entry['name']}"

                # Sync to aggregated repo
                log.info(f"Step 4: Syncing remote '{remote_name}' to aggregated repo")
                success, _ = sync_aggregated_repository(repo_name, remote_name, log)
                if not success:
                    sync_failures.append(repo_entry['name'])

            # Check if all syncs succeeded
            if sync_failures:
                return False, f"Failed to sync repos for {arch}: {', '.join(sync_failures)}"

        # Step 5: Create publication
        log.info(f"Step 5: Creating publication for {arch}")
        success, pub_href = create_aggregated_publication(repo_name, log)
        if not success:
            return False, f"Failed to create publication for aggregated repo {arch}"

        # Step 6: Create/update distribution
        log.info(f"Step 6: Creating/updating distribution for {arch}")
        success, _ = create_aggregated_distribution(arch, pub_href, log)
        if not success:
            return False, f"Failed to create distribution for aggregated repo {arch}"

        log.info(f"Successfully completed aggregated repo management for {arch}")

    log.info("Completed management of all aggregated repositories")
    return True, "success"

def manage_rpm_repositories_multiprocess(rpm_config, log):
    """
    Manage RPM repositories using multiprocessing.

    Args:
        rpm_config (list): A list of dictionaries containing the configuration for each RPM repository.
        log (logging.Logger): Logger instance for logging the process and errors.

    Returns:
        tuple: (bool, str) indicating success and a message
    """

    cpu_count = os.cpu_count()
    process = min(cpu_count, len(rpm_config))
    log.info(f"Number of processes = {process}")

    # Use configurable concurrency from config.py for resource-intensive operations
    # This prevents overwhelming the Pulp server, especially on NFS storage
    # Adjust PULP_SYNC_CONCURRENCY and PULP_PUBLISH_CONCURRENCY in config.py:
    #   - For NFS storage: Use 1 (prevents 500/502/504 errors)
    #   - For local storage: Use 2 for optimal performance
    #   - For high-performance SAN: Can try 3-4 (monitor for errors)
    sync_process = min(PULP_SYNC_CONCURRENCY, process)
    publish_process = min(PULP_PUBLISH_CONCURRENCY, process)

    log.info(f"Configured sync concurrency: {PULP_SYNC_CONCURRENCY}")
    log.info(f"Configured publish concurrency: {PULP_PUBLISH_CONCURRENCY}")
    log.info(f"Actual sync processes (capped by repo count): {sync_process}")
    log.info(f"Actual publish processes (capped by repo count): {publish_process}")

    # Step 1: Concurrent repository creation
    log.info("Step 1: Starting concurrent RPM repository creation")
    with multiprocessing.Pool(processes=process) as pool:
        result = pool.map(partial(create_rpm_repository, log=log), rpm_config)
    failed = [name for success, name in result if not success]
    if failed:
        log.error("Failed during creation of RPM repository for: %s", ", ".join(failed))
        return False, f"During creation of RPM repository for: {', '.join(failed)}"

    # Step 2: Concurrent remote creation
    log.info("Step 2: Starting concurrent RPM remote creation")
    with multiprocessing.Pool(processes=process) as pool:
        result = pool.map(partial(create_rpm_remote, log=log), rpm_config)
    failed = [name for success, name in result if not success]
    if failed:
        log.error("Failed during creation of RPM remote for: %s", ", ".join(failed))
        return False, f"During creation of RPM remote for: {', '.join(failed)}"

    # Step 3: Concurrent synchronization
    log.info("Step 3: Starting concurrent RPM repository synchronization")
    with multiprocessing.Pool(processes=sync_process) as pool:
        result = pool.map(partial(sync_rpm_repository, log=log), rpm_config)
    failed = [name for success, name in result if not success]
    if failed:
        log.error("Failed during synchronization of RPM repository for: %s", ", ".join(failed))
        return False, f"During synchronization of RPM repository for: {', '.join(failed)}. Please refer to the troubleshooting guide for more information."

    # Step 4: Concurrent publication creation
    log.info("Step 4: Starting concurrent RPM publication creation")
    with multiprocessing.Pool(processes=publish_process) as pool:
        result = pool.map(partial(create_publication, log=log), rpm_config)
    failed = [name for success, name in result if not success]
    if failed:
        log.error("Failed during publication of RPM repository for: %s", ", ".join(failed))
        return False, f"During publication of RPM repository for: {', '.join(failed)}. Please refer to the troubleshooting guide for more information."

    # Step 5: Concurrent distribution creation
    log.info("Step 5: Starting concurrent RPM distribution creation")
    with multiprocessing.Pool(processes=process) as pool:
        result = pool.map(partial(create_distribution, log=log), rpm_config)
    failed = [name for success, name in result if not success]
    if failed:
        log.error("Failed during distribution of RPM repository for: %s", ", ".join(failed))
        return False, f"During distribution of RPM repository for: {', '.join(failed)}"

    # --- STEP 6: Fetch Base URLs and Create YUM Repo File ---
    log.info("Step 6: Fetching base URLs and creating yum repo file")
    base_urls = get_base_urls(log)
    if not base_urls:
        log.error("No base URLs retrieved from Pulp. Skipping repo file creation.")
        return False, "Base URLs fetch failed — repo file not created."

    log.info(f"Fetched {len(base_urls)} base URLs from Pulp.")
    create_yum_repo_file(base_urls, log)
    log.info("Successfully created yum repo file with fetched base URLs.")

    return True, "success"

def main():
    """
    The main function of the module.

    This function sets up the argument specifications for the module and initializes the logger.
    It then retrieves the `local_config` and `log_dir` parameters from the module.

    The `local_config` parameter is used to replace single quotes with double quotes to make it valid JSON.
    The JSON string is then parsed and stored in the `rpm_config` variable.

    The `manage_rpm_repositories_multiprocess` function is called with the `rpm_config` and `log` as arguments.

    If `additional_repos_config` is provided, the `manage_aggregated_repos` function is called to handle
    the aggregated repositories feature.

    Finally, the function exits with a JSON response indicating that the RPM configuration has been processed.

    Parameters:
        None

    Returns:
        None
    """
    module_args = {
        "local_config": {"type": "list", "required": True},
        "log_dir": {"type": "str", "required": False, "default": "/tmp/thread_logs"},
        "additional_repos_config": {"type": "dict", "required": False, "default": None}
    }

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=False)

    # Get the local_config parameter from the module
    rpm_config = module.params["local_config"]
    log_dir = module.params["log_dir"]
    additional_repos_config = module.params["additional_repos_config"]

    log = setup_standard_logger(log_dir)

    start_time = datetime.now().strftime("%I:%M:%S %p")

    log.info(f"Start execution time: {start_time}")

    # Call the function to manage RPM repositories
    result, output = manage_rpm_repositories_multiprocess(rpm_config, log)

    if result is False:
        module.fail_json(msg=f"Error {output}, check {STANDARD_LOG_FILE_PATH}")

    # Handle aggregated repos if additional_repos_config is provided
    if additional_repos_config:
        log.info("Processing additional_repos aggregated repositories")
        result, output = manage_aggregated_repos(additional_repos_config, log)
        if result is False:
            module.fail_json(msg=f"Error in aggregated repos: {output}, check {STANDARD_LOG_FILE_PATH}")
        log.info("Successfully processed additional_repos aggregated repositories")

    module.exit_json(changed=True, result="RPM Config Processed")

if __name__ == "__main__":
    main()
