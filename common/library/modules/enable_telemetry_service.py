#!/usr/bin/env python3
#!/usr/bin/env python3
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

"""
Dell iDRAC Telemetry - FAST Enable All Reports.

Optimized with parallel processing and connection pooling.
Supports iDRAC 9 and iDRAC 10.
"""

import argparse

import sys
import time
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any, Tuple

import requests
import urllib3
from ansible.module_utils.basic import AnsibleModule

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Logging configuration
logging.basicConfig(
    format='%(message)s',
    stream=sys.stdout,
    level=logging.INFO
)

#####################################################
# CONFIGURATION
#####################################################

PARALLEL_JOBS: int = 250
REPORT_WORKERS: int = 10
TIMEOUT: int = 30

#####################################################
# ALL 37 TELEMETRY REPORTS (iDRAC 9 & 10)
#####################################################

ALL_REPORTS: List[str] = [
    "AggregationMetrics", "CPUMemMetrics", "CPURegisters",
    "CPUSensor", "MemoryMetrics", "MemorySensor",
    "NVMeSMARTData", "StorageDiskSMARTData", "StorageSensor",
    "NICSensor", "NICStatistics", "FCPortStatistics",
    "FCSensor", "SFPTransceiver", "InfiniBandStatistics",
    "PSUMetrics", "PowerMetrics", "PowerStatistics",
    "FanSensor", "ThermalMetrics", "ThermalSensor",
    "GPUMetrics", "GPUStatistics", "GPUSubsystemPower", "FPGASensor",
    "Sensor", "SerialLog", "SystemUsage", "x86SubsystemPower",
    "OME-ISM-MetricsData", "OME-PMP-Power-B",
    "OME-SFPTransceiver-Metrics", "OME-Telemetry-FCPortStatistics",
    "OME-Telemetry-GPU-Aggregate", "OME-Telemetry-GPU-Aggregate-1",
    "OME-Telemetry-NIC-Statistics", "OME-Telemetry-SMARTData",
]


def get_report_definitions(
    ip_address: str,
    user: str,
    password: str,
    session: requests.Session
) -> Optional[List[str]]:
    """Fetch available report definitions from iDRAC."""
    url = f"https://{ip_address}/redfish/v1/TelemetryService/MetricReportDefinitions"
    try:
        response = session.get(
            url,
            auth=(user, password),
            verify=False,
            timeout=TIMEOUT
        )
        if response.status_code == 200:
            data = response.json()
            return [
                member['@odata.id'].split('/')[-1]
                for member in data.get('Members', [])
            ]
    except (requests.exceptions.RequestException, ValueError, KeyError):
        pass
    return None


def enable_report(
    session: requests.Session,
    url: str,
    user: str,
    password: str
) -> bool:
    """Enable a single telemetry report."""
    try:
        data = {
            "MetricReportDefinitionEnabled": True,
            "Status": {"State": "Enabled"}
        }
        response = session.patch(
            url,
            json=data,
            auth=(user, password),
            verify=False,
            timeout=TIMEOUT
        )
        return response.status_code in [200, 202, 204]
    except requests.exceptions.RequestException:
        return False


def enable_reports_parallel(
    session: requests.Session,
    base_url: str,
    reports_to_enable: List[str],
    user: str,
    password: str
) -> Tuple[List[str], List[str]]:
    """Enable multiple reports in parallel."""
    enabled_reports: List[str] = []
    failed_reports: List[str] = []

    report_urls = {
        report: f"{base_url}/MetricReportDefinitions/{report}"
        for report in reports_to_enable
    }

    with ThreadPoolExecutor(max_workers=REPORT_WORKERS) as executor:
        future_to_report = {
            executor.submit(enable_report, session, url, user, password): report
            for report, url in report_urls.items()
        }
        for future in as_completed(future_to_report):
            report_name = future_to_report[future]
            if future.result():
                enabled_reports.append(report_name)
            else:
                failed_reports.append(report_name)

    return enabled_reports, failed_reports


def configure_server(
    ip_address: str,
    user: str,
    password: str,
    exclude_reports: List[str]
) -> Dict[str, Any]:
    """Configure telemetry for a single server."""
    session = requests.Session()
    session.verify = False

    try:
        base_url = f"https://{ip_address}/redfish/v1/TelemetryService"

        # Enable Telemetry Service
        response = session.patch(
            base_url,
            json={"ServiceEnabled": True},
            auth=(user, password),
            timeout=TIMEOUT
        )

        if response.status_code not in [200, 202, 204]:
            return {
                "ip": ip_address,
                "status": "failed",
                "message": f"Service HTTP {response.status_code}"
            }

        # Get available reports
        available_reports = get_report_definitions(ip_address, user, password, session)
        if not available_reports:
            return {
                "ip": ip_address,
                "status": "failed",
                "message": "Cannot get reports"
            }

        # Filter excluded reports
        reports_to_enable = [r for r in available_reports if r not in exclude_reports]

        # Enable reports
        enabled_reports, failed_reports = enable_reports_parallel(
            session, base_url, reports_to_enable, user, password
        )

        return {
            "ip": ip_address,
            "status": "success",
            "enabled_reports": enabled_reports,
            "failed_reports": failed_reports,
            "skipped_reports": [r for r in available_reports if r in exclude_reports]
        }

    except requests.exceptions.RequestException as e:
        return {
            "ip": ip_address,
            "status": "failed",
            "message": str(e)
        }
    finally:
        session.close()


def run_parallel(
    idrac_ips: List[str],
    username: str,
    password: str,
    exclude_reports: List[str],
    parallel_jobs: int
) -> Tuple[List[Dict], List[Dict]]:
    """Run telemetry configuration in parallel."""
    success_results = []
    failed_results = []

    with ThreadPoolExecutor(max_workers=parallel_jobs) as executor:
        future_to_ip = {
            executor.submit(
                configure_server, ip, username, password, exclude_reports
            ): ip for ip in idrac_ips
        }

        for future in as_completed(future_to_ip):
            result = future.result()
            if result.get("status") == "success":
                success_results.append(result)
            else:
                failed_results.append(result)

    return success_results, failed_results


def main():
    """Main function for Ansible module."""
    module_args = {
        "idrac_ips": {"type": "list", "required": True, "elements": "str"},
        "username": {"type": "str", "required": True},
        "password": {"type": "str", "required": True, "no_log": True},
        "parallel_jobs": {"type": "int", "default": 50},
        "timeout": {"type": "int", "default": 30},
    }

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    idrac_ips = module.params["idrac_ips"]
    username = module.params["username"]
    password = module.params["password"]
    parallel_jobs = module.params["parallel_jobs"]

    global TIMEOUT
    TIMEOUT = module.params["timeout"]

    if module.check_mode:
        module.exit_json(changed=False, msg="Check mode - no changes made")

    if not idrac_ips:
        module.fail_json(msg="No iDRAC IPs provided")

    start_time = time.time()

    success_results, failed_results = run_parallel(
        idrac_ips, username, password, parallel_jobs
    )

    duration = time.time() - start_time

    module.exit_json(
        changed=len(success_results) > 0,
        success_count=len(success_results),
        failed_count=len(failed_results),
        duration_seconds=round(duration, 2),
        success_results=success_results,
        failed_results=failed_results,
        msg=f"Telemetry enabled on {len(success_results)}/{len(idrac_ips)} servers"
    )


if __name__ == "__main__":
    main()
