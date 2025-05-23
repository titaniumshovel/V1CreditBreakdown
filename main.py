import requests
import json
import argparse
from datetime import datetime, timedelta
import os 
import sys 

# --- Configuration ---
SERVERS = {
    "US": "https://api.xdr.trendmicro.com",
    "EU": "https://api.eu.xdr.trendmicro.com",
    "SG": "https://api.sg.xdr.trendmicro.com",
    "JP": "https://api.xdr.trendmicro.co.jp",
    "AU": "https://api.au.xdr.trendmicro.com",
    "IN": "https://api.in.xdr.trendmicro.com",
    "UAE": "https://api.mea.xdr.trendmicro.com"
}
DEFAULT_ENDPOINT_SAMPLE_SIZE = 50
DEFAULT_REGION = "US"
LOG_FILE_HANDLER = None # Initialize as None
VERBOSE_DEBUG = False # Initialize as False

# --- Logging and Output Functions ---
def initialize_logging(output_file_path): # output_file_path will only be passed if -o is used
    """Initializes logging to file."""
    global LOG_FILE_HANDLER
    if output_file_path: # This condition is now effectively always true if called
        try:
            LOG_FILE_HANDLER = open(output_file_path, "w", encoding="utf-8")
            print(f"[INFO] Logging output to: {output_file_path}") # Console message about logging
        except IOError as e:
            print(f"[API ERROR] Could not open log file {output_file_path}: {e}. Outputting to console only.")
            LOG_FILE_HANDLER = None

def _log_message(message):
    """Internal helper to write to log file (if active) and console."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    formatted_message_console = message # Keep console output clean for non-verbose
    formatted_message_file = f"[{timestamp}] {message}"
    
    if VERBOSE_DEBUG and not LOG_FILE_HANDLER: # If verbose but no log file, timestamp console
        print(f"[{timestamp}] {message}")
    else:
        print(formatted_message_console)

    if LOG_FILE_HANDLER:
        try:
            LOG_FILE_HANDLER.write(formatted_message_file + "\n")
            LOG_FILE_HANDLER.flush() 
        except IOError as e:
            # Fallback if file writing fails mid-script
            print(f"[{timestamp}] [API ERROR] Failed to write to log file: {e}")


def print_section_header(title):
    header_line = "\n" + "="*60
    title_line = f"===== {title.upper()} ====="
    _log_message(header_line)
    _log_message(title_line)
    _log_message("="*60)


def print_finding(category, message, severity="INFO", recommendation=None, findings_list=None):
    severity_map = {
        "INFO": "[CONFIGURATION DETAIL]",
        "WARNING": "[POTENTIAL CREDIT IMPACT]",
        "ERROR": "[API ERROR]"
    }
    
    header = f"{severity_map.get(severity, severity)} {category}:"
    if message is not None:
        _log_message(f"{header} {message}")
    else: 
        _log_message(header)

    if recommendation:
        _log_message(f"  -> Recommendation: {recommendation}")

    # Collect finding in structured form if findings_list is provided
    if findings_list is not None:
        findings_list.append({
            "category": category,
            "message": message,
            "severity": severity,
            "recommendation": recommendation
        })

# --- Helper Functions ---
def get_api_data(base_url, token, endpoint_path, params=None, headers_extra=None, is_list=True, fetch_all=False):
    import time
    global VERBOSE_DEBUG

    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json;charset=utf-8"
    }
    if headers_extra:
        headers.update(headers_extra)

    current_url = base_url + endpoint_path
    current_request_params = dict(params) if params else {}
    all_items = []
    page_count = 0
    max_pages_for_sample_safety = 20
    
    initial_top_value_for_sampling = current_request_params.get('top', DEFAULT_ENDPOINT_SAMPLE_SIZE)

    if VERBOSE_DEBUG:
        _log_message(f"  [VERBOSE] get_api_data: endpoint='{endpoint_path}', fetch_all={fetch_all}, initial_params_for_call={current_request_params}")

    while current_url:
        tries = 0
        while tries < 3:
            try:
                http_call_params = current_request_params if page_count == 0 else None
                if VERBOSE_DEBUG:
                    _log_message(f"  [VERBOSE] Page: {page_count + 1}, Fetching URL: {current_url}, HTTP Params: {http_call_params}")
                
                response = requests.get(current_url, headers=headers, params=http_call_params, timeout=45)
                response.raise_for_status()
                data = response.json()

                if not is_list:
                    if VERBOSE_DEBUG: _log_message(f"  [VERBOSE] Endpoint is not a list. Returning data for {endpoint_path}.")
                    return data, None

                items_on_page = data.get("items", [])
                total_count_from_api = data.get("totalCount", "N/A")
                count_on_page_from_api = data.get("count", len(items_on_page) if isinstance(items_on_page, list) else (1 if items_on_page else 0) )

                if VERBOSE_DEBUG:
                    _log_message(f"  [VERBOSE] Received {len(items_on_page) if isinstance(items_on_page, list) else (1 if items_on_page else 0)} items on this page. API reports 'count': {count_on_page_from_api}, 'totalCount': {total_count_from_api}.")

                if isinstance(items_on_page, list):
                    all_items.extend(items_on_page)
                elif items_on_page:
                    all_items.append(items_on_page)
                
                page_count += 1
                current_url = data.get("nextLink")
                
                if VERBOSE_DEBUG:
                    _log_message(f"  [VERBOSE] nextLink from API: {current_url}")
                    _log_message(f"  [VERBOSE] Current total items collected for {endpoint_path}: {len(all_items)}")

                if not fetch_all: 
                    desired_sample_size = current_request_params.get('top', DEFAULT_ENDPOINT_SAMPLE_SIZE)
                    if VERBOSE_DEBUG: _log_message(f"  [VERBOSE] Sampling logic active. Desired sample size: {desired_sample_size}")
                    if not current_url: 
                        if VERBOSE_DEBUG: _log_message(f"  [VERBOSE] Sampling: No nextLink, breaking loop for {endpoint_path}.")
                        break
                    if len(all_items) >= desired_sample_size or page_count >= max_pages_for_sample_safety:
                        if VERBOSE_DEBUG: _log_message(f"  [VERBOSE] Sampling: Sample size ({len(all_items)}) or page count ({page_count}) limit reached for {endpoint_path}. Breaking loop.")
                        if len(all_items) > desired_sample_size: 
                            all_items = all_items[:desired_sample_size]
                            if VERBOSE_DEBUG: _log_message(f"  [VERBOSE] Sampling: Trimmed items to {len(all_items)} for {endpoint_path}")
                        break
                
                if not current_url: 
                    if VERBOSE_DEBUG: _log_message(f"  [VERBOSE] No nextLink. End of data for {endpoint_path}.")
                    break

                # If we got here, the request succeeded, so break out of retry loop
                break

            except requests.exceptions.HTTPError as e:
                error_content = "Unknown error"
                try:
                    error_content = e.response.json()
                except json.JSONDecodeError:
                    error_content = e.response.text
                _log_message(f"[API ERROR] HTTP Error for {endpoint_path}: {e.response.status_code} - {error_content}")
                tries += 1
                if tries < 3:
                    _log_message(f"[API ERROR] Retrying {endpoint_path} in 3 seconds... (Attempt {tries+1}/3)")
                    time.sleep(3)
                else:
                    return None, f"HTTP Error for {endpoint_path}: {e.response.status_code} - {error_content}"
            except requests.exceptions.RequestException as e:
                _log_message(f"[API ERROR] Request Exception for {endpoint_path}: {e}")
                tries += 1
                if tries < 3:
                    _log_message(f"[API ERROR] Retrying {endpoint_path} in 3 seconds... (Attempt {tries+1}/3)")
                    time.sleep(3)
                else:
                    return None, f"Request Exception for {endpoint_path}: {e}"
            except json.JSONDecodeError as e:
                _log_message(f"[API ERROR] JSON Decode Error for {endpoint_path}: {e.msg} in response: {response.text[:200]}")
                tries += 1
                if tries < 3:
                    _log_message(f"[API ERROR] Retrying {endpoint_path} in 3 seconds... (Attempt {tries+1}/3)")
                    time.sleep(3)
                else:
                    return None, f"JSON Decode Error for {endpoint_path}: {e.msg} in response: {response.text[:200]}"
        else:
            # If we exhausted retries, break the while current_url loop
            break
    
    if VERBOSE_DEBUG: _log_message(f"  [VERBOSE] Finished fetching for {endpoint_path}. Total items collected: {len(all_items)}")
    return all_items, None

# --- Analysis Functions (keep check_endpoint_security_credits, check_datalake_pipelines, etc. as they were in the previous response) ---
def check_endpoint_security_credits(base_url, token, fetch_all_endpoints=False, dry_run=False):
    """
    Analyzes Endpoint Security configurations for potential credit impact.
    Focuses on 'creditAllocatedLicenses' and specific EPP/EDR features.
    Returns findings, unique_pro_guids, sampled_count, other_licenses_summary.
    """
    findings = []
    print_section_header("Endpoint Security Analysis")

    params_for_api_call = {'top': 200} if fetch_all_endpoints else {'top': DEFAULT_ENDPOINT_SAMPLE_SIZE}
    select_fields = [
        "agentGuid", "endpointName", "creditAllocatedLicenses",
        "eppAgentStatus", 
        "eppAgentIntegrityMonitoring", 
        "eppAgentLogInspection",       
        "eppAgentApplicationControl",  
        "edrSensorStatus",             
        "edrSensorAdvancedRiskTelemetryStatus"
    ]
    params_for_api_call['select'] = ",".join(select_fields)

    if dry_run:
        _log_message(f"[DRY RUN] Would call: GET {base_url}/v3.0/endpointSecurity/endpoints with params {params_for_api_call} (fetch_all={fetch_all_endpoints})")
        print_finding("Endpoint Security", "DRY RUN: No API call made for endpoint security analysis.", "INFO", findings_list=findings)
        return findings, set(), 0, {}

    if VERBOSE_DEBUG:
        _log_message(f"  [VERBOSE] check_endpoint_security_credits: fetch_all_endpoints={fetch_all_endpoints}, params_for_api_call={params_for_api_call}")

    if fetch_all_endpoints:
        _log_message(f"  Attempting to fetch ALL endpoints with page size {params_for_api_call['top']}. This may take a significant amount of time for large environments...")
    else:
        _log_message(f"  Fetching a sample of up to {params_for_api_call['top']} endpoints...")

    endpoints, error = get_api_data(base_url, token, "/v3.0/endpointSecurity/endpoints", params=params_for_api_call, fetch_all=fetch_all_endpoints)

    if error:
        print_finding("Endpoint Security", f"Error fetching endpoint data: {error}", "ERROR", findings_list=findings)
        return findings, set(), 0, {}

    if not endpoints:
        print_finding("Endpoint Security", "No endpoints found or unable to retrieve endpoint data.", "INFO", findings_list=findings)
        return findings, set(), 0, {}

    pro_license_endpoints = {
        "Advanced Endpoint Security": [],
        "Advanced Server & Workload Protection": [],
        "SAP Scanner for Trend Vision One - Endpoint Security (Pro)": []
    }
    other_licenses_summary = {}
    unique_pro_guids = set()
    sampled_count = len(endpoints)
    
    specific_pro_features_map = {
        "eppAgentIntegrityMonitoring": {"label": "Integrity Monitoring", "endpoints": [], "license_hint": "Advanced Server & Workload Protection"},
        "eppAgentLogInspection": {"label": "Log Inspection", "endpoints": [], "license_hint": "Advanced Server & Workload Protection"},
        "eppAgentApplicationControl": {"label": "Application Control", "endpoints": [], "license_hint": "Advanced Endpoint Security / Advanced Server & Workload Protection"},
        "edrSensorAdvancedRiskTelemetryStatus": {"label": "Advanced Risk Telemetry (EDR)", "endpoints": [], "license_hint": "Potentially higher tier EDR or add-on"}
    }

    for endpoint in endpoints:
        agent_guid = endpoint.get("agentGuid", "Unknown GUID")
        endpoint_name = endpoint.get("endpointName", "Unknown Name")

        licenses = endpoint.get("creditAllocatedLicenses", [])
        for license_name in licenses:
            if license_name in pro_license_endpoints:
                pro_license_endpoints[license_name].append(f"{endpoint_name} (GUID: {agent_guid})")
                unique_pro_guids.add(agent_guid)
            else:
                other_licenses_summary[license_name] = other_licenses_summary.get(license_name, 0) + 1
        
        for feature_key, feature_info in specific_pro_features_map.items():
            status = endpoint.get(feature_key)
            if status == "enabled" or status == "enabling":
                feature_info["endpoints"].append(f"{endpoint_name} (GUID: {agent_guid})")

    print_finding("Endpoint Security", "--- License-Based Analysis ---", "INFO", findings_list=findings)
    found_pro_licenses = False
    for license_type, eps in pro_license_endpoints.items():
        if eps:
            found_pro_licenses = True
            print_finding(
                "License Check",
                f"'{license_type}' (Pro-level license) is allocated to {len(eps)} of the checked endpoints.",
                "WARNING",
                f"Ensure this license tier is intended for these endpoints. Mismatched allocation can lead to higher credit use.",
                findings_list=findings
            )
            _log_message(f"    Endpoints with '{license_type}':")
            for ep_detail in eps:
                _log_message(f"      - {ep_detail}")

    if other_licenses_summary:
         print_finding("License Check", "Other licenses found:", "INFO", findings_list=findings)
         for lic, count in other_licenses_summary.items():
             _log_message(f"    - '{lic}': {count} endpoints")
    if not found_pro_licenses:
        print_finding("License Check", "No explicit Pro-level licenses found via 'creditAllocatedLicenses' on checked endpoints.", "INFO", findings_list=findings)

    print_finding("Endpoint Security", "--- Specific Feature-Based Analysis ---", "INFO", findings_list=findings)
    found_specific_pro_features = False
    for feature_key, feature_info in specific_pro_features_map.items():
        if feature_info["endpoints"]:
            found_specific_pro_features = True
            print_finding(
                "Feature Check",
                f"Feature '{feature_info['label']}' is enabled on {len(feature_info['endpoints'])} of the checked endpoints.",
                "WARNING",
                f"This feature is often associated with '{feature_info['license_hint']}'. Verify if this feature is essential for these endpoints. Check Endpoint Inventory and sensor policies.",
                findings_list=findings
            )
            _log_message(f"    Endpoints with '{feature_info['label']}':")
            for ep_detail in feature_info['endpoints']:
                _log_message(f"      - {ep_detail}")
    
    if not found_specific_pro_features:
        print_finding("Feature Check", "No specific credit-impacting features (like Integrity Monitoring, Log Inspection) were found enabled on the checked endpoints based on direct status fields.", "INFO", findings_list=findings)

    if not fetch_all_endpoints and len(endpoints) >= params_for_api_call.get('top', DEFAULT_ENDPOINT_SAMPLE_SIZE):
        _log_message(f"\nChecked a sample of {len(endpoints)} endpoints. For a full list, re-run with the '-a' or '--all_endpoints' flag (this may take time).")
    else:
        _log_message(f"\nChecked {len(endpoints)} endpoints.")

    return findings, unique_pro_guids, sampled_count, other_licenses_summary


def check_datalake_pipelines(base_url, token, dry_run=False):
    findings = []
    print_section_header("Datalake Pipeline Analysis")
    if dry_run:
        _log_message(f"[DRY RUN] Would call: GET {base_url}/v3.0/datalake/dataPipelines")
        print_finding("Datalake Pipeline", "DRY RUN: No API call made for datalake pipeline analysis.", "INFO", findings_list=findings)
        return findings

    pipelines_data, error = get_api_data(base_url, token, "/v3.0/datalake/dataPipelines", is_list=False)

    if error:
        print_finding("Datalake Pipeline", f"Error fetching datalake pipelines: {error}", "ERROR", findings_list=findings)
        return findings

    pipelines = pipelines_data.get("items", []) if pipelines_data else []
    if pipelines and len(pipelines) > 0:
        print_finding("Datalake Pipeline", f"{len(pipelines)} active datalake pipeline(s) found. These consume credits.", "WARNING", findings_list=findings)
        for pipeline in pipelines:
            pipeline_id = pipeline.get('id', 'Unknown ID')
            pipeline_type = pipeline.get('type', 'Unknown Type')
            sub_type = pipeline.get('subType', [])
            description = pipeline.get('description', 'No description')
            _log_message(f"  - ID: {pipeline_id}, Type: {pipeline_type}, SubTypes: {', '.join(sub_type) if sub_type else 'N/A'}, Description: {description}")
        print_finding("Datalake Pipeline", None, "INFO", "Review active Datalake Pipelines in Vision One console to ensure all bound data types are necessary.", findings_list=findings)
    else:
        print_finding("Datalake Pipeline", "No active Datalake Pipelines found.", "INFO", findings_list=findings)
    return findings

def check_oat_pipelines(base_url, token, dry_run=False):
    findings = []
    print_section_header("Observed Attack Techniques (OAT) Pipeline Analysis")
    if dry_run:
        _log_message(f"[DRY RUN] Would call: GET {base_url}/v3.0/oat/dataPipelines")
        print_finding("OAT Pipeline", "DRY RUN: No API call made for OAT pipeline analysis.", "INFO", findings_list=findings)
        return findings

    pipelines_data, error = get_api_data(base_url, token, "/v3.0/oat/dataPipelines", is_list=False)

    if error:
        print_finding("OAT Pipeline", f"Error fetching OAT pipelines: {error}", "ERROR", findings_list=findings)
        return findings

    pipelines = pipelines_data.get("items", []) if pipelines_data else []
    if pipelines and len(pipelines) > 0:
        print_finding("OAT Pipeline", f"{len(pipelines)} active OAT data pipeline(s) found.", "WARNING", findings_list=findings)
        for pipeline in pipelines:
            pipeline_id = pipeline.get('id', 'Unknown ID')
            risk_levels = pipeline.get('riskLevels', [])
            has_detail = pipeline.get('hasDetail', False)
            description = pipeline.get('description', 'No description')
            _log_message(f"  - ID: {pipeline_id}, Risk Levels: {', '.join(risk_levels)}, Has Detail: {has_detail}, Description: {description}")
        print_finding("OAT Pipeline", "", "INFO", "Review active OAT Pipelines. Enabling 'hasDetail' or including many risk levels might increase data volume and potentially credit consumption if linked to other credit-based services.", findings_list=findings)
    else:
        print_finding("OAT Pipeline", "No active OAT Data Pipelines found.", "INFO", findings_list=findings)
    return findings

def check_attack_surface_discovery_usage(base_url, token, dry_run=False):
    findings = []
    print_section_header("Cyber Risk Exposure Management (CREM) Analysis")
    if dry_run:
        _log_message(f"[DRY RUN] Would call: GET {base_url}/v3.0/asrm/securityPosture")
        _log_message(f"[DRY RUN] Would call: GET {base_url}/v3.0/asrm/vulnerableDevices")
        _log_message(f"[DRY RUN] Would call: GET {base_url}/v3.0/asrm/attackSurfaceDevices")
        print_finding("CREM - Security Posture", "DRY RUN: No API call made for CREM security posture.", "INFO", findings_list=findings)
        print_finding("CREM - Vulnerable Devices", "DRY RUN: No API call made for CREM vulnerable devices.", "INFO", findings_list=findings)
        print_finding("CREM - Attack Surface Devices", "DRY RUN: No API call made for CREM attack surface devices.", "INFO", findings_list=findings)
        return findings
    
    # Check Security Posture endpoint
    sec_posture_data, error_sp = get_api_data(base_url, token, "/v3.0/asrm/securityPosture", is_list=False)
    if error_sp and "403" in str(error_sp) and "credits" in str(error_sp).lower():
         print_finding("CREM - Security Posture", f"Usage likely disabled or restricted due to credit allocation: {error_sp}", "INFO", findings_list=findings)
    elif error_sp:
        if "404" not in str(error_sp):
            print_finding("CREM - Security Posture", "Attempted to check. An error occurred, but this might still indicate CREM is active or configured.", "WARNING", f"Details: {error_sp}", findings_list=findings)
    elif sec_posture_data: 
        print_finding("CREM - Security Posture", "Data retrieved, indicating CREM module is active.", "WARNING",
                      "CREM consumes credits. Review Security Posture and other CREM configurations in Vision One console.", findings_list=findings)
    else: 
        print_finding("CREM - Security Posture", "No specific Security Posture data returned, but no error. CREM might be active with no current posture data.", "INFO", findings_list=findings)

    # Check Vulnerable Devices endpoint - try without filter first, then with simpler approach
    if VERBOSE_DEBUG: 
        _log_message(f"  [VERBOSE] CREM: Probing /v3.0/asrm/vulnerableDevices with basic query")
    
    # Minimal request: only Authorization header, no extra params or filters
    vulnerable_devices, error_vd = get_api_data(
        base_url, token, 
        "/v3.0/asrm/vulnerableDevices"
    )
    
    if error_vd and "403" in str(error_vd) and "credits" in str(error_vd).lower():
        print_finding("CREM - Vulnerable Devices", f"Usage likely disabled or restricted due to credit allocation: {error_vd}", "INFO", findings_list=findings)
    elif error_vd and "400" in str(error_vd):
        # Try alternative approach - check if endpoint exists but has different requirements
        print_finding("CREM - Vulnerable Devices", "Endpoint accessible but may require specific parameters or have no data.", "INFO", 
                     "Vulnerability assessment might be configured but not currently active or may require different query parameters.", findings_list=findings)
    elif not error_vd and vulnerable_devices: 
        print_finding("CREM - Vulnerable Devices", f"Found {len(vulnerable_devices)} vulnerable device(s) (sample check). This indicates active vulnerability assessment.", "WARNING", 
                     "Vulnerability assessment within CREM consumes credits.", findings_list=findings)
    elif error_vd and "404" not in str(error_vd):
         print_finding("CREM - Vulnerable Devices", f"Error checking vulnerable devices: {error_vd}", "ERROR", findings_list=findings)
    else:
        print_finding("CREM - Vulnerable Devices", "No vulnerable devices found in sample check.", "INFO", findings_list=findings)

    # Check Attack Surface Devices endpoint - try without filter first
    if VERBOSE_DEBUG: 
        _log_message(f"  [VERBOSE] CREM: Probing /v3.0/asrm/attackSurfaceDevices with basic query")
    
    # Minimal request: only Authorization header, no extra params or filters
    attack_surface_devices, error_asd = get_api_data(
        base_url, token, 
        "/v3.0/asrm/attackSurfaceDevices"
    )
    
    if error_asd and "403" in str(error_asd) and "credits" in str(error_asd).lower():
        print_finding("CREM - Attack Surface Devices", f"Usage likely disabled or restricted due to credit allocation: {error_asd}", "INFO", findings_list=findings)
    elif error_asd and "400" in str(error_asd):
        # Try alternative approach - check if endpoint exists but has different requirements  
        print_finding("CREM - Attack Surface Devices", "Endpoint accessible but may require specific parameters or have no data.", "INFO",
                     "Attack Surface Discovery might be configured but not currently active or may require different query parameters.", findings_list=findings)
    elif not error_asd and attack_surface_devices:
        print_finding("CREM - Attack Surface Devices", f"Found {len(attack_surface_devices)} discovered device(s) (sample check). This indicates active attack surface discovery.", "WARNING", 
                     "Attack Surface Discovery within CREM consumes credits.", findings_list=findings)
    elif error_asd and "404" not in str(error_asd):
        print_finding("CREM - Attack Surface Devices", f"Error checking attack surface devices: {error_asd}", "ERROR", findings_list=findings)
    else:
        print_finding("CREM - Attack Surface Devices", "No attack surface devices found in sample check.", "INFO", findings_list=findings)
    return findings


def check_sandbox_usage(base_url, token, dry_run=False):
    findings = []
    print_section_header("Sandbox Analysis")
    if dry_run:
        _log_message(f"[DRY RUN] Would call: GET {base_url}/v3.0/sandbox/submissionUsage")
        print_finding("Sandbox Analysis", "DRY RUN: No API call made for sandbox analysis.", "INFO", findings_list=findings)
        return findings

    usage, error = get_api_data(base_url, token, "/v3.0/sandbox/submissionUsage", is_list=False)

    if error:
        print_finding("Sandbox Analysis", f"Error fetching sandbox submission usage: {error}", "ERROR", findings_list=findings)
        return findings

    if usage:
        reserve = usage.get('submissionReserveCount', 'N/A')
        remaining = usage.get('submissionRemainingCount', 'N/A')
        counted = usage.get('submissionCount', 'N/A')
        print_finding("Sandbox Analysis",
                      f"Daily Submission Reserve: {reserve}, Remaining: {remaining}, Analyzed (counted): {counted}.",
                      "INFO",
                      "Each sandbox submission (file or URL) not marked as 'Not analyzed' consumes credits. Monitor your usage.",
                      findings_list=findings)
    else:
        print_finding("Sandbox Analysis", "Could not retrieve sandbox submission usage.", "INFO", findings_list=findings)
    return findings

# --- Main Application ---

def main():
    global DEFAULT_ENDPOINT_SAMPLE_SIZE
    import json as _json
    global VERBOSE_DEBUG
    global LOG_FILE_HANDLER

    parser = argparse.ArgumentParser(
        description="Trend Vision One Credit Usage Analyzer.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-t", "--token",
        help="Trend Vision One API Key token."
    )
    parser.add_argument(
        "-r", "--region",
        choices=SERVERS.keys(),
        default=DEFAULT_REGION,
        help=f"Vision One API region. Choices: {', '.join(SERVERS.keys())}. Default: {DEFAULT_REGION}."
    )
    parser.add_argument(
        "-a", "--all_endpoints",
        action="store_true",
        help=f"Check ALL endpoints for Endpoint Security analysis instead of a sample of {DEFAULT_ENDPOINT_SAMPLE_SIZE}. \nWARNING: This can be very time-consuming for large environments."
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=None,
        help=f"Number of endpoints to sample for Endpoint Security analysis (default: {DEFAULT_ENDPOINT_SAMPLE_SIZE})."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debugging output for API calls and pagination."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be called without making any API requests (for demos)."
    )
    parser.add_argument(
        "-o", "--output_file",
        help="Path to a file where the output will be logged. If not provided, output is to console only."
    )
    parser.add_argument(
        "--export_json",
        help="Path to a JSON file to export findings for offline analysis.",
        default=None
    )
    args = parser.parse_args()

    if args.verbose:
        VERBOSE_DEBUG = True
        print("[INFO] Verbose debugging enabled.\n")

    if args.output_file:
        initialize_logging(args.output_file)
    else:
        LOG_FILE_HANDLER = None 
        print("[INFO] No output file specified. Logging to console only.")

    # Allow user to override sample size
    if args.sample_size is not None and args.sample_size > 0:
        DEFAULT_ENDPOINT_SAMPLE_SIZE = args.sample_size

    DRY_RUN = args.dry_run

    _log_message("Trend Vision One Credit Usage Analyzer - Started")
    _log_message("------------------------------------------------------------")
    _log_message("This tool helps identify configurations that might be consuming significant credits.")
    _log_message("It provides recommendations based on common high-credit features.")
    _log_message("Always cross-reference with official Trend Micro documentation and your account manager for precise credit details.\n")

    api_key_token = args.token
    if not api_key_token:
        print("Enter your Trend Vision One API Key: ", end="")
        sys.stdout.flush() 
        api_key_token = input().strip()

        if not api_key_token:
            _log_message("API Key is required. Exiting.")
            if LOG_FILE_HANDLER: LOG_FILE_HANDLER.close()
            return
        if LOG_FILE_HANDLER: _log_message("[INFO] API Key provided via prompt.")

    selected_region_code = args.region
    base_url = SERVERS.get(selected_region_code)
    if not base_url:
        _log_message(f"Invalid region code '{selected_region_code}' provided. Exiting.")
        if LOG_FILE_HANDLER: LOG_FILE_HANDLER.close()
        return
    _log_message(f"Using region: {selected_region_code} ({base_url})")


    check_all_endpoints_flag = args.all_endpoints
    if check_all_endpoints_flag:
        _log_message("\n[IMPORTANT] Checking ALL endpoints for Endpoint Security. This may take a significant amount of time...")
    else:
        _log_message(f"\nFor Endpoint Security, checking a sample of up to {DEFAULT_ENDPOINT_SAMPLE_SIZE} endpoints. Use -a or --all_endpoints to check all.")

    # Collect findings from each check
    findings = []
    pro_findings, unique_pro_guids, sampled_count, other_licenses_summary = check_endpoint_security_credits(
        base_url, api_key_token, check_all_endpoints_flag, dry_run=DRY_RUN
    )
    findings += pro_findings or []
    findings += check_datalake_pipelines(base_url, api_key_token, dry_run=DRY_RUN) or []
    findings += check_oat_pipelines(base_url, api_key_token, dry_run=DRY_RUN) or []
    findings += check_attack_surface_discovery_usage(base_url, api_key_token, dry_run=DRY_RUN) or []
    findings += check_sandbox_usage(base_url, api_key_token, dry_run=DRY_RUN) or []

    print_section_header("Analysis Complete - General Recommendations")
    _log_message("- Review the findings above and compare them with your organization's security needs.")
    _log_message("- Consult the Trend Vision One console for detailed configurations of each module.")
    _log_message("- Pay special attention to 'Advanced' or 'Pro' level features if your credit tier is 'Essentials'.")
    _log_message("- For Datalake and OAT pipelines, ensure only necessary data types and detail levels are enabled.")
    _log_message("- Regularly monitor your credit usage dashboard in Trend Vision One.")
    _log_message("- If unsure, contact your Trend Micro account manager or support for a personalized credit usage review.")
    _log_message("\nCredit analysis finished.")

    # --- Summary Table ---
    def summarize_findings(findings):
        summary = {
            "pro_license_endpoints": 0,
            "datalake_pipelines": 0,
            "oat_pipelines": 0,
            "crem_vuln_devices": 0,
            "crem_attack_surface_devices": 0,
            "sandbox_submissions": None,
        }
        for f in findings:
            if f["category"] == "License Check" and f["severity"] == "WARNING":
                # "'Advanced Endpoint Security' (Pro-level license) is allocated to X of the checked endpoints."
                msg = f["message"] or ""
                import re
                m = re.search(r"allocated to (\d+) of the checked endpoints", msg)
                if m:
                    summary["pro_license_endpoints"] += int(m.group(1))
            if f["category"] == "Datalake Pipeline" and f["severity"] == "WARNING":
                msg = f["message"] or ""
                import re
                m = re.search(r"(\d+) active datalake pipeline", msg)
                if m:
                    summary["datalake_pipelines"] += int(m.group(1))
            if f["category"] == "OAT Pipeline" and f["severity"] == "WARNING":
                msg = f["message"] or ""
                import re
                m = re.search(r"(\d+) active OAT data pipeline", msg)
                if m:
                    summary["oat_pipelines"] += int(m.group(1))
            if f["category"] == "CREM - Vulnerable Devices" and f["severity"] == "WARNING":
                msg = f["message"] or ""
                import re
                m = re.search(r"Found (\d+) vulnerable device", msg)
                if m:
                    summary["crem_vuln_devices"] += int(m.group(1))
            if f["category"] == "CREM - Attack Surface Devices" and f["severity"] == "WARNING":
                msg = f["message"] or ""
                import re
                m = re.search(r"Found (\d+) discovered device", msg)
                if m:
                    summary["crem_attack_surface_devices"] += int(m.group(1))
            if f["category"] == "Sandbox Analysis" and f["severity"] == "INFO" and f["message"]:
                msg = f["message"]
                import re
                m = re.search(r"Analyzed \(counted\): ([\dN/A]+)", msg)
                if m:
                    summary["sandbox_submissions"] = m.group(1)
        return summary

    summary = summarize_findings(findings)
    _log_message("\nSummary:")
    _log_message(f"- {len(unique_pro_guids)} unique endpoints with Pro licenses")
    _log_message(f"- {sampled_count} endpoints sampled")
    _log_message(f"- {summary['datalake_pipelines']} active Datalake pipelines")
    _log_message(f"- {summary['oat_pipelines']} active OAT pipelines")
    _log_message(f"- {summary['crem_vuln_devices']} CREM vulnerable devices")
    _log_message(f"- {summary['crem_attack_surface_devices']} CREM attack surface devices")
    if other_licenses_summary:
        _log_message(f"- Other license types:")
        for lic, count in other_licenses_summary.items():
            _log_message(f"    - {lic}: {count} endpoints")
    if summary["sandbox_submissions"] is not None:
        _log_message(f"- {summary['sandbox_submissions']} sandbox submissions (analyzed)")
    else:
        _log_message(f"- Sandbox submission count: N/A")

    # Export findings to JSON if requested
    if args.export_json:
        try:
            with open(args.export_json, "w", encoding="utf-8") as f:
                _json.dump(findings, f, indent=2)
            _log_message(f"[INFO] Findings exported to {args.export_json}")
        except Exception as e:
            _log_message(f"[API ERROR] Failed to export findings to JSON: {e}")

    if LOG_FILE_HANDLER:
        LOG_FILE_HANDLER.close()

if __name__ == "__main__":
    main()
