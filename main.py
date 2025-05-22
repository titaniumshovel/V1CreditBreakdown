import requests
import json
import argparse # For command-line arguments
from datetime import datetime, timedelta

# --- Configuration ---
# Base URLs for different Vision One regions
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
DEFAULT_REGION = "US" # Default region

# Global flag for verbose debugging, controlled by command-line argument
VERBOSE_DEBUG = False

# --- Helper Functions ---
def get_api_data(base_url, token, endpoint_path, params=None, headers_extra=None, is_list=True, fetch_all=False):
    """
    Generic function to make GET requests to the Vision One API, handling pagination.

    Args:
        base_url (str): The base URL for the Vision One API region.
        token (str): The API authentication token.
        endpoint_path (str): The specific API endpoint path (e.g., "/v3.0/endpointSecurity/endpoints").
        params (dict, optional): Query parameters for the initial request. Defaults to None.
        headers_extra (dict, optional): Additional headers for the request. Defaults to None.
        is_list (bool, optional): True if the endpoint is expected to return a list of items under an "items" key.
                                  False if it returns a single JSON object directly. Defaults to True.
        fetch_all (bool, optional): True to fetch all pages of data. False to fetch only the first page
                                    (or up to the 'top' parameter if specified for sampling). Defaults to False.

    Returns:
        tuple: (data, error_message)
               - data: The collected JSON data (list of items or a single dictionary).
               - error_message: A string containing an error message if an error occurred, otherwise None.
    """
    global VERBOSE_DEBUG # Access the global verbose flag

    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json;charset=utf-8"
    }
    if headers_extra:
        headers.update(headers_extra)

    current_url = base_url + endpoint_path
    current_params = dict(params) if params else {} # Use a copy for the first request
    all_items = []
    page_count = 0
    # Safety break for sampling if API returns many pages for a small 'top' or if a single page is huge.
    max_pages_for_sample_safety = 20

    # Determine the 'top' value for the initial API call and for sampling break condition
    # For fetch_all, we usually set a higher 'top' in the calling function (e.g., 200 for endpoints)
    # For sampling, it's either the passed 'top' or DEFAULT_ENDPOINT_SAMPLE_SIZE
    initial_top_value_for_sampling = current_params.get('top', DEFAULT_ENDPOINT_SAMPLE_SIZE)

    if VERBOSE_DEBUG:
        print(f"  [VERBOSE] get_api_data: endpoint='{endpoint_path}', fetch_all={fetch_all}, initial_params={params}")

    while current_url:
        try:
            # For the first request, use current_params. For subsequent, params are in nextLink.
            request_params_for_this_call = current_params if page_count == 0 else None
            if VERBOSE_DEBUG:
                print(f"  [VERBOSE] Page: {page_count + 1}, Fetching URL: {current_url}, Params: {request_params_for_this_call}")
            
            response = requests.get(current_url, headers=headers, params=request_params_for_this_call, timeout=45)
            response.raise_for_status() # Raises HTTPError for bad responses (4XX or 5XX)
            data = response.json()

            if not is_list: # For endpoints returning a single JSON object
                if VERBOSE_DEBUG: print(f"  [VERBOSE] Endpoint is not a list. Returning data for {endpoint_path}.")
                return data, None

            # Process list-based endpoints
            items_on_page = data.get("items", [])
            total_count_from_api = data.get("totalCount", "N/A")
            count_on_page_from_api = data.get("count", len(items_on_page) if isinstance(items_on_page, list) else (1 if items_on_page else 0) )

            if VERBOSE_DEBUG:
                print(f"  [VERBOSE] Received {len(items_on_page) if isinstance(items_on_page, list) else 1} items on this page. API reports 'count': {count_on_page_from_api}, 'totalCount': {total_count_from_api}.")

            if isinstance(items_on_page, list):
                all_items.extend(items_on_page)
            elif items_on_page: # Should ideally not happen if is_list is True and API is consistent
                all_items.append(items_on_page)
            
            page_count += 1
            current_url = data.get("nextLink")
            if VERBOSE_DEBUG:
                print(f"  [VERBOSE] nextLink from API: {current_url}")
                print(f"  [VERBOSE] Current total items collected for {endpoint_path}: {len(all_items)}")

            # Pagination control
            if not fetch_all: # Sampling logic
                if VERBOSE_DEBUG: print(f"  [VERBOSE] Sampling logic active. Desired sample size: {initial_top_value_for_sampling}")
                if not current_url: # No more pages
                    if VERBOSE_DEBUG: print(f"  [VERBOSE] Sampling: No nextLink, breaking loop for {endpoint_path}.")
                    break
                # Stop if desired sample size reached or safety page limit hit
                if len(all_items) >= initial_top_value_for_sampling or page_count >= max_pages_for_sample_safety:
                    if VERBOSE_DEBUG: print(f"  [VERBOSE] Sampling: Sample size ({len(all_items)}) or page count ({page_count}) limit reached for {endpoint_path}. Breaking loop.")
                    if len(all_items) > initial_top_value_for_sampling: # Trim if overshot
                        all_items = all_items[:initial_top_value_for_sampling]
                        if VERBOSE_DEBUG: print(f"  [VERBOSE] Sampling: Trimmed items to {len(all_items)} for {endpoint_path}")
                    break
            
            if not current_url: # End of data if no nextLink (for both fetch_all and sampling)
                if VERBOSE_DEBUG: print(f"  [VERBOSE] No nextLink. End of data for {endpoint_path}.")
                break
            
            current_params = None # Params for subsequent pages are in nextLink

        except requests.exceptions.HTTPError as e:
            error_content = "Unknown error"
            try:
                error_content = e.response.json()
            except json.JSONDecodeError:
                error_content = e.response.text
            return None, f"HTTP Error for {endpoint_path}: {e.response.status_code} - {error_content}"
        except requests.exceptions.RequestException as e:
            return None, f"Request Exception for {endpoint_path}: {e}"
        except json.JSONDecodeError as e: # If API returns non-JSON for an error
            return None, f"JSON Decode Error for {endpoint_path}: {e.msg} in response: {response.text[:200]}" # Show start of bad response
    
    if VERBOSE_DEBUG: print(f"  [VERBOSE] Finished fetching for {endpoint_path}. Total items collected: {len(all_items)}")
    return all_items, None

def print_section_header(title):
    """Prints a formatted section header."""
    print("\n" + "="*60)
    print(f"===== {title.upper()} =====")
    print("="*60)

def print_finding(category, message, severity="INFO", recommendation=None):
    """
    Prints a finding with a severity prefix and an optional recommendation.
    Severity levels: INFO, WARNING, ERROR.
    """
    severity_map = {
        "INFO": "[CONFIGURATION DETAIL]",
        "WARNING": "[POTENTIAL CREDIT IMPACT]",
        "ERROR": "[API ERROR]"
    }
    # Ensure message is not None before printing to avoid "None" string
    if message is not None:
        print(f"{severity_map.get(severity, severity)} {category}: {message}")
    elif severity_map.get(severity, severity): # Print severity tag even if message is None
        print(f"{severity_map.get(severity, severity)} {category}:")


    if recommendation:
        print(f"  -> Recommendation: {recommendation}")

# --- Analysis Functions ---

def check_endpoint_security_credits(base_url, token, fetch_all_endpoints=False):
    """
    Analyzes Endpoint Security configurations for potential credit impact.
    Focuses on 'creditAllocatedLicenses'.
    """
    print_section_header("Endpoint Security Analysis")

    # Define parameters for the API call based on whether we fetch all or a sample
    # The '/v3.0/endpointSecurity/endpoints' endpoint supports 'top' up to 1000.
    params_for_api_call = {'top': 200} if fetch_all_endpoints else {'top': DEFAULT_ENDPOINT_SAMPLE_SIZE}

    if VERBOSE_DEBUG:
        print(f"  [VERBOSE] check_endpoint_security_credits: fetch_all_endpoints={fetch_all_endpoints}, params_for_api_call={params_for_api_call}")

    if fetch_all_endpoints:
        print(f"  Attempting to fetch ALL endpoints with page size {params_for_api_call['top']}. This may take a significant amount of time for large environments...")
    else:
        print(f"  Fetching a sample of up to {params_for_api_call['top']} endpoints...")

    endpoints, error = get_api_data(base_url, token, "/v3.0/endpointSecurity/endpoints", params=params_for_api_call, fetch_all=fetch_all_endpoints)

    if error:
        print_finding("Endpoint Security", f"Error fetching endpoint data: {error}", "ERROR")
        return

    if not endpoints:
        print_finding("Endpoint Security", "No endpoints found or unable to retrieve endpoint data.", "INFO")
        return

    # Dictionary to store endpoints associated with Pro-level licenses
    pro_license_endpoints = {
        "Advanced Endpoint Security": [],
        "Advanced Server & Workload Protection": [],
        "SAP Scanner for Trend Vision One - Endpoint Security (Pro)": []
    }
    # Dictionary to summarize other licenses
    other_licenses_summary = {}

    # Iterate through endpoints to check their licenses
    for endpoint in endpoints:
        agent_guid = endpoint.get("agentGuid", "Unknown GUID")
        endpoint_name = endpoint.get("endpointName", "Unknown Name")
        licenses = endpoint.get("creditAllocatedLicenses", [])

        for license_name in licenses:
            if license_name in pro_license_endpoints:
                pro_license_endpoints[license_name].append(f"{endpoint_name} (GUID: {agent_guid})")
            else:
                other_licenses_summary[license_name] = other_licenses_summary.get(license_name, 0) + 1

    found_pro_features = False
    for license_type, eps in pro_license_endpoints.items():
        if eps:
            found_pro_features = True
            print_finding(
                "Endpoint Security",
                f"'{license_type}' (Pro-level feature) is enabled on {len(eps)} of the checked endpoints.",
                "WARNING",
                f"Review if '{license_type}' is required for all these endpoints. Check Endpoint Inventory and associated Sensor Policies in Vision One console."
            )
            # Display a limited number of examples if the list is long
            if len(eps) > 3:
                print(f"    Examples: {', '.join(eps[:3])}..., and {len(eps)-3} more.")
            else:
                print(f"    Endpoints: {', '.join(eps)}")

    if other_licenses_summary:
         print_finding("Endpoint Security", "Other licenses found (typically Essentials or base EDR):", "INFO")
         for lic, count in other_licenses_summary.items():
             print(f"    - '{lic}': {count} endpoints")

    if not found_pro_features:
        print_finding("Endpoint Security", "No Pro-level Endpoint Security licenses found on the checked endpoints.", "INFO")

    # Provide context on the number of endpoints checked
    if not fetch_all_endpoints and len(endpoints) == params_for_api_call['top']:
        print(f"\nChecked a sample of {len(endpoints)} endpoints. This may be the limit of the sample size. For a full list, re-run with the '-a' or '--all_endpoints' flag (this may take time).")
    else:
        print(f"\nChecked {len(endpoints)} endpoints.")


def check_datalake_pipelines(base_url, token):
    """Analyzes Datalake Pipeline configurations, as these consume credits."""
    print_section_header("Datalake Pipeline Analysis")
    # This endpoint returns an object where 'items' is the list of pipelines
    pipelines_data, error = get_api_data(base_url, token, "/v3.0/datalake/dataPipelines", is_list=False)

    if error:
        print_finding("Datalake Pipeline", f"Error fetching datalake pipelines: {error}", "ERROR")
        return

    pipelines = pipelines_data.get("items", []) if pipelines_data else [] # Safely get items
    if pipelines and len(pipelines) > 0:
        print_finding("Datalake Pipeline", f"{len(pipelines)} active datalake pipeline(s) found. These consume credits.", "WARNING")
        for pipeline in pipelines:
            pipeline_id = pipeline.get('id', 'Unknown ID')
            pipeline_type = pipeline.get('type', 'Unknown Type')
            sub_type = pipeline.get('subType', [])
            description = pipeline.get('description', 'No description')
            print(f"  - ID: {pipeline_id}, Type: {pipeline_type}, SubTypes: {', '.join(sub_type) if sub_type else 'N/A'}, Description: {description}")
        print_finding("Datalake Pipeline", "", "INFO", "Review active Datalake Pipelines in Vision One console to ensure all bound data types are necessary.")
    else:
        print_finding("Datalake Pipeline", "No active Datalake Pipelines found.", "INFO")

def check_attack_surface_discovery_usage(base_url, token):
    """
    Checks if Cyber Risk Exposure Management (CREM) modules are active by querying the security posture.
    """
    print_section_header("Cyber Risk Exposure Management (CREM) Analysis")
    # Attempt to fetch security posture data; success implies CREM is active.
    _, error = get_api_data(base_url, token, "/v3.0/asrm/securityPosture", is_list=False)

    if error and "403" in str(error) and "credits" in str(error).lower():
         print_finding("CREM", f"CREM usage is likely disabled or restricted due to credit allocation: {error}", "INFO")
    elif error:
        # A 404 might mean this specific sub-endpoint isn't used, not that CREM is entirely off.
        # Other errors might still indicate activity.
        if "404" not in str(error):
            print_finding("CREM", "Attempted to check CREM Security Posture. An error occurred, but this might still indicate CREM is active or configured.", "WARNING", f"Details: {error}")
        else:
            print_finding("CREM", "Could not confirm CREM Security Posture data (endpoint might not be used or general error).", "INFO")
    else:
        print_finding("CREM", "Security Posture data retrieved, indicating CREM module is active.", "WARNING",
                      "CREM (Cyber Risk Exposure Management) consumes credits. Review its configuration and usage in Vision One console.")

def check_sandbox_usage(base_url, token):
    """Checks Sandbox Analysis submission usage."""
    print_section_header("Sandbox Analysis")
    usage, error = get_api_data(base_url, token, "/v3.0/sandbox/submissionUsage", is_list=False)

    if error:
        print_finding("Sandbox Analysis", f"Error fetching sandbox submission usage: {error}", "ERROR")
        return

    if usage:
        reserve = usage.get('submissionReserveCount', 'N/A')
        remaining = usage.get('submissionRemainingCount', 'N/A')
        counted = usage.get('submissionCount', 'N/A')
        print_finding("Sandbox Analysis",
                      f"Daily Submission Reserve: {reserve}, Remaining: {remaining}, Analyzed (counted): {counted}.",
                      "INFO",
                      "Each sandbox submission (file or URL) not marked as 'Not analyzed' consumes credits. Monitor your usage.")
    else:
        print_finding("Sandbox Analysis", "Could not retrieve sandbox submission usage.", "INFO")

def check_oat_pipelines(base_url, token):
    """Checks for active Observed Attack Techniques (OAT) Pipelines."""
    print_section_header("Observed Attack Techniques (OAT) Pipeline Analysis")
    pipelines_data, error = get_api_data(base_url, token, "/v3.0/oat/dataPipelines", is_list=False)

    if error:
        print_finding("OAT Pipeline", f"Error fetching OAT pipelines: {error}", "ERROR")
        return

    pipelines = pipelines_data.get("items", []) if pipelines_data else []
    if pipelines and len(pipelines) > 0:
        print_finding("OAT Pipeline", f"{len(pipelines)} active OAT data pipeline(s) found.", "WARNING")
        for pipeline in pipelines:
            pipeline_id = pipeline.get('id', 'Unknown ID')
            risk_levels = pipeline.get('riskLevels', [])
            has_detail = pipeline.get('hasDetail', False)
            description = pipeline.get('description', 'No description')
            print(f"  - ID: {pipeline_id}, Risk Levels: {', '.join(risk_levels)}, Has Detail: {has_detail}, Description: {description}")
        print_finding("OAT Pipeline", "", "INFO", "Review active OAT Pipelines. Enabling 'hasDetail' or including many risk levels might increase data volume and potentially credit consumption if linked to other credit-based services.")
    else:
        print_finding("OAT Pipeline", "No active OAT Data Pipelines found.", "INFO")

# --- Main Application ---
def main():
    """
    Main function to parse arguments, get user input if needed, and run analyses.
    """
    global VERBOSE_DEBUG # To set it based on command-line arg

    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(
        description="Trend Vision One Credit Usage Analyzer.",
        formatter_class=argparse.RawTextHelpFormatter # Allows for better formatting in help
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
        action="store_true", # Makes it a boolean flag
        help=f"Check ALL endpoints for Endpoint Security analysis instead of a sample of {DEFAULT_ENDPOINT_SAMPLE_SIZE}. \nWARNING: This can be very time-consuming for large environments."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debugging output for API calls and pagination."
    )
    args = parser.parse_args()

    if args.verbose:
        VERBOSE_DEBUG = True
        print("[INFO] Verbose debugging enabled.\n")

    # --- Initial Setup & User Interaction ---
    print("Trend Vision One Credit Usage Analyzer")
    print("--------------------------------------")
    print("This tool helps identify configurations that might be consuming significant credits.")
    print("It provides recommendations based on common high-credit features.")
    print("Always cross-reference with official Trend Micro documentation and your account manager for precise credit details.\n")

    api_key_token = args.token
    if not api_key_token:
        api_key_token = input("Enter your Trend Vision One API Key: ").strip()
        if not api_key_token:
            print("API Key is required. Exiting.")
            return

    selected_region_code = args.region
    base_url = SERVERS.get(selected_region_code)
    if not base_url: # Should not happen if argparse choices are used correctly
        print(f"Invalid region code '{selected_region_code}' provided. Exiting.")
        return
    print(f"Using region: {selected_region_code} ({base_url})")

    check_all_endpoints_flag = args.all_endpoints
    if check_all_endpoints_flag:
        print("\n[IMPORTANT] Checking ALL endpoints. This may take a significant amount of time...")
    else:
        print(f"\nFor Endpoint Security, checking a sample of up to {DEFAULT_ENDPOINT_SAMPLE_SIZE} endpoints. Use -a or --all_endpoints to check all.")

    # --- Perform Analysis ---
    check_endpoint_security_credits(base_url, api_key_token, check_all_endpoints_flag)
    check_datalake_pipelines(base_url, api_key_token)
    check_oat_pipelines(base_url, api_key_token)
    check_attack_surface_discovery_usage(base_url, api_key_token)
    check_sandbox_usage(base_url, api_key_token)

    # --- Final Recommendations ---
    print("\n" + "="*60)
    print("===== ANALYSIS COMPLETE =====")
    print("="*60)
    print("\nGeneral Recommendations:")
    print("- Review the findings above and compare them with your organization's security needs.")
    print("- Consult the Trend Vision One console for detailed configurations of each module.")
    print("- Pay special attention to 'Advanced' or 'Pro' level features if your credit tier is 'Essentials'.")
    print("- For Datalake and OAT pipelines, ensure only necessary data types and detail levels are enabled.")
    print("- Regularly monitor your credit usage dashboard in Trend Vision One.")
    print("- If unsure, contact your Trend Micro account manager or support for a personalized credit usage review.")

if __name__ == "__main__":
    main()