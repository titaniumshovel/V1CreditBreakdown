# Trend Vision One Credit Usage Analyzer

This Python script helps identify configurations within a Trend Vision One environment that might be consuming a significant amount of service credits. It queries various API endpoints to gather information about enabled features and provides a summary with general recommendations.

**Disclaimer:** This tool provides an initial assessment based on common credit-consuming features identifiable via the public API. It does **not** calculate exact credit usage. Always consult your Trend Vision One credit usage dashboard, official Trend Micro documentation, and your account manager for precise credit details and billing information.

## Prerequisites

* Python 3.6+
* `requests` library (`pip install requests`)

## Setup

1. Save the script as `credit_analyzer.py` (or any other `.py` name).
2. Ensure you have a Trend Vision One API Key with sufficient permissions. The required permissions for full functionality include:
    * **Endpoint Inventory:** View
    * **Datalake Pipeline:** View, filter, and search
    * **Observed Attack Techniques Pipeline:** View, filter, and search
    * **Reports (for Cyber Risk Exposure Management data):** View
    * **Sandbox Analysis:** View, filter, and search

## Command-Line Options

* -t `<TOKEN>`, --token `<TOKEN>`:
Your Trend Vision One API Key.
If not provided, the script will prompt you to enter it.
* -r `<REGION_CODE>`, --region `<REGION_CODE>`:
The Vision One API region to connect to.
Choices: US, EU, SG, JP, AU, IN, UAE
Default: US
* -a, --all_endpoints:
If specified, the script will attempt to fetch information for ALL endpoints for the Endpoint Security analysis.
WARNING: This can be very time-consuming for environments with a large number of endpoints.
Default: Checks a sample of 50 endpoints.
* -v, --verbose:
Enable verbose debugging output, primarily for API call and pagination details. Useful for troubleshooting.
Default: Disabled.
* -h, --help:
Show the help message and exit.

## Usage

The script can be run from the command line.

```bash
python credit_analyzer.py [options]
