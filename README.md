# Trend Vision One Credit Usage Analyzer

This Python script helps identify configurations within a Trend Vision One environment that might be consuming a significant amount of service credits. It queries various API endpoints to gather information about enabled features and provides a summary with general recommendations.

**Disclaimer:** This tool provides an initial assessment based on common credit-consuming features identifiable via the public API. It does **not** calculate exact credit usage. Always consult your Trend Vision One credit usage dashboard, official Trend Micro documentation, and your account manager for precise credit details and billing information.

## Prerequisites

*   Python 3.6+
*   `requests` library (`pip install requests`)

## Setup

1.  Save the script as `credit_analyzer.py` (or any other `.py` name).
2.  Ensure you have a Trend Vision One API Key with sufficient permissions. The required permissions for full functionality include:
    *   **Endpoint Inventory:** View
    *   **Datalake Pipeline:** View, filter, and search
    *   **Observed Attack Techniques Pipeline:** View, filter, and search
    *   **Reports (for Cyber Risk Exposure Management data):** View
    *   **Sandbox Analysis:** View, filter, and search

## Usage

The script can be run from the command line.

```bash
python credit_analyzer.py [options]