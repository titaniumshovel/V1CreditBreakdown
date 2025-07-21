# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Trend Vision One Credit Usage Analyzer** - a Python command-line diagnostic tool that helps identify configurations consuming service credits in Trend Vision One environments. The tool queries Trend Micro's public APIs to assess credit-consuming features across multiple security modules.

## Common Commands

### Development and Testing
```bash
# Install required dependency
pip install requests

# Run the analyzer (interactive mode)
python main.py

# Run with specific token and region
python main.py -t YOUR_API_KEY -r EU

# Verbose debugging with log output
python main.py -t YOUR_API_KEY -v -o analysis_log.txt

# Sample fewer endpoints for testing
python main.py -t YOUR_API_KEY --sample-size 10

# Full analysis (caution: can be slow for large environments)
python main.py -t YOUR_API_KEY -a

# Dry run mode for testing without API calls
python main.py --dry-run

# Export findings to JSON
python main.py -t YOUR_API_KEY --export_json findings.json
```

### No Build/Test Commands
This project has no build system, linting, or testing infrastructure. The single Python script runs directly.

## Architecture and Code Structure

### Single-File Application
- **main.py**: Contains the entire application (~1400+ lines)
- **test_analyzer.py**: Comprehensive test suite for all functionality
- **No external config files**: All configuration is code-based or command-line driven

### Key Components

#### API Configuration (`main.py:9-17`)
```python
SERVERS = {
    "US": "https://api.xdr.trendmicro.com",
    "EU": "https://api.eu.xdr.trendmicro.com", 
    # ... other regions
}
```

#### Core Analysis Functions (Enhanced v3.0 API Integration)
- `check_endpoint_security_credits()` - Analyzes Pro licenses and security features
- `check_datalake_pipelines()` - Lists active data pipelines
- `check_oat_pipelines()` - Checks Observed Attack Techniques pipelines  
- `check_attack_surface_discovery_usage()` - CREM vulnerability/attack surface analysis
- `check_sandbox_usage()` - Sandbox submission analysis
- **`check_search_statistics_usage()`** - **NEW**: Direct search activity and sensor statistics analysis
- **`check_workbench_alerts_usage()`** - **NEW**: Investigation activity credit analysis  
- **`check_enhanced_asrm_usage()`** - **NEW**: Comprehensive CREM analysis (high-risk devices, users, compromise indicators)
- `check_oat_detections_usage()` - Active OAT detection analysis

#### API Client (`get_api_data()`)
- Handles pagination automatically
- Includes retry logic (3 attempts with exponential backoff)
- Supports both single requests and paginated list fetching
- Rate limit handling with delays

#### Logging System
- Dual output: console + optional file logging
- Structured findings collection for JSON export
- Verbose debugging mode with timestamps
- Three severity levels: INFO, WARNING, ERROR

### API Permissions Required
The Trend Vision One API key needs these permissions:
- Endpoint Inventory: View
- Datalake Pipeline: View, filter, and search
- Observed Attack Techniques Pipeline: View, filter, and search  
- Reports (for CREM data): View
- Sandbox Analysis: View, filter, and search

### Analysis Modules (Enhanced v3.0 Coverage)
1. **Endpoint Security**: Checks `creditAllocatedLicenses` and Pro-tier features (Integrity Monitoring, Log Inspection, Application Control, Advanced Risk Telemetry)
2. **Datalake Pipelines**: Lists active pipelines consuming credits
3. **OAT Pipelines**: Observed Attack Techniques pipeline analysis  
4. **CREM (Basic)**: Cyber Risk Exposure Management via security posture endpoints
5. **Sandbox**: Daily submission usage analysis
6. **OAT Detections**: Active detection analysis with MITRE tactic/technique breakdown
7. **🆕 Search Statistics**: Direct search activity volume and sensor statistics analysis
8. **🆕 Workbench Investigations**: Alert investigation activity and impact analysis
9. **🆕 Enhanced CREM**: Comprehensive risk analysis including high-risk devices, users, and compromise indicators

### Output Format
- Console output with prefixed severity levels
- Optional timestamped log files
- JSON export for structured analysis
- Summary table with counts by category

## Working with This Codebase

### Code Conventions
- Single-file architecture - all code in `main.py`
- Global variables for configuration and state
- Functional programming style with helper functions
- Error handling with try/except blocks and API retries
- No external dependencies beyond `requests` library

### When Making Changes
- Test with `--dry-run` mode first
- Use verbose mode (`-v`) for debugging API interactions
- Consider API rate limits when modifying pagination logic
- Maintain backward compatibility with existing CLI arguments
- Be careful with API endpoint changes as they map to specific Trend Vision One features

### Limitations to Be Aware Of
- No automated testing - manual verification required
- Single-threaded execution - all API calls are sequential
- No dependency management files (requirements.txt, etc.)
- Hard-coded API endpoints and feature mappings
- No configuration file support - all settings via CLI args