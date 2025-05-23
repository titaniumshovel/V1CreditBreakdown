
# Trend Vision One Credit Usage Analyzer

This Python script helps identify configurations within a Trend Vision One environment that might be consuming a significant amount of service credits. It queries various API endpoints to gather information about enabled features and provides a summary with general recommendations. The script now supports early API key validation, robust retry logic, and exporting findings to a JSON file for offline analysis.

## ⚠️ Disclaimer

This tool provides an initial assessment based on common credit-consuming features identifiable via the public API. It does **not** calculate exact credit usage. Always consult your Trend Vision One credit usage dashboard, official Trend Micro documentation, and your account manager for precise credit details and billing information.

## Prerequisites

- Python 3.7+
- `requests` library: `pip install requests`

## Setup

1. Save the Python script as `credit_analyzer.py` (or your preferred `.py` name).
2. Ensure you have a Trend Vision One API Key with sufficient permissions.

### Required API Permissions

The API key requires the following permissions for full functionality:

- **Endpoint Inventory:** View  
- **Datalake Pipeline:** View, filter, and search  
- **Observed Attack Techniques Pipeline:** View, filter, and search  
- **Reports (for Cyber Risk Exposure Management data):** View  
- **Sandbox Analysis:** View, filter, and search  

## Usage

Run the script from the command line:

```bash
python credit_analyzer.py [options]
```

### Command-Line Options

| Option                                        | Description                                                                                                                           |
|----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| `-t <TOKEN>`, `--token <TOKEN>`              | Your Trend Vision One API Key. If not provided, the script will prompt you to enter it.                                               |
| `-r <REGION_CODE>`, `--region <REGION_CODE>` | The Vision One API region to connect to. **Choices:** US, EU, SG, JP, AU, IN, UAE **Default:** US                                     |
| `-a`, `--all_endpoints`                      | Fetch information for ALL endpoints for the Endpoint Security analysis. API will be queried with a page size of 200.                 |
|                                              | ⚠️ **WARNING:** This can be very time-consuming for environments with a large number of endpoints. **Default:** Samples 50 endpoints |
| `--sample-size <N>`                          | Number of endpoints to sample for Endpoint Security analysis. Overrides the default sample size (default: 50).                        |
| `-v`, `--verbose`                            | Enable verbose debugging output for API calls and pagination details. Output goes to both console and log file. **Default:** Disabled |
| `--dry-run`                                  | Show what would be called without making any API requests (for demos).                                                                |
| `-o <FILE_PATH>`, `--output_file <FILE_PATH>`| Path to a file where full output will be logged with timestamps. **Default:** `v1_credit_analyzer_log_YYYYMMDD_HHMMSS.txt`           |
| `--export_json <FILE_PATH>`                  | Path to a JSON file to export findings for offline analysis.                                                                          |
| `-h`, `--help`                               | Show help message and exit.                                                                                                            |

### Examples

**Run interactively** (prompts for token, uses US region, samples endpoints):

```bash
python credit_analyzer.py
```

**Specify token and region with verbose logging:**

```bash
python credit_analyzer.py -t YOUR_API_KEY_HERE -r EU -v -o ./analysis_reports/eu_credit_check.log
```

**Change the sample size for endpoint analysis:**

```bash
python credit_analyzer.py -t YOUR_API_KEY_HERE --sample-size 100
```

**Check ALL endpoints** (use with caution):

```bash
python credit_analyzer.py -t YOUR_API_KEY_HERE -a
```

**Full analysis for Japan region and export findings to JSON:**

```bash
python credit_analyzer.py --token YOUR_API_KEY_HERE --region JP --all_endpoints --export_json jp_full_analysis.json
```

## Output

The script prints findings to the console and logs them to a file with timestamps. Findings are categorized by Vision One module. If the `--export_json` option is used, all findings are also saved in structured JSON format for offline analysis or upload.

At the end of the run, a summary table is appended, for example:

```text
Summary:
- 3 endpoints with Pro licenses
- 2 active Datalake pipelines
- 0 OAT pipelines
- 0 CREM vulnerable devices
- 0 CREM attack surface devices
- 5 sandbox submissions (analyzed)
```

If you use `--dry-run`, the script will only log what would be called, without making any API requests. This is useful for demos or testing.

### Analysis Categories

#### 🖥️ Endpoint Security Analysis

- Checks for explicitly allocated Pro-level licenses (`creditAllocatedLicenses`)
- Identifies specific features indicating Pro-tier usage:
  - Integrity Monitoring
  - Log Inspection
  - Application Control
  - Advanced Risk Telemetry

#### 📊 Datalake Pipeline Analysis

- Lists active Datalake pipelines

#### 🎯 Observed Attack Techniques (OAT) Pipeline Analysis

- Lists active OAT pipelines

#### 🛡️ Cyber Risk Exposure Management (CREM) Analysis

- Checks if CREM is active via `/v3.0/asrm/securityPosture` endpoint
- Probes `/v3.0/asrm/vulnerableDevices` for active vulnerability assessment
- Probes `/v3.0/asrm/attackSurfaceDevices` for active attack surface discovery

#### 🔍 Sandbox Analysis

- Shows daily sandbox submission usage

### Output Prefixes

- `[POTENTIAL CREDIT IMPACT]`: Features or configurations known to consume credits  
- `[CONFIGURATION DETAIL]`: Informational details  
- `[API ERROR]`: Errors occurred while fetching data from the API  

General recommendations are provided at the end of each analysis.

## How It Works

The script uses the Trend Vision One Public API (v3.0) to:

1. **Validate API Key**: Before running any analysis, the script validates your API key with a lightweight endpoint to ensure it is correct and has sufficient permissions.
2. **Fetch endpoint data** (sample or all) and check their `creditAllocatedLicenses` and security feature statuses.
3. **List active pipelines** for Datalake and OAT that require credits.
4. **Query CREM data** by checking security posture and related endpoints.
5. **Analyze sandbox usage** to identify submission patterns.
6. **Export findings**: If requested, findings are saved to a JSON file for offline review.

The script highlights areas that commonly contribute to higher credit consumption based on API documentation and typical product behavior.

## Reliability Features

- **Early API Key Validation**: Provides immediate feedback if the key is invalid.
- **Robust Retry Logic**: API requests retry up to 3 times with delay on transient failures. (Exponential backoff and rate limit handling are planned for future releases.)
- **Structured Findings Export**: Use `--export_json` to save results for offline analysis or upload.

## Limitations

### ⚠️ Important Considerations

- **No Exact Credit Calculation**: Identifies potentially credit-heavy features but doesn't calculate exact usage.
- **API Rate Limits**: For large environments using `--all_endpoints`, the script may encounter rate limits. (Backoff logic is planned.)
- **Scope of Analysis**: Only includes data accessible via documented API endpoints.
- **Feature Interpretation**: "Pro" tier detection is inferred from common packaging.

### Credit Calculation Complexity

Exact credit calculation depends on:

- Specific SKUs and tiers
- Data volumes
- Product configurations not fully exposed via public API

## Support

For precise credit details and billing information, consult:

- Your Trend Vision One credit usage dashboard
- Official Trend Micro documentation
- Your Trend Micro account manager

## License

This tool is provided as-is for assessment purposes. Please refer to Trend Micro's official documentation and support channels for production use guidance.
