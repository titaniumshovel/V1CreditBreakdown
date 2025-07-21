# Vision One Credit Usage Analyzer (Enhanced v3.0)

A comprehensive Python tool that analyzes **actual credit consumption patterns** in Trend Vision One environments through direct API usage statistics, investigation activity, and feature utilization analysis.

## 🎯 What This Tool Does

Unlike basic configuration checkers, this analyzer provides **real insight into credit consumption** by examining:

- **🔍 Search Activity**: Direct analysis of data lake query volumes and patterns
- **📊 Investigation Workload**: Alert investigation activity and impact analysis  
- **🛡️ CREM Utilization**: Comprehensive cyber risk exposure management usage
- **🥪 Sandbox Usage**: Precise quota tracking and submission analysis
- **🕵️ OAT Activity**: Active threat detection and analysis patterns
- **📈 Sensor Statistics**: Data ingestion volumes affecting search costs

## ⚠️ Important Disclaimers

- **Not a billing calculator**: Provides usage insights, not exact credit calculations
- **Assessment tool**: Helps identify high-credit areas for optimization
- **Requires API access**: Needs Trend Vision One API key with appropriate permissions
- **Consult official sources**: Always verify with Trend Vision One console and account manager

## 🚀 Quick Start

### Prerequisites
- Python 3.7+
- Trend Vision One API Key
- `requests` library: `pip install requests`

### Basic Usage
```bash
# Interactive mode (prompts for API key)
python main.py

# Specify API key and region
python main.py -t YOUR_API_KEY -r EU

# Full analysis with verbose logging
python main.py -t YOUR_API_KEY -a -v -o detailed_analysis.log

# Export findings to JSON for further analysis
python main.py -t YOUR_API_KEY --export_json credit_analysis.json
```

## 📋 Required API Permissions

Your API key needs these permissions for comprehensive analysis:

| Permission | Module | Purpose |
|------------|--------|---------|
| **Search** → View, filter, and search | Search Statistics | Direct credit usage tracking |
| **Workbench** → View, filter, and search | Investigation Analysis | Alert activity patterns |
| **Reports** → View | CREM Analysis | Risk management usage |
| **Endpoint Inventory** → View | License Analysis | Pro-tier feature allocation |
| **Datalake Pipeline** → View, filter, and search | Pipeline Analysis | Data ingestion tracking |
| **Observed Attack Techniques** → View, filter, and search | OAT Analysis | Threat detection activity |
| **Sandbox Analysis** → View, filter, and search | Sandbox Usage | File/URL analysis tracking |

## 🔧 Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-t`, `--token` | API key (prompted if not provided) | `-t abc123...` |
| `-r`, `--region` | Vision One region (US/EU/SG/JP/AU/IN/UAE) | `-r EU` |
| `-a`, `--all_endpoints` | Analyze ALL endpoints (vs sample) ⚠️ | `-a` |
| `--sample-size N` | Custom endpoint sample size | `--sample-size 100` |
| `-v`, `--verbose` | Enable detailed debugging | `-v` |
| `--dry-run` | Show what would be called (demo mode) | `--dry-run` |
| `-o FILE` | Log output to file | `-o analysis.log` |
| `--export_json FILE` | Export findings to JSON | `--export_json results.json` |

## 📊 Analysis Modules

### 🔍 **Search & Data Usage Statistics** ⭐ *New*
- **Direct credit correlation**: Actual search query volumes
- **Sensor activity tracking**: Data ingestion patterns
- **Time-based analysis**: 24h, 7d, 30d patterns
- **Product breakdown**: Activity by Vision One component

### 📋 **Workbench Investigation Analysis** ⭐ *New*  
- **Alert investigation volume**: Major credit consumer
- **Impact scope analysis**: Multi-entity investigations
- **Severity patterns**: High-priority alert trends
- **Investigation status tracking**: Active vs completed analysis

### 🛡️ **Enhanced CREM Analysis** ⭐ *Enhanced*
- **⚠️ Credit allocation required** (post-Nov 1, 2024)
- **High-risk device/user analysis**: Risk scoring patterns
- **Account compromise detection**: Identity threat analysis
- **Attack surface discovery**: Application/asset visibility

### 🥪 **Sandbox Analysis**
- **Quota utilization**: Daily submission tracking
- **Credit efficiency**: Analyzed vs exempted files
- **Usage patterns**: Submission frequency analysis

### 🕵️ **OAT (Observed Attack Techniques)**
- **Detection activity**: MITRE tactic/technique coverage
- **Endpoint coverage**: Analysis scope tracking
- **Risk level distribution**: Detection severity patterns

### 🖥️ **Endpoint Security**
- **Pro license allocation**: Credit-consuming tier analysis
- **Feature utilization**: Advanced capabilities usage
- **Compliance coverage**: Enterprise vs Pro features

### 📊 **Data Pipelines**
- **Datalake pipeline status**: Data ingestion tracking
- **OAT pipeline analysis**: Threat detection data flow

## 📈 Sample Output

```
============================================================
===== SEARCH & DATA USAGE STATISTICS ANALYSIS =====
============================================================
[POTENTIAL CREDIT IMPACT] Search Statistics: Activity volume (7d): 15,847 total activities
  -> Recommendation: High search activity volumes directly correlate to credit consumption...

[POTENTIAL CREDIT IMPACT] Search Statistics: Sensor activity (7d): 1,245/1,456 active sensors (85.5%)
  -> Recommendation: Active sensors generate telemetry data that fills the data lake...

============================================================
===== WORKBENCH ALERT INVESTIGATION ANALYSIS =====
============================================================
[POTENTIAL CREDIT IMPACT] Workbench Analysis: Found 89 workbench alerts in the last 30 days
  -> Recommendation: Each alert investigation involves data lake searches and analysis...

[POTENTIAL CREDIT IMPACT] Workbench Analysis: 23 high/critical severity alerts requiring investigation
  -> Recommendation: High-severity alerts typically require more extensive investigation...
```

## 🧪 Testing

Run the comprehensive test suite:
```bash
python test_analyzer.py
```

Tests cover:
- ✅ Dry-run functionality
- ✅ Command-line options
- ✅ JSON export
- ✅ Output logging  
- ✅ Error handling

## 🏗️ Architecture

### Single-File Design
- **`main.py`**: Complete analyzer (~1400+ lines)
- **`test_analyzer.py`**: Comprehensive test suite
- **`CLAUDE.md`**: Development guidance for Claude Code
- **`V3_API_ANALYSIS.md`**: Complete v3.0 API analysis reference

### Key Functions
- **Direct Usage Analysis**: Search statistics, investigation tracking
- **Enhanced CREM**: Comprehensive risk management analysis
- **Real Credit Insights**: Actual usage patterns vs configuration inference

## 📚 Understanding Output

### Severity Levels
- **`[POTENTIAL CREDIT IMPACT]`**: Features/usage consuming credits
- **`[CONFIGURATION DETAIL]`**: Informational findings
- **`[API ERROR]`**: API access or permission issues

### Credit Correlation
- **High search volumes** → Higher data lake credit usage
- **Active investigations** → More search queries and analysis
- **CREM feature usage** → Dedicated credit pool consumption (post-Nov 2024)
- **Pro-tier licensing** → Premium feature credit allocation

## 🔒 Security & Privacy

- **Read-only analysis**: No configuration changes made
- **API key security**: Prompted interactively if not provided
- **Regional compliance**: Supports all Vision One regions
- **Local processing**: All analysis performed locally

## 📞 Support & Verification

For precise credit calculations and billing:
- **Vision One Console**: Credit usage dashboard
- **Official Documentation**: Trend Micro credit allocation guides  
- **Account Manager**: Billing and optimization consultation

## 🤝 Contributing

This tool is designed for Vision One administrators and security teams. For issues or enhancements:
- Review `V3_API_ANALYSIS.md` for available API improvements
- Check `CLAUDE.md` for development guidance
- Ensure test suite passes with `python test_analyzer.py`

## 📄 License

Provided as-is for assessment purposes. Refer to Trend Micro's official documentation for production deployment guidance.

---

**🎯 Bottom Line**: This tool helps you understand *where* your Vision One credits are being consumed so you can optimize usage, right-size deployments, and make informed decisions about feature allocation.