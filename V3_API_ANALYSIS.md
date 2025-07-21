# Vision One v3.0 API Analysis for Credit Usage Enhancement

> **Purpose**: This document preserves the comprehensive analysis of the Vision One v3.0 API specification (3.4MB) to avoid re-analyzing it in the future. It contains all key findings and implementation recommendations for credit usage optimization.

## Executive Summary

The v3.0 API provides significantly better endpoints for credit usage analysis compared to inferring usage from basic configurations. Key improvements include direct usage statistics, comprehensive CREM analysis, and investigation activity tracking.

## Key API Categories Analyzed

### 1. 🎯 **Direct Credit/Usage APIs** (HIGHEST PRIORITY)

#### Implemented ✅
- **`/v3.0/sandbox/submissionUsage`** (GET) - Sandbox quota and usage statistics
  - Returns: Daily quotas, submission counts, exemption counts
  - Headers: `TMV1-Submission-Reserve-Count`, `TMV1-Submission-Remaining-Count`, etc.

#### Available for Future Enhancement
- No other direct billing/credit APIs found in v3.0 specification

### 2. 🔍 **Search & Data Lake APIs** (MAJOR CREDIT CONSUMERS)

#### Implemented ✅
- **`/v3.0/search/activityStatistics`** (GET) - Direct search activity volume tracking
  - Parameters: `period` (24h, 7d, 30d)
  - Returns: Activity counts by product and type
  - **Credit Impact**: High search volumes = high credit consumption

- **`/v3.0/search/sensorStatistics`** (GET) - Sensor data ingestion statistics  
  - Parameters: `period` (24h, 7d, 30d)
  - Returns: Active sensor counts by product
  - **Credit Impact**: More sensors = more data = higher search costs

#### Available for Future Enhancement (Medium Priority)
- **`/v3.0/search/endpointActivities`** (GET) - Endpoint-specific search patterns
- **`/v3.0/search/cloudActivities`** (GET) - Cloud activity search volume
- **`/v3.0/search/emailActivities`** (GET) - Email search patterns
- **`/v3.0/search/networkActivities`** (GET) - Network activity search volume
- **`/v3.0/search/detections`** (GET) - Detection search activity
- **`/v3.0/search/containerActivities`** (GET) - Container search patterns
- **`/v3.0/search/mobileActivities`** (GET) - Mobile search volume
- **`/v3.0/search/identityActivities`** (GET) - Identity search patterns

### 3. 📊 **Investigation & Alert APIs** (HIGH CREDIT IMPACT)

#### Implemented ✅
- **`/v3.0/workbench/alerts`** (GET) - Alert investigation activity analysis
  - Filters: TMV1-Filter header with date ranges
  - Returns: Alert severity, investigation status, impact scope
  - **Credit Impact**: Investigations consume search credits for timeline analysis

#### Available for Future Enhancement
- **`/v3.0/workbench/alerts/{id}`** (GET) - Detailed individual alert analysis
- **`/v3.0/workbench/alerts/{alertId}/notes`** (GET) - Investigation notes and activity

### 4. 🛡️ **Enhanced CREM/ASRM APIs** (CREDIT ALLOCATION POST-NOV 2024)

> **⚠️ IMPORTANT**: All ASRM endpoints require CREM credit allocation after November 1, 2024

#### Implemented ✅
- **`/v3.0/asrm/securityPosture`** (GET) - Basic CREM status check
- **`/v3.0/asrm/vulnerableDevices`** (GET) - Vulnerability assessment
- **`/v3.0/asrm/attackSurfaceDevices`** (GET) - Attack surface discovery
- **`/v3.0/asrm/highRiskDevices`** (GET) - High-risk device analysis
- **`/v3.0/asrm/highRiskUsers`** (GET) - User risk profiling  
- **`/v3.0/asrm/accountCompromiseIndicators`** (GET) - Account compromise detection
- **`/v3.0/asrm/attackSurfaceLocalApps`** (GET) - Local application discovery

#### Available for Future Enhancement (Medium Priority)
- **`/v3.0/asrm/attackSurfaceCloudAssets`** (GET) - Cloud asset discovery
- **`/v3.0/asrm/internalAssetVulnerabilities`** (GET) - Internal vulnerability assessment
- **`/v3.0/asrm/internetFacingAssetVulnerabilities`** (GET) - External vulnerability assessment
- **`/v3.0/asrm/containerVulnerabilities`** (GET) - Container security assessment
- **`/v3.0/asrm/cloudVmVulnerabilities`** (GET) - Cloud VM vulnerability assessment
- **`/v3.0/asrm/serverlessFunctionVulnerabilities`** (GET) - Serverless function assessment

### 5. 🕵️ **OAT (Observed Attack Techniques) APIs**

#### Implemented ✅
- **`/v3.0/oat/dataPipelines`** (GET) - OAT pipeline status
- **`/v3.0/oat/detections`** (GET) - Active OAT detection analysis
  - Parameters: `detectedStartDateTime`, `detectedEndDateTime`, `top`
  - Filters: TMV1-Filter header for advanced filtering
  - Returns: Risk levels, MITRE tactics/techniques, endpoint coverage

### 6. 🥪 **Sandbox APIs**

#### Implemented ✅
- **`/v3.0/sandbox/submissionUsage`** (GET) - Usage statistics

#### Available for Future Enhancement (Low Priority)
- **`/v3.0/sandbox/tasks`** (GET) - Detailed submission history
- **`/v3.0/sandbox/analysisResults`** (GET) - Analysis results with processing details
- **`/v3.0/sandbox/files/analyze`** (POST) - File submission (returns quota headers)
- **`/v3.0/sandbox/urls/analyze`** (POST) - URL submission (returns quota headers)

### 7. 🏢 **New Credit-Consuming Areas** (Not Yet Analyzed)

#### Container Security (Medium Priority)
- **`/v3.0/containerSecurity/kubernetesClusters`** - K8s cluster monitoring
- **`/v3.0/containerSecurity/vulnerabilities`** - Container vulnerability scanning

#### Email Security (Low Priority)  
- **`/v3.0/emailAssetInventory/emailAccounts`** - Email asset discovery
- **`/v3.0/emailAssetInventory/emailDomains`** - Email domain analysis

#### Threat Intelligence (Low Priority)
- **`/v3.0/threatintel/intelligenceReports`** - TI report usage
- **`/v3.0/threatintel/suspiciousObjects`** - Suspicious object analysis

## Implementation Status

### ✅ **Phase 1 Complete** (High-Impact Direct Credit Tracking)
1. Search activity statistics (`/v3.0/search/activityStatistics`)
2. Sensor statistics (`/v3.0/search/sensorStatistics`) 
3. Enhanced CREM analysis (multiple `/v3.0/asrm/` endpoints)
4. Workbench investigation tracking (`/v3.0/workbench/alerts`)

### 🔄 **Phase 2 Available** (Comprehensive Credit Coverage)
1. Individual search activity endpoints by data source
2. Enhanced sandbox analysis (`/v3.0/sandbox/tasks`)
3. Additional CREM vulnerability endpoints
4. Detailed workbench investigation analysis

### 🔮 **Phase 3 Available** (New Credit-Consuming Areas)
1. Container security APIs
2. Email asset inventory APIs  
3. Threat intelligence usage APIs
4. Additional vulnerability assessment APIs

## Credit Correlation Insights

### 🎯 **Direct Credit Indicators**
- **Sandbox quota usage**: Actual credit consumption tracking
- **Search activity volumes**: Direct correlation to search credit usage
- **CREM feature utilization**: Post-Nov 2024 credit pool consumption

### 📈 **Indirect Credit Indicators**  
- **Alert investigation frequency**: Correlates to search activity
- **Sensor activity levels**: Affects data lake size and search costs
- **Pipeline activity**: Impacts data ingestion and retention costs
- **High-risk entity counts**: Indicates CREM processing intensity

## API Performance & Efficiency Notes

### Pagination Support
- Most endpoints support `top` parameter for page size control
- TMV1-Filter headers provide advanced filtering capabilities
- Endpoint export APIs available for bulk data retrieval

### Rate Limiting
- No explicit rate limits documented in v3.0 spec
- Current implementation includes retry logic with exponential backoff
- Monitor API response headers for rate limit indicators

### Regional Support
All endpoints support the standard Vision One regions:
- US: `https://api.xdr.trendmicro.com`
- EU: `https://api.eu.xdr.trendmicro.com`
- SG: `https://api.sg.xdr.trendmicro.com`
- JP: `https://api.xdr.trendmicro.co.jp`
- AU: `https://api.au.xdr.trendmicro.com`
- IN: `https://api.in.xdr.trendmicro.com`
- UAE: `https://api.mea.xdr.trendmicro.com`

## Future Enhancement Roadmap

### Immediate Opportunities (Next Implementation Phase)
1. **Individual Search Endpoints**: Implement all `/v3.0/search/*` endpoints for granular credit tracking
2. **Enhanced Sandbox Analysis**: Use `/v3.0/sandbox/tasks` for submission history analysis
3. **Detailed Investigation Tracking**: Individual alert analysis for deeper investigation insights

### Long-term Opportunities
1. **Container & Email Security**: Analyze new credit-consuming product areas
2. **Threat Intelligence Usage**: Track TI credit consumption patterns
3. **Advanced Vulnerability Assessment**: Comprehensive vulnerability scanning credit analysis

## API Specification Details

- **Source**: `https://automation.trendmicro.com/sp-api-open-v3.0.json`
- **Size**: 3.4MB (significantly larger than v2.0's 970KB)
- **Analysis Date**: July 21, 2025
- **Key Insight**: v3.0 provides much richer filtering, statistics, and direct usage data compared to v2.0

---

*This analysis represents a comprehensive review of the Vision One v3.0 API specification for credit usage optimization. All endpoints and recommendations are based on the official API documentation as of the analysis date.*