#!/usr/bin/env python3
"""
Test script for Vision One Credit Usage Analyzer
Tests all major functionality without requiring real API credentials.
"""

import subprocess
import sys
import os
import json
from datetime import datetime

def test_dry_run_functionality():
    """Test the analyzer in dry-run mode to verify all endpoints are called correctly"""
    print("=" * 60)
    print("TESTING: Dry-run functionality")
    print("=" * 60)
    
    cmd = [sys.executable, "main.py", "--dry-run", "-v"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            print(f"❌ FAILED: Dry-run returned non-zero exit code: {result.returncode}")
            print("STDERR:", result.stderr)
            return False
        
        output = result.stdout
        
        # Check for all expected analysis sections (v3.0 endpoints + new enhancements)
        expected_sections = [
            "ENDPOINT SECURITY ANALYSIS",
            "DATALAKE PIPELINE ANALYSIS", 
            "OBSERVED ATTACK TECHNIQUES (OAT) PIPELINE ANALYSIS",
            "CYBER RISK EXPOSURE MANAGEMENT (CREM) ANALYSIS",
            "SANDBOX ANALYSIS",
            "OAT DETECTIONS USAGE ANALYSIS",
            "SEARCH & DATA USAGE STATISTICS ANALYSIS",
            "WORKBENCH ALERT INVESTIGATION ANALYSIS", 
            "ENHANCED CREM (CYBER RISK EXPOSURE MANAGEMENT) ANALYSIS"
        ]
        
        missing_sections = []
        for section in expected_sections:
            if section not in output:
                missing_sections.append(section)
        
        if missing_sections:
            print(f"❌ FAILED: Missing analysis sections: {missing_sections}")
            return False
        
        # Check for expected API calls (v3.0 endpoints + new enhancements)
        expected_calls = [
            "/v3.0/endpointSecurity/endpoints",
            "/v3.0/datalake/dataPipelines",
            "/v3.0/oat/dataPipelines",
            "/v3.0/asrm/securityPosture",
            "/v3.0/sandbox/submissionUsage",
            "/v3.0/oat/detections",
            "/v3.0/search/activityStatistics",
            "/v3.0/search/sensorStatistics",
            "/v3.0/workbench/alerts",
            "/v3.0/asrm/highRiskDevices",
            "/v3.0/asrm/highRiskUsers"
        ]
        
        missing_calls = []
        for call in expected_calls:
            if call not in output:
                missing_calls.append(call)
        
        if missing_calls:
            print(f"❌ FAILED: Missing API calls: {missing_calls}")
            return False
        
        print("✅ PASSED: All analysis sections present")
        print("✅ PASSED: All expected API endpoints called")
        print(f"✅ PASSED: Analysis completed successfully")
        
        return True
        
    except subprocess.TimeoutExpired:
        print("❌ FAILED: Dry-run test timed out after 30 seconds")
        return False
    except Exception as e:
        print(f"❌ FAILED: Exception during dry-run test: {e}")
        return False

def test_command_line_options():
    """Test various command-line options"""
    print("\n" + "=" * 60)
    print("TESTING: Command-line options")
    print("=" * 60)
    
    tests = [
        {
            "name": "Help option",
            "cmd": [sys.executable, "main.py", "-h"],
            "expect_success": True,
            "check_output": "Trend Vision One Credit Usage Analyzer"
        },
        {
            "name": "Sample size option", 
            "cmd": [sys.executable, "main.py", "--dry-run", "--sample-size", "25"],
            "expect_success": True,
            "check_output": "checking a sample of up to 25 endpoints"
        },
        {
            "name": "All endpoints option",
            "cmd": [sys.executable, "main.py", "--dry-run", "-a"],
            "expect_success": True,
            "check_output": "Checking ALL endpoints"
        },
        {
            "name": "Region selection",
            "cmd": [sys.executable, "main.py", "--dry-run", "-r", "EU"],
            "expect_success": True,
            "check_output": "Using region: EU"
        },
        {
            "name": "Verbose mode",
            "cmd": [sys.executable, "main.py", "--dry-run", "-v"],
            "expect_success": True,
            "check_output": "Verbose debugging enabled"
        }
    ]
    
    all_passed = True
    
    for test in tests:
        try:
            result = subprocess.run(test["cmd"], capture_output=True, text=True, timeout=15)
            
            if test["expect_success"] and result.returncode != 0:
                print(f"❌ FAILED: {test['name']} - Expected success but got return code {result.returncode}")
                all_passed = False
                continue
                
            if test.get("check_output") and test["check_output"] not in result.stdout:
                print(f"❌ FAILED: {test['name']} - Expected output '{test['check_output']}' not found")
                all_passed = False
                continue
                
            print(f"✅ PASSED: {test['name']}")
            
        except subprocess.TimeoutExpired:
            print(f"❌ FAILED: {test['name']} - Timed out")
            all_passed = False
        except Exception as e:
            print(f"❌ FAILED: {test['name']} - Exception: {e}")
            all_passed = False
    
    return all_passed

def test_json_export_functionality():
    """Test JSON export functionality"""
    print("\n" + "=" * 60)
    print("TESTING: JSON export functionality")
    print("=" * 60)
    
    json_file = "test_export.json"
    
    try:
        # Clean up any existing test file
        if os.path.exists(json_file):
            os.remove(json_file)
        
        cmd = [sys.executable, "main.py", "--dry-run", "--export_json", json_file]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        
        if result.returncode != 0:
            print(f"❌ FAILED: JSON export returned non-zero exit code: {result.returncode}")
            return False
        
        if not os.path.exists(json_file):
            print("❌ FAILED: JSON export file was not created")
            return False
        
        # Validate JSON structure
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        if not isinstance(data, list):
            print("❌ FAILED: JSON export should be a list of findings")
            return False
        
        # Check for expected structure in findings
        if data:  # If there are findings
            sample_finding = data[0]
            required_fields = ["category", "message", "severity"]
            for field in required_fields:
                if field not in sample_finding:
                    print(f"❌ FAILED: JSON finding missing required field: {field}")
                    return False
        
        print(f"✅ PASSED: JSON export created successfully with {len(data)} findings")
        
        # Clean up
        os.remove(json_file)
        return True
        
    except Exception as e:
        print(f"❌ FAILED: JSON export test exception: {e}")
        # Clean up on failure
        if os.path.exists(json_file):
            os.remove(json_file)
        return False

def test_output_logging():
    """Test output logging functionality"""
    print("\n" + "=" * 60)
    print("TESTING: Output logging functionality")
    print("=" * 60)
    
    log_file = "test_output.log"
    
    try:
        # Clean up any existing test file
        if os.path.exists(log_file):
            os.remove(log_file)
        
        cmd = [sys.executable, "main.py", "--dry-run", "-o", log_file]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        
        if result.returncode != 0:
            print(f"❌ FAILED: Output logging returned non-zero exit code: {result.returncode}")
            return False
        
        if not os.path.exists(log_file):
            print("❌ FAILED: Output log file was not created")
            return False
        
        # Check log file content
        with open(log_file, 'r') as f:
            log_content = f.read()
        
        # Should contain timestamps and analysis sections
        if "ENDPOINT SECURITY ANALYSIS" not in log_content:
            print("❌ FAILED: Log file missing expected analysis content")
            return False
        
        # Should contain timestamp format [YYYY-MM-DD HH:MM:SS.mmm]
        import re
        if not re.search(r'\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\]', log_content):
            print("❌ FAILED: Log file missing expected timestamp format")
            return False
        
        print(f"✅ PASSED: Output logging created successfully")
        print(f"✅ PASSED: Log file contains timestamps and analysis content")
        
        # Clean up
        os.remove(log_file)
        return True
        
    except Exception as e:
        print(f"❌ FAILED: Output logging test exception: {e}")
        # Clean up on failure
        if os.path.exists(log_file):
            os.remove(log_file)
        return False

def test_error_handling():
    """Test error handling for invalid inputs"""
    print("\n" + "=" * 60)
    print("TESTING: Error handling")
    print("=" * 60)
    
    tests = [
        {
            "name": "Invalid region",
            "cmd": [sys.executable, "main.py", "--dry-run", "-r", "INVALID"],
            "expect_failure": True,
            "check_output": "invalid choice"
        },
        {
            "name": "Invalid sample size", 
            "cmd": [sys.executable, "main.py", "--dry-run", "--sample-size", "abc"],
            "expect_failure": True,
            "check_output": "invalid int value"  # argparse error
        }
    ]
    
    all_passed = True
    
    for test in tests:
        try:
            result = subprocess.run(test["cmd"], capture_output=True, text=True, timeout=10)
            
            if test["expect_failure"] and result.returncode == 0:
                print(f"❌ FAILED: {test['name']} - Expected failure but got success")
                all_passed = False
                continue
                
            if test.get("check_output"):
                combined_output = result.stdout + result.stderr
                if test["check_output"] not in combined_output:
                    print(f"❌ FAILED: {test['name']} - Expected error message not found")
                    all_passed = False
                    continue
                    
            print(f"✅ PASSED: {test['name']}")
            
        except subprocess.TimeoutExpired:
            print(f"❌ FAILED: {test['name']} - Timed out")
            all_passed = False
        except Exception as e:
            print(f"❌ FAILED: {test['name']} - Exception: {e}")
            all_passed = False
    
    return all_passed

def main():
    """Run all tests"""
    print("Vision One Credit Usage Analyzer - Test Suite")
    print("=" * 60)
    print(f"Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    tests = [
        ("Dry-run functionality", test_dry_run_functionality),
        ("Command-line options", test_command_line_options), 
        ("JSON export functionality", test_json_export_functionality),
        ("Output logging", test_output_logging),
        ("Error handling", test_error_handling)
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ FAILED: {test_name} - Unhandled exception: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"📊 Total:  {passed + failed}")
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED!")
        return 0
    else:
        print(f"\n⚠️  {failed} TEST(S) FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(main())