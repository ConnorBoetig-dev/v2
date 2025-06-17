#!/usr/bin/env python3
"""
Test Suite Runner - Run comprehensive tests for NetworkMapper
"""

import subprocess
import sys
import time
from pathlib import Path


def run_command(cmd, description):
    """Run a command and report results"""
    print(f"\n{'='*60}")
    print(f"🧪 {description}")
    print(f"{'='*60}")
    
    start_time = time.time()
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    end_time = time.time()
    
    duration = end_time - start_time
    
    if result.returncode == 0:
        print(f"✅ PASSED ({duration:.2f}s)")
        if result.stdout.strip():
            print(f"\nOutput:\n{result.stdout}")
    else:
        print(f"❌ FAILED ({duration:.2f}s)")
        if result.stderr.strip():
            print(f"\nError:\n{result.stderr}")
        if result.stdout.strip():
            print(f"\nOutput:\n{result.stdout}")
    
    return result.returncode == 0


def main():
    """Run the test suite"""
    print("🚀 NetworkMapper Test Suite")
    print("=" * 60)
    
    # Change to project directory
    project_dir = Path(__file__).parent
    os.chdir(project_dir)
    
    # Test categories to run
    test_suites = [
        {
            'cmd': 'python3 -m pytest tests/test_enhanced_scanner.py -v',
            'desc': 'Enhanced Scanner Tests'
        },
        {
            'cmd': 'python3 -m pytest tests/test_cli_workflows.py::TestCLIWorkflows::test_scan_type_selection -v',
            'desc': 'CLI Workflow - Scan Type Selection'
        },
        {
            'cmd': 'python3 -m pytest tests/test_data_factory.py -v',
            'desc': 'Test Data Factory'
        },
        {
            'cmd': 'python3 -m pytest tests/test_network_simulation.py::TestNetworkSimulation::test_change_detection_new_devices -v',
            'desc': 'Network Simulation - Change Detection'
        },
        {
            'cmd': 'python3 -m pytest tests/unit/test_scanner.py -v',
            'desc': 'Unit Tests - Scanner'
        },
        {
            'cmd': 'python3 -m pytest tests/unit/test_classifier.py -v',
            'desc': 'Unit Tests - Classifier'
        },
        {
            'cmd': 'python3 -m pytest tests/test_parser.py -v',
            'desc': 'Parser Tests'
        }
    ]
    
    # Run individual test suites
    passed = 0
    failed = 0
    
    for test in test_suites:
        success = run_command(test['cmd'], test['desc'])
        if success:
            passed += 1
        else:
            failed += 1
    
    # Summary
    print(f"\n{'='*60}")
    print(f"📊 TEST SUMMARY")
    print(f"{'='*60}")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"📈 Success Rate: {(passed/(passed+failed)*100):.1f}%")
    
    # Run coverage if requested
    if '--coverage' in sys.argv:
        print(f"\n{'='*60}")
        print(f"📊 COVERAGE REPORT")
        print(f"{'='*60}")
        run_command(
            'python3 -m pytest tests/ --cov=core --cov=utils --cov-report=html --cov-report=term',
            'Coverage Analysis'
        )
    
    # Run performance tests if requested
    if '--performance' in sys.argv:
        print(f"\n{'='*60}")
        print(f"🚀 PERFORMANCE TESTS")
        print(f"{'='*60}")
        run_command(
            'python3 -m pytest tests/test_network_simulation.py::TestNetworkSimulation::test_performance_with_large_dataset -v',
            'Performance Test - Large Dataset'
        )
    
    # Final status
    if failed == 0:
        print(f"\n🎉 All tests passed! NetworkMapper is ready for production.")
        return 0
    else:
        print(f"\n⚠️  {failed} test(s) failed. Please review and fix issues.")
        return 1


if __name__ == "__main__":
    import os
    exit_code = main()
    sys.exit(exit_code)