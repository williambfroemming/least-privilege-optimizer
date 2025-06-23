#!/usr/bin/env python3
"""
Standalone test runner for IAM Analyzer Lambda Integration Tests

This script runs the lambda function locally against real AWS resources
and shows you exactly what would be in the GitHub PRs.

Usage:
    python run_integration_tests.py              # Dry run mode
    python run_integration_tests.py --live-pr    # Create real PRs
    python run_integration_tests.py --help       # Show help
"""

import argparse
import os
import sys
from pathlib import Path
import subprocess
from dotenv import load_dotenv

def setup_environment():
    """Setup environment and validate configuration"""
    # Load environment variables
    env_path = Path(__file__).parent / ".env"
    if not env_path.exists():
        print("❌ Error: No .env file found!")
        print("📝 Please copy .env.example to .env and configure it with your AWS credentials")
        print(f"   cp {Path(__file__).parent / '.env.example'} {env_path}")
        sys.exit(1)
    
    load_dotenv(env_path)
    
    # Check required environment variables
    required_vars = [
        'AWS_REGION', 'ANALYZER_ARN', 'S3_BUCKET', 'S3_PREFIX', 'GITHUB_REPO'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print(f"❌ Error: Missing required environment variables: {', '.join(missing_vars)}")
        print("📝 Please update your .env file with the missing values")
        sys.exit(1)
    
    print("✅ Environment configuration validated")
    return True

def print_banner():
    """Print banner with test information"""
    print("="*80)
    print("🔍 IAM Analyzer Lambda - Real AWS Integration Tests")
    print("="*80)
    print()
    print("This test suite will:")
    print("  1. Connect to your real AWS Access Analyzer")
    print("  2. Fetch IAM resources from your S3 bucket")
    print("  3. Analyze Access Analyzer findings")
    print("  4. Generate policy recommendations")
    print("  5. Show you exactly what would be in GitHub PRs")
    print()
    
    # Show current configuration
    print("📋 Current Configuration:")
    print(f"   AWS Region: {os.getenv('AWS_REGION')}")
    print(f"   Analyzer ARN: {os.getenv('ANALYZER_ARN')}")
    print(f"   S3 Bucket: {os.getenv('S3_BUCKET')}")
    print(f"   S3 Prefix: {os.getenv('S3_PREFIX')}")
    print(f"   GitHub Repo: {os.getenv('GITHUB_REPO')}")
    print(f"   Dry Run: {os.getenv('DRY_RUN', 'true')}")
    print(f"   Create Real PRs: {os.getenv('CREATE_REAL_PR', 'false')}")
    
    if os.getenv('TEST_RESOURCE_FILTER'):
        print(f"   Resource Filter: {os.getenv('TEST_RESOURCE_FILTER')}")
    
    print()

def run_tests(live_pr=False, specific_test=None):
    """Run the integration tests"""
    
    # Determine test file path
    test_file = Path(__file__).parent / "test" / "test_real_integration.py"
    if not test_file.exists():
        print(f"❌ Test file not found: {test_file}")
        sys.exit(1)
    
    # Build pytest command
    cmd = [
        sys.executable, "-m", "pytest",
        str(test_file),
        "-v", "-s",  # verbose output and show prints
        "--tb=short",  # shorter tracebacks
        "--color=yes",  # colored output
    ]
    
    # Add specific test if requested
    if specific_test:
        cmd.extend(["-k", specific_test])
    
    # Add live PR marker if requested
    if live_pr:
        cmd.extend(["-m", "live_pr"])
        print("⚠️  LIVE PR MODE: Real GitHub PRs will be created!")
        
        # Confirm with user
        response = input("Are you sure you want to create real PRs? (y/N): ")
        if response.lower() != 'y':
            print("Cancelled.")
            sys.exit(0)
    else:
        print("🔒 DRY RUN MODE: No real GitHub changes will be made")
    
    print("\n🚀 Starting tests...\n")
    
    # Run the tests
    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode == 0
    except KeyboardInterrupt:
        print("\n⚠️  Tests interrupted by user")
        return False
    except Exception as e:
        print(f"❌ Error running tests: {e}")
        return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Run IAM Analyzer Lambda integration tests against real AWS resources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_integration_tests.py                    # Run all tests in dry-run mode
  python run_integration_tests.py --live-pr          # Create real GitHub PRs
  python run_integration_tests.py --test connectivity # Run only connectivity test
  python run_integration_tests.py --test workflow    # Run only workflow test
        """
    )
    
    parser.add_argument(
        '--live-pr', 
        action='store_true',
        help='Create real GitHub PRs (default: dry run mode)'
    )
    
    parser.add_argument(
        '--test',
        choices=['connectivity', 'resources', 'findings', 'workflow', 'policy-format'],
        help='Run only a specific test'
    )
    
    parser.add_argument(
        '--config',
        action='store_true',
        help='Show current configuration and exit'
    )
    
    args = parser.parse_args()
    
    # Setup environment
    setup_environment()
    
    # Print banner
    print_banner()
    
    # Show config and exit if requested
    if args.config:
        print("Configuration shown above. Exiting.")
        return
    
    # Map test names to pytest filter patterns
    test_mapping = {
        'connectivity': 'test_aws_connectivity',
        'resources': 'test_fetch_real_resources', 
        'findings': 'test_fetch_real_findings',
        'workflow': 'test_complete_lambda_workflow_dry_run',
        'policy-format': 'test_policy_recommender_output_format'
    }
    
    specific_test = test_mapping.get(args.test) if args.test else None
    
    # Set environment for live PR mode
    if args.live_pr:
        os.environ['CREATE_REAL_PR'] = 'true'
        os.environ['DRY_RUN'] = 'false'
    
    # Run tests
    success = run_tests(live_pr=args.live_pr, specific_test=specific_test)
    
    if success:
        print("\n✅ All tests completed successfully!")
        if not args.live_pr:
            print("💡 Tip: Run with --live-pr to create real GitHub PRs")
    else:
        print("\n❌ Some tests failed. Check the output above for details.")
        sys.exit(1)

if __name__ == "__main__":
    main()