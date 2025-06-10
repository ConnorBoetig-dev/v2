# NetworkMapper v2 Makefile
# Comprehensive test suite and development tasks

.PHONY: all test unit integration lint clean coverage install dev-install help

# Python interpreter
PYTHON := python3
PIP := pip3

# Directories
TEST_DIR := tests
UNIT_TEST_DIR := $(TEST_DIR)/unit
INTEGRATION_TEST_DIR := $(TEST_DIR)/integration
COV_DIR := htmlcov
OUTPUT_DIR := output

# Test discovery patterns
UNIT_TESTS := $(UNIT_TEST_DIR)/test_*.py
INTEGRATION_TESTS := $(INTEGRATION_TEST_DIR)/test_*.py

# Default target
all: lint test

# Help target
help:
	@echo "NetworkMapper v2 - Available targets:"
	@echo "  make install      - Install production dependencies"
	@echo "  make dev-install  - Install development dependencies"
	@echo "  make test         - Run all tests (unit + integration)"
	@echo "  make unit         - Run unit tests only"
	@echo "  make integration  - Run integration tests only"
	@echo "  make lint         - Run code linting"
	@echo "  make coverage     - Run tests with coverage report"
	@echo "  make clean        - Clean temporary files and caches"
	@echo "  make test-scanner - Test scanner module only"
	@echo "  make test-parser  - Test parser module only"
	@echo "  make test-classifier - Test classifier module only"
	@echo "  make test-tracker - Test tracker module only"
	@echo "  make test-annotator - Test annotator module only"
	@echo "  make quick        - Run quick smoke tests"
	@echo "  make verbose      - Run tests with verbose output"

# Install dependencies
install:
	$(PIP) install -r requirements.txt

# Install development dependencies
dev-install: install
	$(PIP) install pytest pytest-cov pytest-timeout pytest-mock flake8 mypy black isort

# Run all tests
test: unit integration
	@echo "All tests completed successfully!"

# Run unit tests
unit:
	@echo "Running unit tests..."
	$(PYTHON) -m pytest $(UNIT_TEST_DIR) -v --tb=short

# Run integration tests
integration:
	@echo "Running integration tests..."
	$(PYTHON) -m pytest $(INTEGRATION_TEST_DIR) -v --tb=short

# Run specific module tests
test-scanner:
	@echo "Testing scanner module..."
	$(PYTHON) -m pytest $(UNIT_TEST_DIR)/test_scanner.py -v

test-parser:
	@echo "Testing parser module..."
	$(PYTHON) -m pytest $(UNIT_TEST_DIR)/test_parser.py -v

test-classifier:
	@echo "Testing classifier module..."
	$(PYTHON) -m pytest $(UNIT_TEST_DIR)/test_classifier.py -v

test-tracker:
	@echo "Testing tracker module..."
	$(PYTHON) -m pytest $(UNIT_TEST_DIR)/test_tracker.py -v

test-annotator:
	@echo "Testing annotator module..."
	$(PYTHON) -m pytest $(UNIT_TEST_DIR)/test_annotator.py -v

# Quick smoke tests (fastest tests only)
quick:
	@echo "Running quick smoke tests..."
	$(PYTHON) -m pytest $(TEST_DIR) -v -m "not slow" --tb=short -x

# Verbose test output
verbose:
	@echo "Running tests with verbose output..."
	$(PYTHON) -m pytest $(TEST_DIR) -vv --tb=long

# Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	$(PYTHON) -m pytest $(TEST_DIR) --cov=core --cov=utils --cov-report=html --cov-report=term
	@echo "Coverage report generated in $(COV_DIR)/"

# Lint code
lint:
	@echo "Running linting checks..."
	@echo "1. Running flake8..."
	-$(PYTHON) -m flake8 core utils mapper.py --max-line-length=100 --ignore=E203,W503
	@echo "2. Running mypy type checking..."
	-$(PYTHON) -m mypy core utils mapper.py --ignore-missing-imports
	@echo "3. Checking black formatting..."
	-$(PYTHON) -m black --check core utils mapper.py tests
	@echo "4. Checking import sorting..."
	-$(PYTHON) -m isort --check-only core utils mapper.py tests

# Format code
format:
	@echo "Formatting code..."
	$(PYTHON) -m black core utils mapper.py tests
	$(PYTHON) -m isort core utils mapper.py tests

# Clean temporary files
clean:
	@echo "Cleaning temporary files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	rm -rf $(COV_DIR)
	rm -rf .coverage
	rm -rf .mypy_cache
	rm -f $(OUTPUT_DIR)/test_*
	@echo "Cleanup complete!"

# Run tests in parallel
parallel:
	@echo "Running tests in parallel..."
	$(PYTHON) -m pytest $(TEST_DIR) -v -n auto

# Run tests with specific markers
test-critical:
	@echo "Running critical tests only..."
	$(PYTHON) -m pytest $(TEST_DIR) -v -m "critical"

test-slow:
	@echo "Running slow tests only..."
	$(PYTHON) -m pytest $(TEST_DIR) -v -m "slow"

# Continuous integration target
ci: lint test coverage
	@echo "CI pipeline completed!"

# Development test loop (watches for changes)
watch:
	@echo "Starting test watcher..."
	$(PYTHON) -m pytest_watch $(TEST_DIR) --clear

# Generate test report
test-report:
	@echo "Generating detailed test report..."
	$(PYTHON) -m pytest $(TEST_DIR) -v --html=test_report.html --self-contained-html

# Check test coverage thresholds
check-coverage: coverage
	@echo "Checking coverage thresholds..."
	$(PYTHON) -m pytest $(TEST_DIR) --cov=core --cov=utils --cov-fail-under=80

# Profile tests to find slow ones
profile-tests:
	@echo "Profiling test execution time..."
	$(PYTHON) -m pytest $(TEST_DIR) --durations=10

# Run security checks
security:
	@echo "Running security checks..."
	$(PIP) install safety bandit
	-$(PYTHON) -m safety check
	-$(PYTHON) -m bandit -r core utils mapper.py

# Full test suite with all checks
full-test: clean lint test coverage security
	@echo "Full test suite completed!"

# Debug a specific test
debug:
	@echo "Running tests in debug mode..."
	$(PYTHON) -m pytest $(TEST_DIR) -v --pdb --pdbcls=IPython.terminal.debugger:TerminalPdb

# Create test fixtures
fixtures:
	@echo "Generating test fixtures..."
	$(PYTHON) generate_test_data.py
	$(PYTHON) generate_minimal_network_test.py

# Run tests with specific Python version
test-py38:
	python3.8 -m pytest $(TEST_DIR) -v

test-py39:
	python3.9 -m pytest $(TEST_DIR) -v

test-py310:
	python3.10 -m pytest $(TEST_DIR) -v

test-py311:
	python3.11 -m pytest $(TEST_DIR) -v

# Benchmark tests
benchmark:
	@echo "Running performance benchmarks..."
	$(PYTHON) -m pytest $(TEST_DIR) -v --benchmark-only

# Memory profiling
memtest:
	@echo "Running memory profiling..."
	$(PIP) install pytest-memray
	$(PYTHON) -m pytest $(TEST_DIR) --memray

# Test documentation examples
test-docs:
	@echo "Testing documentation examples..."
	$(PYTHON) -m doctest -v core/*.py utils/*.py

# Generate test coverage badge
badge:
	@echo "Generating coverage badge..."
	$(PIP) install coverage-badge
	coverage-badge -o coverage.svg

# Run mutation testing
mutate:
	@echo "Running mutation testing..."
	$(PIP) install mutmut
	mutmut run --paths-to-mutate=core/,utils/

# Test environment setup
test-env:
	@echo "Setting up test environment..."
	mkdir -p $(OUTPUT_DIR)/test_scans
	mkdir -p $(OUTPUT_DIR)/test_reports
	mkdir -p $(OUTPUT_DIR)/test_changes
	mkdir -p $(OUTPUT_DIR)/test_annotations

# Integration with CI systems
jenkins:
	$(PYTHON) -m pytest $(TEST_DIR) --junitxml=test-results.xml

gitlab:
	$(PYTHON) -m pytest $(TEST_DIR) --junit-xml=report.xml

# Docker test environment
docker-test:
	docker build -t networkmapper-test .
	docker run --rm networkmapper-test make test

# Stress testing
stress-test:
	@echo "Running stress tests..."
	$(PYTHON) -m pytest $(TEST_DIR) -v -k "stress or performance or large"

# Compatibility testing
compat-test:
	@echo "Running compatibility tests..."
	tox

# Pre-commit hook
pre-commit: lint quick
	@echo "Pre-commit checks passed!"

# Post-merge hook
post-merge: install test
	@echo "Post-merge checks passed!"

.PHONY: test-all-modules
test-all-modules: test-scanner test-parser test-classifier test-tracker test-annotator
	@echo "All module tests completed!"

# Default test configuration
.DEFAULT_GOAL := help