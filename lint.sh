#!/bin/bash
# NetworkMapper v2 - Code Quality Check Script

echo "NetworkMapper v2 - Running Code Quality Checks"
echo "=============================================="

# Run black formatter
echo -e "\n[1/4] Running Black formatter..."
black . --line-length 100 --check --diff
if [ $? -eq 0 ]; then
    echo "✓ Black: Code is properly formatted"
else
    echo "⚠ Black: Code needs formatting. Run: black . --line-length 100"
fi

# Run isort
echo -e "\n[2/4] Running isort..."
isort . --profile black --line-length 100 --check-only --diff
if [ $? -eq 0 ]; then
    echo "✓ isort: Imports are properly sorted"
else
    echo "⚠ isort: Imports need sorting. Run: isort . --profile black --line-length 100"
fi

# Run flake8
echo -e "\n[3/4] Running flake8..."
flake8
if [ $? -eq 0 ]; then
    echo "✓ flake8: No style issues found"
else
    echo "⚠ flake8: Style issues found"
fi

# Run mypy
echo -e "\n[4/4] Running mypy..."
mypy . --ignore-missing-imports
if [ $? -eq 0 ]; then
    echo "✓ mypy: Type checking passed"
else
    echo "⚠ mypy: Type issues found"
fi

echo -e "\n=============================================="
echo "To automatically fix formatting issues, run:"
echo "  black . --line-length 100"
echo "  isort . --profile black --line-length 100"
