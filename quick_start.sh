#!/bin/bash
# Quick start script for NetworkMapper v2

echo "🚀 NetworkMapper v2 - Quick Start"
echo "================================="
echo ""

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "📦 Activating virtual environment..."
    source venv/bin/activate
fi

# Check dependencies
echo "🔍 Checking dependencies..."
python3 -c "import typer, rich" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  Installing dependencies..."
    pip3 install -r requirements.txt
fi

# Run installation verification
echo "✅ Verifying installation..."
python3 scripts/verify_installation.py

if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 Ready to go! Choose an option:"
    echo "1. 🌟 Start NetworkMapper (Main Application)"
    echo "2. 🎯 Run Demo First"
    echo "3. 🧪 Test Installation"
    echo ""
    
    read -p "Select option (1-3): " choice
    
    case $choice in
        1)
            echo "🌟 Starting NetworkMapper..."
            python3 mapper.py
            ;;
        2)
            echo "🎯 Running demo..."
            ./run_demo.sh
            ;;
        3)
            echo "🧪 Testing installation..."
            python3 scripts/test_core_functionality.py
            ;;
        *)
            echo "❌ Invalid selection"
            ;;
    esac
else
    echo "❌ Installation verification failed. Please check the output above."
fi