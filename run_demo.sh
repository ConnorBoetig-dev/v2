#!/bin/bash
# Quick demo runner for NetworkMapper v2

echo "🎯 NetworkMapper v2 - Demo Runner"
echo "================================="
echo ""
echo "Available demos:"
echo "1. 🌐 Large Network Demo (46 devices)"
echo "2. 🚀 Full Simulation (with traffic flows)"
echo "3. 🏢 Enterprise Test Data"
echo "4. 🔬 Minimal Network Test"
echo "5. 📊 View Demo Data"
echo ""

read -p "Select demo (1-5): " choice

case $choice in
    1)
        echo "🌐 Running large network demo..."
        python3 demos/demo_large_network.py
        ;;
    2)
        echo "🚀 Running full simulation..."
        python3 demos/demo_full_simulation.py
        ;;
    3)
        echo "🏢 Generating enterprise test data..."
        python3 demos/generate_enterprise_test.py
        ;;
    4)
        echo "🔬 Running minimal network test..."
        python3 demos/generate_minimal_network_test.py
        ;;
    5)
        echo "📊 Viewing demo data..."
        python3 demos/view_demo.py
        ;;
    *)
        echo "❌ Invalid selection"
        exit 1
        ;;
esac

echo ""
echo "✅ Demo completed! Run 'python3 mapper.py' to view results."