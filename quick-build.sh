#!/bin/bash
# Quick development build and test script for PCAPture

echo "🚀 PCAPture Quick Build & Test"
echo "================================"

# Clean previous build
echo "🧹 Cleaning previous build..."
make clean > /dev/null 2>&1

# Build in development mode
echo "🔨 Building in development mode..."
if make dev; then
    echo "✅ Build successful!"
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        echo "🎯 Testing with 5 packets..."
        ./pcapture --count 5 --verbose
    else
        echo "⚡ Build completed! Run with: sudo ./pcapture"
        echo "💡 For testing: sudo ./pcapture --count 5 --verbose"
    fi
else
    echo "❌ Build failed!"
    exit 1
fi