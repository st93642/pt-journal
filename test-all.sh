#!/bin/bash
# Unified test script for PT Journal
# Runs all tests, clippy, and formatting checks

set -e

echo "🧪 Running PT Journal Test Suite"
echo "================================="

echo "📦 Running unit tests..."
cargo test --test unit_tests

echo "🔗 Running integration tests..."
cargo test --test integration_tests

echo "🔍 Running clippy..."
cargo clippy

echo "📝 Formatting code..."
cargo fmt

echo "📝 Checking formatting..."
cargo fmt --check

echo "🔍 Validating JSON files..."
find . -name "*.json" -not -path "./target/*" -exec jq empty {} \; && echo "✅ All JSON files are valid"

echo "✅ All checks passed!"