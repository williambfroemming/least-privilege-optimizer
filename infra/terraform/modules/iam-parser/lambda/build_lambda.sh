#!/bin/bash

set -e

echo "[*] Cleaning up old build..."
rm -rf build iam_analyzer_engine.zip

echo "[*] Creating build directory..."
mkdir build

echo "[*] Installing dependencies..."
pip install -r requirements.txt -t build

echo "[*] Copying source code..."
cp -r *.py build/
cp -r modules build/

echo "[*] Done. Lambda package ready in build/ directory."