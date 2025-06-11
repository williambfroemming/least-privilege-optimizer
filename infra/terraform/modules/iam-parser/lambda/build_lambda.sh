#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting Lambda build process...${NC}"

# Clean up previous builds
if [ -d "build" ]; then
    echo -e "${YELLOW}Cleaning previous build...${NC}"
    rm -rf build
fi

if [ -d "layer" ]; then
    echo -e "${YELLOW}Cleaning previous layer...${NC}"
    rm -rf layer
fi

# Create build directories
mkdir -p build
mkdir -p layer/python

echo -e "${GREEN}Installing dependencies to layer...${NC}"

# Install dependencies to layer (for heavy dependencies)
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt \
        --target ./layer/python \
        --platform manylinux2014_x86_64 \
        --implementation cp \
        --python-version 39 \
        --only-binary=:all: \
        --upgrade \
        --no-deps || {
        echo -e "${YELLOW}Binary-only install failed, trying with source packages...${NC}"
        pip install -r requirements.txt \
            --target ./layer/python \
            --upgrade
    }
else
    echo -e "${RED}requirements.txt not found!${NC}"
    exit 1
fi

echo -e "${GREEN}Copying Lambda function code to build directory...${NC}"

# Copy Lambda function code (lightweight)
cp *.py build/ 2>/dev/null || echo "No Python files to copy"

# Remove test files and unnecessary items from build
echo -e "${YELLOW}Cleaning up build directory...${NC}"
find build/ -name "*.pyc" -delete
find build/ -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find build/ -name "test_*" -delete 2>/dev/null || true
find build/ -name "*_test.py" -delete 2>/dev/null || true

# Create layer zip for Terraform
echo -e "${GREEN}Creating layer archive...${NC}"
cd layer
zip -r ../layer.zip . -q
cd ..

# Create function zip for Terraform
echo -e "${GREEN}Creating function archive...${NC}"
cd build
zip -r ../iam_analyzer_engine.zip . -q
cd ..

echo -e "${GREEN}Build complete!${NC}"
echo -e "Function package: ${YELLOW}iam_analyzer_engine.zip${NC}"
echo -e "Layer package: ${YELLOW}layer.zip${NC}"

# Optional: Show package sizes
if command -v du &> /dev/null; then
    echo -e "\nPackage sizes:"
    echo -e "Function: $(du -h iam_analyzer_engine.zip | cut -f1)"
    echo -e "Layer: $(du -h layer.zip | cut -f1)"
fi