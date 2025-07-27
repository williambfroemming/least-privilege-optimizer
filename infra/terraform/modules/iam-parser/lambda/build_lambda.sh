#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting Lambda build process...${NC}"

# Time synchronization to prevent AWS signature errors
echo -e "${BLUE}Checking system time synchronization...${NC}"

sync_time() {
    if command -v ntpdate &> /dev/null; then
        echo -e "${YELLOW}Syncing time with NIST server...${NC}"
        sudo ntpdate -s time.nist.gov 2>/dev/null || {
            echo -e "${YELLOW}ntpdate failed, trying alternative time servers...${NC}"
            sudo ntpdate -s pool.ntp.org 2>/dev/null || {
                echo -e "${YELLOW}Could not sync with ntpdate, checking timedatectl...${NC}"
            }
        }
    elif command -v timedatectl &> /dev/null; then
        echo -e "${YELLOW}Enabling NTP synchronization...${NC}"
        sudo timedatectl set-ntp true 2>/dev/null || {
            echo -e "${YELLOW}Could not enable NTP sync with timedatectl${NC}"
        }
        # Force a sync
        sudo systemctl restart systemd-timesyncd 2>/dev/null || true
        sleep 2
    elif command -v w32tm &> /dev/null; then
        echo -e "${YELLOW}Windows detected - resyncing time...${NC}"
        w32tm /resync 2>/dev/null || {
            echo -e "${YELLOW}w32tm resync failed${NC}"
        }
    else
        echo -e "${YELLOW}No time sync utility found. Please ensure your system clock is accurate.${NC}"
        echo -e "${YELLOW}AWS requires system time to be within 5 minutes of server time.${NC}"
    fi
}

# Attempt time sync
sync_time

# Display current time for verification
echo -e "${BLUE}Current system time: $(date -u '+%Y-%m-%d %H:%M:%S UTC')${NC}"

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
    echo -e "${BLUE}Installing Python dependencies...${NC}"
    
    # Retry mechanism for pip install in case of network/time issues
    install_deps() {
        local attempt=1
        local max_attempts=3
        
        while [ $attempt -le $max_attempts ]; do
            echo -e "${YELLOW}Dependency installation attempt $attempt/$max_attempts...${NC}"
            
            if pip install -r requirements.txt \
                --target ./layer/python \
                --platform manylinux2014_x86_64 \
                --implementation cp \
                --python-version 39 \
                --only-binary=:all: \
                --upgrade; then
                echo -e "${GREEN}Binary-only installation successful!${NC}"
                return 0
            elif [ $attempt -eq $max_attempts ]; then
                echo -e "${YELLOW}Binary-only install failed on all attempts, trying with source packages...${NC}"
                if pip install -r requirements.txt \
                    --target ./layer/python \
                    --upgrade; then
                    echo -e "${GREEN}Source package installation successful!${NC}"
                    return 0
                else
                    echo -e "${RED}All installation attempts failed!${NC}"
                    return 1
                fi
            else
                echo -e "${YELLOW}Attempt $attempt failed, retrying...${NC}"
                sleep 5
                # Re-sync time before retry
                sync_time
            fi
            
            ((attempt++))
        done
    }
    
    # Execute installation with retry logic
    if ! install_deps; then
        echo -e "${RED}Dependency installation failed after all attempts!${NC}"
        exit 1
    fi
    
    # Also explicitly install typing_extensions which is commonly needed
    echo -e "${BLUE}Installing typing_extensions...${NC}"
    pip install typing_extensions \
        --target ./layer/python \
        --upgrade || {
        echo -e "${YELLOW}typing_extensions installation failed, continuing...${NC}"
    }
else
    echo -e "${RED}requirements.txt not found!${NC}"
    exit 1
fi

echo -e "${GREEN}Copying Lambda function code to build directory...${NC}"

# Install minimal dependencies directly to build directory
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt \
        --target ./build \
        --upgrade \
        --no-deps || {
        echo -e "${YELLOW}Direct dependency installation failed, continuing...${NC}"
    }
fi

# Copy Lambda function code from src directory
cp *.py build/ 2>/dev/null || echo -e "${YELLOW}No Python files to copy${NC}"
cp -r modules build/ 2>/dev/null || echo -e "${YELLOW}No modules directory to copy${NC}"

# Remove test files and unnecessary items from build
echo -e "${YELLOW}Cleaning up build directory...${NC}"
find build/ -name "*.pyc" -delete 2>/dev/null || true
find build/ -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find build/ -name "test_*" -delete 2>/dev/null || true
find build/ -name "*_test.py" -delete 2>/dev/null || true

# Clean up layer directory as well
echo -e "${YELLOW}Cleaning up layer directory...${NC}"
find layer/ -name "*.pyc" -delete 2>/dev/null || true
find layer/ -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find layer/ -name "test*" -delete 2>/dev/null || true

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
    echo -e "Function: ${BLUE}$(du -h iam_analyzer_engine.zip | cut -f1)${NC}"
    echo -e "Layer: ${BLUE}$(du -h layer.zip | cut -f1)${NC}"
fi

# Verify zip files were created successfully
if [ ! -f "iam_analyzer_engine.zip" ] || [ ! -f "layer.zip" ]; then
    echo -e "${RED}Error: Archive creation failed!${NC}"
    exit 1
fi

echo -e "${GREEN}All archives created successfully and ready for deployment!${NC}"
echo -e "${BLUE}Final system time: $(date -u '+%Y-%m-%d %H:%M:%S UTC')${NC}"