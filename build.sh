#!/bin/bash

# Build script for JWT Auth module
# This creates a distributable tar.gz file with dependencies included

set -e

VERSION=${1:-dev}
BUILD_DIR="build"
RELEASE_NAME="webtrees-jwt-auth-${VERSION}"

echo "Building JWT Auth module version ${VERSION}..."

# Clean previous build
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/${RELEASE_NAME}"

# Copy module files
echo "Copying module files..."
rsync -av --exclude="${BUILD_DIR}" \
          --exclude=".git" \
          --exclude=".github" \
          --exclude=".gitignore" \
          --exclude="vendor" \
          --exclude="composer.lock" \
          --exclude="*.tar.gz" \
          --exclude="build.sh" \
          ./ "${BUILD_DIR}/${RELEASE_NAME}/"

# Install production dependencies
echo "Installing production dependencies..."
cd "${BUILD_DIR}/${RELEASE_NAME}"
composer install --no-dev --optimize-autoloader --no-interaction
cd ../..

# Remove composer files from distribution
echo "Cleaning up..."
rm -f "${BUILD_DIR}/${RELEASE_NAME}/composer.json"
rm -f "${BUILD_DIR}/${RELEASE_NAME}/composer.lock"

# Create archive
echo "Creating archive..."
cd "${BUILD_DIR}"
tar -czf "../${RELEASE_NAME}.tar.gz" "${RELEASE_NAME}/"
cd ..

# Clean build directory
rm -rf "${BUILD_DIR}"

echo "✓ Build complete: ${RELEASE_NAME}.tar.gz"
echo ""
echo "To install:"
echo "  cd /path/to/webtrees/modules_v4/"
echo "  tar -xzf ${RELEASE_NAME}.tar.gz"
echo ""
echo "To test extraction:"
echo "  tar -tzf ${RELEASE_NAME}.tar.gz | head -20"
