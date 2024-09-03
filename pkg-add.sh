#!/bin/bash

# Author: Ayush Singh <ayush.singh@asians.cloud>

# Description:
# This script automates the process of installing a specified package and updating
# the `pyproject.$env.toml` files for all environments. It avoids manual edits to these
# files, except for deleting or changing package versions. The script can add the package
# to default dependencies or to specific groups such as "dev" or "test" as specified.
# After updating the TOML files, it runs `poetry lock --no-update` and `poetry install`
# to apply the changes and ensure the package is properly installed.

# Usage:
# ./pkg-add

# Define the TOML files
TOML_FILES=("pyproject.uat.toml" "pyproject.staging.toml" "pyproject.prod.toml")

# Prompt dev for package name
read -p "Enter the package name: " PACKAGE_NAME
if [ -z "$PACKAGE_NAME" ]; then
  echo "Package name cannot be empty."
  exit 1
fi

# Prompt dev for version
echo "Enter the version with specifier (e.g., ~=3.2, ==3.2.0, >=1.0) or press Enter to skip:"
read -p "Version: " VERSION
VERSION="${VERSION:-*}"

# Adjust version for dry-run check
if [ "$VERSION" == "*" ]; then
  DRY_RUN_VERSION="==*"
else
  DRY_RUN_VERSION="$VERSION"
fi

# Inform the dev that validation is in progress
echo "Checking the package and version compatibility..."

# Validate package and version using poetry
if ! poetry add "$PACKAGE_NAME$DRY_RUN_VERSION" --dry-run &> /dev/null; then
  # Check for version conflicts
  if poetry show "$PACKAGE_NAME" &> /dev/null; then
    echo "The specified version conflicts with the existing constraints of the package '$PACKAGE_NAME'."
  else
    echo "Invalid package or version. Please check the version specifier format."
  fi
  exit 1
fi

# Prompt dev for group
echo "Select the dependency group (or press Enter to skip for global):"
echo "1. Development (dev)"
echo "2. Test (test)"
read -p "Enter the number of your choice: " GROUP_CHOICE

case "$GROUP_CHOICE" in
  1)
    GROUP="--dev"
    ;;
  2)
    GROUP="--test"
    ;;
  *)
    GROUP=""
    ;;
esac

# Function to update the TOML file
update_toml() {
  local file="$1"
  local package="$2"
  local version="$3"
  local group="$4"

  # Create a temporary file for processing
  local temp_file=$(mktemp)
  local sorted_file=$(mktemp)
  trap 'rm -f "$temp_file" "$sorted_file"' EXIT

  # Determine the section to add the dependency
  if [ "$group" == "--dev" ]; then
    section="[tool.poetry.group.dev.dependencies]"
  elif [ "$group" == "--test" ]; then
    section="[tool.poetry.group.test.dependencies]"
  else
    section="[tool.poetry.dependencies]"
  fi

  # Update or add the dependency in the dedicated section
  awk -v pkg="$package" -v ver="$version" -v sec="$section" '
  BEGIN { in_section = 0; updated = 0 }
  $0 == sec { in_section = 1; updated = 0; print; next }
  $0 ~ /^\[tool.poetry/ && $0 != sec { in_section = 0 }
  in_section && $0 ~ /^[^#]*=/ {
    if ($0 ~ "^" pkg " ") {
      print pkg " = \"" ver "\""
      updated = 1
    } else {
      print
    }
    next
  }
  in_section && $0 ~ /^$/ {
    if (!updated) {
      print pkg " = \"" ver "\""
    }
    in_section = 0
  }
  { print }
  ' "$file" > "$temp_file"

  # Ensure only one header for each section
  awk -v sec="$section" '
  BEGIN { header_printed = 0 }
  /^\[tool\.poetry/ {
    if ($0 == sec) {
      if (header_printed) next
      header_printed = 1
    } else {
      header_printed = 0
    }
  }
  { print }
  ' "$temp_file" > "$sorted_file"

  mv "$sorted_file" "$file"
}

# Update all TOML files
for toml_file in "${TOML_FILES[@]}"; do
  update_toml "$toml_file" "$PACKAGE_NAME" "$VERSION" "$GROUP"
done

# Pick the environment variable
ENVIRON="${ENVIRON:-uat}"

# Copy the appropriate TOML file
cp "pyproject.${ENVIRON}.toml" pyproject.toml

# Check if poetry is installed
if ! command -v poetry &> /dev/null; then
  echo "poetry command not found. Please install Poetry."
  exit 1
fi

# Run poetry commands
if ! poetry lock --no-update; then
  echo "Failed to update the lock file."
  exit 1
fi

if ! poetry install; then
  echo "Failed to install dependencies."
  exit 1
fi

# Log message
echo "Dependency '$PACKAGE_NAME' with version '$VERSION' has been installed."