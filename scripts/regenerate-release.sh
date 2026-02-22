#!/bin/bash
# Rebuild release artifacts in release/
# Copies root-level .html and .js files, plus resources/ and stix-visualization/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$SCRIPT_DIR/.." && pwd)"
RELEASE_DIR="$SRC/release"

if [ ! -d "$RELEASE_DIR" ]; then
    echo "Error: release directory not found at $RELEASE_DIR"
    exit 1
fi

echo "=== Regenerate Release Artifacts ==="
echo "Source: $SRC"
echo "Target: $RELEASE_DIR"
echo ""
echo "This will permanently remove all existing files inside release/."
read -r -p "Continue? [y/N]: " confirm

case "$confirm" in
    y|Y|yes|YES)
        ;;
    *)
        echo "Aborted."
        exit 0
        ;;
esac

echo ""
echo "Clearing release directory..."
find "$RELEASE_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +

echo "Copying root HTML/JS files..."
found_root_files=false
while IFS= read -r file; do
    cp -f "$file" "$RELEASE_DIR/"
    basename "$file" | sed 's/^/  /'
    found_root_files=true
done < <(find "$SRC" -maxdepth 1 -type f \( -name "*.html" -o -name "*.js" \) | sort)

if [ "$found_root_files" = false ]; then
    echo "  (none found)"
fi

echo "Copying additional release files..."
EXTRA_FILES=(
    "CHANGELOG.md"
    "README.md"
    "LICENSE"
    "favicon.ico"
)

for name in "${EXTRA_FILES[@]}"; do
    src_file="$SRC/$name"
    if [ -f "$src_file" ]; then
        cp -f "$src_file" "$RELEASE_DIR/"
        echo "  $name"
    else
        echo "  $name (missing, skipped)"
    fi
done

if [ -d "$SRC/resources" ]; then
    echo "Copying resources directory..."
    rsync -a --delete "$SRC/resources/" "$RELEASE_DIR/resources/"
    echo "  resources/"
else
    echo "Warning: resources/ directory not found in source"
fi

if [ -d "$SRC/stix-visualization" ]; then
    echo "Copying stix-visualization directory..."
    rsync -a --delete "$SRC/stix-visualization/" "$RELEASE_DIR/stix-visualization/"
    echo "  stix-visualization/"
else
    echo "Warning: stix-visualization/ directory not found in source"
fi

echo ""
echo "=== Release Artifacts Ready ==="
echo "Output: $RELEASE_DIR"
