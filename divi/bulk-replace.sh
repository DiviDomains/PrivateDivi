#!/bin/bash
# Phase 2D: Global String Replacements for PrivateDivi
# Order matters - most specific patterns first

set -e

echo "Starting bulk string replacements..."
echo "Working directory: $(pwd)"

# Count total files to process
total_files=$(find . -type f \( -name "*.cpp" -o -name "*.h" -o -name "*.am" -o -name "*.ac" -o -name "*.md" -o -name "*.txt" \) \
  ! -path "./src/leveldb/*" \
  ! -path "./src/secp256k1/*" \
  ! -path "./src/univalue/*" \
  -exec grep -l -E "DIVI|Divi|divi" {} \; | wc -l)

echo "Found $total_files files to process"

# Process each file
count=0
find . -type f \( -name "*.cpp" -o -name "*.h" -o -name "*.am" -o -name "*.ac" -o -name "*.md" -o -name "*.txt" \) \
  ! -path "./src/leveldb/*" \
  ! -path "./src/secp256k1/*" \
  ! -path "./src/univalue/*" \
  -exec grep -l -E "DIVI|Divi|divi" {} \; | while read file; do

    count=$((count + 1))
    echo "[$count/$total_files] Processing: $file"

    # Perform replacements in order (most specific first)
    sed -i '' \
      -e 's/DIVI Core/PrivateDivi Core/g' \
      -e 's/Divi Core/PrivateDivi Core/g' \
      -e 's/diviproject\.org/divi.domains/g' \
      -e 's/DIVID/PRIVATEDIVID/g' \
      -e 's/divid/privatedivid/g' \
      "$file"
done

echo ""
echo "Replacement complete!"
echo "Files processed: $total_files"
echo ""
echo "Next steps:"
echo "1. Review changes: git diff"
echo "2. Check for unintended replacements in license headers"
echo "3. Verify third-party libs were not modified"
