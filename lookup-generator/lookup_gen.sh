#!/bin/bash

# File name and size target
OUTPUT_FILE="splunk_lookup.csv"
TARGET_SIZE_MB=14
TARGET_SIZE_BYTES=$((TARGET_SIZE_MB * 1024 * 1024))

# Detect OS for stat command compatibility
if [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "freebsd"* ]]; then
  # macOS/BSD uses -f flag
  STAT_CMD="stat -f%z"
else
  # Linux uses -c flag
  STAT_CMD="stat -c%s"
fi

# Check available disk space (requires at least TARGET_SIZE_MB + 10MB buffer)
REQUIRED_SPACE=$((TARGET_SIZE_MB + 10))
if command -v df >/dev/null 2>&1; then
  AVAILABLE_MB=$(df -m . | awk 'NR==2 {print $4}')
  if [ "$AVAILABLE_MB" -lt "$REQUIRED_SPACE" ]; then
    echo "Error: Insufficient disk space. Need ${REQUIRED_SPACE}MB, have ${AVAILABLE_MB}MB available."
    exit 1
  fi
fi

# Header row for the CSV file
echo "id,username,email,age,country" > "$OUTPUT_FILE" || {
  echo "Error: Cannot write to $OUTPUT_FILE"
  exit 1
}

# Function to generate a random string
generate_random_string() {
  local length=$1
  tr -dc A-Za-z0-9 </dev/urandom | head -c "$length"
}

# Function to get random country (works without shuf on macOS)
get_random_country() {
  countries=(USA Canada UK Germany France Australia)
  echo "${countries[$((RANDOM % ${#countries[@]}))]}"
}

# Generate rows until the file size reaches the target
ITERATIONS=0
MAX_ITERATIONS=1000000  # Safety limit to prevent infinite loops

while [ "$($STAT_CMD "$OUTPUT_FILE" 2>/dev/null || echo 0)" -lt "$TARGET_SIZE_BYTES" ]; do
  # Safety check for infinite loops
  ITERATIONS=$((ITERATIONS + 1))
  if [ "$ITERATIONS" -gt "$MAX_ITERATIONS" ]; then
    echo "Error: Reached maximum iterations without reaching target size."
    echo "Current size: $($STAT_CMD "$OUTPUT_FILE") bytes"
    exit 1
  fi

  id=$(generate_random_string 8)
  username=$(generate_random_string 10)
  email="${username}@example.com"
  age=$((RANDOM % 60 + 18)) # Random age between 18 and 77
  country=$(get_random_country)

  # Append a row to the CSV file
  echo "$id,$username,$email,$age,$country" >> "$OUTPUT_FILE" || {
    echo "Error: Failed to write to $OUTPUT_FILE"
    exit 1
  }
done

# Confirm completion
FINAL_SIZE_MB=$((($($STAT_CMD "$OUTPUT_FILE") + 524288) / 1048576))  # Round to nearest MB
echo "Lookup file '$OUTPUT_FILE' created successfully with size of approximately ${FINAL_SIZE_MB}MB."
