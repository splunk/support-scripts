#!/bin/bash

# File name and size target
OUTPUT_FILE="splunk_lookup.csv"
TARGET_SIZE_MB=14
TARGET_SIZE_BYTES=$((TARGET_SIZE_MB * 1024 * 1024))

# Header row for the CSV file
echo "id,username,email,age,country" > "$OUTPUT_FILE"

# Function to generate a random string
generate_random_string() {
  local length=$1
  tr -dc A-Za-z0-9 </dev/urandom | head -c "$length"
}

# Generate rows until the file size reaches the target
while [ "$(stat -c%s "$OUTPUT_FILE")" -lt "$TARGET_SIZE_BYTES" ]; do
  id=$(generate_random_string 8)
  username=$(generate_random_string 10)
  email="${username}@example.com"
  age=$((RANDOM % 60 + 18)) # Random age between 18 and 77
  country=$(shuf -n 1 -e USA Canada UK Germany France Australia)

  # Append a row to the CSV file
  echo "$id,$username,$email,$age,$country" >> "$OUTPUT_FILE"
done

# Confirm completion
echo "Lookup file '$OUTPUT_FILE' has been created with a size of approximately $TARGET_SIZE_MB MB."
