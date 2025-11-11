
find . -name inputs.conf -exec grep -H 'monitor' {} \; | awk -F'[][]' '{raw_path = substr($2, index($2, "monitor://") + length("monitor://")); normalized_path = tolower(raw_path); gsub(/\\/, "/", normalized_path); sub(/\/[^/]*[\\.\\*][^/]*$/, "", normalized_path); lines[normalized_path][++count[normalized_path]] = $0;} END {for (path in count) {if (count[path] > 1) {for (i = 1; i <= count[path]; i++) {print lines[path][i];}}}}'

