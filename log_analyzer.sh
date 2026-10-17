#!/usr/bin/env bash
# ==============================================================================
# Script Name: log_analyzer.sh
# Description: Production-grade Bash tool for analyzing web, system, and
#              application log files. Extracts metrics, filters by level/status,
#              identifies top IP addresses/endpoints, and detects anomalies.
# Author:      SysOps & DevOps Tooling
# Version:     1.2.0
# License:     MIT
# ==============================================================================

# Exit immediately if a command exits with a non-zero status in sensitive operations,
# treat unset variables as an error when substituting, and prevent masking errors in pipelines.
set -o pipefail

# ------------------------------------------------------------------------------
# Global Constants & Color Definitions
# ------------------------------------------------------------------------------
VERSION="1.2.0"
SCRIPT_NAME=$(basename "$0")

# ANSI color codes for rich terminal output
# Checks if terminal supports colors (or overridden by flag)
COLOR_AUTO=true
RED=""
GREEN=""
YELLOW=""
BLUE=""
MAGENTA=""
CYAN=""
BOLD=""
DIM=""
RESET=""

init_colors() {
    if [[ "$COLOR_MODE" == "never" ]]; then
        return
    fi

    if [[ "$COLOR_MODE" == "always" ]] || [[ -t 1 ]]; then
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[0;33m'
        BLUE='\033[0;34m'
        MAGENTA='\033[0;35m'
        CYAN='\033[0;36m'
        BOLD='\033[1m'
        DIM='\033[2m'
        RESET='\033[0m'
    fi
}

# ------------------------------------------------------------------------------
# Default Configuration Variables
# ------------------------------------------------------------------------------
LOG_FILE=""
FILTER_LEVEL=""
FILTER_STATUS=""
FILTER_PATTERN=""
FILTER_DATE=""
TOP_COUNT=10
OUTPUT_FILE=""
OUTPUT_FORMAT="text" # "text" or "json"
SHOW_SUMMARY=false
COLOR_MODE="auto"
VERBOSE=false

# ------------------------------------------------------------------------------
# Usage / Help Display
# ------------------------------------------------------------------------------
show_help() {
    cat << EOF
${BOLD}${CYAN}Log Analyzer v${VERSION}${RESET} - A fast, flexible Bash tool for inspecting and analyzing log files.

${BOLD}USAGE:${RESET}
    ${SCRIPT_NAME} [OPTIONS] -f <LOG_FILE>
    cat <LOG_FILE> | ${SCRIPT_NAME} [OPTIONS]

${BOLD}OPTIONS:${RESET}
    ${GREEN}-f, --file <PATH>${RESET}       Path to the log file to analyze (optional if piped via STDIN)
    ${GREEN}-l, --level <LEVEL>${RESET}      Filter by log level (DEBUG, INFO, WARN, WARNING, ERROR, CRITICAL, FATAL)
    ${GREEN}-s, --status <CODE>${RESET}      Filter by HTTP status code (e.g. 200, 404, 500 or prefix like 4xx, 5xx)
    ${GREEN}-t, --top <NUM>${RESET}          Number of top occurrences to report (Default: 10)
    ${GREEN}-p, --pattern <REGEX>${RESET}    Filter lines matching a custom regular expression
    ${GREEN}-d, --date <DATE>${RESET}        Filter logs for a specific date (e.g. 2026-10-16 or 16/Oct/2026)
    ${GREEN}--summary${RESET}               Generate a comprehensive aggregated summary report
    ${GREEN}--json${RESET}                  Output analysis metrics in JSON format
    ${GREEN}-o, --output <PATH>${RESET}     Save results to the specified file instead of STDOUT
    ${GREEN}-c, --color <MODE>${RESET}      Color output: 'auto' (default), 'always', or 'never'
    ${GREEN}-v, --version${RESET}           Display tool version information
    ${GREEN}-h, --help${RESET}              Display this help message and exit

${BOLD}EXAMPLES:${RESET}
    ${DIM}# Display a comprehensive summary of an Nginx access log:${RESET}
    ${SCRIPT_NAME} -f /var/log/nginx/access.log --summary

    ${DIM}# Find top 5 attacking IPs or frequent visitors:${RESET}
    ${SCRIPT_NAME} -f /var/log/nginx/access.log --top 5

    ${DIM}# Find all ERROR lines in an application log:${RESET}
    ${SCRIPT_NAME} -f /var/log/app.log --level ERROR

    ${DIM}# Inspect 500 Internal Server Errors in JSON format:${RESET}
    ${SCRIPT_NAME} -f access.log --status 500 --json

    ${DIM}# Pipe logs directly through STDIN:${RESET}
    grep "2026-10" /var/log/syslog | ${SCRIPT_NAME} --level WARN

    ${DIM}# Search for authentication failures in auth.log:${RESET}
    ${SCRIPT_NAME} -f /var/log/auth.log -p "Failed password" --top 10

EOF
}

show_version() {
    echo "Log Analyzer v${VERSION} (Bash Tool)"
}

# ------------------------------------------------------------------------------
# Error Handling Helper
# ------------------------------------------------------------------------------
error_exit() {
    local message="$1"
    local exit_code="${2:-1}"
    echo -e "${RED}${BOLD}[ERROR]${RESET} ${message}" >&2
    exit "$exit_code"
}

log_warn() {
    local message="$1"
    echo -e "${YELLOW}${BOLD}[WARNING]${RESET} ${message}" >&2
}

log_info() {
    if [[ "$VERBOSE" == true ]]; then
        echo -e "${BLUE}${BOLD}[INFO]${RESET} $1" >&2
    fi
}

# ------------------------------------------------------------------------------
# Parse Command-Line Arguments
# ------------------------------------------------------------------------------
parse_arguments() {
    # If no arguments are passed and STDIN is a terminal, display help
    if [[ $# -eq 0 ]] && [[ -t 0 ]]; then
        show_help
        exit 0
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                show_version
                exit 0
                ;;
            -f|--file)
                if [[ -z "$2" || "$2" =~ ^- ]]; then
                    error_exit "Option '$1' requires a valid log file path."
                fi
                LOG_FILE="$2"
                shift 2
                ;;
            -l|--level)
                if [[ -z "$2" || "$2" =~ ^- ]]; then
                    error_exit "Option '$1' requires a log level (e.g. INFO, WARN, ERROR)."
                fi
                FILTER_LEVEL=$(echo "$2" | tr '[:lower:]' '[:upper:]')
                shift 2
                ;;
            -s|--status)
                if [[ -z "$2" || "$2" =~ ^- ]]; then
                    error_exit "Option '$1' requires an HTTP status code (e.g. 404, 500)."
                fi
                FILTER_STATUS="$2"
                shift 2
                ;;
            -t|--top)
                if [[ -z "$2" || ! "$2" =~ ^[0-9]+$ || "$2" -le 0 ]]; then
                    error_exit "Option '$1' requires a positive integer argument."
                fi
                TOP_COUNT="$2"
                shift 2
                ;;
            -p|--pattern)
                if [[ -z "$2" ]]; then
                    error_exit "Option '$1' requires a regular expression pattern."
                fi
                FILTER_PATTERN="$2"
                shift 2
                ;;
            -d|--date)
                if [[ -z "$2" || "$2" =~ ^- ]]; then
                    error_exit "Option '$1' requires a date string (e.g. 2026-10-16)."
                fi
                FILTER_DATE="$2"
                shift 2
                ;;
            --summary)
                SHOW_SUMMARY=true
                shift
                ;;
            --json)
                OUTPUT_FORMAT="json"
                shift
                ;;
            -o|--output)
                if [[ -z "$2" || "$2" =~ ^- ]]; then
                    error_exit "Option '$1' requires an output file path."
                fi
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -c|--color)
                if [[ -z "$2" || ! "$2" =~ ^(auto|always|never)$ ]]; then
                    error_exit "Invalid color mode '$2'. Allowed values: auto, always, never."
                fi
                COLOR_MODE="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            *)
                error_exit "Unknown option: '$1'. Run '${SCRIPT_NAME} --help' for usage instructions."
                ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# Input Validation & Ingestion
# ------------------------------------------------------------------------------
validate_input() {
    TEMP_DIR=$(mktemp -d /tmp/log_analyzer.XXXXXX)
    INPUT_STREAM="${TEMP_DIR}/stream.log"

    # Trap cleanup on exit
    trap 'rm -rf "${TEMP_DIR}"' EXIT INT TERM

    # Check whether data is coming from a file or from standard input pipe
    if [[ -n "$LOG_FILE" ]]; then
        if [[ ! -f "$LOG_FILE" ]]; then
            error_exit "Log file '${LOG_FILE}' does not exist or is not a regular file."
        fi
        if [[ ! -r "$LOG_FILE" ]]; then
            error_exit "Permission denied: Cannot read '${LOG_FILE}'."
        fi
        if [[ ! -s "$LOG_FILE" ]]; then
            log_warn "Log file '${LOG_FILE}' is empty."
            touch "$INPUT_STREAM"
        else
            cp "$LOG_FILE" "$INPUT_STREAM"
        fi
    elif [[ ! -t 0 ]]; then
        # Read from STDIN pipe
        cat > "$INPUT_STREAM"
    else
        error_exit "No input provided. Specify a file with -f <file> or pipe data via STDIN."
    fi
}

# ------------------------------------------------------------------------------
# Core Log Analysis Functions
# ------------------------------------------------------------------------------

# Filter stream based on active CLI filters
apply_filters() {
    local source_file="$1"
    local target_file="$2"

    cp "$source_file" "$target_file"

    # Filter by Date
    if [[ -n "$FILTER_DATE" ]]; then
        grep -E "$FILTER_DATE" "$target_file" > "${target_file}.tmp" || true
        mv "${target_file}.tmp" "$target_file"
    fi

    # Filter by Level
    if [[ -n "$FILTER_LEVEL" ]]; then
        grep -E -i "(\b${FILTER_LEVEL}\b|\[${FILTER_LEVEL}\]|level=${FILTER_LEVEL})" "$target_file" > "${target_file}.tmp" || true
        mv "${target_file}.tmp" "$target_file"
    fi

    # Filter by HTTP Status
    if [[ -n "$FILTER_STATUS" ]]; then
        # Matches status in quotes followed by space and status, e.g. "HTTP/1.1" 404
        local regex_status
        if [[ "$FILTER_STATUS" =~ ^([0-9])xx$ ]]; then
            local prefix="${BASH_REMATCH[1]}"
            regex_status="\" [${prefix}][0-9]{2} "
        else
            regex_status="\" ${FILTER_STATUS} "
        fi
        grep -E "$regex_status" "$target_file" > "${target_file}.tmp" || true
        mv "${target_file}.tmp" "$target_file"
    fi

    # Filter by Custom Regex Pattern
    if [[ -n "$FILTER_PATTERN" ]]; then
        grep -E "$FILTER_PATTERN" "$target_file" > "${target_file}.tmp" || true
        mv "${target_file}.tmp" "$target_file"
    fi
}

# Compute high-level statistics
compute_statistics() {
    local file="$1"

    TOTAL_LINES=$(wc -l < "$file" | tr -d ' ')
    [[ -z "$TOTAL_LINES" ]] && TOTAL_LINES=0

    # Count Log Levels
    COUNT_ERROR=$(grep -E -i -c "(\bERROR\b|\bFATAL\b|\bCRITICAL\b|\[ERROR\])" "$file" || true)
    COUNT_WARN=$(grep -E -i -c "(\bWARN\b|\bWARNING\b|\[WARN\])" "$file" || true)
    COUNT_INFO=$(grep -E -i -c "(\bINFO\b|\[INFO\])" "$file" || true)
    COUNT_DEBUG=$(grep -E -i -c "(\bDEBUG\b|\[DEBUG\])" "$file" || true)

    # HTTP Status Code Buckets (for web server logs)
    COUNT_2XX=$(grep -E -c "\" 2[0-9]{2} " "$file" || true)
    COUNT_3XX=$(grep -E -c "\" 3[0-9]{2} " "$file" || true)
    COUNT_4XX=$(grep -E -c "\" 4[0-9]{2} " "$file" || true)
    COUNT_5XX=$(grep -E -c "\" 5[0-9]{2} " "$file" || true)

    # Calculate error percentage
    if [[ "$TOTAL_LINES" -gt 0 ]]; then
        ERROR_PERCENT=$(awk -v e="$COUNT_ERROR" -v t="$TOTAL_LINES" 'BEGIN { printf "%.2f", (e/t)*100 }')
    else
        ERROR_PERCENT="0.00"
    fi
}

# Draw visual ASCII progress bar
draw_bar() {
    local pct="$1"
    local width=20
    local filled=$(awk -v p="$pct" -v w="$width" 'BEGIN { printf "%d", (p * w) / 100 }')
    local empty=$((width - filled))

    printf "["
    for ((i=0; i<filled; i++)); do printf "█"; done
    for ((i=0; i<empty; i++)); do printf "░"; done
    printf "] %s%%" "$pct"
}

# ------------------------------------------------------------------------------
# Render Output (Text & JSON)
# ------------------------------------------------------------------------------
render_text_report() {
    local filtered_file="$1"

    echo -e "${BOLD}${CYAN}======================================================================${RESET}"
    echo -e "${BOLD}${CYAN}                     LOG ANALYZER REPORT                              ${RESET}"
    echo -e "${BOLD}${CYAN}======================================================================${RESET}"
    echo -e "Analyzed at: ${BOLD}$(date '+%Y-%m-%d %H:%M:%S')${RESET}"
    if [[ -n "$LOG_FILE" ]]; then
        echo -e "Target File: ${BOLD}${LOG_FILE}${RESET}"
    else
        echo -e "Target File: ${BOLD}<STDIN stream>${RESET}"
    fi

    # Display active filters
    if [[ -n "$FILTER_LEVEL" || -n "$FILTER_STATUS" || -n "$FILTER_PATTERN" || -n "$FILTER_DATE" ]]; then
        echo -e "\n${BOLD}${YELLOW}[Active Filters]${RESET}"
        [[ -n "$FILTER_DATE" ]] && echo -e "  • Date:     ${FILTER_DATE}"
        [[ -n "$FILTER_LEVEL" ]] && echo -e "  • Level:    ${FILTER_LEVEL}"
        [[ -n "$FILTER_STATUS" ]] && echo -e "  • Status:   ${FILTER_STATUS}"
        [[ -n "$FILTER_PATTERN" ]] && echo -e "  • Pattern:  ${FILTER_PATTERN}"
    fi

    echo -e "\n${BOLD}${MAGENTA}--- Summary Statistics ---${RESET}"
    printf "  Total Entries:        %'d\n" "$TOTAL_LINES"
    printf "  Error Rate:           %s%% \n" "$ERROR_PERCENT"
    echo -e "  Error Level Count:    ${RED}${COUNT_ERROR}${RESET}"
    echo -e "  Warning Level Count:  ${YELLOW}${COUNT_WARN}${RESET}"
    echo -e "  Info Level Count:     ${GREEN}${COUNT_INFO}${RESET}"
    echo -e "  Debug Level Count:    ${BLUE}${COUNT_DEBUG}${RESET}"

    # If web status codes were found
    local web_total=$((COUNT_2XX + COUNT_3XX + COUNT_4XX + COUNT_5XX))
    if [[ "$web_total" -gt 0 ]]; then
        echo -e "\n${BOLD}${MAGENTA}--- HTTP Status Breakdown ---${RESET}"
        printf "  2xx (Success):        %-8d " "$COUNT_2XX"
        local p2xx=$(awk -v c="$COUNT_2XX" -v t="$web_total" 'BEGIN { printf "%.1f", (c/t)*100 }')
        echo -e "${GREEN}$(draw_bar "$p2xx")${RESET}"

        printf "  3xx (Redirect):       %-8d " "$COUNT_3XX"
        local p3xx=$(awk -v c="$COUNT_3XX" -v t="$web_total" 'BEGIN { printf "%.1f", (c/t)*100 }')
        echo -e "${CYAN}$(draw_bar "$p3xx")${RESET}"

        printf "  4xx (Client Error):   %-8d " "$COUNT_4XX"
        local p4xx=$(awk -v c="$COUNT_4XX" -v t="$web_total" 'BEGIN { printf "%.1f", (c/t)*100 }')
        echo -e "${YELLOW}$(draw_bar "$p4xx")${RESET}"

        printf "  5xx (Server Error):   %-8d " "$COUNT_5XX"
        local p5xx=$(awk -v c="$COUNT_5XX" -v t="$web_total" 'BEGIN { printf "%.1f", (c/t)*100 }')
        echo -e "${RED}$(draw_bar "$p5xx")${RESET}"
    fi

    # Extract and report Top IP addresses
    echo -e "\n${BOLD}${MAGENTA}--- Top ${TOP_COUNT} IP Addresses ---${RESET}"
    local top_ips
    top_ips=$(grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$filtered_file" | sort | uniq -c | sort -nr | head -n "$TOP_COUNT")
    if [[ -n "$top_ips" ]]; then
        printf "  %-10s %-20s\n" "COUNT" "IP ADDRESS"
        printf "  %-10s %-20s\n" "-----" "----------"
        while read -r count ip; do
            printf "  %-10d %-20s\n" "$count" "$ip"
        done <<< "$top_ips"
    else
        echo "  (No IP addresses detected in current log stream)"
    fi

    # Extract and report Top Request Endpoints (if standard web log format)
    echo -e "\n${BOLD}${MAGENTA}--- Top ${TOP_COUNT} Request Endpoints ---${RESET}"
    local top_endpoints
    top_endpoints=$(grep -oE '\"(GET|POST|PUT|DELETE|PATCH|HEAD) [^ "]+' "$filtered_file" | sed 's/"//' | sort | uniq -c | sort -nr | head -n "$TOP_COUNT")
    if [[ -n "$top_endpoints" ]]; then
        printf "  %-10s %-8s %-40s\n" "COUNT" "METHOD" "ENDPOINT"
        printf "  %-10s %-8s %-40s\n" "-----" "------" "--------"
        while read -r count method endpoint; do
            printf "  %-10d %-8s %-40s\n" "$count" "$method" "$endpoint"
        done <<< "$top_endpoints"
    else
        echo "  (No HTTP request endpoints detected)"
    fi

    # Sample matching lines if filtering was applied
    if [[ -n "$FILTER_LEVEL" || -n "$FILTER_STATUS" || -n "$FILTER_PATTERN" ]]; then
        echo -e "\n${BOLD}${MAGENTA}--- Sample Filtered Lines (First 5) ---${RESET}"
        head -n 5 "$filtered_file" | while IFS= read -r line; do
            echo "  $line"
        done
    fi

    echo -e "\n${BOLD}${CYAN}======================================================================${RESET}"
    echo -e "${GREEN}✔ Analysis completed successfully.${RESET}"
}

render_json_report() {
    local filtered_file="$1"

    # Gather top IPs as JSON array
    local top_ips_json="[]"
    local raw_ips
    raw_ips=$(grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$filtered_file" | sort | uniq -c | sort -nr | head -n "$TOP_COUNT")
    if [[ -n "$raw_ips" ]]; then
        top_ips_json=$(awk 'BEGIN { printf "[" } { if (NR>1) printf ","; printf "{\"count\":%d,\"ip\":\"%s\"}", $1, $2 } END { printf "]" }' <<< "$raw_ips")
    fi

    # Gather top endpoints as JSON array
    local top_endpoints_json="[]"
    local raw_endpoints
    raw_endpoints=$(grep -oE '\"(GET|POST|PUT|DELETE|PATCH|HEAD) [^ "]+' "$filtered_file" | sed 's/"//' | sort | uniq -c | sort -nr | head -n "$TOP_COUNT")
    if [[ -n "$raw_endpoints" ]]; then
        top_endpoints_json=$(awk 'BEGIN { printf "[" } { if (NR>1) printf ","; printf "{\"count\":%d,\"method\":\"%s\",\"endpoint\":\"%s\"}", $1, $2, $3 } END { printf "]" }' <<< "$raw_endpoints")
    fi

    cat << EOF
{
  "version": "${VERSION}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "file": "${LOG_FILE:-"STDIN"}",
  "metrics": {
    "total_lines": ${TOTAL_LINES},
    "error_rate_pct": ${ERROR_PERCENT},
    "levels": {
      "error": ${COUNT_ERROR},
      "warn": ${COUNT_WARN},
      "info": ${COUNT_INFO},
      "debug": ${COUNT_DEBUG}
    },
    "http_status_buckets": {
      "2xx": ${COUNT_2XX},
      "3xx": ${COUNT_3XX},
      "4xx": ${COUNT_4XX},
      "5xx": ${COUNT_5XX}
    }
  },
  "top_ips": ${top_ips_json},
  "top_endpoints": ${top_endpoints_json}
}
EOF
}

# ------------------------------------------------------------------------------
# Main Execution Entry Point
# ------------------------------------------------------------------------------
main() {
    parse_arguments "$@"
    init_colors
    validate_input

    FILTERED_STREAM="${TEMP_DIR}/filtered.log"
    apply_filters "$INPUT_STREAM" "$FILTERED_STREAM"
    compute_statistics "$FILTERED_STREAM"

    # Direct output to file if requested, or STDOUT
    if [[ -n "$OUTPUT_FILE" ]]; then
        if [[ "$OUTPUT_FORMAT" == "json" ]]; then
            render_json_report "$FILTERED_STREAM" > "$OUTPUT_FILE"
        else
            # Strip ANSI color codes when writing to plain text file
            render_text_report "$FILTERED_STREAM" | sed 's/\x1b\[[0-9;]*m//g' > "$OUTPUT_FILE"
        fi
        echo -e "${GREEN}Report saved to:${RESET} ${OUTPUT_FILE}"
    else
        if [[ "$OUTPUT_FORMAT" == "json" ]]; then
            render_json_report "$FILTERED_STREAM"
        else
            render_text_report "$FILTERED_STREAM"
        fi
    fi
}

main "$@"
