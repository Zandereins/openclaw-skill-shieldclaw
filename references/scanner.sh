#!/usr/bin/env bash
# ShieldClaw Scanner v0.2 — Scan skills/files for prompt injection patterns
# Usage: bash scanner.sh [options] <path-to-skill-folder-or-file>
# Options:
#   --json              Output findings as JSON
#   --stdin             Read content from stdin instead of files
#   --severity LEVEL    Minimum severity to report (CRITICAL|HIGH|MEDIUM)
# Exit codes: 0 = clean, 1 = warnings found, 2 = critical findings

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATTERN_DIR="${SCRIPT_DIR}/patterns"

# Parse options
JSON_OUTPUT=0
STDIN_MODE=0
MIN_SEVERITY="MEDIUM"
TARGET=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) JSON_OUTPUT=1; shift ;;
        --stdin) STDIN_MODE=1; shift ;;
        --severity)
            MIN_SEVERITY="${2:-MEDIUM}"
            shift 2
            ;;
        -*)
            echo -e "${RED}Unknown option: $1${NC}" >&2
            exit 1
            ;;
        *)
            TARGET="$1"
            shift
            ;;
    esac
done

if [[ "$STDIN_MODE" -eq 0 && -z "$TARGET" ]]; then
    echo -e "${RED}Usage: bash scanner.sh [--json] [--stdin] [--severity LEVEL] <path>${NC}" >&2
    exit 1
fi

if [[ "$STDIN_MODE" -eq 0 && ! -e "$TARGET" ]]; then
    echo -e "${RED}Error: '$TARGET' not found${NC}" >&2
    exit 1
fi

# Severity filtering
should_report() {
    local severity="$1"
    case "$MIN_SEVERITY" in
        CRITICAL) [[ "$severity" == "CRITICAL" ]] ;;
        HIGH) [[ "$severity" == "CRITICAL" || "$severity" == "HIGH" ]] ;;
        MEDIUM) return 0 ;;
        *) return 0 ;;
    esac
}

CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
TOTAL_FILES=0
SCANNED_FILES=0
JSON_FINDINGS="[]"

if [[ "$JSON_OUTPUT" -eq 0 ]]; then
    echo -e "${BOLD}${CYAN}🛡️  ShieldClaw Scanner v0.2${NC}"
    if [[ "$STDIN_MODE" -eq 1 ]]; then
        echo -e "${CYAN}Scanning: stdin${NC}"
    else
        echo -e "${CYAN}Scanning: ${TARGET}${NC}"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi

add_json_finding() {
    local file="$1" category="$2" severity="$3" description="$4" line_num="$5" match="$6"
    # Escape JSON strings
    match="${match//\\/\\\\}"
    match="${match//\"/\\\"}"
    match="${match//$'\n'/\\n}"
    description="${description//\\/\\\\}"
    description="${description//\"/\\\"}"
    file="${file//\\/\\\\}"
    file="${file//\"/\\\"}"
    local entry="{\"file\":\"${file}\",\"category\":\"${category}\",\"severity\":\"${severity}\",\"description\":\"${description}\",\"line\":${line_num},\"match\":\"${match}\"}"
    if [[ "$JSON_FINDINGS" == "[]" ]]; then
        JSON_FINDINGS="[${entry}]"
    else
        JSON_FINDINGS="${JSON_FINDINGS%]},${entry}]"
    fi
}

scan_file() {
    local file="$1"
    local filename="$(basename "$file")"
    local ext="${filename##*.}"

    case "$ext" in
        png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|zip|tar|gz|skill) return ;;
    esac

    # Text detection by extension (portable, no 'file' command needed)
    case "$ext" in
        md|txt|json|yaml|yml|toml|sh|bash|js|ts|py|rb|go|rs|html|css|xml|csv|cfg|conf|ini|env|log|mdx|jsx|tsx|sql|lock) ;;
        *) return ;;
    esac
    if [[ ! -s "$file" ]]; then
        return
    fi

    ((SCANNED_FILES++)) || true
    local file_has_findings=0

    for pattern_file in "$PATTERN_DIR"/*.txt; do
        [[ -f "$pattern_file" ]] || continue

        while IFS= read -r line; do
            # Skip comments and empty lines
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// /}" ]] && continue

            # Parse: CATEGORY|SEVERITY|REGEX (may contain pipes)|DESCRIPTION (last field)
            # Split first two fields
            category="${line%%|*}"
            local rest="${line#*|}"
            severity="${rest%%|*}"
            rest="${rest#*|}"
            # Description = last field (after last pipe), Pattern = everything before
            description="${rest##*|}"
            pattern="${rest%|*}"

            # Trim whitespace (portable bash)
            category="${category#"${category%%[![:space:]]*}"}"
            category="${category%"${category##*[![:space:]]}"}"
            severity="${severity#"${severity%%[![:space:]]*}"}"
            severity="${severity%"${severity##*[![:space:]]}"}"
            pattern="${pattern#"${pattern%%[![:space:]]*}"}"
            pattern="${pattern%"${pattern##*[![:space:]]}"}"
            description="${description#"${description%%[![:space:]]*}"}"
            description="${description%"${description##*[![:space:]]}"}"

            [[ -z "$category" ]] && continue
            [[ -z "$pattern" ]] && continue

            matches=$(grep -cPn "$pattern" "$file" 2>/dev/null || true)

            if [[ "$matches" -gt 0 ]] && should_report "$severity"; then
                first_match=$(grep -Pn "$pattern" "$file" 2>/dev/null | head -1)
                line_num="0"
                line_content=""
                if [[ -n "$first_match" ]]; then
                    line_num="${first_match%%:*}"
                    line_content="${first_match#*:}"
                    if [[ ${#line_content} -gt 120 ]]; then
                        line_content="${line_content:0:117}..."
                    fi
                fi

                if [[ "$JSON_OUTPUT" -eq 1 ]]; then
                    add_json_finding "$file" "$category" "$severity" "$description" "$line_num" "$line_content"
                else
                    if [[ "$file_has_findings" -eq 0 ]]; then
                        echo -e "\n${BOLD}📄 ${file}${NC}"
                        file_has_findings=1
                    fi

                    case "$severity" in
                        CRITICAL)
                            echo -e "  ${RED}🔴 CRITICAL${NC} [$category] $description"
                            ;;
                        HIGH)
                            echo -e "  ${YELLOW}🟡 HIGH${NC}     [$category] $description"
                            ;;
                        MEDIUM)
                            echo -e "  ${CYAN}🔵 MEDIUM${NC}   [$category] $description"
                            ;;
                    esac

                    if [[ -n "$line_content" ]]; then
                        echo -e "    Line $line_num: ${line_content}"
                    fi

                    if [[ "$matches" -gt 1 ]]; then
                        echo -e "    (+ $((matches - 1)) more matches)"
                    fi
                fi

                case "$severity" in
                    CRITICAL) ((CRITICAL_COUNT++)) || true ;;
                    HIGH) ((HIGH_COUNT++)) || true ;;
                    MEDIUM) ((MEDIUM_COUNT++)) || true ;;
                esac
            fi
        done < "$pattern_file"
    done
}

if [[ "$STDIN_MODE" -eq 1 ]]; then
    # Read from stdin into a temp file with .txt extension (needed for scan_file)
    TMPFILE=$(mktemp /tmp/shieldclaw-stdin-XXXXXX.txt)
    trap 'rm -f "$TMPFILE"' EXIT
    cat > "$TMPFILE"
    TOTAL_FILES=1
    scan_file "$TMPFILE"
elif [[ -f "$TARGET" ]]; then
    TOTAL_FILES=1
    scan_file "$TARGET"
elif [[ -d "$TARGET" ]]; then
    while IFS= read -r -d '' file; do
        ((TOTAL_FILES++)) || true
        scan_file "$file"
    done < <(find "$TARGET" -type f -not -path '*/node_modules/*' -not -path '*/.git/*' -print0)
fi

TOTAL=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT))

if [[ "$JSON_OUTPUT" -eq 1 ]]; then
    echo "{\"files_scanned\":${SCANNED_FILES},\"findings\":${JSON_FINDINGS},\"summary\":{\"critical\":${CRITICAL_COUNT},\"high\":${HIGH_COUNT},\"medium\":${MEDIUM_COUNT},\"total\":${TOTAL}}}"
else
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${BOLD}📊 Scan Summary${NC}"
    echo "   Files scanned: $SCANNED_FILES / $TOTAL_FILES"

    if [[ $CRITICAL_COUNT -gt 0 ]]; then
        echo -e "   ${RED}🔴 Critical: $CRITICAL_COUNT${NC}"
    fi
    if [[ $HIGH_COUNT -gt 0 ]]; then
        echo -e "   ${YELLOW}🟡 High:     $HIGH_COUNT${NC}"
    fi
    if [[ $MEDIUM_COUNT -gt 0 ]]; then
        echo -e "   ${CYAN}🔵 Medium:   $MEDIUM_COUNT${NC}"
    fi
fi

if [[ $TOTAL -eq 0 ]]; then
    [[ "$JSON_OUTPUT" -eq 0 ]] && echo -e "   ${GREEN}✅ No injection patterns detected${NC}"
    exit 0
elif [[ $CRITICAL_COUNT -gt 0 ]]; then
    [[ "$JSON_OUTPUT" -eq 0 ]] && echo -e "\n${RED}${BOLD}⛔ CRITICAL findings — DO NOT install this skill without review${NC}"
    exit 2
else
    [[ "$JSON_OUTPUT" -eq 0 ]] && echo -e "\n${YELLOW}${BOLD}⚠️  Findings detected — review before installing${NC}"
    exit 1
fi
