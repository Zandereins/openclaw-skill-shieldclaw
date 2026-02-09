#!/usr/bin/env bash
# ShieldClaw Scanner v0.1 — Scan skills/files for prompt injection patterns
# Usage: bash scanner.sh <path-to-skill-folder-or-file>
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

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    echo -e "${RED}Usage: bash scanner.sh <path-to-skill-folder-or-file>${NC}"
    exit 1
fi

if [[ ! -e "$TARGET" ]]; then
    echo -e "${RED}Error: '$TARGET' not found${NC}"
    exit 1
fi

CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
TOTAL_FILES=0
SCANNED_FILES=0

echo -e "${BOLD}${CYAN}🛡️  ShieldClaw Scanner v0.1${NC}"
echo -e "${CYAN}Scanning: ${TARGET}${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

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

        while IFS='|' read -r category severity pattern description; do
            [[ "$category" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$category" ]] && continue

            severity="${severity#"${severity%%[![:space:]]*}"}"
            severity="${severity%"${severity##*[![:space:]]}"}"
            pattern="${pattern#"${pattern%%[![:space:]]*}"}"
            pattern="${pattern%"${pattern##*[![:space:]]}"}"
            description="${description#"${description%%[![:space:]]*}"}"
            description="${description%"${description##*[![:space:]]}"}"

            matches=$(grep -cPn "$pattern" "$file" 2>/dev/null || true)

            if [[ "$matches" -gt 0 ]]; then
                if [[ "$file_has_findings" -eq 0 ]]; then
                    echo -e "\n${BOLD}📄 ${file}${NC}"
                    file_has_findings=1
                fi

                case "$severity" in
                    CRITICAL)
                        echo -e "  ${RED}🔴 CRITICAL${NC} [$category] $description"
                        ((CRITICAL_COUNT++)) || true
                        ;;
                    HIGH)
                        echo -e "  ${YELLOW}🟡 HIGH${NC}     [$category] $description"
                        ((HIGH_COUNT++)) || true
                        ;;
                    MEDIUM)
                        echo -e "  ${CYAN}🔵 MEDIUM${NC}   [$category] $description"
                        ((MEDIUM_COUNT++)) || true
                        ;;
                esac

                first_match=$(grep -Pn "$pattern" "$file" 2>/dev/null | head -1)
                if [[ -n "$first_match" ]]; then
                    line_num="${first_match%%:*}"
                    line_content="${first_match#*:}"
                    if [[ ${#line_content} -gt 120 ]]; then
                        line_content="${line_content:0:117}..."
                    fi
                    echo -e "    Line $line_num: ${line_content}"
                fi

                if [[ "$matches" -gt 1 ]]; then
                    echo -e "    (+ $((matches - 1)) more matches)"
                fi
            fi
        done < "$pattern_file"
    done
}

if [[ -f "$TARGET" ]]; then
    TOTAL_FILES=1
    scan_file "$TARGET"
elif [[ -d "$TARGET" ]]; then
    while IFS= read -r -d '' file; do
        ((TOTAL_FILES++)) || true
        scan_file "$file"
    done < <(find "$TARGET" -type f -not -path '*/node_modules/*' -not -path '*/.git/*' -print0)
fi

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

TOTAL=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT))
if [[ $TOTAL -eq 0 ]]; then
    echo -e "   ${GREEN}✅ No injection patterns detected${NC}"
    exit 0
elif [[ $CRITICAL_COUNT -gt 0 ]]; then
    echo -e "\n${RED}${BOLD}⛔ CRITICAL findings — DO NOT install this skill without review${NC}"
    exit 2
else
    echo -e "\n${YELLOW}${BOLD}⚠️  Findings detected — review before installing${NC}"
    exit 1
fi
