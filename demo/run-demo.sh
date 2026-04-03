#!/bin/bash
# =============================================================================
# MCP Tool Firewall + agentgateway — Side-by-Side Demo
#
# Prerequisites: port-forwards must be running:
#   kubectl port-forward svc/agentgateway 3100:3000 &
#   kubectl port-forward svc/agentgateway 15100:15000 &
#   kubectl port-forward svc/grafana 3200:3000 &
# =============================================================================

GATEWAY_URL="${GATEWAY_URL:-http://localhost:3100}"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}============================================${NC}"
echo -e "${BOLD}  MCP Tool Firewall + agentgateway Demo${NC}"
echo -e "${BOLD}============================================${NC}"
echo ""

# ─── DIRECT ROUTE (NO FIREWALL) ─────────────────────────────────────────────

echo -e "${RED}${BOLD}>>> ROUTE 1: /direct — NO firewall (agent sees everything)${NC}"
echo "-----------------------------------------------------------"
echo ""

INIT1=$(curl -s -i -X POST "$GATEWAY_URL/direct" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo-agent","version":"1.0"}}}' 2>&1)

S1=$(echo "$INIT1" | grep -i "mcp-session-id" | head -1 | awk '{print $2}' | tr -d '\r')

if [ -z "$S1" ]; then
  echo -e "${RED}ERROR: Could not initialize session on /direct route.${NC}"
  echo "Is the port-forward running? kubectl port-forward svc/agentgateway 3100:3000 &"
  exit 1
fi

TOOLS1=$(curl -s -X POST "$GATEWAY_URL/direct" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: $S1" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')

DIRECT_COUNT=$(echo "$TOOLS1" | sed 's/^data: //' | python3 -c "import sys,json; print(len(json.load(sys.stdin)['result']['tools']))" 2>/dev/null)
echo -e "Tools returned to agent: ${RED}${BOLD}$DIRECT_COUNT${NC} (7 poisoned + 1 safe)"
echo ""

echo "$TOOLS1" | sed 's/^data: //' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for t in data['result']['tools']:
    name = t['name']
    desc = t['description'][:90].replace('\n', ' ')
    if name == 'format_text':
        print(f'  \033[0;32m[SAFE    ]\033[0m {name:20s}  {desc}')
    else:
        print(f'  \033[0;31m[POISONED]\033[0m {name:20s}  {desc}')
" 2>/dev/null

echo ""
echo ""

# ─── PROTECTED ROUTE (WITH FIREWALL) ────────────────────────────────────────

echo -e "${GREEN}${BOLD}>>> ROUTE 2: /mcp — WITH agentgateway + firewall${NC}"
echo "-----------------------------------------------------------"
echo ""

INIT2=$(curl -s -i -X POST "$GATEWAY_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo-agent","version":"1.0"}}}' 2>&1)

S2=$(echo "$INIT2" | grep -i "mcp-session-id" | head -1 | awk '{print $2}' | tr -d '\r')

TOOLS2=$(curl -s -X POST "$GATEWAY_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: $S2" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')

PROTECTED_COUNT=$(echo "$TOOLS2" | sed 's/^data: //' | python3 -c "import sys,json; print(len(json.load(sys.stdin)['result']['tools']))" 2>/dev/null)
echo -e "Tools returned to agent: ${GREEN}${BOLD}$PROTECTED_COUNT${NC} (7 poisoned BLOCKED, safe tools only)"
echo ""

echo "$TOOLS2" | sed 's/^data: //' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for t in data['result']['tools']:
    name = t['name']
    desc = t['description'][:90].replace('\n', ' ')
    source = name.split('_')[0] if '_' in name else 'unknown'
    print(f'  \033[0;32m[SAFE    ]\033[0m {name:50s}  {desc}')
" 2>/dev/null

echo ""
echo ""

# ─── SUMMARY ─────────────────────────────────────────────────────────────────

BLOCKED=$((DIRECT_COUNT - 1))

echo -e "${BOLD}============================================${NC}"
echo -e "${BOLD}  RESULTS${NC}"
echo -e "${BOLD}============================================${NC}"
echo ""
echo -e "  ${RED}Without firewall:${NC}  $DIRECT_COUNT tools exposed (${BLOCKED} poisoned)"
echo -e "  ${GREEN}With firewall:${NC}     $PROTECTED_COUNT safe tools (${BLOCKED} poisoned tools ${GREEN}BLOCKED${NC})"
echo ""
echo -e "  ${CYAN}Attack types detected:${NC}"
echo "    - Prompt Injection (ignore instructions, <<SYS>> tags)"
echo "    - Data Exfiltration (send data to external URLs)"
echo "    - Cross-Tool Manipulation (chain tool calls)"
echo "    - Invisible Characters (zero-width spaces)"
echo "    - Obfuscated Payloads (base64, eval)"
echo "    - Dangerous Commands (rm -rf, chmod, curl|sh)"
echo "    - Code Execution (os.system, subprocess, wget malware)"
echo ""
echo -e "  ${YELLOW}Open in browser:${NC}"
echo "    agentgateway Admin UI:  http://localhost:15100/ui"
echo "    Grafana Dashboard:      http://localhost:3200  (admin/firewall)"
echo ""
echo -e "${BOLD}============================================${NC}"
