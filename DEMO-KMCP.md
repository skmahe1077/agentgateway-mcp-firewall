# Full Kubernetes Demo Walkthrough

This guide deploys the complete MCP Tool Poisoning Firewall stack on Kubernetes using kind, kmcp, and kagent.

## Prerequisites

- Docker
- [kind](https://kind.sigs.k8s.io/)
- kubectl
- [kagent CLI](https://kagent.dev)
- Anthropic API key (for kagent agent)

## Step 1: Create Kind Cluster

```bash
kind create cluster --name mcp-firewall-demo
kubectl cluster-info --context kind-mcp-firewall-demo
```

## Step 2: Install kagent

```bash
# Install kagent operator
kagent install

# Create API key secret
kubectl create namespace kagent
kubectl create secret generic kagent-anthropic \
  --namespace kagent \
  --from-literal=ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY
```

## Step 3: Build Container Images

```bash
# Build firewall image and load into kind
docker build -t mcp-tool-firewall:latest .
kind load docker-image mcp-tool-firewall:latest --name mcp-firewall-demo

# Build malicious server image and load into kind
docker build -t malicious-mcp-server:latest demo/malicious-mcp-server/
kind load docker-image malicious-mcp-server:latest --name mcp-firewall-demo
```

## Step 4: Deploy Malicious MCP Server via kmcp

```bash
kubectl apply -f demo/malicious-mcp-server/kmcp.yaml
kubectl wait --for=condition=ready pod -l app=malicious-mcp-server --timeout=60s
```

## Step 5: Deploy the Firewall

```bash
kubectl apply -f deploy/k8s/firewall-deployment.yaml
kubectl wait --for=condition=ready pod -l app=mcp-tool-firewall --timeout=60s
```

## Step 6: Deploy agentgateway (Governance Layer)

agentgateway provides the governance plane: MCP authentication (JWT), MCP authorization (CEL-based RBAC per tool), rate limiting, access logging, and an admin UI for visibility.

```bash
kubectl apply -f deploy/k8s/agentgateway.yaml
kubectl wait --for=condition=ready pod -l app=agentgateway --timeout=60s

# Verify agentgateway admin UI and metrics are accessible
kubectl port-forward svc/agentgateway 15000:15000 &
# Open http://localhost:15000 — agentgateway Admin UI
# View http://localhost:15020/metrics — MCP-specific Prometheus metrics
```

## Step 7: Deploy kagent Security Auditor Agent

```bash
kubectl apply -f deploy/k8s/kagent-security-agent.yaml
```

## Step 8: Test WITHOUT Firewall (Direct to Malicious Server)

```bash
# Port-forward to malicious server directly
kubectl port-forward svc/malicious-mcp-server 9999:9999 &

# List tools — all 8 tools returned (including 7 poisoned ones)
curl -s -X POST http://localhost:9999/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | python3 -m json.tool

# You'll see all 8 tools with their poisoned descriptions
```

## Step 9: Test WITH Governance + Firewall (Through agentgateway)

Traffic now flows: Agent → agentgateway (auth, RBAC, rate limit, logging) → Firewall (scan, block) → upstream

```bash
# Port-forward to agentgateway
kubectl port-forward svc/agentgateway 3000:3000 &

# List tools — agentgateway authenticates, firewall scans, only 1 safe tool returned
curl -s -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | python3 -m json.tool

# Only format_text passes through — the firewall blocked 7 poisoned tools
```

## Step 10: Interact with kagent Security Auditor

Open the kagent dashboard:

```bash
kagent dashboard
```

Navigate to the **mcp-security-auditor** agent and start a conversation:

```
You: Scan the MCP server at malicious-mcp-server:9999 for poisoning attacks

Agent: [calls scan_mcp_server tool]
       Found 8 tools, 7 blocked:
       - get_weather: Prompt Injection (score 85)
       - translate_text: Data Exfiltration (score 90)
       - search_files: Cross-Tool Manipulation + Dangerous Commands (score 80)
       - calculate: Invisible Characters + Obfuscated Payloads (score 80)
       - send_email: Prompt Injection (score 85)
       - read_database: Data Exfiltration + Cross-Tool Manipulation (score 90)
       - run_diagnostics: Dangerous Commands (score 80)

       1 safe: format_text (score 0)

       Recommendation: Block this server immediately.

You: Generate a full security report

Agent: [calls generate_security_report tool]
       [Returns full markdown report with executive summary, per-tool analysis,
        and remediation recommendations]
```

## Step 11: Cleanup

```bash
kind delete cluster --name mcp-firewall-demo
```

## Recording Script (3-5 min demo video)

| Timestamp | Action | Script |
|-----------|--------|--------|
| 0:00-0:30 | Intro | "Secure & Govern MCP — a two-layer defense for AI agents using agentgateway + firewall + kagent" |
| 0:30-1:00 | Show problem | curl malicious server directly — all 8 tools returned, show poisoned descriptions |
| 1:00-1:30 | Show architecture | Two layers: agentgateway (governance: auth, RBAC, rate limits) → firewall (content: poisoning detection) |
| 1:30-2:00 | Deploy stack | `kubectl apply` all manifests, show agentgateway Admin UI on :15000 |
| 2:00-2:30 | agentgateway governance | Show MCP AuthZ rules (CEL), rate limiting config, access logging for MCP traffic |
| 2:30-3:00 | Test firewall | curl through agentgateway → firewall, show 7 blocked / 1 allowed |
| 3:00-3:30 | Show metrics | View agentgateway metrics (:15020) + firewall metrics (:8888/metrics) — both Prometheus |
| 3:30-4:00 | kagent agent | Open kagent dashboard, ask agent to scan malicious server, show analysis |
| 4:00-4:30 | Response scanning | Ask agent to check a response containing an AWS key — show redaction |
| 4:30-5:00 | Wrap up | "Two-layer defense: agentgateway governs WHO, firewall secures WHAT. 3 ecosystem projects." |
