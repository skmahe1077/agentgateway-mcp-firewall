"""
MCP Tool Firewall Proxy

An aiohttp-based proxy that sits between agents and MCP servers,
intercepting tools/list responses and scanning for poisoning attacks.

Features:
- Inbound: scans tools/list responses, blocks poisoned tool descriptions
- Outbound: scans tools/call responses for secrets, PII, data leaks
- Kill switch: emergency deny-all mode
- Metrics: Prometheus-compatible /metrics endpoint
- Admin API: /admin/status, /admin/kill-switch
"""

import argparse
import json
import logging
import time

from aiohttp import web, ClientSession

from .scanner import ToolScanner
from .reporter import AuditReporter
from .response_scanner import ResponseScanner
from .metrics import MetricsCollector

logger = logging.getLogger("mcp-firewall")


class MCPToolFirewall:
    def __init__(
        self,
        upstream_host: str = "localhost",
        upstream_port: int = 9999,
        block_threshold: int = 51,
        warn_threshold: int = 26,
        log_dir: str = "logs",
        kill_switch: bool = False,
    ):
        self.upstream_url = f"http://{upstream_host}:{upstream_port}"
        self.scanner = ToolScanner(
            block_threshold=block_threshold,
            warn_threshold=warn_threshold,
        )
        self.reporter = AuditReporter(log_dir=log_dir)
        self.response_scanner = ResponseScanner()
        self.metrics = MetricsCollector()
        self.kill_switch = kill_switch
        self.pending_requests: dict = {}

        self.metrics.record_kill_switch(kill_switch)

        self.app = web.Application()
        self.app.router.add_post("/mcp", self.handle_jsonrpc)
        self.app.router.add_get("/health", self.handle_health)
        self.app.router.add_get("/metrics", self.handle_metrics)
        self.app.router.add_get("/admin/status", self.handle_admin_status)
        self.app.router.add_post("/admin/kill-switch", self.handle_kill_switch)

    async def handle_health(self, request: web.Request) -> web.Response:
        return web.json_response({
            "status": "healthy",
            "kill_switch": self.kill_switch,
        })

    async def handle_metrics(self, request: web.Request) -> web.Response:
        return web.Response(
            text=self.metrics.generate_metrics(),
            content_type="text/plain; version=0.0.4; charset=utf-8",
        )

    async def handle_admin_status(self, request: web.Request) -> web.Response:
        return web.json_response({
            "kill_switch": self.kill_switch,
            "upstream": self.upstream_url,
            "stats": self.reporter.get_stats(),
            "response_scanner_stats": self.response_scanner.get_stats(),
        })

    async def handle_kill_switch(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
            enabled = body.get("enabled", False)
            self.kill_switch = bool(enabled)
            self.metrics.record_kill_switch(self.kill_switch)
            logger.warning(f"Kill switch {'ENABLED' if self.kill_switch else 'DISABLED'}")
            return web.json_response({
                "kill_switch": self.kill_switch,
                "message": f"Kill switch {'enabled — all tools blocked' if self.kill_switch else 'disabled — normal operation resumed'}",
            })
        except Exception as e:
            return web.json_response(
                {"error": str(e)}, status=400
            )

    async def handle_jsonrpc(self, request: web.Request) -> web.Response:
        try:
            body = await request.read()
            req_data = json.loads(body)

            req_id = req_data.get("id")
            method = req_data.get("method", "")

            if req_id is not None:
                self.pending_requests[req_id] = method

            async with ClientSession() as session:
                async with session.post(
                    f"{self.upstream_url}/mcp",
                    data=body,
                    headers={"Content-Type": "application/json"},
                ) as resp:
                    resp_body = await resp.read()
                    resp_data = json.loads(resp_body)

            inspected = self._inspect_message(req_id, method, resp_data)

            if req_id is not None:
                self.pending_requests.pop(req_id, None)

            return web.json_response(inspected)

        except json.JSONDecodeError:
            return web.json_response(
                {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None},
                status=400,
            )
        except Exception as e:
            logger.error(f"Proxy error: {e}")
            return web.json_response(
                {"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}, "id": None},
                status=502,
            )

    def _inspect_message(self, req_id, method: str, resp_data: dict) -> dict:
        stored_method = self.pending_requests.get(req_id, method)

        # Handle tools/list — inbound scanning
        if stored_method == "tools/list":
            return self._inspect_tools_list(resp_data)

        # Handle tools/call — outbound response scanning
        if stored_method == "tools/call":
            return self._inspect_tool_response(resp_data)

        return resp_data

    def _inspect_tools_list(self, resp_data: dict) -> dict:
        result = resp_data.get("result", {})
        tools = result.get("tools", None)

        if tools is None:
            return resp_data

        # Kill switch: block everything
        if self.kill_switch:
            resp_data["result"]["tools"] = []
            resp_data["result"]["_firewall"] = {
                "kill_switch": True,
                "tools_blocked": len(tools),
                "message": "Kill switch active — all tools blocked",
            }
            return resp_data

        start = time.time()
        server_name = f"upstream-{self.upstream_url}"
        filtered_tools, report = self.scanner.filter_tools_list(server_name, tools)
        duration = time.time() - start

        self.reporter.log_scan(report)

        # Record metrics
        self.metrics.record_scan(
            total_tools=report.total_tools,
            blocked=report.tools_blocked,
            warned=report.tools_warned,
            safe=report.tools_safe,
        )
        self.metrics.record_scan_duration(duration)
        for r in report.results:
            self.metrics.record_risk_score(r.risk_score)
            for d in r.detections:
                if d.matched:
                    self.metrics.record_detection(d.pattern_name)

        resp_data["result"]["tools"] = filtered_tools

        if report.tools_blocked > 0:
            resp_data["result"]["_firewall"] = {
                "tools_blocked": report.tools_blocked,
                "tools_warned": report.tools_warned,
                "max_risk_score": report.max_risk_score,
                "blocked_tools": [
                    r.tool_name for r in report.results if r.blocked
                ],
            }

        return resp_data

    def _inspect_tool_response(self, resp_data: dict) -> dict:
        """Scan tool call responses for secrets, PII, and data leaks."""
        result = resp_data.get("result", {})
        content_list = result.get("content", [])

        for item in content_list:
            if item.get("type") != "text":
                continue

            text = item.get("text", "")
            if not text:
                continue

            scan_result = self.response_scanner.scan_response(text)

            if scan_result.findings:
                # Record metrics for response findings
                for finding in scan_result.findings:
                    self.metrics.record_response_finding(finding.finding_type)

                # Add firewall metadata about findings
                if "_firewall_response" not in resp_data.get("result", {}):
                    resp_data.setdefault("result", {})["_firewall_response"] = {
                        "findings_count": len(scan_result.findings),
                        "risk_level": scan_result.risk_level,
                        "findings": [f.to_dict() for f in scan_result.findings],
                    }

                # If critical, redact the sensitive content
                if scan_result.should_redact:
                    for finding in scan_result.findings:
                        if finding.severity >= 80 and finding.evidence:
                            text = text.replace(
                                finding.evidence,
                                f"[REDACTED:{finding.finding_type}]"
                            )
                    item["text"] = text

        return resp_data


def main():
    parser = argparse.ArgumentParser(description="MCP Tool Poisoning Firewall")
    parser.add_argument("--port", type=int, default=8888, help="Firewall proxy port")
    parser.add_argument("--upstream-host", default="localhost", help="Upstream MCP server host")
    parser.add_argument("--upstream-port", type=int, default=9999, help="Upstream MCP server port")
    parser.add_argument("--block-threshold", type=int, default=51, help="Risk score threshold for blocking")
    parser.add_argument("--warn-threshold", type=int, default=26, help="Risk score threshold for warnings")
    parser.add_argument("--log-dir", default="logs", help="Directory for audit logs")
    parser.add_argument("--kill-switch", action="store_true", help="Start with kill switch enabled")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    firewall = MCPToolFirewall(
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        block_threshold=args.block_threshold,
        warn_threshold=args.warn_threshold,
        log_dir=args.log_dir,
        kill_switch=args.kill_switch,
    )

    print(f"MCP Tool Firewall starting on port {args.port}")
    print(f"Upstream: {firewall.upstream_url}")
    print(f"Block threshold: {args.block_threshold}, Warn threshold: {args.warn_threshold}")
    print(f"Kill switch: {'ENABLED' if args.kill_switch else 'disabled'}")
    print(f"Endpoints: /mcp (proxy), /health, /metrics, /admin/status, /admin/kill-switch")

    web.run_app(firewall.app, port=args.port)


if __name__ == "__main__":
    main()
