from mitmproxy import http, ctx
from datetime import datetime
import json
from ..detection.engine import DetectionEngine
import time

class RedHunterAddon:
    def __init__(self):
        self.engine = DetectionEngine()
        self.blocked_ips = {}

    def request(self, flow: http.HTTPFlow):
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else None
        
        # Check IP blacklist
        if self._is_ip_blocked(client_ip):
            ctx.log.warn(f"Blocked blacklisted IP: {client_ip}")
            flow.response = self._block_response()
            return

        request_data = {
            "url": flow.request.pretty_url,
            "method": flow.request.method,
            "headers": dict(flow.request.headers),
            "body": flow.request.get_text(strict=False),
            "client_ip": client_ip,
            "timestamp": datetime.utcnow().isoformat()
        }

        result = self.engine.analyze(request_data)
        self._log_request(request_data, result)

        if result["action"] == "block":
            flow.response = self._block_response()
            self._block_ip(client_ip)
        elif result["action"] == "captcha":
            flow.response = self._captcha_response()

    def _is_ip_blocked(self, ip: str) -> bool:
        if not ip or ip not in self.blocked_ips:
            return False
        return time.time() - self.blocked_ips[ip] < 3600  # 1 hour block

    def _block_ip(self, ip: str):
        if ip:
            self.blocked_ips[ip] = time.time()

    def _log_request(self, request: Dict, result: Dict):
        log_entry = {
            **request,
            "waf_result": result,
            "@timestamp": datetime.utcnow().isoformat()
        }
        ctx.log.info(json.dumps(log_entry))

    def _block_response(self):
        return http.Response.make(
            403,
            json.dumps({"error": "Request blocked by RedHunter WAF"}),
            {"Content-Type": "application/json"}
        )

    def _captcha_response(self):
        return http.Response.make(
            429,
            json.dumps({"error": "CAPTCHA verification required"}),
            {"Content-Type": "application/json"}
        )