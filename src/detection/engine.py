import re
import yaml
from pathlib import Path
from typing import Dict, List
from datetime import datetime, timedelta
import requests

class ThreatIntelligence:
    def __init__(self):
        self.cache = {}
        self.last_updated = None
        self.update_interval = timedelta(hours=1)
        
    def update_feeds(self):
        if self.last_updated and datetime.now() - self.last_updated < self.update_interval:
            return
            
        feeds = [
            "https://feeds.dshield.org/block.txt",
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        ]
        
        for feed in feeds:
            try:
                response = requests.get(feed, timeout=10)
                for line in response.text.splitlines():
                    if not line.startswith("#") and line.strip():
                        ip = line.split()[0]
                        self.cache[ip] = {"source": feed, "timestamp": datetime.now()}
            except Exception as e:
                print(f"Failed to update {feed}: {str(e)}")
                
        self.last_updated = datetime.now()
    
    def is_malicious(self, ip: str) -> bool:
        self.update_feeds()
        return ip in self.cache

class DetectionEngine:
    def __init__(self, config_path: str = None, test_mode: bool = False):
        if config_path is None:
            config_path = Path(__file__).parent.parent / "config" / "waf-config.yaml"
        
        self.config = self._load_config(config_path)
        self.rules = self._load_rules()
        self.threat_intel = ThreatIntelligence()
        
    def _load_config(self, path: str) -> Dict:
        """Load YAML config file"""
        with open(path) as f:
            return yaml.safe_load(f)

    def _load_rules(self) -> Dict:
        """Load all rule files"""
        rules_dir = Path(__file__).parent.parent / self.config["rules"]["custom_rules_dir"]
        rules = {}
        
        for rule_file in rules_dir.glob("*.yaml"):
            with open(rule_file) as f:
                rules[rule_file.stem] = yaml.safe_load(f)
        return rules

    def analyze(self, request: Dict) -> Dict:
        """Analyze a request for threats"""
        result = {
            "threats": [],
            "score": 0,
            "action": "allow"
        }

        client_ip = request.get("client_ip")
        if client_ip and self.threat_intel.is_malicious(client_ip):
            result["threats"].append({
                "id": "THREAT-IP-001",
                "type": "malicious_ip",
                "severity": "critical"
            })
            result["score"] = self._severity_score("critical")
            result["action"] = "block"
            return result

        for rule_group in self.rules.values():
            for rule in rule_group:
                if self._matches_rule(request, rule):
                    threat = {
                        "id": rule["id"],
                        "type": rule.get("category", "unknown"),
                        "severity": rule["severity"]
                    }
                    result["threats"].append(threat)
                    result["score"] += self._severity_score(rule["severity"])
                    
                    if rule.get("action") == "block":
                        result["action"] = "block"
                        return result

        if result["score"] >= self.config["protection"]["block_threshold"]:
            result["action"] = "block"
        elif result["score"] >= self.config["protection"]["captcha_threshold"]:
            result["action"] = "captcha"

        return result

    def _matches_rule(self, request: Dict, rule: Dict) -> bool:
        """Check if request matches a rule"""
        try:
            pattern = re.compile(rule["pattern"], re.IGNORECASE)
            
            for location in rule.get("locations", ["url", "body"]):
                if location not in request:
                    continue

                if location == "headers":
                    for header_name, header_value in request["headers"].items():
                        if (pattern.search(str(header_name)) or 
                            pattern.search(str(header_value))):
                            return True
                else:
                    if pattern.search(str(request[location])):
                        return True
                        
            return False
        except Exception as e:
            print(f"Error matching rule {rule.get('id')}: {str(e)}")
            return False

    def _severity_score(self, severity: str) -> int:
        """Convert severity to numerical score"""
        return {
            "critical": 10,
            "high": 7,
            "medium": 5,
            "low": 3
        }.get(severity.lower(), 0)