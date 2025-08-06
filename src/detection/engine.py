import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional
import joblib
from sklearn.ensemble import IsolationForest

class DetectionEngine:
    def __init__(self, config_path: str = "config/waf-config.yaml"):
        self.config = self._load_config(config_path)
        self.rules = self._load_rules()
        self.ml_models = {
            'xss': joblib.load('models/xss_detector.pkl'),
            'sqli': joblib.load('models/sqli_detector.pkl')
        }
        self.ip_reputation = {}

    def _load_config(self, path: str) -> Dict:
        with open(path) as f:
            return yaml.safe_load(f)

    def _load_rules(self) -> Dict:
        rules = {}
        rules_dir = Path(self.config['rules']['custom_rules_dir'])
        for rule_file in rules_dir.glob("*.yaml"):
            with open(rule_file) as f:
                rules[rule_file.stem] = yaml.safe_load(f)
        return rules

    def analyze(self, request: Dict) -> Dict:
        result = {
            "threats": [],
            "score": 0,
            "action": "allow"
        }
        
        # Signature-based detection
        for rule_group in self.rules.values():
            for rule in rule_group:
                if self._match_rule(request, rule):
                    result["threats"].append({
                        "id": rule["id"],
                        "type": rule.get("category", "unknown"),
                        "severity": rule["severity"]
                    })
                    result["score"] += self._severity_score(rule["severity"])

        # ML-based detection
        ml_result = self._ml_analysis(request)
        result["threats"].extend(ml_result["threats"])
        result["score"] += ml_result["score"]

        # Determine action
        if result["score"] >= self.config['protection']['block_threshold']:
            result["action"] = "block"
        elif result["score"] >= self.config['protection']['captcha_threshold']:
            result["action"] = "captcha"
            
        return result

    def _match_rule(self, request: Dict, rule: Dict) -> bool:
        pattern = re.compile(rule["pattern"], re.IGNORECASE)
        for location in rule.get("locations", ["url", "body"]):
            if location in request and pattern.search(str(request[location])):
                return True
        return False

    def _ml_analysis(self, request: Dict) -> Dict:
        # Feature extraction would happen here
        features = self._extract_features(request)
        result = {"threats": [], "score": 0}
        
        for threat_type, model in self.ml_models.items():
            prediction = model.predict([features])[0]
            if prediction == -1:  # Anomaly detected
                result["threats"].append({
                    "id": f"ML-{threat_type.upper()}",
                    "type": threat_type,
                    "severity": "high"
                })
                result["score"] += 3
                
        return result

    def _severity_score(self, severity: str) -> int:
        return {"critical": 5, "high": 3, "medium": 2, "low": 1}.get(severity, 0)