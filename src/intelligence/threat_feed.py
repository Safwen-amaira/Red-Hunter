import requests
from datetime import datetime, timedelta

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