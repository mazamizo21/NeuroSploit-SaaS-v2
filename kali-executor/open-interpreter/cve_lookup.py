#!/usr/bin/env python3
"""
CVE Lookup Service
Provides CVE information from multiple sources without API keys
"""

import requests
import json
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict


@dataclass
class CVEInfo:
    """CVE information"""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published_date: str
    references: List[str]
    cpe: List[str]
    source: str


class CVELookup:
    """CVE lookup from multiple free sources"""
    
    def __init__(self):
        self.sources = {
            "circl": "https://cve.circl.lu/api/cve/",
            "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=",
        }
    
    def lookup(self, cve_id: str) -> Optional[CVEInfo]:
        """
        Lookup CVE information
        Tries multiple sources until one succeeds
        """
        cve_id = cve_id.upper().strip()
        
        # Try CIRCL first (no rate limit, no API key)
        try:
            return self._lookup_circl(cve_id)
        except Exception as e:
            print(f"CIRCL lookup failed: {e}")
        
        # Try NVD (has rate limits but no API key required)
        try:
            return self._lookup_nvd(cve_id)
        except Exception as e:
            print(f"NVD lookup failed: {e}")
        
        return None
    
    def _lookup_circl(self, cve_id: str) -> Optional[CVEInfo]:
        """Lookup from CIRCL CVE database"""
        url = f"{self.sources['circl']}{cve_id}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if not data or "id" not in data:
            return None
        
        # Extract CVSS score
        cvss_score = 0.0
        if "cvss" in data:
            cvss_score = float(data["cvss"])
        elif "impact" in data and "baseMetricV3" in data["impact"]:
            cvss_score = data["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
        
        # Determine severity
        severity = "UNKNOWN"
        if cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
        elif cvss_score > 0:
            severity = "LOW"
        
        # Extract references
        references = []
        if "references" in data:
            references = [ref.get("url", "") for ref in data["references"][:5]]
        
        # Extract CPE
        cpe = []
        if "vulnerable_configuration" in data:
            cpe = data["vulnerable_configuration"][:5]
        
        return CVEInfo(
            cve_id=cve_id,
            description=data.get("summary", "No description available"),
            severity=severity,
            cvss_score=cvss_score,
            published_date=data.get("Published", "Unknown"),
            references=references,
            cpe=cpe,
            source="CIRCL"
        )
    
    def _lookup_nvd(self, cve_id: str) -> Optional[CVEInfo]:
        """Lookup from NVD database"""
        url = f"{self.sources['nvd']}{cve_id}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if "vulnerabilities" not in data or len(data["vulnerabilities"]) == 0:
            return None
        
        vuln = data["vulnerabilities"][0]["cve"]
        
        # Extract CVSS score
        cvss_score = 0.0
        severity = "UNKNOWN"
        
        if "metrics" in vuln:
            if "cvssMetricV31" in vuln["metrics"]:
                metric = vuln["metrics"]["cvssMetricV31"][0]
                cvss_score = metric["cvssData"]["baseScore"]
                severity = metric["cvssData"]["baseSeverity"]
            elif "cvssMetricV3" in vuln["metrics"]:
                metric = vuln["metrics"]["cvssMetricV3"][0]
                cvss_score = metric["cvssData"]["baseScore"]
                severity = metric["cvssData"]["baseSeverity"]
        
        # Extract description
        description = "No description available"
        if "descriptions" in vuln:
            for desc in vuln["descriptions"]:
                if desc["lang"] == "en":
                    description = desc["value"]
                    break
        
        # Extract references
        references = []
        if "references" in vuln:
            references = [ref["url"] for ref in vuln["references"][:5]]
        
        # Extract CPE
        cpe = []
        if "configurations" in vuln:
            for config in vuln["configurations"][:5]:
                if "nodes" in config:
                    for node in config["nodes"]:
                        if "cpeMatch" in node:
                            for match in node["cpeMatch"][:3]:
                                cpe.append(match.get("criteria", ""))
        
        return CVEInfo(
            cve_id=cve_id,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            published_date=vuln.get("published", "Unknown"),
            references=references,
            cpe=cpe,
            source="NVD"
        )
    
    def search_exploits(self, cve_id: str) -> List[str]:
        """
        Search for exploits related to CVE using searchsploit
        Returns list of exploit paths
        """
        import subprocess
        
        try:
            result = subprocess.run(
                ["searchsploit", "--json", cve_id],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                exploits = []
                
                if "RESULTS_EXPLOIT" in data:
                    for exploit in data["RESULTS_EXPLOIT"][:10]:
                        exploits.append({
                            "title": exploit.get("Title", ""),
                            "path": exploit.get("Path", ""),
                            "platform": exploit.get("Platform", "")
                        })
                
                return exploits
        except Exception as e:
            print(f"Searchsploit error: {e}")
        
        return []
    
    def format_cve_info(self, cve_info: CVEInfo, include_exploits: bool = True) -> str:
        """Format CVE information for display"""
        output = f"""
## {cve_info.cve_id}

**Severity:** {cve_info.severity} (CVSS: {cve_info.cvss_score})
**Published:** {cve_info.published_date}
**Source:** {cve_info.source}

**Description:**
{cve_info.description}

**References:**
"""
        for ref in cve_info.references:
            output += f"- {ref}\n"
        
        if cve_info.cpe:
            output += "\n**Affected Products:**\n"
            for product in cve_info.cpe:
                output += f"- {product}\n"
        
        if include_exploits:
            exploits = self.search_exploits(cve_info.cve_id)
            if exploits:
                output += "\n**Available Exploits:**\n"
                for exploit in exploits:
                    output += f"- {exploit['title']} ({exploit['platform']})\n"
                    output += f"  Path: {exploit['path']}\n"
        
        return output


def main():
    """Test CVE lookup"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python cve_lookup.py CVE-YYYY-NNNN")
        sys.exit(1)
    
    cve_id = sys.argv[1]
    lookup = CVELookup()
    
    print(f"Looking up {cve_id}...")
    cve_info = lookup.lookup(cve_id)
    
    if cve_info:
        print(lookup.format_cve_info(cve_info))
    else:
        print(f"CVE {cve_id} not found")


if __name__ == "__main__":
    main()
