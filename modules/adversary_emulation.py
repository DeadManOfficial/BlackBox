"""
Adversary Emulation Framework
=============================

MITRE ATT&CK aligned adversary emulation - Atomic Red Team, detection validation, threat mapping.

1500+ adversary emulation tests via Atomic Red Team integration.

Author: DeadMan Toolkit v5.3
"""

import re, json, urllib.request, urllib.error
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Dict, Set, Optional, Any

# =============================================================================
# ATOMIC RED TEAM
# =============================================================================

class Platform(Enum):
    WINDOWS = "windows"; LINUX = "linux"; MACOS = "macos"; CONTAINERS = "containers"
    IAAS_AWS = "iaas:aws"; IAAS_GCP = "iaas:gcp"; IAAS_AZURE = "iaas:azure"
    OFFICE365 = "office-365"; GOOGLE_WORKSPACE = "google-workspace"

class TechniqueCategory(Enum):
    RECONNAISSANCE = "reconnaissance"; RESOURCE_DEVELOPMENT = "resource-development"; INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"; PERSISTENCE = "persistence"; PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"; CREDENTIAL_ACCESS = "credential-access"; DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"; COLLECTION = "collection"; COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"; IMPACT = "impact"

@dataclass
class AtomicTest:
    technique_id: str; name: str; description: str; platforms: List[Platform]; executor: str; commands: str
    cleanup_commands: Optional[str] = None; dependencies: List[Dict] = field(default_factory=list)
    input_arguments: Dict[str, Any] = field(default_factory=dict); elevation_required: bool = False

@dataclass
class Technique:
    technique_id: str; name: str; description: str; tactic: TechniqueCategory
    atomic_tests: List[AtomicTest] = field(default_factory=list); detection: str = ""; references: List[str] = field(default_factory=list)

class AtomicRedTeam:
    GITHUB_RAW_BASE = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master"
    ATOMICS_INDEX_URL = f"{GITHUB_RAW_BASE}/atomics/Indexes/Indexes-CSV/index.csv"
    TECHNIQUE_ALIASES = {
        'credential_dumping': 'T1003', 'password_spraying': 'T1110.003', 'kerberoasting': 'T1558.003', 'browser_credentials': 'T1555.003',
        'powershell': 'T1059.001', 'command_shell': 'T1059.003', 'python': 'T1059.006', 'javascript': 'T1059.007',
        'registry_run_keys': 'T1547.001', 'scheduled_task': 'T1053.005', 'process_injection': 'T1055', 'masquerading': 'T1036',
        'obfuscation': 'T1027', 'disable_defender': 'T1562.001', 'system_info': 'T1082', 'network_discovery': 'T1046',
        'rdp': 'T1021.001', 'smb': 'T1021.002', 'ssh': 'T1021.004', 'psexec': 'T1570', 'clipboard': 'T1115',
        'screen_capture': 'T1113', 'keylogging': 'T1056.001', 'exfil_http': 'T1041', 'exfil_dns': 'T1048.003',
        'ransomware': 'T1486', 'data_destruction': 'T1485', 'defacement': 'T1491',
    }

    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir or Path.home() / ".blackbox" / "atomic-red-team"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._index_cache: Optional[List[Dict]] = None

    def _fetch_url(self, url: str) -> Optional[str]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "BlackBox/5.3"})
            with urllib.request.urlopen(req, timeout=30) as response: return response.read().decode('utf-8')
        except (urllib.error.URLError, urllib.error.HTTPError): return None

    def _get_index(self) -> List[Dict]:
        if self._index_cache: return self._index_cache
        index_file = self.cache_dir / "index.csv"
        content = index_file.read_text(encoding='utf-8') if index_file.exists() else self._fetch_url(self.ATOMICS_INDEX_URL)
        if content and not index_file.exists(): index_file.write_text(content, encoding='utf-8')
        if not content: return []
        lines = content.strip().split('\n')
        if not lines: return []
        headers = lines[0].split(',')
        self._index_cache = [dict(zip(headers, line.split(','))) for line in lines[1:] if len(line.split(',')) >= len(headers)]
        return self._index_cache

    def search(self, query: str, platform: Optional[Platform] = None, limit: int = 20) -> List[Dict]:
        index, results, q = self._get_index(), [], query.lower()
        if q in self.TECHNIQUE_ALIASES: q = self.TECHNIQUE_ALIASES[q].lower()
        for entry in index:
            if q in entry.get("Technique #", "").lower() or q in entry.get("Technique Name", "").lower() or q in entry.get("Test Name", "").lower():
                results.append(entry)
        if platform: results = [r for r in results if platform.value in r.get("Supported Platforms", "").lower()]
        return results[:limit]

    def get_technique(self, technique_id: str) -> Optional[Dict]:
        tid = technique_id.upper() if technique_id.upper().startswith("T") else f"T{technique_id.upper()}"
        content = self._fetch_url(f"{self.GITHUB_RAW_BASE}/atomics/{tid}/{tid}.yaml")
        return self._parse_atomic_yaml(content) if content else None

    def _parse_atomic_yaml(self, content: str) -> Dict:
        result = {"attack_technique": "", "display_name": "", "atomic_tests": []}
        current_test, current_key = None, None
        for line in content.split('\n'):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'): continue
            if line.startswith("attack_technique:"): result["attack_technique"] = stripped.split(":", 1)[1].strip()
            elif line.startswith("display_name:"): result["display_name"] = stripped.split(":", 1)[1].strip().strip('"\'')
            elif stripped.startswith("- name:"):
                if current_test: result["atomic_tests"].append(current_test)
                current_test = {"name": stripped.split(":", 1)[1].strip().strip('"\''), "description": "", "platforms": [], "executor": {}}
            elif current_test:
                if stripped.startswith("description:"): current_test["description"] = stripped.split(":", 1)[1].strip().strip('"\'')
                elif stripped.startswith("supported_platforms:"): current_key = "platforms"
                elif stripped.startswith("executor:"): current_key = "executor"
                elif stripped.startswith("- ") and current_key == "platforms": current_test["platforms"].append(stripped[2:].strip())
                elif stripped.startswith("name:") and current_key == "executor": current_test["executor"]["name"] = stripped.split(":", 1)[1].strip()
                elif stripped.startswith("command:"): current_test["executor"]["command"] = stripped.split(":", 1)[1].strip()
        if current_test: result["atomic_tests"].append(current_test)
        return result

    def generate_test(self, description: str, platform: Platform = Platform.LINUX, technique_id: Optional[str] = None) -> str:
        return f'''- name: {description}
  auto_generated_guid: blackbox-{hash(description) & 0xFFFFFFFF:08x}
  description: |
    {description}
    Generated by BlackBox Adversary Emulation.
  supported_platforms:
  - {platform.value}
  executor:
    command: |
      # TODO: Add commands
      echo "Test: {description[:50]}"
    cleanup_command: |
      echo "Cleanup complete"
    name: {"powershell" if platform == Platform.WINDOWS else "bash"}
    elevation_required: false
'''

    def validate_test(self, yaml_content: str) -> Dict[str, Any]:
        errors, warnings = [], []
        for field in ["name", "description", "supported_platforms", "executor"]:
            if f"{field}:" not in yaml_content: errors.append(f"Missing: {field}")
        if "executor:" in yaml_content and "command:" not in yaml_content: errors.append("Executor missing command")
        if "cleanup_command:" not in yaml_content: warnings.append("Missing cleanup_command")
        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}

    def refresh_cache(self) -> bool:
        content = self._fetch_url(self.ATOMICS_INDEX_URL)
        if content:
            (self.cache_dir / "index.csv").write_text(content, encoding='utf-8')
            self._index_cache = None
            return True
        return False

    def list_platforms(self) -> List[str]: return [p.value for p in Platform]

    def export_tests(self, technique_ids: List[str], output_dir: Path, platform: Optional[Platform] = None) -> Dict[str, bool]:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        results = {}
        for tid in technique_ids:
            technique = self.get_technique(tid)
            if technique:
                if platform: technique["atomic_tests"] = [t for t in technique["atomic_tests"] if platform.value in t.get("platforms", [])]
                (Path(output_dir) / f"{tid}.json").write_text(json.dumps(technique, indent=2), encoding='utf-8')
                results[tid] = True
            else: results[tid] = False
        return results

# =============================================================================
# DETECTION VALIDATOR
# =============================================================================

class DetectionFramework(Enum):
    SIGMA = "sigma"; SPLUNK = "splunk"; ELASTIC = "elastic"; CHRONICLE = "chronicle"
    MICROSOFT_SENTINEL = "sentinel"; YARA = "yara"; SNORT = "snort"; SURICATA = "suricata"

@dataclass
class DetectionRule:
    id: str; name: str; framework: DetectionFramework; technique_ids: List[str]; rule_content: str
    severity: str = "medium"; false_positive_rate: str = "unknown"; data_sources: List[str] = field(default_factory=list)

@dataclass
class CoverageReport:
    total_techniques: int; covered_techniques: int; coverage_percentage: float
    gaps: List[str]; partial_coverage: List[str]; recommendations: List[str]

class DetectionValidator:
    TECHNIQUE_PATTERNS = {
        DetectionFramework.SIGMA: [r"attack\.technique[:\s]*T\d{4}(?:\.\d{3})?", r"tags:.*T\d{4}(?:\.\d{3})?"],
        DetectionFramework.SPLUNK: [r"mitre_attack_id\s*=\s*\"?T\d{4}(?:\.\d{3})?\"?"],
        DetectionFramework.ELASTIC: [r"threat\.technique\.id[:\s]*T\d{4}(?:\.\d{3})?"],
        DetectionFramework.YARA: [r"MITRE_ATT&CK\s*=\s*\"?T\d{4}(?:\.\d{3})?\"?"],
    }
    HIGH_VALUE_TECHNIQUES = {
        "T1190": "Exploit Public-Facing Application", "T1133": "External Remote Services", "T1566": "Phishing",
        "T1059": "Command and Scripting Interpreter", "T1003": "OS Credential Dumping", "T1555": "Credentials from Password Stores",
        "T1055": "Process Injection", "T1027": "Obfuscated Files", "T1562": "Impair Defenses",
        "T1041": "Exfiltration Over C2", "T1567": "Exfiltration Over Web Service",
    }

    def __init__(self): self.art = AtomicRedTeam()

    def parse_detection_rule(self, content: str, framework: DetectionFramework) -> DetectionRule:
        technique_ids = []
        for pattern in self.TECHNIQUE_PATTERNS.get(framework, []):
            for match in re.findall(pattern, content, re.IGNORECASE):
                tid_match = re.search(r"T\d{4}(?:\.\d{3})?", match)
                if tid_match: technique_ids.append(tid_match.group().upper())
        name_patterns = {DetectionFramework.SIGMA: r"title:\s*(.+)", DetectionFramework.SPLUNK: r"search_name\s*=\s*\"([^\"]+)\"",
            DetectionFramework.ELASTIC: r"\"name\":\s*\"([^\"]+)\"", DetectionFramework.YARA: r"rule\s+(\w+)"}
        name = "Unknown Rule"
        if framework in name_patterns:
            m = re.search(name_patterns[framework], content)
            if m: name = m.group(1)
        rule_id = f"{framework.value}_{hash(content) & 0xFFFF:04x}"
        id_match = re.search(r"id:\s*([a-f0-9-]+)", content, re.IGNORECASE)
        if id_match: rule_id = id_match.group(1)
        return DetectionRule(id=rule_id, name=name, framework=framework, technique_ids=list(set(technique_ids)), rule_content=content)

    def load_rules_from_directory(self, directory: Path, framework: DetectionFramework) -> List[DetectionRule]:
        rules, exts = [], {DetectionFramework.SIGMA: [".yml", ".yaml"], DetectionFramework.SPLUNK: [".conf", ".spl"],
            DetectionFramework.ELASTIC: [".json", ".ndjson"], DetectionFramework.YARA: [".yar", ".yara"]}.get(framework, [".yml", ".yaml", ".json"])
        for ext in exts:
            for f in Path(directory).rglob(f"*{ext}"):
                try: rules.append(self.parse_detection_rule(f.read_text(encoding='utf-8'), framework))
                except: continue
        return rules

    def analyze_coverage(self, technique_ids: List[str], rules: Optional[List[DetectionRule]] = None) -> CoverageReport:
        covered = set()
        if rules:
            for r in rules: covered.update(r.technique_ids)
        technique_set = set(t.upper() for t in technique_ids)
        covered_set, gaps = covered & technique_set, technique_set - (covered & technique_set)
        recommendations = [f"HIGH PRIORITY: {g} - {self.HIGH_VALUE_TECHNIQUES[g]}" if g in self.HIGH_VALUE_TECHNIQUES else f"Create detection for {g}" for g in gaps]
        return CoverageReport(total_techniques=len(technique_set), covered_techniques=len(covered_set),
            coverage_percentage=round((len(covered_set) / len(technique_set) * 100) if technique_set else 0, 1),
            gaps=sorted(gaps), partial_coverage=[], recommendations=recommendations)

    def find_detection_gaps(self, rules_path: Path, framework: DetectionFramework = DetectionFramework.SIGMA) -> CoverageReport:
        rules = self.load_rules_from_directory(rules_path, framework)
        all_techniques = {e.get("Technique #", "").upper() for e in self.art._get_index() if e.get("Technique #")}
        return self.analyze_coverage(list(all_techniques), rules)

    def map_test_to_detection(self, technique_id: str) -> Dict[str, Any]:
        technique = self.art.get_technique(technique_id)
        if not technique: return {"error": f"Technique {technique_id} not found"}
        result = {"technique_id": technique_id, "display_name": technique.get("display_name", ""), "tests": []}
        for test in technique.get("atomic_tests", []):
            executor = test.get("executor", {})
            result["tests"].append({"name": test.get("name", ""), "platforms": test.get("platforms", []),
                "detection_hints": self._generate_detection_suggestions(technique_id, executor.get("name", ""), executor.get("command", ""))})
        return result

    def _generate_detection_suggestions(self, technique_id: str, executor: str, command: str) -> List[str]:
        suggestions = []
        if executor in ["powershell", "command_prompt", "bash"]: suggestions.append("Monitor process creation")
        if executor == "powershell": suggestions.extend(["Enable PowerShell ScriptBlock logging (4104)", "Monitor encoded commands"])
        if any(p in command.lower() for p in ["curl", "wget", "invoke-webrequest", "nc "]): suggestions.append("Monitor outbound connections")
        if any(p in command.lower() for p in ["mimikatz", "lsass", "sam", "credential"]): suggestions.extend(["Monitor LSASS access (Event 10)", "Alert on SAM access"])
        return suggestions

    def generate_sigma_rule(self, technique_id: str, test_name: str) -> str:
        technique = self.art.get_technique(technique_id)
        display_name = technique.get("display_name", technique_id) if technique else technique_id
        return f'''title: {display_name} - {test_name}
id: blackbox-{hash(technique_id + test_name) & 0xFFFFFFFF:08x}
status: experimental
description: Detects {display_name}. Generated by BlackBox.
references:
    - https://attack.mitre.org/techniques/{technique_id}/
tags:
    - attack.{technique_id.lower()}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'PLACEHOLDER'
    condition: selection
level: medium
'''

    def export_coverage_report(self, report: CoverageReport, output_path: Path, format: str = "json"):
        if format == "json":
            Path(output_path).write_text(json.dumps({"total": report.total_techniques, "covered": report.covered_techniques,
                "coverage": report.coverage_percentage, "gaps": report.gaps, "recommendations": report.recommendations}, indent=2), encoding='utf-8')
        elif format == "markdown":
            Path(output_path).write_text("\n".join([f"# Detection Coverage Report", "", f"**Coverage:** {report.coverage_percentage}%",
                f"**Covered:** {report.covered_techniques}/{report.total_techniques}", "", "## Gaps", "", *[f"- {g}" for g in report.gaps],
                "", "## Recommendations", "", *[f"- {r}" for r in report.recommendations]]), encoding='utf-8')

# =============================================================================
# THREAT MAPPER
# =============================================================================

@dataclass
class ThreatMapping:
    source: str; identified_techniques: List[str]; identified_groups: List[str]; identified_software: List[str]
    confidence: float; keywords_matched: Dict[str, List[str]]

@dataclass
class TestPlaybook:
    name: str; description: str; techniques: List[str]; tests: List[Dict[str, Any]]; platform: Platform; execution_order: List[str]

class ThreatMapper:
    TECHNIQUE_KEYWORDS = {
        "T1566.001": ["phishing", "spearphishing", "malicious attachment"], "T1566.002": ["phishing link", "credential harvesting"],
        "T1190": ["exploit", "vulnerability", "cve-", "rce"], "T1133": ["vpn", "rdp exposed", "citrix"],
        "T1059.001": ["powershell", "invoke-expression", "iex", "bypass"], "T1059.003": ["cmd", "command prompt", ".bat"],
        "T1204.002": ["malicious document", "macro", "vba"], "T1053.005": ["scheduled task", "schtasks"],
        "T1547.001": ["run key", "registry run", "autorun"], "T1548.002": ["uac bypass", "eventvwr", "fodhelper"],
        "T1055": ["process injection", "dll injection"], "T1027": ["obfuscated", "encoded", "base64"],
        "T1562.001": ["disable defender", "disable av"], "T1003.001": ["lsass", "mimikatz", "credential dump"],
        "T1555.003": ["browser credential", "chrome password"], "T1110": ["brute force", "password spray"],
        "T1082": ["system info", "systeminfo", "hostname"], "T1021.001": ["rdp", "remote desktop"],
        "T1021.002": ["smb", "psexec", "admin$"], "T1071.001": ["http c2", "https beacon"],
        "T1486": ["ransomware", "encrypt files"], "T1485": ["data destruction", "wipe"],
    }
    THREAT_GROUPS = {
        "apt29": ["apt29", "cozy bear", "yttrium"], "apt28": ["apt28", "fancy bear", "sofacy"],
        "lazarus": ["lazarus", "hidden cobra", "zinc"], "fin7": ["fin7", "carbanak"],
        "conti": ["conti", "wizard spider", "ryuk"], "lockbit": ["lockbit", "lockbit 2.0", "lockbit 3.0"],
    }
    MALWARE_TOOLS = {
        "cobalt_strike": ["cobalt strike", "beacon"], "mimikatz": ["mimikatz", "sekurlsa"],
        "metasploit": ["metasploit", "meterpreter"], "bloodhound": ["bloodhound", "sharphound"],
    }

    def __init__(self): self.art = AtomicRedTeam()

    def analyze_report(self, text: str, min_confidence: float = 0.5) -> ThreatMapping:
        text_lower, techniques, groups, software = text.lower(), {}, [], []
        for tid, keywords in self.TECHNIQUE_KEYWORDS.items():
            matched = [k for k in keywords if k.lower() in text_lower]
            if matched: techniques[tid] = matched
        for gid, aliases in self.THREAT_GROUPS.items():
            if any(a.lower() in text_lower for a in aliases): groups.append(gid)
        for tool_id, names in self.MALWARE_TOOLS.items():
            if any(n.lower() in text_lower for n in names): software.append(tool_id)
        return ThreatMapping(source=text[:500], identified_techniques=list(techniques.keys()), identified_groups=list(set(groups)),
            identified_software=list(set(software)), confidence=min(1.0, len(techniques) / 10), keywords_matched=techniques)

    def generate_test_playbook(self, mapping: ThreatMapping, platform: Platform = Platform.WINDOWS) -> TestPlaybook:
        tests, execution_order = [], []
        for tid in mapping.identified_techniques:
            for result in self.art.search(tid, platform=platform)[:2]:
                test_id = f"{tid}_{len(tests)}"
                tests.append({"id": test_id, "technique_id": tid, "name": result.get("Test Name", "Unknown"), "platforms": result.get("Supported Platforms", "")})
                execution_order.append(test_id)
        name = f"{mapping.identified_groups[0].upper()} Emulation Playbook" if mapping.identified_groups else "Custom Threat Playbook"
        return TestPlaybook(name=name, description=f"Emulates identified threat techniques", techniques=mapping.identified_techniques,
            tests=tests, platform=platform, execution_order=execution_order)

    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        iocs = {"ipv4": list(set(re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text))),
            "urls": list(set(re.findall(r'https?://[^\s<>"\'}\]]+', text))),
            "hashes_md5": list(set(re.findall(r'\b[a-fA-F0-9]{32}\b', text))),
            "hashes_sha256": list(set(re.findall(r'\b[a-fA-F0-9]{64}\b', text))),
            "emails": list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text))),
            "file_paths": list(set(re.findall(r'[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*', text))),
            "registry_keys": list(set(re.findall(r'(?:HKEY_[A-Z_]+|HK[A-Z]{2})\\[^\s]+', text)))}
        return {k: v for k, v in iocs.items() if v}

    def create_detection_requirements(self, mapping: ThreatMapping) -> List[Dict[str, Any]]:
        high_priority = {"T1003", "T1055", "T1059", "T1486", "T1041"}
        requirements = []
        for tid in mapping.identified_techniques:
            requirements.append({"technique_id": tid, "priority": "high" if any(tid.startswith(t) for t in high_priority) else "medium",
                "keywords_identified": mapping.keywords_matched.get(tid, [])})
        return sorted(requirements, key=lambda x: (x["priority"] != "high", x["technique_id"]))

    def export_playbook(self, playbook: TestPlaybook, output_path: Path, format: str = "yaml"):
        if format == "yaml":
            Path(output_path).write_text("\n".join([f"name: {playbook.name}", f"description: {playbook.description}",
                f"platform: {playbook.platform.value}", "techniques:", *[f"  - {t}" for t in playbook.techniques], "tests:",
                *[f"  - id: {t['id']}\n    technique: {t['technique_id']}\n    name: {t['name']}" for t in playbook.tests]]), encoding='utf-8')
        elif format == "json":
            Path(output_path).write_text(json.dumps({"name": playbook.name, "description": playbook.description,
                "platform": playbook.platform.value, "techniques": playbook.techniques, "tests": playbook.tests}, indent=2), encoding='utf-8')

__all__ = ['AtomicRedTeam', 'AtomicTest', 'Technique', 'TechniqueCategory', 'Platform', 'DetectionValidator', 'DetectionRule',
    'DetectionFramework', 'CoverageReport', 'ThreatMapper', 'ThreatMapping', 'TestPlaybook']
