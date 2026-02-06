#!/usr/bin/env python3
"""
Security Research Signal Monitor

Monitors RSS feeds from security research sources, government advisories,
and vulnerability databases to aggregate security intelligence signals.

Features:
- Parallel RSS feed fetching with asyncio
- Categorization by threat type (CVE, malware, APT, advisory)
- Severity detection based on keywords
- Deduplication of existing signals
- GitHub Pages compatible output

Usage:
    python scripts/security_monitor.py [--dry-run] [--verbose]
"""

import asyncio
import json
import hashlib
import re
import sys
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import logging

try:
    import feedparser
    import aiohttp
except ImportError:
    print("Required packages not installed. Run: pip install feedparser aiohttp")
    sys.exit(1)

# Import environment tagger
try:
    from env_tagger import tag_with_keywords, tag_with_llm
    ENV_TAGGER_AVAILABLE = True
except ImportError:
    ENV_TAGGER_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Lookback window - signals older than this are ignored
LOOKBACK_DAYS = 30

# Paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
DATA_DIR = PROJECT_ROOT / "data"

SECURITY_SOURCES_PATH = DATA_DIR / "security_sources.json"
SIGNALS_OUTPUT_PATH = PROJECT_ROOT / "security-signals-data.json"
MONITOR_STATE_PATH = DATA_DIR / "security_monitor_state.json"


@dataclass
class SecuritySignal:
    """Represents a detected security signal from RSS feeds."""
    id: str
    source_name: str
    source_type: str
    signal_category: str  # cve, malware, apt, advisory, research, news
    severity: str  # critical, high, medium, low, informational
    title: str
    summary: str
    source_url: str
    source_date: str
    tags: List[str]
    cve_ids: List[str]  # Any CVE IDs mentioned
    threat_actors: List[str]  # Any threat actor names mentioned
    malware_families: List[str]  # Any malware families mentioned
    env_tags: List[str] = None  # Environment/infrastructure tags for filtering
    # Extended contextual attributes
    mitre_tactics: List[str] = None  # MITRE ATT&CK tactics
    mitre_techniques: List[str] = None  # MITRE ATT&CK technique IDs
    campaign_names: List[str] = None  # Named campaigns/operations
    motivation: str = None  # espionage, financial, hacktivism, destruction
    target_industries: List[str] = None  # Targeted sectors
    target_regions: List[str] = None  # Geographic targeting
    attack_phase: str = None  # recon, weaponization, delivery, exploitation, installation, c2, exfiltration
    confidence_level: str = None  # high, medium, low
    first_seen: str = None  # When indicator was first observed
    ioc_types: List[str] = None  # Types of IOCs (ip, domain, hash, url, email)
    affected_products: List[str] = None  # Specific products/vendors affected
    exploit_type: str = None  # Type of exploit (buffer overflow, injection, etc.)
    is_fraud_trust_safety: bool = False  # Fraud, Trust & Safety related signal


# CVE pattern
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

# Known threat actors (partial list for detection)
KNOWN_THREAT_ACTORS = [
    'apt28', 'apt29', 'apt41', 'lazarus', 'cozy bear', 'fancy bear',
    'wizard spider', 'evil corp', 'fin7', 'fin11', 'sandworm',
    'turla', 'carbanak', 'cobalt group', 'ta505', 'emotet',
    'conti', 'lockbit', 'blackcat', 'alphv', 'cl0p', 'revil',
    'darkside', 'blackmatter', 'hive', 'royal', 'play',
    'kimsuky', 'mustang panda', 'hafnium', 'nobelium', 'lapsus',
    'scattered spider', 'volt typhoon', 'charcoal typhoon'
]

# Known malware families (partial list)
KNOWN_MALWARE = [
    'emotet', 'trickbot', 'qakbot', 'qbot', 'cobalt strike', 'beacon',
    'mimikatz', 'metasploit', 'sliver', 'brute ratel', 'havoc',
    'asyncrat', 'remcos', 'njrat', 'agent tesla', 'formbook',
    'redline', 'raccoon', 'vidar', 'lumma', 'stealc',
    'icedid', 'bumblebee', 'pikabot', 'darkgate', 'smokeloader',
    'systembc', 'solarmarker', 'gootloader', 'socgholish',
    'blackcat', 'lockbit', 'akira', 'play', 'royal', 'rhysida'
]

# Severity keywords
CRITICAL_KEYWORDS = [
    'critical', 'zero-day', '0-day', 'zero day', 'actively exploited',
    'in the wild', 'rce', 'remote code execution', 'pre-auth',
    'unauthenticated', 'wormable', 'cvss 9', 'cvss 10',
    'emergency', 'patch now', 'exploitation'
]

HIGH_KEYWORDS = [
    'high severity', 'privilege escalation', 'authentication bypass',
    'sql injection', 'command injection', 'arbitrary code',
    'ransomware', 'apt', 'nation-state', 'cvss 7', 'cvss 8'
]

MEDIUM_KEYWORDS = [
    'medium severity', 'information disclosure', 'denial of service',
    'dos', 'xss', 'cross-site', 'cvss 4', 'cvss 5', 'cvss 6'
]

# MITRE ATT&CK Tactics
MITRE_TACTICS = {
    'reconnaissance': ['reconnaissance', 'recon', 'scanning', 'enumeration', 'osint', 'footprinting'],
    'resource_development': ['resource development', 'infrastructure', 'acquire infrastructure', 'develop capabilities'],
    'initial_access': ['initial access', 'phishing', 'spearphishing', 'drive-by', 'exploit public', 'valid accounts', 'supply chain'],
    'execution': ['execution', 'command and scripting', 'powershell', 'cmd', 'wmi', 'scheduled task', 'user execution'],
    'persistence': ['persistence', 'boot or logon', 'registry run', 'scheduled task', 'create account', 'implant'],
    'privilege_escalation': ['privilege escalation', 'privesc', 'uac bypass', 'token manipulation', 'sudo', 'setuid'],
    'defense_evasion': ['defense evasion', 'obfuscation', 'masquerading', 'disable security', 'rootkit', 'timestomp'],
    'credential_access': ['credential access', 'credential dumping', 'keylogging', 'brute force', 'password spray', 'mimikatz'],
    'discovery': ['discovery', 'network scanning', 'system information', 'account discovery', 'permission groups'],
    'lateral_movement': ['lateral movement', 'pass the hash', 'pass the ticket', 'remote services', 'rdp', 'smb', 'psexec'],
    'collection': ['collection', 'data from local', 'screen capture', 'keylogging', 'clipboard', 'email collection'],
    'command_and_control': ['command and control', 'c2', 'c&c', 'beacon', 'encrypted channel', 'proxy', 'tunneling'],
    'exfiltration': ['exfiltration', 'data exfil', 'exfiltrate', 'transfer data', 'staging'],
    'impact': ['impact', 'ransomware', 'data destruction', 'defacement', 'disk wipe', 'resource hijacking', 'cryptomining']
}

# Common MITRE Technique patterns
MITRE_TECHNIQUE_PATTERN = re.compile(r'T\d{4}(?:\.\d{3})?', re.IGNORECASE)

# Threat Actor Motivations
MOTIVATION_KEYWORDS = {
    'espionage': ['espionage', 'cyber espionage', 'nation-state', 'state-sponsored', 'intelligence gathering', 'surveillance'],
    'financial': ['financial', 'ransomware', 'extortion', 'banking trojan', 'cryptojacking', 'fraud', 'payment card'],
    'hacktivism': ['hacktivist', 'hacktivism', 'activist', 'political', 'ddos protest', 'anonymous'],
    'destruction': ['wiper', 'destructive', 'sabotage', 'disk wipe', 'data destruction']
}

# Target Industries
INDUSTRY_KEYWORDS = {
    'finance': ['bank', 'banking', 'financial', 'fintech', 'payment', 'credit card', 'insurance', 'trading'],
    'healthcare': ['healthcare', 'hospital', 'medical', 'pharma', 'health system', 'patient data', 'hipaa'],
    'government': ['government', 'federal', 'state agency', 'municipal', 'public sector', 'defense', 'military'],
    'energy': ['energy', 'power grid', 'utility', 'oil', 'gas', 'nuclear', 'renewable', 'pipeline'],
    'technology': ['tech', 'software', 'saas', 'cloud provider', 'it services', 'semiconductor'],
    'manufacturing': ['manufacturing', 'industrial', 'ics', 'scada', 'ot', 'plc', 'factory'],
    'retail': ['retail', 'e-commerce', 'pos', 'point of sale', 'merchant'],
    'telecom': ['telecom', 'telecommunications', 'carrier', 'isp', '5g', 'mobile network'],
    'education': ['education', 'university', 'school', 'academic', 'research institution'],
    'transportation': ['transportation', 'aviation', 'airline', 'shipping', 'logistics', 'rail']
}

# Geographic Regions
REGION_KEYWORDS = {
    'north_america': ['united states', 'us', 'usa', 'canada', 'north america', 'american'],
    'europe': ['europe', 'european', 'eu', 'uk', 'germany', 'france', 'nato'],
    'asia_pacific': ['asia', 'apac', 'china', 'japan', 'korea', 'taiwan', 'australia', 'india'],
    'middle_east': ['middle east', 'israel', 'iran', 'saudi', 'uae', 'gulf'],
    'russia_cis': ['russia', 'russian', 'ukraine', 'cis', 'eastern europe'],
    'latin_america': ['latin america', 'brazil', 'mexico', 'south america']
}

# Attack Phases (Kill Chain)
ATTACK_PHASE_KEYWORDS = {
    'recon': ['reconnaissance', 'scanning', 'enumeration', 'osint', 'target selection'],
    'weaponization': ['weaponization', 'payload', 'exploit kit', 'malware creation'],
    'delivery': ['delivery', 'phishing email', 'malicious attachment', 'drive-by download', 'watering hole'],
    'exploitation': ['exploitation', 'exploit', 'vulnerability exploitation', 'code execution'],
    'installation': ['installation', 'implant', 'backdoor', 'persistence mechanism', 'dropper'],
    'command_control': ['command and control', 'c2', 'c&c', 'beacon', 'callback'],
    'actions_on_objectives': ['exfiltration', 'data theft', 'ransomware deployment', 'impact', 'objective']
}

# IOC Types
IOC_TYPE_KEYWORDS = {
    'ip': ['ip address', 'ipv4', 'ipv6', 'c2 ip', 'malicious ip'],
    'domain': ['domain', 'malicious domain', 'c2 domain', 'dga'],
    'hash': ['hash', 'md5', 'sha256', 'sha1', 'file hash', 'ioc hash'],
    'url': ['url', 'malicious url', 'phishing url', 'payload url'],
    'email': ['email address', 'sender', 'phishing email', 'malicious email'],
    'file': ['filename', 'file name', 'malicious file', 'dropper']
}

# Affected Products/Vendors
PRODUCT_KEYWORDS = [
    'microsoft', 'windows', 'office', 'exchange', 'sharepoint', 'azure',
    'cisco', 'fortinet', 'palo alto', 'juniper', 'checkpoint',
    'vmware', 'citrix', 'ivanti', 'pulse secure', 'sonicwall',
    'apache', 'nginx', 'wordpress', 'drupal', 'joomla',
    'oracle', 'sap', 'salesforce', 'atlassian', 'confluence', 'jira',
    'linux', 'ubuntu', 'redhat', 'centos', 'debian',
    'android', 'ios', 'chrome', 'firefox', 'safari', 'edge',
    'aws', 'gcp', 'google cloud', 'kubernetes', 'docker',
    'zoom', 'slack', 'teams', 'webex'
]

# Fraud, Trust & Safety Keywords (precise terms only - avoid generic security terms)
FRAUD_TRUST_SAFETY_KEYWORDS = [
    # Fraud schemes (specific)
    'scam', 'scammer', 'scams', 'fraudster',
    'business email compromise', 'bec scam', 'ceo fraud', 'invoice fraud', 'wire fraud',
    'payment fraud', 'credit card fraud', 'card fraud', 'chargeback fraud',
    'synthetic identity', 'identity theft', 'identity fraud', 'stolen identity',
    'account takeover attack', 'credential stuffing attack',
    'romance scam', 'pig butchering', 'investment scam', 'crypto scam',
    'advance fee fraud', '419 scam', 'nigerian prince',
    'tech support scam', 'refund scam', 'lottery scam', 'prize scam',
    'elder fraud', 'senior scam', 'grandparent scam',
    # Trust & Safety (platform-specific)
    'trust and safety', 'trust & safety', 'trust safety team',
    'content moderation', 'platform abuse', 'abuse detection',
    'fake account', 'fake accounts', 'bot network', 'bot farm',
    'coordinated inauthentic', 'influence operation',
    'disinformation campaign', 'misinformation campaign',
    'deepfake fraud', 'deepfake scam', 'voice cloning scam',
    'impersonation scam', 'impersonator',
    # Financial crime (specific)
    'money laundering scheme', 'money mule', 'mule account', 'mule network',
    'terrorist financing',
    # Consumer protection
    'ftc warning', 'consumer alert', 'fraud alert', 'scam alert',
    # Marketplace fraud
    'seller fraud', 'buyer fraud', 'marketplace fraud', 'fake review',
    'counterfeit goods', 'fake product',
    # Specific phishing contexts (not general phishing)
    'phishing kit', 'phishing-as-a-service', 'phishing campaign targets',
    'vishing attack', 'smishing attack', 'quishing'
]


class SecurityMonitor:
    """Monitors security RSS feeds and detects signals."""

    def __init__(self, dry_run: bool = False, verbose: bool = False):
        self.dry_run = dry_run
        self.verbose = verbose
        self.security_sources = self._load_security_sources()
        self.existing_signals = self._load_existing_signals()
        self.monitor_state = self._load_monitor_state()
        self.new_signals: List[SecuritySignal] = []

    def _load_security_sources(self) -> Dict:
        """Load security sources configuration."""
        if SECURITY_SOURCES_PATH.exists():
            with open(SECURITY_SOURCES_PATH) as f:
                return json.load(f)
        return {"sources": []}

    def _load_existing_signals(self) -> List[Dict]:
        """Load existing signals from output file."""
        if SIGNALS_OUTPUT_PATH.exists():
            with open(SIGNALS_OUTPUT_PATH) as f:
                return json.load(f)
        return []

    def _load_monitor_state(self) -> Dict:
        """Load monitor state."""
        if MONITOR_STATE_PATH.exists():
            with open(MONITOR_STATE_PATH) as f:
                return json.load(f)
        return {
            "last_run": None,
            "feeds_checked": {},
            "signals_generated": 0
        }

    def _save_monitor_state(self):
        """Save monitor state."""
        self.monitor_state["last_run"] = datetime.utcnow().isoformat()
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(MONITOR_STATE_PATH, "w") as f:
            json.dump(self.monitor_state, f, indent=2)

    def _generate_signal_id(self, url: str, source: str) -> str:
        """Generate unique signal ID from URL and source."""
        content = f"{url}:{source}"
        return f"sec_{hashlib.md5(content.encode()).hexdigest()[:12]}"

    def _is_duplicate(self, url: str) -> bool:
        """Check if signal already exists."""
        for signal in self.existing_signals:
            if signal.get("source_url") == url:
                return True
        return False

    def _extract_cves(self, text: str) -> List[str]:
        """Extract CVE IDs from text."""
        return list(set(CVE_PATTERN.findall(text.upper())))

    def _extract_threat_actors(self, text: str) -> List[str]:
        """Extract known threat actor names from text."""
        text_lower = text.lower()
        found = []
        for actor in KNOWN_THREAT_ACTORS:
            if actor in text_lower:
                found.append(actor.title())
        return list(set(found))

    def _extract_malware(self, text: str) -> List[str]:
        """Extract known malware family names from text."""
        text_lower = text.lower()
        found = []
        for malware in KNOWN_MALWARE:
            if malware in text_lower:
                found.append(malware.title())
        return list(set(found))

    def _determine_severity(self, text: str, cves: List[str]) -> str:
        """Determine signal severity based on content analysis."""
        text_lower = text.lower()

        # Check for critical indicators
        if any(kw in text_lower for kw in CRITICAL_KEYWORDS):
            return "critical"

        # Check for high severity indicators
        if any(kw in text_lower for kw in HIGH_KEYWORDS):
            return "high"

        # CVEs typically indicate at least medium severity
        if cves:
            return "high"

        # Check for medium severity indicators
        if any(kw in text_lower for kw in MEDIUM_KEYWORDS):
            return "medium"

        return "informational"

    def _detect_mitre_tactics(self, text: str) -> List[str]:
        """Detect MITRE ATT&CK tactics from content."""
        text_lower = text.lower()
        detected = []
        for tactic, keywords in MITRE_TACTICS.items():
            if any(kw in text_lower for kw in keywords):
                detected.append(tactic)
        return detected[:5]  # Limit to top 5

    def _detect_mitre_techniques(self, text: str) -> List[str]:
        """Extract MITRE ATT&CK technique IDs (e.g., T1059)."""
        return list(set(MITRE_TECHNIQUE_PATTERN.findall(text)))[:10]

    def _detect_motivation(self, text: str) -> Optional[str]:
        """Detect threat actor motivation."""
        text_lower = text.lower()
        for motivation, keywords in MOTIVATION_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                return motivation
        return None

    def _detect_industries(self, text: str) -> List[str]:
        """Detect targeted industries."""
        text_lower = text.lower()
        detected = []
        for industry, keywords in INDUSTRY_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                detected.append(industry)
        return detected[:5]

    def _detect_regions(self, text: str) -> List[str]:
        """Detect geographic targeting."""
        text_lower = text.lower()
        detected = []
        for region, keywords in REGION_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                detected.append(region)
        return detected[:3]

    def _detect_attack_phase(self, text: str) -> Optional[str]:
        """Detect attack lifecycle phase."""
        text_lower = text.lower()
        for phase, keywords in ATTACK_PHASE_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                return phase
        return None

    def _detect_ioc_types(self, text: str) -> List[str]:
        """Detect types of IOCs mentioned."""
        text_lower = text.lower()
        detected = []
        for ioc_type, keywords in IOC_TYPE_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                detected.append(ioc_type)
        return detected

    def _detect_products(self, text: str) -> List[str]:
        """Detect affected products/vendors."""
        text_lower = text.lower()
        detected = []
        for product in PRODUCT_KEYWORDS:
            if product in text_lower:
                detected.append(product.title())
        return list(set(detected))[:8]

    def _determine_confidence(self, source_type: str, has_cves: bool, has_actors: bool) -> str:
        """Determine confidence level based on source and content."""
        # Government and major vendor sources are high confidence
        if source_type in ['government', 'vendor_research']:
            return 'high'
        # If has specific CVEs or threat actors, medium-high
        if has_cves or has_actors:
            return 'medium'
        return 'low'

    def _detect_fraud_trust_safety(self, text: str) -> bool:
        """Detect if content is related to fraud, trust & safety."""
        text_lower = text.lower()
        return any(kw in text_lower for kw in FRAUD_TRUST_SAFETY_KEYWORDS)

    def _determine_category(self, text: str, source_category: str, cves: List[str],
                           threat_actors: List[str], malware: List[str]) -> str:
        """Determine signal category."""
        text_lower = text.lower()

        # Check source category first
        if 'advisory' in source_category or 'government' in source_category:
            return 'advisory'

        if 'cve' in source_category or 'vulnerability' in source_category:
            return 'cve'

        # Content-based detection
        if cves:
            return 'cve'

        if threat_actors or 'apt' in text_lower or 'threat actor' in text_lower:
            return 'apt'

        if malware or 'malware' in text_lower or 'ransomware' in text_lower:
            return 'malware'

        if 'research' in source_category or 'analysis' in text_lower:
            return 'research'

        return 'news'

    def _extract_tags(self, text: str, source_topics: List[str]) -> List[str]:
        """Extract relevant tags from content."""
        tags = []
        text_lower = text.lower()

        # Add source topics
        tags.extend(source_topics[:3])

        # Content-based tags
        tag_keywords = {
            'ransomware': ['ransomware', 'ransom', 'encryption'],
            'phishing': ['phishing', 'spear-phishing', 'credential theft'],
            'zero-day': ['zero-day', '0-day', 'zero day'],
            'patch': ['patch', 'update', 'fix', 'remediation'],
            'exploit': ['exploit', 'poc', 'proof of concept'],
            'ics': ['ics', 'scada', 'ot ', 'industrial control'],
            'cloud': ['cloud', 'aws', 'azure', 'gcp'],
            'supply-chain': ['supply chain', 'supply-chain', 'solarwinds'],
            'credentials': ['credential', 'password', 'authentication']
        }

        for tag, keywords in tag_keywords.items():
            if any(kw in text_lower for kw in keywords):
                tags.append(tag)

        return list(set(tags))[:5]

    def _extract_summary(self, text: str, max_length: int = 300) -> str:
        """Extract a clean summary from text."""
        # Remove HTML tags
        clean = re.sub(r'<[^>]+>', '', text)
        # Remove extra whitespace
        clean = ' '.join(clean.split())
        # Truncate
        if len(clean) > max_length:
            clean = clean[:max_length].rsplit(' ', 1)[0] + "..."
        return clean

    async def _fetch_feed(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict]:
        """Fetch and parse a single RSS feed."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30), headers=headers) as response:
                if response.status == 200:
                    content = await response.text()
                    feed = feedparser.parse(content)
                    return feed
                else:
                    if self.verbose:
                        logger.warning(f"Failed to fetch {url}: HTTP {response.status}")
        except Exception as e:
            if self.verbose:
                logger.warning(f"Error fetching {url}: {e}")
        return None

    def _process_feed_entry(self, entry: Dict, source: Dict) -> Optional[SecuritySignal]:
        """Process a single feed entry and create a signal if relevant."""
        title = entry.get("title", "")
        summary = entry.get("summary", entry.get("description", ""))
        link = entry.get("link", "")
        published = entry.get("published", entry.get("updated", ""))

        # Skip if no link or already exists
        if not link or self._is_duplicate(link):
            return None

        # Combine text for analysis
        full_text = f"{title} {summary}"

        # Extract entities
        cves = self._extract_cves(full_text)
        threat_actors = self._extract_threat_actors(full_text)
        malware = self._extract_malware(full_text)

        # Determine category and severity
        category = self._determine_category(
            full_text, source.get("category", ""),
            cves, threat_actors, malware
        )
        severity = self._determine_severity(full_text, cves)

        # Extract tags
        tags = self._extract_tags(full_text, source.get("topics", []))

        # Parse date
        try:
            if published:
                # Common timezone abbreviations
                tz_map = {
                    "PST": "-0800", "PDT": "-0700",
                    "MST": "-0700", "MDT": "-0600",
                    "CST": "-0600", "CDT": "-0500",
                    "EST": "-0500", "EDT": "-0400",
                    "GMT": "+0000", "UTC": "+0000"
                }
                normalized = published
                for tz_abbr, tz_offset in tz_map.items():
                    if tz_abbr in normalized:
                        normalized = normalized.replace(tz_abbr, tz_offset)
                        break

                for fmt in ["%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"]:
                    try:
                        dt = datetime.strptime(normalized, fmt)
                        source_date = dt.strftime("%Y-%m-%d")
                        break
                    except ValueError:
                        continue
                else:
                    source_date = datetime.utcnow().strftime("%Y-%m-%d")
            else:
                source_date = datetime.utcnow().strftime("%Y-%m-%d")
        except Exception:
            source_date = datetime.utcnow().strftime("%Y-%m-%d")

        # Enforce lookback window
        cutoff_date = (datetime.utcnow() - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%d")
        if source_date < cutoff_date:
            return None

        # Generate environment tags for filtering (using LLM for better accuracy)
        env_tags = []
        if ENV_TAGGER_AVAILABLE:
            env_tags = tag_with_llm(title, summary)

        # Detect contextual attributes
        mitre_tactics = self._detect_mitre_tactics(full_text)
        mitre_techniques = self._detect_mitre_techniques(full_text)
        motivation = self._detect_motivation(full_text)
        target_industries = self._detect_industries(full_text)
        target_regions = self._detect_regions(full_text)
        attack_phase = self._detect_attack_phase(full_text)
        ioc_types = self._detect_ioc_types(full_text)
        affected_products = self._detect_products(full_text)
        is_fraud_trust_safety = self._detect_fraud_trust_safety(full_text)
        confidence = self._determine_confidence(
            source.get("source_type", "unknown"),
            bool(cves),
            bool(threat_actors)
        )

        # Create signal
        signal = SecuritySignal(
            id=self._generate_signal_id(link, source.get("source_name", "")),
            source_name=source.get("source_name", "Unknown"),
            source_type=source.get("source_type", "unknown"),
            signal_category=category,
            severity=severity,
            title=title,
            summary=self._extract_summary(summary),
            source_url=link,
            source_date=source_date,
            tags=tags,
            cve_ids=cves,
            threat_actors=threat_actors,
            malware_families=malware,
            env_tags=env_tags,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            motivation=motivation,
            target_industries=target_industries,
            target_regions=target_regions,
            attack_phase=attack_phase,
            confidence_level=confidence,
            first_seen=source_date,
            ioc_types=ioc_types,
            affected_products=affected_products,
            is_fraud_trust_safety=is_fraud_trust_safety
        )

        return signal

    async def _process_feeds_for_source(self, session: aiohttp.ClientSession,
                                        source: Dict) -> List[SecuritySignal]:
        """Process all feeds for a single source."""
        signals = []
        feeds = source.get("rss_feeds", [])

        for feed_url in feeds:
            if self.verbose:
                logger.info(f"Fetching: {feed_url}")

            feed = await self._fetch_feed(session, feed_url)
            if not feed or not feed.get("entries"):
                continue

            # Record check
            self.monitor_state["feeds_checked"][feed_url] = datetime.utcnow().isoformat()

            # Process entries (last 20)
            for entry in feed.entries[:20]:
                signal = self._process_feed_entry(entry, source)
                if signal:
                    signals.append(signal)
                    if self.verbose:
                        logger.info(f"  Found signal: {signal.severity}/{signal.signal_category} - {signal.title[:50]}...")

        return signals

    async def _fetch_cisa_ics_advisories(self, session: aiohttp.ClientSession) -> List[SecuritySignal]:
        """Fetch CISA ICS-CERT advisories from GitHub CSAF repository."""
        signals = []

        # Get list of recent 2026 advisories
        url = "https://api.github.com/repos/cisagov/CSAF/contents/csaf_files/OT/white/2026"

        if self.verbose:
            logger.info(f"Fetching CISA ICS advisories from GitHub")

        headers = {
            "User-Agent": "SecurityMonitor/1.0",
            "Accept": "application/vnd.github.v3+json"
        }

        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30), headers=headers) as response:
                if response.status != 200:
                    logger.warning(f"Failed to fetch CISA ICS list: HTTP {response.status}")
                    return signals

                files = await response.json()
                json_files = [f for f in files if f['name'].endswith('.json') and not f['name'].endswith('.sha512')]

                # Fetch last 10 advisories
                for file_info in json_files[-10:]:
                    try:
                        async with session.get(file_info['download_url'], timeout=aiohttp.ClientTimeout(total=15), headers=headers) as adv_response:
                            if adv_response.status != 200:
                                continue

                            # GitHub raw returns text/plain, so read as text and parse
                            text_content = await adv_response.text()
                            adv_data = json.loads(text_content)
                            doc = adv_data.get('document', {})
                            tracking = doc.get('tracking', {})

                            adv_id = tracking.get('id', file_info['name'].replace('.json', ''))
                            title = doc.get('title', 'Unknown')
                            release_date = tracking.get('current_release_date', '')[:10]

                            # Skip if we already have this
                            signal_id = f"cisa_ics_{adv_id}".lower().replace('-', '_')
                            if self._is_duplicate(adv_id):
                                continue

                            # Extract CVEs
                            vulns = adv_data.get('vulnerabilities', [])
                            cves = [v.get('cve') for v in vulns if v.get('cve')]

                            summary = f"CISA ICS Advisory for {title}. "
                            if cves:
                                summary += f"CVEs: {', '.join(cves[:3])}"

                            # Generate environment tags (using LLM for better accuracy)
                            ics_env_tags = ["on_prem"]  # ICS systems are typically on-prem
                            if ENV_TAGGER_AVAILABLE:
                                ics_env_tags = tag_with_llm(title, summary)
                                if "on_prem" not in ics_env_tags:
                                    ics_env_tags.append("on_prem")  # ICS typically on-prem

                            # Detect contextual attributes for ICS advisories
                            ics_full_text = f"{title} {summary}"
                            ics_mitre_tactics = self._detect_mitre_tactics(ics_full_text)
                            ics_mitre_techniques = self._detect_mitre_techniques(ics_full_text)
                            ics_industries = self._detect_industries(ics_full_text)
                            ics_regions = self._detect_regions(ics_full_text)
                            ics_products = self._detect_products(ics_full_text)
                            ics_fraud = self._detect_fraud_trust_safety(ics_full_text)
                            # ICS advisories are typically about manufacturing/energy
                            if not ics_industries:
                                ics_industries = ["manufacturing", "energy"]

                            signal = SecuritySignal(
                                id=signal_id,
                                source_name="CISA ICS-CERT",
                                source_type="government",
                                signal_category="advisory",
                                severity="high",  # ICS advisories are typically high severity
                                title=f"{adv_id}: {title}",
                                summary=summary[:400],
                                source_url=f"https://www.cisa.gov/news-events/ics-advisories/{adv_id.lower()}",
                                source_date=release_date,
                                tags=["CISA", "ICS", "SCADA", "OT"],
                                cve_ids=cves,
                                threat_actors=[],
                                malware_families=[],
                                env_tags=ics_env_tags,
                                mitre_tactics=ics_mitre_tactics if ics_mitre_tactics else ["initial_access"],
                                mitre_techniques=ics_mitre_techniques,
                                motivation=None,  # ICS attacks can be various motivations
                                target_industries=ics_industries,
                                target_regions=ics_regions,
                                attack_phase="exploitation",  # ICS advisories are about exploitation
                                confidence_level="high",  # Government source
                                first_seen=release_date,
                                ioc_types=[],
                                affected_products=ics_products,
                                is_fraud_trust_safety=ics_fraud
                            )
                            signals.append(signal)

                            if self.verbose:
                                logger.info(f"  Found ICS advisory: {adv_id} - {title[:40]}...")

                    except Exception as e:
                        if self.verbose:
                            logger.warning(f"Error fetching advisory {file_info['name']}: {e}")
                        continue

                logger.info(f"CISA ICS-CERT: Found {len(signals)} recent advisories")

        except Exception as e:
            logger.warning(f"Error fetching CISA ICS advisories: {e}")

        return signals

    async def _fetch_cisa_kev(self, session: aiohttp.ClientSession) -> List[SecuritySignal]:
        """Fetch and process CISA Known Exploited Vulnerabilities catalog."""
        signals = []
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

        if self.verbose:
            logger.info(f"Fetching CISA KEV: {url}")

        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        }

        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30), headers=headers) as response:
                if response.status != 200:
                    logger.warning(f"Failed to fetch CISA KEV: HTTP {response.status}")
                    return signals

                data = await response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                # Only process recent entries (last 14 days)
                cutoff = datetime.utcnow() - timedelta(days=14)

                for vuln in vulnerabilities:
                    date_added = vuln.get("dateAdded", "")
                    if not date_added:
                        continue

                    try:
                        added_date = datetime.strptime(date_added, "%Y-%m-%d")
                        if added_date < cutoff:
                            continue
                    except:
                        continue

                    cve_id = vuln.get("cveID", "")
                    signal_id = f"cisa_kev_{cve_id}".lower().replace("-", "_")

                    # Skip duplicates
                    if self._is_duplicate(cve_id):
                        continue

                    # Build signal
                    title = f"{cve_id}: {vuln.get('vulnerabilityName', 'Unknown')}"
                    vendor = vuln.get("vendorProject", "")
                    product = vuln.get("product", "")
                    description = vuln.get("shortDescription", "")
                    due_date = vuln.get("dueDate", "")
                    ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")

                    summary = f"{description} (Vendor: {vendor}, Product: {product})"
                    if due_date:
                        summary += f" | Due: {due_date}"
                    if ransomware and ransomware != "Unknown":
                        summary += f" | Ransomware: {ransomware}"

                    # Determine severity - all KEV entries are critical by definition
                    severity = "critical"

                    # Generate environment tags (using LLM for better accuracy)
                    kev_env_tags = ["zero_day"]  # KEV entries are actively exploited
                    if ransomware == "Known":
                        kev_env_tags.append("ransomware")
                    if ENV_TAGGER_AVAILABLE:
                        kev_env_tags = tag_with_llm(title, summary)
                        if "zero_day" not in kev_env_tags:
                            kev_env_tags.append("zero_day")  # KEV = actively exploited
                        if ransomware == "Known" and "ransomware" not in kev_env_tags:
                            kev_env_tags.append("ransomware")

                    # Detect contextual attributes for KEV entries
                    kev_full_text = f"{title} {summary} {vendor} {product}"
                    kev_mitre_tactics = self._detect_mitre_tactics(kev_full_text)
                    kev_mitre_techniques = self._detect_mitre_techniques(kev_full_text)
                    kev_industries = self._detect_industries(kev_full_text)
                    kev_regions = self._detect_regions(kev_full_text)
                    kev_products = self._detect_products(kev_full_text)
                    # Add vendor/product if not already detected
                    if vendor and vendor.title() not in kev_products:
                        kev_products.append(vendor.title())
                    if product and product.title() not in kev_products:
                        kev_products.append(product.title())
                    kev_products = kev_products[:8]  # Limit

                    # KEV entries are actively exploited, so motivation varies
                    kev_motivation = "financial" if ransomware == "Known" else self._detect_motivation(kev_full_text)
                    kev_fraud = self._detect_fraud_trust_safety(kev_full_text)

                    signal = SecuritySignal(
                        id=signal_id,
                        source_name="CISA KEV",
                        source_type="government",
                        signal_category="cve",
                        severity=severity,
                        title=title,
                        summary=summary[:500],
                        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        source_date=date_added,
                        tags=["CISA", "KEV", "actively-exploited", vendor.lower()[:20] if vendor else ""],
                        cve_ids=[cve_id],
                        threat_actors=[],
                        malware_families=["ransomware"] if ransomware == "Known" else [],
                        env_tags=kev_env_tags,
                        mitre_tactics=kev_mitre_tactics if kev_mitre_tactics else ["exploitation"],
                        mitre_techniques=kev_mitre_techniques,
                        motivation=kev_motivation,
                        target_industries=kev_industries,
                        target_regions=kev_regions,
                        attack_phase="exploitation",  # KEV = actively exploited
                        confidence_level="high",  # Government source, confirmed exploitation
                        first_seen=date_added,
                        ioc_types=[],
                        affected_products=kev_products,
                        is_fraud_trust_safety=kev_fraud
                    )
                    signals.append(signal)

                    if self.verbose:
                        logger.info(f"  Found KEV signal: {cve_id} - {vuln.get('vulnerabilityName', '')[:40]}...")

                logger.info(f"CISA KEV: Found {len(signals)} recent actively exploited vulnerabilities")

        except Exception as e:
            logger.warning(f"Error fetching CISA KEV: {e}")

        return signals

    async def run_monitor(self) -> List[SecuritySignal]:
        """Run the monitoring process."""
        logger.info("Starting security signal monitor...")
        all_signals = []
        feed_tasks = []

        async with aiohttp.ClientSession() as session:
            # Fetch CISA KEV (Known Exploited Vulnerabilities)
            kev_signals = await self._fetch_cisa_kev(session)
            all_signals.extend(kev_signals)

            # Fetch CISA ICS-CERT advisories from GitHub
            ics_signals = await self._fetch_cisa_ics_advisories(session)
            all_signals.extend(ics_signals)

            # Process all security sources
            for source in self.security_sources.get("sources", []):
                if source.get("rss_feeds"):
                    task = self._process_feeds_for_source(session, source)
                    feed_tasks.append(task)

            # Run all feed processing concurrently
            if feed_tasks:
                results = await asyncio.gather(*feed_tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, list):
                        all_signals.extend(result)
                    elif isinstance(result, Exception):
                        logger.warning(f"Feed processing error: {result}")

        self.new_signals = all_signals
        logger.info(f"Found {len(all_signals)} new signals")

        return all_signals

    def save_signals(self):
        """Save new signals to the output file."""
        if self.dry_run:
            logger.info("Dry run - not saving signals")
            for signal in self.new_signals:
                print(json.dumps(asdict(signal), indent=2))
            return

        # Merge with existing signals
        merged = self.existing_signals.copy()
        existing_ids = {s.get("id") for s in merged}

        for signal in self.new_signals:
            signal_dict = asdict(signal)
            if signal.id not in existing_ids:
                merged.append(signal_dict)
                existing_ids.add(signal.id)

        # Sort by date (newest first)
        merged.sort(key=lambda x: x.get("source_date", ""), reverse=True)

        # Save
        SIGNALS_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(SIGNALS_OUTPUT_PATH, "w") as f:
            json.dump(merged, f, indent=2)

        logger.info(f"Saved {len(merged)} total signals to {SIGNALS_OUTPUT_PATH}")

        # Update state
        self.monitor_state["signals_generated"] += len(self.new_signals)
        self._save_monitor_state()


def main():
    parser = argparse.ArgumentParser(description="Security Research Signal Monitor")
    parser.add_argument("--dry-run", action="store_true", help="Don't save signals, just print them")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    monitor = SecurityMonitor(dry_run=args.dry_run, verbose=args.verbose)

    # Run async monitor
    asyncio.run(monitor.run_monitor())

    # Save results
    monitor.save_signals()

    print(f"\nMonitor complete:")
    print(f"  - New signals found: {len(monitor.new_signals)}")
    print(f"  - Output file: {SIGNALS_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
