#!/usr/bin/env python3
"""
Live VC Signal Monitor

Monitors RSS feeds from VC partners and media voices, detects relevant signals,
and updates the signals-data.json file for the dashboard.

Features:
- Parallel RSS feed fetching with asyncio
- Keyword-based signal detection (hard and soft signals)
- Deduplication of existing signals
- Automatic timestamp updates
- GitHub Pages compatible output

Usage:
    python scripts/live_monitor.py [--dry-run] [--verbose]
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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Lookback window - signals older than this are ignored
# 30 days to support monthly trend analysis; engagement UI highlights recent signals
LOOKBACK_DAYS = 30

# Paths - relative to github-pages directory
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
DATA_DIR = PROJECT_ROOT / "data"

VC_WATCHLIST_PATH = DATA_DIR / "vc_watchlist.json"
MEDIA_VOICES_PATH = DATA_DIR / "cyber_media_voices.json"
INDUSTRY_SOURCES_PATH = DATA_DIR / "industry_sources.json"
SIGNALS_OUTPUT_PATH = PROJECT_ROOT / "signals-data.json"
MONITOR_STATE_PATH = DATA_DIR / "monitor_state.json"

# Outreach tracker - located in output directory (parent of github-pages)
OUTPUT_DIR = PROJECT_ROOT.parent / "output"
OUTREACH_TRACKER_PATH = OUTPUT_DIR / "outreach-tracker.json"


@dataclass
class Signal:
    """Represents a detected signal from RSS feeds."""
    id: str
    person_name: str
    firm: str
    signal_type: str  # 'hard' or 'soft'
    signal_category: str
    summary: str
    excerpt: str
    source_url: str
    source_type: str
    source_date: str  # YYYY-MM-DD for backward compatibility
    confidence: str
    suggested_outreach_window: str = "contextual"
    source_timestamp: str = ""  # Full ISO timestamp when available (e.g., 2026-02-01T14:32:00Z)
    # Pipeline contact matching
    matched_contacts: List[Dict] = None  # Contacts from outreach tracker that match this signal
    has_pipeline_match: bool = False  # Quick flag for UI filtering

    def __post_init__(self):
        if self.matched_contacts is None:
            self.matched_contacts = []


# Hard signal keywords - direct investment/fundraising activity
HARD_SIGNAL_KEYWORDS = {
    "new_fund_raised": [
        "raised", "closes fund", "new fund", "fund announcement",
        "million fund", "billion fund", "announces fund", "fund raise"
    ],
    "new_security_investment": [
        "led the", "led seed", "led series", "invested in", "portfolio company",
        "backs", "invests", "funding round", "announces investment",
        "seed round", "series a", "series b"
    ],
    "actively_looking": [
        "looking for", "seeking", "open to meeting", "pitch me",
        "office hours", "want to meet", "interested in"
    ],
    "new_thesis_statement": [
        "our thesis", "investment thesis", "why we invested",
        "our investment in", "partnering with"
    ]
}

# Soft signal keywords - market commentary and thought leadership
SOFT_SIGNAL_KEYWORDS = {
    "security_trend_commentary": [
        "ai security", "agentic", "autonomous", "cybersecurity trends",
        "security landscape", "threat landscape", "security market",
        "cyber investment", "infosec", "zero trust"
    ],
    "problem_post_soc_pain": [
        "soc", "alert fatigue", "false positives", "security operations",
        "detection", "threat detection", "incident response",
        "overwhelmed", "alert overload", "noise"
    ],
    "problem_post_detection_gaps": [
        "detection gaps", "visibility", "blind spots", "coverage gaps",
        "missed threats", "evasion", "detection engineering"
    ],
    "portfolio_adjacent_win": [
        "acquisition", "acquired", "exit", "ipo", "valuation",
        "unicorn", "portfolio", "congratulations"
    ],
    # Detection Engineering focus
    "detection_engineering": [
        "detection engineering", "detection-as-code", "detection rules",
        "sigma rules", "yara", "detection content", "detection logic",
        "threat hunting", "hunting queries", "kql", "splunk queries",
        "elastic rules", "detection coverage", "mitre att&ck",
        "attack techniques", "detection gaps", "security content",
        "detection strategy", "purple team", "detection maturity"
    ],
    # Threat Intelligence focus
    "threat_intelligence": [
        "threat intel", "threat intelligence", "cti", "threat actor",
        "apt", "threat report", "ioc", "indicators of compromise",
        "threat feed", "intelligence sharing", "threat landscape",
        "adversary", "campaign", "malware analysis", "threat briefing",
        "intelligence requirements", "threat assessment", "ttps",
        "threat hunting", "dark web", "threat trends"
    ]
}

# Priority keywords - signals containing these get higher confidence
PRIORITY_KEYWORDS = [
    # Detection Engineering - KTLYST core focus
    "detection engineering", "detection-as-code", "detection content",
    "threat detection", "alert fatigue", "soc analyst", "false positives",
    "detection rules", "sigma", "yara", "mitre att&ck",
    # Threat Intelligence
    "threat intel", "threat intelligence", "threat hunting", "cti",
    # AI/Agentic Security - KTLYST differentiator
    "agentic", "ai security", "ai-powered", "autonomous security",
    "llm security", "ai soc", "automated detection"
]

# Industry keywords to filter relevant content
RELEVANCE_KEYWORDS = [
    # Core security
    "security", "cybersecurity", "cyber", "infosec", "soc",
    # Detection Engineering (KTLYST focus)
    "detection", "detection engineering", "threat detection", "alert",
    "sigma", "yara", "mitre", "att&ck", "detection rules",
    # Threat Intelligence
    "threat intel", "threat intelligence", "threat hunting", "cti",
    "threat actor", "apt", "ioc", "malware",
    # AI/Automation
    "ai", "agentic", "autonomous", "llm", "machine learning",
    # Investment
    "startup", "venture", "investment", "fund", "seed", "series",
    "enterprise", "raise", "funding"
]


class FeedMonitor:
    """Monitors RSS feeds and detects signals."""

    def __init__(self, dry_run: bool = False, verbose: bool = False):
        self.dry_run = dry_run
        self.verbose = verbose
        self.vc_watchlist = self._load_watchlist()
        self.media_voices = self._load_media_voices()
        self.industry_sources = self._load_industry_sources()
        self.outreach_tracker = self._load_outreach_tracker()
        self.existing_signals = self._load_existing_signals()
        self.monitor_state = self._load_monitor_state()
        self.new_signals: List[Signal] = []
        self.checked_persons: set = set()  # Track who was successfully checked

    def _load_watchlist(self) -> Dict:
        """Load VC watchlist data."""
        if VC_WATCHLIST_PATH.exists():
            with open(VC_WATCHLIST_PATH) as f:
                return json.load(f)
        return {"watchlist": []}

    def _load_media_voices(self) -> Dict:
        """Load media voices data."""
        if MEDIA_VOICES_PATH.exists():
            with open(MEDIA_VOICES_PATH) as f:
                return json.load(f)
        return {"voices": []}

    def _load_industry_sources(self) -> Dict:
        """Load industry sources data (publications, press releases, conferences, etc.)."""
        if INDUSTRY_SOURCES_PATH.exists():
            with open(INDUSTRY_SOURCES_PATH) as f:
                return json.load(f)
        return {"sources": []}

    def _load_outreach_tracker(self) -> Dict:
        """Load outreach tracker data for pipeline contact matching."""
        if OUTREACH_TRACKER_PATH.exists():
            with open(OUTREACH_TRACKER_PATH) as f:
                return json.load(f)
        return {"contacts": [], "super_connectors": []}

    def _enrich_signal_with_contacts(self, signal: Signal) -> Signal:
        """Tag signal with matched pipeline contacts from outreach tracker."""
        matches = []
        content = (signal.summary + " " + signal.excerpt + " " + signal.person_name + " " + signal.firm).lower()

        for contact in self.outreach_tracker.get("contacts", []):
            name = contact.get("person_name", "").lower()
            firm = contact.get("firm", "").lower()

            # Check for name or firm match
            if (name and len(name) > 2 and name in content) or (firm and len(firm) > 2 and firm in content):
                match_type = "name" if name in content else "firm"
                matches.append({
                    "contact_id": contact.get("id", ""),
                    "name": contact.get("person_name", ""),
                    "firm": contact.get("firm", ""),
                    "status": contact.get("status", "not_started"),
                    "tier": contact.get("tier", ""),
                    "match_type": match_type
                })

        signal.matched_contacts = matches
        signal.has_pipeline_match = len(matches) > 0

        return signal

    def _load_existing_signals(self) -> List[Dict]:
        """Load existing signals from output file."""
        if SIGNALS_OUTPUT_PATH.exists():
            with open(SIGNALS_OUTPUT_PATH) as f:
                return json.load(f)
        return []

    def _load_monitor_state(self) -> Dict:
        """Load monitor state (last check times, etc.)."""
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

    def _update_last_checked_timestamps(self):
        """Update last_checked timestamps in source files for successfully checked persons."""
        if self.dry_run:
            logger.info("Dry run - not updating last_checked timestamps")
            return

        now = datetime.utcnow().isoformat()
        vc_updated = 0
        media_updated = 0

        # Update VC watchlist
        for vc in self.vc_watchlist.get("watchlist", []):
            name = vc.get("person_name", "")
            if name in self.checked_persons:
                vc["last_checked"] = now
                vc_updated += 1

        # Update media voices
        for voice in self.media_voices.get("voices", []):
            name = voice.get("person_name", "")
            if name in self.checked_persons:
                # Add last_checked field if it doesn't exist
                voice["last_checked"] = now
                media_updated += 1

        # Save updated files
        if vc_updated > 0:
            with open(VC_WATCHLIST_PATH, "w") as f:
                json.dump(self.vc_watchlist, f, indent=2)
            logger.info(f"Updated last_checked for {vc_updated} VCs")

        if media_updated > 0:
            with open(MEDIA_VOICES_PATH, "w") as f:
                json.dump(self.media_voices, f, indent=2)
            logger.info(f"Updated last_checked for {media_updated} media voices")

    def _generate_signal_id(self, url: str, person: str) -> str:
        """Generate unique signal ID from URL and person."""
        content = f"{url}:{person}"
        return f"rss_{hashlib.md5(content.encode()).hexdigest()[:12]}"

    def _is_duplicate(self, url: str) -> bool:
        """Check if signal already exists."""
        for signal in self.existing_signals:
            if signal.get("source_url") == url:
                return True
        return False

    def _is_relevant(self, text: str) -> bool:
        """Check if content is relevant to cybersecurity/VC space."""
        text_lower = text.lower()
        return any(kw in text_lower for kw in RELEVANCE_KEYWORDS)

    def _detect_signal_type(self, text: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Detect signal type and category from text.
        Returns (signal_type, signal_category) or (None, None) if no match.
        """
        text_lower = text.lower()

        # Check hard signals first (higher priority)
        for category, keywords in HARD_SIGNAL_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                return ("hard", category)

        # Check soft signals
        for category, keywords in SOFT_SIGNAL_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                return ("soft", category)

        return (None, None)

    def _determine_confidence(self, text: str, signal_type: str) -> str:
        """Determine confidence level based on content analysis."""
        text_lower = text.lower()

        # High confidence indicators for investment signals
        high_indicators = [
            "announces", "raised", "million", "billion", "led",
            "closes", "invests", "portfolio"
        ]

        # Boost confidence for KTLYST-relevant content (detection/threat intel)
        priority_match = any(kw in text_lower for kw in PRIORITY_KEYWORDS)

        if signal_type == "hard" and any(ind in text_lower for ind in high_indicators):
            return "high"
        elif priority_match:
            # Detection engineering / threat intel content gets high confidence
            return "high"
        elif signal_type == "soft":
            return "med"
        return "med"

    def _determine_outreach_window(self, signal_type: str, category: str) -> str:
        """Determine suggested outreach timing."""
        if signal_type == "hard":
            if category in ["new_security_investment", "new_fund_raised"]:
                return "1week"
            elif category == "actively_looking":
                return "anytime"
        return "contextual"

    def _extract_excerpt(self, text: str, max_length: int = 200) -> str:
        """Extract a clean excerpt from text."""
        # Remove HTML tags
        clean = re.sub(r'<[^>]+>', '', text)
        # Remove extra whitespace
        clean = ' '.join(clean.split())
        # Truncate
        if len(clean) > max_length:
            clean = clean[:max_length].rsplit(' ', 1)[0] + "..."
        return clean

    def _match_to_person(self, text: str, url: str) -> Tuple[Optional[str], Optional[str], str]:
        """
        Match content to a tracked person.
        Returns (person_name, firm, source_type).
        """
        text_lower = text.lower()
        url_lower = url.lower()

        # Check VC watchlist
        for vc in self.vc_watchlist.get("watchlist", []):
            name = vc.get("person_name", "")
            firm = vc.get("firm", "")
            feeds = vc.get("rss_feeds", [])

            # Check if this feed belongs to this person
            for feed in feeds:
                if feed.lower() in url_lower or url_lower in feed.lower():
                    return (name, firm, self._detect_source_type(url))

            # Check if name or firm mentioned in text
            if name.lower() in text_lower or firm.lower() in text_lower:
                return (name, firm, self._detect_source_type(url))

        # Check media voices
        for voice in self.media_voices.get("voices", []):
            name = voice.get("person_name", "")
            outlet = voice.get("outlet_or_primary_affiliation", "")
            feeds = voice.get("rss_feeds", [])

            for feed in feeds:
                if feed.lower() in url_lower or url_lower in feed.lower():
                    return (name, outlet, self._detect_source_type(url))

            if name.lower() in text_lower:
                return (name, outlet, self._detect_source_type(url))

        return (None, None, self._detect_source_type(url))

    def _detect_source_type(self, url: str) -> str:
        """Detect source type from URL."""
        url_lower = url.lower()

        # Substack and newsletter sources
        if "substack.com" in url_lower or any(nl in url_lower for nl in [
            "ventureinsecurity.net", "zetter-zeroday.com", "returnonsecurity.com",
            "tldrsec.com", "tldr.tech/infosec"
        ]):
            return "substack"
        elif "medium.com" in url_lower:
            return "medium"
        elif "linkedin.com" in url_lower:
            return "linkedin"
        elif "twitter.com" in url_lower or "x.com" in url_lower or "nitter" in url_lower or "rsshub.app/twitter" in url_lower:
            return "x"
        elif "youtube.com" in url_lower:
            return "youtube"
        elif "crunchbase.com" in url_lower:
            return "crunchbase"
        elif "producthunt.com" in url_lower:
            return "producthunt"
        elif "news.ycombinator.com" in url_lower or "ycombinator.com" in url_lower:
            return "hackernews"
        elif "angellist.com" in url_lower or "wellfound.com" in url_lower:
            return "angellist"
        elif any(news in url_lower for news in ["techcrunch", "wired", "arstechnica", "darkreading", "securityweek", "therecord", "bleepingcomputer", "thehackernews"]):
            return "news"
        elif any(pr in url_lower for pr in ["prnewswire", "businesswire", "globenewswire"]):
            return "press"
        elif any(pod in url_lower for pod in ["megaphone.fm", "libsyn.com", "anchor.fm", "podcasts.apple", "feeds.simplecast", "feeds.twit.tv", "risky.biz"]):
            return "podcast"
        elif any(conf in url_lower for conf in ["rsaconference", "blackhat", "defcon", "bsides"]):
            return "conference"
        else:
            return "blog"

    async def _fetch_feed(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict]:
        """Fetch and parse a single RSS feed."""
        # Use browser-like user-agent to avoid blocks from sites like Crunchbase
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

    def _process_feed_entry(self, entry: Dict, feed_url: str, person_hint: str = None, firm_hint: str = None) -> Optional[Signal]:
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

        # Check relevance
        if not self._is_relevant(full_text):
            return None

        # Detect signal type
        signal_type, signal_category = self._detect_signal_type(full_text)

        # For industry sources (with hints), allow general market signals even without specific category
        is_industry_source = person_hint is not None
        if not signal_type and is_industry_source:
            # Default to soft/market signal for industry sources
            signal_type = "soft"
            signal_category = "security_trend_commentary"

        if not signal_type:
            return None

        # Match to person
        person, firm, source_type = self._match_to_person(full_text, link)

        # Use hints if no match found (industry sources always use hints)
        if not person and person_hint:
            person = person_hint
            firm = firm_hint or ""
            # For industry sources, use the configured source_type instead of URL detection
            if firm_hint and firm_hint in ['crunchbase', 'conference', 'hackernews', 'substack', 'producthunt', 'podcast', 'press', 'news']:
                source_type = firm_hint

        if not person:
            # Can't attribute to anyone, skip
            return None

        # Parse date and timestamp
        source_timestamp = ""
        try:
            if published:
                # Common timezone abbreviations to UTC offset mapping
                tz_map = {
                    "PST": "-0800", "PDT": "-0700",
                    "MST": "-0700", "MDT": "-0600",
                    "CST": "-0600", "CDT": "-0500",
                    "EST": "-0500", "EDT": "-0400",
                    "GMT": "+0000", "UTC": "+0000",
                    "Z": "+0000"
                }
                normalized = published
                for tz_abbr, tz_offset in tz_map.items():
                    if tz_abbr in normalized:
                        normalized = normalized.replace(tz_abbr, tz_offset)
                        break

                # Try common date formats
                for fmt in ["%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"]:
                    try:
                        dt = datetime.strptime(normalized, fmt)
                        source_date = dt.strftime("%Y-%m-%d")
                        # Capture full timestamp for engagement tracking
                        source_timestamp = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                        break
                    except ValueError:
                        continue
                else:
                    source_date = datetime.utcnow().strftime("%Y-%m-%d")
                    source_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            else:
                source_date = datetime.utcnow().strftime("%Y-%m-%d")
                source_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            source_date = datetime.utcnow().strftime("%Y-%m-%d")
            source_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        # Enforce lookback window - skip signals older than LOOKBACK_DAYS
        cutoff_date = (datetime.utcnow() - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%d")
        if source_date < cutoff_date:
            if self.verbose:
                logger.debug(f"Skipping old entry (dated {source_date}): {link}")
            return None

        # Create signal
        signal = Signal(
            id=self._generate_signal_id(link, person),
            person_name=person,
            firm=firm,
            signal_type=signal_type,
            signal_category=signal_category,
            summary=title,
            excerpt=self._extract_excerpt(summary),
            source_url=link,
            source_type=source_type,
            source_date=source_date,
            confidence=self._determine_confidence(full_text, signal_type),
            suggested_outreach_window=self._determine_outreach_window(signal_type, signal_category),
            source_timestamp=source_timestamp
        )

        # Enrich with pipeline contact matches
        signal = self._enrich_signal_with_contacts(signal)

        return signal

    async def _process_feeds_for_source(self, session: aiohttp.ClientSession,
                                        feeds: List[str], person: str, firm: str) -> List[Signal]:
        """Process all feeds for a single source (person/firm)."""
        signals = []
        feeds_fetched = 0

        for feed_url in feeds:
            if self.verbose:
                logger.info(f"Fetching: {feed_url}")

            feed = await self._fetch_feed(session, feed_url)
            if not feed or not feed.get("entries"):
                continue

            feeds_fetched += 1

            # Record check
            self.monitor_state["feeds_checked"][feed_url] = datetime.utcnow().isoformat()

            # Process entries (last 10)
            for entry in feed.entries[:10]:
                signal = self._process_feed_entry(entry, feed_url, person, firm)
                if signal:
                    signals.append(signal)
                    if self.verbose:
                        logger.info(f"  Found signal: {signal.signal_type}/{signal.signal_category} - {signal.summary[:50]}...")

        # Mark this person as successfully checked if at least one feed was fetched
        if feeds_fetched > 0 and person:
            self.checked_persons.add(person)

        return signals

    async def run_monitor(self) -> List[Signal]:
        """Run the monitoring process."""
        logger.info("Starting live signal monitor...")
        all_signals = []

        # Collect all feeds to check
        feed_tasks = []

        async with aiohttp.ClientSession() as session:
            # Process VC watchlist feeds
            for vc in self.vc_watchlist.get("watchlist", []):
                feeds = vc.get("rss_feeds", [])
                if feeds:
                    task = self._process_feeds_for_source(
                        session, feeds,
                        vc.get("person_name", ""),
                        vc.get("firm", "")
                    )
                    feed_tasks.append(task)

            # Process media voice feeds
            for voice in self.media_voices.get("voices", []):
                feeds = voice.get("rss_feeds", [])
                if feeds:
                    task = self._process_feeds_for_source(
                        session, feeds,
                        voice.get("person_name", ""),
                        voice.get("outlet_or_primary_affiliation", "")
                    )
                    feed_tasks.append(task)

            # Process industry sources (publications, press releases, conferences, X feeds)
            for source in self.industry_sources.get("sources", []):
                feeds = source.get("rss_feeds", [])
                if feeds:
                    task = self._process_feeds_for_source(
                        session, feeds,
                        source.get("source_name", ""),  # Use source name as person_name
                        source.get("source_type", "")   # Use source type as firm
                    )
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

        # Update last_checked timestamps in source files
        self._update_last_checked_timestamps()


def main():
    parser = argparse.ArgumentParser(description="Live VC Signal Monitor")
    parser.add_argument("--dry-run", action="store_true", help="Don't save signals, just print them")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    monitor = FeedMonitor(dry_run=args.dry_run, verbose=args.verbose)

    # Run async monitor
    asyncio.run(monitor.run_monitor())

    # Save results
    monitor.save_signals()

    print(f"\nMonitor complete:")
    print(f"  - New signals found: {len(monitor.new_signals)}")
    print(f"  - Output file: {SIGNALS_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
