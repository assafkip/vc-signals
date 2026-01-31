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

# Paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
DATA_DIR = PROJECT_ROOT / "data"

VC_WATCHLIST_PATH = DATA_DIR / "vc_watchlist.json"
MEDIA_VOICES_PATH = DATA_DIR / "cyber_media_voices.json"
SIGNALS_OUTPUT_PATH = PROJECT_ROOT / "signals-data.json"
MONITOR_STATE_PATH = DATA_DIR / "monitor_state.json"


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
    source_date: str
    confidence: str
    suggested_outreach_window: str = "contextual"


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
    ]
}

# Industry keywords to filter relevant content
RELEVANCE_KEYWORDS = [
    "security", "cybersecurity", "cyber", "infosec", "soc",
    "detection", "threat", "ai", "agentic", "enterprise",
    "startup", "venture", "investment", "fund", "seed", "series"
]


class FeedMonitor:
    """Monitors RSS feeds and detects signals."""

    def __init__(self, dry_run: bool = False, verbose: bool = False):
        self.dry_run = dry_run
        self.verbose = verbose
        self.vc_watchlist = self._load_watchlist()
        self.media_voices = self._load_media_voices()
        self.existing_signals = self._load_existing_signals()
        self.monitor_state = self._load_monitor_state()
        self.new_signals: List[Signal] = []

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

        # High confidence indicators
        high_indicators = [
            "announces", "raised", "million", "billion", "led",
            "closes", "invests", "portfolio"
        ]

        if signal_type == "hard" and any(ind in text_lower for ind in high_indicators):
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

        if "substack.com" in url_lower:
            return "substack"
        elif "medium.com" in url_lower:
            return "medium"
        elif "linkedin.com" in url_lower:
            return "linkedin"
        elif "twitter.com" in url_lower or "x.com" in url_lower:
            return "x"
        elif "youtube.com" in url_lower:
            return "youtube"
        elif any(news in url_lower for news in ["techcrunch", "wired", "arstechnica"]):
            return "news"
        elif any(pr in url_lower for pr in ["prnewswire", "businesswire", "globenewswire"]):
            return "press"
        else:
            return "blog"

    async def _fetch_feed(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict]:
        """Fetch and parse a single RSS feed."""
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
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
        if not signal_type:
            return None

        # Match to person
        person, firm, source_type = self._match_to_person(full_text, link)

        # Use hints if no match found
        if not person and person_hint:
            person = person_hint
            firm = firm_hint or ""

        if not person:
            # Can't attribute to anyone, skip
            return None

        # Parse date
        try:
            if published:
                # Try common date formats
                for fmt in ["%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"]:
                    try:
                        dt = datetime.strptime(published.replace("Z", "+0000"), fmt)
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
            suggested_outreach_window=self._determine_outreach_window(signal_type, signal_category)
        )

        return signal

    async def _process_feeds_for_source(self, session: aiohttp.ClientSession,
                                        feeds: List[str], person: str, firm: str) -> List[Signal]:
        """Process all feeds for a single source (person/firm)."""
        signals = []

        for feed_url in feeds:
            if self.verbose:
                logger.info(f"Fetching: {feed_url}")

            feed = await self._fetch_feed(session, feed_url)
            if not feed or not feed.get("entries"):
                continue

            # Record check
            self.monitor_state["feeds_checked"][feed_url] = datetime.utcnow().isoformat()

            # Process entries (last 10)
            for entry in feed.entries[:10]:
                signal = self._process_feed_entry(entry, feed_url, person, firm)
                if signal:
                    signals.append(signal)
                    if self.verbose:
                        logger.info(f"  Found signal: {signal.signal_type}/{signal.signal_category} - {signal.summary[:50]}...")

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
