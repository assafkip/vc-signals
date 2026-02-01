---
name: rss-monitor
description: Run the RSS feed monitor to collect signals from blogs, newsletters, and podcasts. Safe to run anytime - no account risk.
allowed-tools: Bash(python*)
argument-hint: "[theme: detection | threat-intel | all]"
---

# RSS Monitor

Run the RSS feed monitor to collect VC signals from public feeds.

## Usage

- `/rss-monitor` - Collect all signals
- `/rss-monitor detection` - Filter results to detection engineering
- `/rss-monitor threat-intel` - Filter results to threat intelligence

## Steps

1. Run the monitor:
   ```bash
   python scripts/live_monitor.py
   ```

2. If theme argument provided (`$ARGUMENTS`), filter the results:

   **detection**: Show only signals containing:
   - detection engineering, detection-as-code, detection rules
   - sigma, yara, threat hunting, MITRE ATT&CK

   **threat-intel**: Show only signals containing:
   - threat intel, threat actor, APT, IOC
   - malware analysis, TTPs, threat landscape

3. Report results to user:
   - New signals found (filtered if theme specified)
   - Total signals in database
   - Any errors or failed feeds

4. If new signals found:
   - Show a summary of the new signals
   - Ask if user wants to commit and push changes

## Sources Monitored

- VC blogs (Boldstart, Rain Capital, Lightspeed, etc.)
- Security newsletters (Venture in Security, Schneier, Krebs, etc.)
- Podcasts (Security Now, Darknet Diaries, etc.)
- Tech news (TechCrunch security, Ars Technica, etc.)

## Notes

- Safe to run anytime - uses public RSS feeds only
- 30-day lookback window
- Dates extracted from RSS pubDate fields
