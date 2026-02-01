---
name: rss-monitor
description: Run the RSS feed monitor to collect signals from blogs, newsletters, and podcasts. Safe to run anytime - no account risk.
allowed-tools: Bash(python*)
---

# RSS Monitor

Run the RSS feed monitor to collect VC signals from public feeds.

## Steps

1. Run the monitor:
   ```bash
   python scripts/live_monitor.py
   ```

2. Report results to user:
   - New signals found
   - Total signals in database
   - Any errors or failed feeds

3. If new signals found:
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
