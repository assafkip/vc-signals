# /rss-monitor

Run the RSS feed monitor to collect signals from blogs, newsletters, and podcasts.

## Trigger
When user types `/rss-monitor`

## Instructions

1. Run the RSS monitor:
   ```bash
   python scripts/live_monitor.py
   ```

2. Report results:
   ```
   RSS Monitor Complete

   New signals found: X
   Total signals: Y

   Sources checked:
   - VC blogs (Boldstart, Rain Capital, etc.)
   - Security newsletters (Venture in Security, Schneier, etc.)
   - Podcasts (Security Now, Darknet Diaries, etc.)

   New signals added:
   - [list any new signals]
   ```

3. If new signals found, remind user to push changes:
   ```
   Run `git add signals-data.json && git commit -m "RSS monitor update" && git push` to deploy
   ```

## Notes
- Safe to run anytime - no account risk (uses public RSS feeds)
- 30-day lookback window for RSS content
- Dates are extracted from RSS pubDate fields
