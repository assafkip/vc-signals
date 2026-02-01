# VC Signal Monitoring Tool: Architecture & Operations Guide

## What This Tool Does

This tool monitors 37 venture capital partners and 30 cybersecurity media voices to detect "signals" relevant to KTLYST's fundraising efforts. It tracks their public activity across blogs, newsletters, social media, and news to identify:

- **Investment activity**: New funds raised, deals announced, thesis statements
- **Market commentary**: Thoughts on SOC pain points, AI security, detection gaps
- **Outreach opportunities**: Office hours, "pitch me" posts, active interest signals

The end result is a live dashboard showing all detected signals, filterable by person, firm, signal type, and time range.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           DATA SOURCES                                   │
├─────────────────────────────────────────────────────────────────────────┤
│  RSS Feeds          │  LinkedIn Profiles  │  X/Twitter Profiles         │
│  (Blogs, Substacks, │  (61 profiles)      │  (31 profiles)              │
│   Medium, Podcasts) │                     │                             │
└─────────┬───────────┴─────────┬───────────┴──────────┬──────────────────┘
          │                     │                      │
          │ AUTOMATED           │ MANUAL               │ MANUAL
          │ (GitHub Actions)    │ (Claude Code)        │ (Claude Code)
          │                     │                      │
          ▼                     ▼                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         PROCESSING LAYER                                 │
├─────────────────────────────────────────────────────────────────────────┤
│  live_monitor.py             │  Browser Automation (Claude in Chrome)   │
│  - Fetches RSS feeds         │  - Navigates to LinkedIn/X profiles      │
│  - Detects keywords          │  - Reads recent activity                 │
│  - Classifies signals        │  - Detects signals from posts            │
│  - Runs hourly via Actions   │  - Triggered daily by user               │
└─────────────────┬────────────┴──────────────────────┬───────────────────┘
                  │                                   │
                  └─────────────────┬─────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         signals-data.json                                │
│  Central database of all detected signals                                │
│  - ~180+ signals currently                                               │
│  - Hard signals (investment activity) + Soft signals (commentary)       │
│  - Updated by both automated and manual processes                        │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            DASHBOARD                                     │
│  index.html (GitHub Pages)                                               │
│  - Fetches signals-data.json                                             │
│  - Displays signals with filters                                         │
│  - Shows stats, trending themes                                          │
│  - Accessible at: https://[username].github.io/[repo]/                  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## The Two Update Channels

### Channel 1: Automated RSS Monitoring (Hourly)

**What it monitors:**
- VC firm blogs (Boldstart, Greylock, Battery, etc.)
- Substack newsletters (Rain Capital, Venture in Security, Zero Day)
- Personal blogs (danielmiessler.com, schneier.com, krebsonsecurity.com)
- Media outlets (TechCrunch, Ars Technica, Wired author feeds)
- Podcasts (Darknet Diaries, CISO Series, Security Now)

**How it works:**

1. **GitHub Actions** triggers `live_monitor.py` every hour
2. The script loads the watchlists (`vc_watchlist.json`, `cyber_media_voices.json`)
3. It fetches all RSS feeds in parallel using `aiohttp`
4. Each feed entry is analyzed for keywords
5. If keywords match, a signal is created with:
   - Signal type: `hard` (investment activity) or `soft` (commentary)
   - Category: specific classification (e.g., `new_fund_raised`, `security_trend_commentary`)
   - Confidence level: `high` or `medium`
6. New signals are appended to `signals-data.json`
7. Changes are auto-committed back to the repository

**Keyword detection logic:**

| Signal Type | Categories | Example Keywords |
|-------------|------------|------------------|
| **Hard** | `new_fund_raised` | "raised", "closes fund", "million fund" |
| **Hard** | `new_security_investment` | "led the", "invested in", "seed round" |
| **Hard** | `actively_looking` | "looking for", "pitch me", "office hours" |
| **Soft** | `security_trend_commentary` | "ai security", "agentic", "threat landscape" |
| **Soft** | `problem_post_soc_pain` | "soc", "alert fatigue", "false positives" |
| **Soft** | `portfolio_adjacent_win` | "acquisition", "exit", "ipo" |

### Channel 2: Manual Social Scanning (Daily)

**What it monitors:**
- 61 LinkedIn profiles
- 31 X/Twitter profiles

**Why manual?**
LinkedIn and X/Twitter don't have public APIs for reading posts. They actively block scraping. The only reliable way to read this content is through a browser.

**How it works:**

1. **Daily GitHub Issue** is created at 9am Pacific reminding you to scan
2. You open terminal in the `github-pages` directory and run `claude`
3. You say: "Scan social profiles for signals"
4. Claude Code reads the manifest (`social_scan_manifest.json`) with all 92 profiles
5. Using browser automation, Claude:
   - Navigates to each profile
   - Scrolls through recent activity
   - Looks for signal keywords
   - Creates signal entries for relevant posts
6. New signals are added to `signals-data.json`

**The manifest contains:**
- All profile URLs pre-organized
- Priority levels (1 = scan first, 2 = if time permits, 3 = weekly)
- Category labels (vc vs media)

---

## File Structure

```
q-VC-Sourcing/
├── data/
│   ├── vc_watchlist.json          # 37 VC partners with all their URLs
│   ├── cyber_media_voices.json    # 30 media voices with all their URLs
│   ├── monitor_state.json         # Tracks last RSS check times
│   └── review_rotation_state.json # Tracks manual review rotation
│
├── github-pages/
│   ├── index.html                 # The dashboard (single-page app)
│   ├── signals-data.json          # THE CENTRAL DATABASE (~180 signals)
│   ├── CLAUDE.md                  # Instructions for Claude Code
│   ├── ARCHITECTURE.md            # This document
│   │
│   ├── scripts/
│   │   ├── live_monitor.py        # Automated RSS monitoring
│   │   ├── review_twitter.py      # Opens browser tabs for manual review
│   │   ├── social_scan_manifest.json    # All 92 social profiles
│   │   └── SOCIAL_SCAN_INSTRUCTIONS.md  # Detailed scanning procedure
│   │
│   └── .github/workflows/
│       ├── monitor.yml            # Hourly RSS monitoring
│       └── daily-reminder.yml     # 9am reminder to scan social
```

---

## Signal Data Schema

Each signal in `signals-data.json` follows this structure:

```json
{
  "id": "unique_identifier",
  "person_name": "Ed Sim",
  "firm": "Boldstart Ventures",
  "signal_type": "hard",
  "signal_category": "new_fund_raised",
  "summary": "Boldstart Fund VII announced - $250M to back autonomous enterprise founders",
  "excerpt": "From Inception. Before the world believes...",
  "source_url": "https://linkedin.com/in/edsim",
  "source_type": "linkedin",
  "source_date": "2026-01-31",
  "confidence": "high",
  "suggested_outreach_window": "1week",
  "scan_source": "claude_chrome_scan"
}
```

**Field explanations:**

| Field | Purpose |
|-------|---------|
| `id` | Unique identifier for deduplication |
| `person_name` | Who created this signal |
| `firm` | Their company/outlet |
| `signal_type` | `hard` (actionable) or `soft` (context) |
| `signal_category` | Specific classification from taxonomy |
| `summary` | Human-readable description |
| `excerpt` | Key quote from the source |
| `source_url` | Where to find the original |
| `source_type` | Platform: blog, linkedin, x, substack, etc. |
| `source_date` | When the content was published |
| `confidence` | How certain we are this is a real signal |
| `suggested_outreach_window` | Timing recommendation |
| `scan_source` | How it was detected (rss or claude_chrome_scan) |

---

## The Dashboard

The dashboard (`index.html`) is a single-page JavaScript application that:

1. **Fetches** `signals-data.json` on load
2. **Displays** all signals as cards with visual styling
3. **Provides filters** for:
   - Time range (1 day, 7 days, 14 days, month, all time)
   - Source type (blog, LinkedIn, X, Substack, etc.)
   - Person
   - Firm
   - Theme (Investments, SOC Pain, Agentic AI, etc.)
   - Signal type (Hard only, Soft only, All)
4. **Shows statistics**: Total signals, VCs tracked, Hard signals count, Last updated
5. **Highlights themes**: Cards showing which topics have the most signals

The dashboard is hosted on GitHub Pages and updates automatically when `signals-data.json` changes.

---

## Daily Workflow

### Morning (Automated)
- 9:00 AM Pacific: GitHub creates a reminder issue
- Every hour: `monitor.yml` runs, checks RSS feeds, commits any new signals

### When You Scan (Manual, ~15-25 minutes)
1. Check the GitHub issue for the reminder
2. Open terminal: `cd /path/to/github-pages && claude`
3. Say: "Scan social profiles for signals"
4. Claude scans profiles in priority order
5. New signals appear on dashboard
6. Close the GitHub issue

### Priority Order for Scanning
- **Priority 1** (~28 profiles): Most relevant VCs and key media voices
- **Priority 2** (~63 profiles): Broader network, if time permits
- **Priority 3** (~1 profile): Weekly rotation

---

## Current Coverage

| Source Type | Coverage | Method |
|-------------|----------|--------|
| VC Blogs | ~70% | Automated RSS |
| Substacks | 100% | Automated RSS |
| Medium | 100% | Automated RSS |
| Podcasts | ~80% | Automated RSS |
| LinkedIn | 100% | Manual (Claude) |
| X/Twitter | 100% | Manual (Claude) |
| YouTube | ~50% | Automated RSS |

---

## Possible Next Steps

### Short-term Improvements

1. **Add more RSS feeds**
   - Some VCs have blogs we haven't discovered yet
   - More podcast feeds could be added

2. **Improve keyword detection**
   - Add more industry-specific terms
   - Tune for fewer false positives

3. **Better deduplication**
   - Catch signals that appear in multiple sources
   - Avoid near-duplicate entries

### Medium-term Enhancements

4. **Scoring/ranking signals**
   - Weight signals by recency, person priority, and keyword match strength
   - Show "hottest" signals at the top

5. **Email/Slack notifications**
   - Send daily digest of new signals
   - Alert immediately for hard signals

6. **Historical tracking**
   - Track when each person was last active
   - Show activity trends over time

### Long-term Possibilities

7. **X/Twitter API integration** ($100/month)
   - Fully automate X monitoring
   - No manual scanning needed

8. **RSS bridges for social**
   - Use Nitter or RSS.app to convert X profiles to RSS
   - Partial automation for X content

9. **Chrome extension for LinkedIn**
   - Build a helper that flags signals while browsing
   - Export to the system automatically

10. **AI-powered signal classification**
    - Use LLM to classify signals more accurately
    - Better summarization of long posts

---

## Troubleshooting

**Dashboard shows no signals:**
- Check that `signals-data.json` exists and has content
- Verify the file is valid JSON (no trailing commas)
- Check browser console for fetch errors

**RSS monitor finds no new signals:**
- Check if feeds are still active (some may have changed URLs)
- Verify `monitor_state.json` is being updated
- Run `python scripts/live_monitor.py --verbose` locally to debug

**Manual scan can't access profiles:**
- LinkedIn may be rate-limiting; wait 30 seconds between profiles
- Some profiles may require login; skip and note for later
- Check if the URL in the manifest is correct

**GitHub Actions not running:**
- Check the Actions tab for workflow errors
- Verify `requirements.txt` has all dependencies
- Check that the repository has Actions enabled

---

## Summary

This tool gives you early visibility into VC and media activity relevant to cybersecurity fundraising. It combines:

- **Automated hourly monitoring** of blogs and newsletters via RSS
- **Manual daily scanning** of LinkedIn and X/Twitter via browser automation
- **A live dashboard** that displays all signals with filtering and search

The goal is to catch investment signals, thesis statements, and market commentary that could inform your outreach timing and messaging.
