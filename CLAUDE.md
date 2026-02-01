# CLAUDE.md - VC Signal Dashboard

## What This Does

This is the GitHub Pages-hosted dashboard for tracking VC and media voice signals. It displays real-time signals detected from social media profiles and RSS feeds.

## Key Commands

When the user says **"Scan social profiles for signals"**, follow these steps:

1. Read `scripts/SOCIAL_SCAN_INSTRUCTIONS.md` for the full procedure
2. Read `scripts/social_scan_manifest.json` for all 92 profiles to scan
3. Use browser automation tools to scan LinkedIn and X/Twitter profiles
4. Add detected signals to `signals-data.json`

## Lookback Rules (IMPORTANT)

**Never look at posts older than 14 days from today.**

- Maximum lookback window: 14 days
- Skip any posts dated before this window
- After the initial scan, only check for new activity since the last scan
- Update `last_scan_date` in the manifest after each scan session
- This applies to ALL platforms (LinkedIn, X/Twitter, blogs, etc.)

## Files

| File | Purpose |
|------|---------|
| `signals-data.json` | Live signal database (dashboard reads this) |
| `scripts/social_scan_manifest.json` | All 92 profiles with URLs to scan |
| `scripts/SOCIAL_SCAN_INSTRUCTIONS.md` | Detailed scanning procedure |
| `scripts/live_monitor.py` | Automated RSS feed monitoring |
| `scripts/review_twitter.py` | Manual browser tab opener |
| `index.html` | Dashboard frontend |

## Signal Taxonomy

### Hard Signals (Actionable)
- `new_fund_raised` - Fund announcement
- `new_security_investment` - Security company investment
- `actively_looking` - "Looking for founders", "pitch me"
- `office_hours_announced` - Open meetings scheduled
- `new_thesis_statement` - Investment thesis shared

### Soft Signals (Context)
- `problem_post_soc_pain` - SOC/alert fatigue discussion
- `security_trend_commentary` - Market/trend observations
- `portfolio_adjacent_win` - Portfolio company success

## Signal Entry Format

```json
{
  "id": "linkedin_scan_[lastname]_[unique]",
  "person_name": "Name",
  "firm": "Firm",
  "signal_type": "hard" or "soft",
  "signal_category": "[from taxonomy]",
  "summary": "What was found",
  "source_url": "https://linkedin.com/in/... or https://twitter.com/...",
  "source_type": "linkedin" or "x_twitter",
  "source_date": "YYYY-MM-DD",
  "confidence": "high" or "medium",
  "scan_source": "claude_chrome_scan"
}
```

## Profile Counts

- **LinkedIn**: 61 profiles (37 VCs + 24 media voices)
- **X/Twitter**: 31 profiles (2 VCs + 29 media voices)
- **Total**: 92 unique profiles

## Priority 1 Profiles (Scan First)

**VCs:**
- Ed Sim (Boldstart) - Fund VII just closed, agentic AI focus
- Asheem Chandna (Greylock) - 7AI investor, agentic security thesis
- Shardul Shah (Index) - Led 7AI $130M Series A
- Jay Leek (SYN) - SOC/alert fatigue focus
- Kobi Samboursky (Glilot) - AI + cyber thesis
- Arif Janmohamed (Lightspeed) - AI SOC speaker

**Media:**
- Ross Haleliuk - Venture in Security newsletter
- Daniel Miessler - Unsupervised Learning (100K+ subscribers)
- Katie Nickels - Red Canary, MITRE ATT&CK
- Brian Krebs - Security investigations
- Kim Zetter - Zero Day newsletter

## Keywords to Watch

**Investment signals:**
- "just led", "announced investment", "portfolio company"
- "looking for", "seeking founders", "pitch me"
- "new fund", "closed fund", "raising"

**Thesis alignment:**
- SOC, detection, alert fatigue
- AI security, agentic, autonomous
- threat intel, SIEM, XDR

## 🎯 KTLYST Priority Content

**Detection Engineering (HIGH PRIORITY):**
- detection engineering, detection-as-code, detection rules
- sigma rules, yara, mitre att&ck
- threat hunting, detection coverage, detection gaps

**Threat Intelligence (HIGH PRIORITY):**
- threat intel, threat intelligence, cti
- threat actor, apt, ioc, malware analysis
- threat report, ttps, threat landscape

**AI/Agentic Security:**
- agentic, ai security, autonomous security
- llm security, ai soc, automated detection

Signals with these keywords should be marked as `confidence: high`
