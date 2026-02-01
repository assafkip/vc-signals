# Daily Social Profile Scan Instructions

This document defines the systematic process for scanning X/Twitter and LinkedIn profiles for signals relevant to KTLYST's fundraising efforts.

## ⚠️ CRITICAL: Lookback Rules

**NEVER look at posts older than 14 days from today.**

- Maximum lookback window: **14 days**
- Skip any posts dated before this window
- If a profile has no activity in the last 14 days, move to the next profile
- This applies to ALL platforms (LinkedIn, X/Twitter)

## Quick Start

When the user says "Scan social profiles for signals", follow this process:

1. Get browser context: `mcp__claude-in-chrome__tabs_context_mcp`
2. Create a new tab: `mcp__claude-in-chrome__tabs_create_mcp`
3. Load the manifest: Read `scripts/social_scan_manifest.json`
4. Scan profiles systematically (Priority 1 first, then 2, then 3)
5. Save signals to `signals-data.json`

---

## Profile Counts

| Platform | Priority 1 | Priority 2 | Priority 3 | Total |
|----------|------------|------------|------------|-------|
| LinkedIn | ~20 | ~40 | ~1 | 61 |
| X/Twitter | ~8 | ~23 | 0 | 31 |

**Estimated time:** 15-25 minutes for full scan

---

## Signal Detection Criteria

### HARD Signals (High Value - Create signal entry)

Look for posts/activity indicating:

- **New fund announcements**: "raised", "closed fund", "announcing Fund X"
- **Active deal making**: "just led", "excited to invest", "portfolio company"
- **Open to pitches**: "looking for", "seeking founders", "office hours", "pitch me"
- **Thesis statements**: "investing in", "focused on", "our thesis"
- **Security-specific**: Mentions of SOC, detection, AI security, agentic security

### SOFT Signals (Context Value - Create signal entry)

Look for posts/activity indicating:

- **Problem awareness**: Alert fatigue, SOC pain, detection gaps
- **Market commentary**: Security trends, AI in security, autonomous systems
- **Portfolio wins**: Exits, funding rounds, acquisitions of portfolio companies
- **Content creation**: Blog posts, podcasts, threads about security topics

---

## 🎯 Content Focus (KTLYST Priority)

### Detection Engineering (HIGH PRIORITY)

These keywords should trigger HIGH confidence signals:

- `detection engineering`, `detection-as-code`, `detection rules`
- `sigma rules`, `yara`, `detection content`, `detection logic`
- `threat hunting`, `hunting queries`, `kql`, `splunk queries`
- `detection coverage`, `mitre att&ck`, `attack techniques`
- `detection gaps`, `security content`, `purple team`

### Threat Intelligence (HIGH PRIORITY)

- `threat intel`, `threat intelligence`, `cti`
- `threat actor`, `apt`, `threat report`
- `ioc`, `indicators of compromise`, `threat feed`
- `malware analysis`, `threat briefing`, `ttps`
- `threat landscape`, `adversary`, `campaign`

### AI/Agentic Security (KTLYST Differentiator)

- `agentic`, `ai security`, `ai-powered`, `autonomous security`
- `llm security`, `ai soc`, `automated detection`

**When you see these keywords, mark the signal as `confidence: high`**

---

## Scanning Process

### For Each Profile:

1. **Navigate** to the profile URL
2. **Wait** for page to load (2-3 seconds)
3. **Check recent activity** (last 2-4 weeks of posts)
4. **Look for signal keywords** in posts
5. **If signal found**, create a signal entry
6. **Screenshot** if needed for complex signals

### LinkedIn Scanning

```
1. Navigate to linkedin.com/in/[username]
2. Scroll to "Activity" section
3. Look for recent posts (not just reposts)
4. Check for: fund announcements, thesis posts, security commentary
5. Note follower count and engagement levels
```

### X/Twitter Scanning

```
1. Navigate to twitter.com/[username] or x.com/[username]
2. Scroll through recent tweets (last 2 weeks)
3. Check for: investment announcements, thesis threads, security takes
4. Note engagement levels on security-related content
```

---

## Signal Entry Format

When a signal is detected, create an entry in this format:

```json
{
  "id": "[platform]_scan_[person_lastname]_[unique_id]",
  "person_name": "Full Name",
  "firm": "Firm Name or Outlet",
  "signal_type": "hard" or "soft",
  "signal_category": "[category from taxonomy]",
  "summary": "Brief description of what was found",
  "excerpt": "Key quote if applicable (keep short)",
  "source_url": "https://www.linkedin.com/in/username or https://twitter.com/username",
  "source_type": "linkedin" or "x_twitter",
  "source_date": "YYYY-MM-DD",
  "confidence": "high" or "medium",
  "suggested_outreach_window": "immediate" or "1week" or "2weeks",
  "scan_source": "claude_chrome_scan"
}
```

### Signal Categories (from taxonomy)

**Hard signals:**
- `new_fund_raised`
- `new_security_investment`
- `new_partner_joins`
- `actively_looking`
- `public_ask_intros`
- `office_hours_announced`
- `new_thesis_statement`

**Soft signals:**
- `problem_post_soc_pain`
- `problem_post_detection_gaps`
- `detection_engineering` ← KTLYST PRIORITY
- `threat_intelligence` ← KTLYST PRIORITY
- `critique_current_tools`
- `security_trend_commentary`
- `portfolio_adjacent_win`

---

## Priority Order

Scan in this order:

### Priority 1 (Must scan daily) - ~28 profiles
Key security-focused VCs and influential media voices most relevant to KTLYST

### Priority 2 (Scan if time permits) - ~63 profiles
Broader VC network and general security media

### Priority 3 (Weekly rotation) - ~1 profile
Lower relevance but worth occasional monitoring

---

## Session Summary

After completing a scan, perform these steps:

### 1. Update Timestamps

**Update `social_scan_manifest.json`:**
```json
"lookback_config": {
  "last_scan_date": "YYYY-MM-DD"  // Set to today's date
}
```

**Update `last_checked` in source files for scanned profiles:**
- For each LinkedIn/X profile successfully scanned, update the `last_checked` field in the corresponding entry in `data/vc_watchlist.json` or `data/cyber_media_voices.json`
- Use ISO format: `"last_checked": "2026-02-01T15:30:00"`

### 2. Provide Summary

```
## Scan Summary - [Date]

**Profiles Scanned:**
- LinkedIn: X/61
- X/Twitter: X/31

**Signals Found:**
- Hard: X
- Soft: X

**Notable Findings:**
- [Brief bullets]

**New Signals Added to signals-data.json:**
- [List IDs]

**Timestamps Updated:**
- social_scan_manifest.json: last_scan_date set to [date]
- vc_watchlist.json: X VCs updated
- cyber_media_voices.json: X voices updated
```

---

## Error Handling

- **Rate limiting**: If LinkedIn/X shows limits, pause 30 seconds
- **Login required**: Skip profile, note for manual review
- **Profile not found**: Log error, continue to next
- **Page load failure**: Retry once, then skip

---

## Tips for Efficient Scanning

1. **Batch by platform**: Do all LinkedIn, then all X/Twitter
2. **Use keyboard shortcuts**: Tab between posts quickly
3. **Only create signals for actionable content**: Skip generic reposts
4. **ENFORCE 14-DAY RULE**: Skip ANY content older than 14 days - no exceptions
5. **Trust the keywords**: If no keywords match, likely not a signal
6. **Boost detection/TI content**: Mark as high confidence when found
7. **Check post dates**: Verify the date before creating a signal
