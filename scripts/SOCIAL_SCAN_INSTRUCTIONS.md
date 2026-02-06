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

### 🎯 "PITCH ME" Pattern (HIGHEST VALUE)

**Example post (Justin Somaini, Feb 2026):**
> "I'm spending time on two things:
> 1. Security leaders who are genuinely interested in early-stage cyber (Seed/A)
> 2. Founders who are ideating on what to build and want a thought partner
> If that's you, reach out."

**Look for these patterns:**
- "If that's you, reach out" / "DM me" / "happy to chat"
- "Helping founders" / "advising startups" / "thought partner"
- Career transition: "left [firm]" / "taking time" / "what's next"
- Stage-specific focus: "Seed/A" / "early-stage" / "pre-seed"
- Availability signals: "spending time on" / "open to" / "looking to help"

**When you find this pattern:**
- Signal type: `hard`
- Signal category: `actively_looking`
- Outreach window: `immediate`
- Confidence: `high`

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

### ⚠️ CRITICAL: Name Extraction Rule

**NEVER use pre-populated names from source files (watchlist, manifest, etc.)**

When creating a signal entry, you MUST extract the person's name directly from:
1. **LinkedIn**: The profile page header or browser tab title (e.g., "Justin Somaini | LinkedIn")
2. **X/Twitter**: The profile display name on the page

**Why:** Source files may contain typos or outdated names. The actual profile is the source of truth.

**How to verify:**
- After navigating to a profile, check the browser tab title or page header
- Use that exact name in the `person_name` field
- If the name differs from source data, update the source data file too

### ⚠️ CRITICAL: Post URL Extraction Rule

**NEVER use profile URLs as source_url. Always get the specific post URL.**

When you find a signal post:
1. **Click on the post** to open it in detail view
2. **Copy the specific post URL** from the browser address bar
3. **Use that URL** in the `source_url` field

**LinkedIn post URLs look like:**
- `https://www.linkedin.com/posts/username_activity-1234567890123456789-xxxx`
- `https://www.linkedin.com/feed/update/urn:li:activity:1234567890123456789`

**X/Twitter post URLs look like:**
- `https://x.com/username/status/1234567890123456789`

**Why:** Profile URLs don't link to the specific insight. Users need to click and see the exact post that supports the claim.

❌ BAD: `source_url: "https://www.linkedin.com/in/jsomaini/"`
✅ GOOD: `source_url: "https://www.linkedin.com/posts/jsomaini_activity-7292123456789012345-abcd"`

### For Each Profile:

1. **Navigate** to the profile URL
2. **Wait** for page to load (2-3 seconds)
3. **Extract the actual name** from the profile header/tab title ← CRITICAL
4. **Check recent activity** (last 2-4 weeks of posts)
5. **Look for signal keywords** in posts
6. **If signal found:**
   - Click into the post to get the specific post URL ← CRITICAL
   - Create a signal entry using the extracted name AND post URL
7. **Screenshot** if needed for complex signals

### LinkedIn Scanning

```
1. Navigate to linkedin.com/in/[username]
2. VERIFY the actual name from the profile header (not from watchlist)
3. Scroll to "Activity" section
4. Look for recent posts (not just reposts)
5. When you find a signal post:
   a. Click on the post timestamp or "..." menu → "Copy link to post"
   b. Or click into the post and copy URL from address bar
   c. Use this specific URL as source_url
6. Check for: fund announcements, thesis posts, security commentary
7. Note follower count and engagement levels
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
  "person_name": "Full Name (EXTRACTED FROM PROFILE, not from watchlist)",
  "firm": "Firm Name or Outlet",
  "signal_type": "hard" or "soft",
  "signal_category": "[category from taxonomy]",
  "summary": "Brief description of what was found",
  "excerpt": "Key quote if applicable (keep short)",
  "source_url": "SPECIFIC POST URL - e.g. https://www.linkedin.com/posts/username_activity-123... or https://x.com/username/status/123...",
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

## ⚠️ CRITICAL: Citation Requirements

**Every claim in summaries must cite a specific source.**

❌ BAD: "Multiple VCs actively seeking early-stage cyber founders"
✅ GOOD: "Justin Somaini seeking cyber founders: 'If that's you, reach out' (post 2/2)"

❌ BAD: "Agentic Security emerging as funded category"
✅ GOOD: "WitnessAI $58M Agentic Security round (Barmak Meftah post 2/2)"

**For every theme or summary point, include:**
- Person name
- Specific quote or fact
- Post date (MM/DD format)

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
