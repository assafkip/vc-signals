---
name: research-linkedin
description: Scan LinkedIn profiles for VC signals. Use when the user wants to check LinkedIn for investment signals. Requires user presence to watch the browser.
disable-model-invocation: true
argument-hint: "[theme: detection | threat-intel | all]"
---

# LinkedIn Research

Scan LinkedIn profiles for VC signals relevant to KTLYST fundraising.

## Usage

- `/research-linkedin` - Broad scan for all signals
- `/research-linkedin detection` - Focus on detection engineering content
- `/research-linkedin threat-intel` - Focus on threat intelligence content

## Theme Filters

### detection (Detection Engineering)
Prioritize posts containing:
- detection engineering, detection-as-code, detection rules
- sigma rules, yara, detection content, detection logic
- threat hunting, hunting queries, kql, splunk
- detection coverage, detection gaps, purple team
- MITRE ATT&CK techniques

### threat-intel (Threat Intelligence)
Prioritize posts containing:
- threat intel, threat intelligence, CTI
- threat actor, APT, threat report
- IOC, indicators of compromise, threat feed
- malware analysis, TTPs, threat landscape
- adversary tracking, campaign analysis

### all (Default)
Look for any investment signals, thesis statements, portfolio news

## Steps

1. Read `scripts/social_scan_manifest.json` and extract `metadata.linkedin_scan.last_run`

2. Report to user:
   - Last LinkedIn scan date/time
   - Theme filter being applied: `$ARGUMENTS` (or "all" if none)
   - Number of Priority 1 profiles to scan

3. Ask: "Ready to watch the browser? (y/n)"

4. **Wait for user confirmation before proceeding**

5. If confirmed, use browser automation to:
   - Navigate to each Priority 1 LinkedIn profile from the manifest
   - Check recent activity (last 14 days only)
   - **If theme specified**: Only flag posts matching that theme's keywords
   - When creating signals, extract the specific post URL (not profile URL)
   - Mark theme-matching signals as `confidence: high`
   - Create signal entries in `signals-data.json`

6. After completion:
   - Update `metadata.linkedin_scan.last_run` in `scripts/social_scan_manifest.json`
   - Commit and push changes
   - Report summary: "Found X signals matching [theme]"

## Important Rules

- Never run LinkedIn automation without explicit user confirmation
- User must be watching to handle CAPTCHAs or warnings
- Extract specific post URLs, not profile URLs
- Only look at posts from the last 14 days
