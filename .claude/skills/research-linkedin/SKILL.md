---
name: research-linkedin
description: Scan LinkedIn profiles for VC signals. Use when the user wants to check LinkedIn for investment signals. Requires user presence to watch the browser.
disable-model-invocation: true
---

# LinkedIn Research

Scan LinkedIn profiles for VC signals relevant to KTLYST fundraising.

## Steps

1. Read `scripts/social_scan_manifest.json` and extract `metadata.linkedin_scan.last_run`

2. Report to user:
   - Last LinkedIn scan date/time
   - How long ago that was
   - Number of Priority 1 profiles to scan

3. Ask: "Ready to watch the browser? (y/n)"

4. **Wait for user confirmation before proceeding**

5. If confirmed, use browser automation to:
   - Navigate to each Priority 1 LinkedIn profile from the manifest
   - Check recent activity (last 14 days only)
   - Look for investment signals, thesis statements, portfolio news
   - When creating signals, extract the specific post URL (not profile URL)
   - Create signal entries in `signals-data.json`

6. After completion:
   - Update `metadata.linkedin_scan.last_run` in `scripts/social_scan_manifest.json` to current timestamp
   - Update `metadata.linkedin_scan.profiles_scanned` count
   - Commit and push changes
   - Report summary of signals found

## Important Rules

- Never run LinkedIn automation without explicit user confirmation
- User must be watching to handle CAPTCHAs or warnings
- Extract specific post URLs, not profile URLs
- Only look at posts from the last 14 days
