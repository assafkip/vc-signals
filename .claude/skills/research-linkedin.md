# /research-linkedin

Scan LinkedIn profiles for VC signals. Requires user presence to watch the browser.

## Trigger
When user types `/research-linkedin`

## Instructions

1. Read `scripts/social_scan_manifest.json` and extract `metadata.linkedin_scan.last_run`

2. Report to user:
   ```
   Last LinkedIn scan: [date/time] ([X days ago])
   Profiles to scan: Priority 1 LinkedIn profiles (security-focused VCs)

   Ready to watch the browser? (y/n)
   ```

3. Wait for user confirmation before proceeding

4. If confirmed, use browser automation to:
   - Navigate to each Priority 1 LinkedIn profile
   - Check recent activity (last 14 days only)
   - When creating signals, extract the specific post URL (not profile URL)
   - Create signal entries in `signals-data.json`

5. After completion:
   - Update `metadata.linkedin_scan.last_run` in `scripts/social_scan_manifest.json`
   - Update `metadata.linkedin_scan.profiles_scanned` count
   - Report summary of signals found

## Important
- Never run LinkedIn automation without user confirmation
- User must be watching to handle CAPTCHAs or warnings
- Extract specific post URLs, not profile URLs
