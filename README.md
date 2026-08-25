# VC Signals Dashboard

Real-time intelligence on cybersecurity VC investments and market trends. 101
signals from 67 VCs across 59 firms, classified as hard or soft and filterable
by theme, source, person, firm, and time range.

**Hard signals**: a fund closed, a security investment made, a firm publicly
hunting deals. **Soft signals**: thesis statements, trend commentary, SOC pain
points, detection-engineering interest. The difference matters when you need to
know who is actively writing checks versus who is thinking out loud.

## Features

- 101 signals from 67 VCs across 59 firms
- Hard vs soft signal categorization
- Filter by theme, source, person, firm, and time range
- Direct links back to the source content of every signal

## The data pipeline

The feed is produced by an hourly RSS monitor ([helios](https://github.com/assafkip/helios)):
VC-partner and cybersecurity-media feeds are pulled every hour, each item is
classified hard or soft, attributed to a person + firm, deduplicated, and kept
in a 30-day window. Pure RSS. No LinkedIn, X/Twitter, or scraping dependency.

This repo is the dashboard half: static HTML reading one JSON file. No backend,
no database, no build step.

## Deploy your own

1. Push this repository to GitHub
2. Settings > Pages > Deploy from branch > main > `/docs` (or root)
3. Your dashboard is live at `https://YOUR-USERNAME.github.io/REPO-NAME/`

## Files

- `index.html` - the interactive dashboard (self-contained)
- `signals-data.json` - raw signal data
