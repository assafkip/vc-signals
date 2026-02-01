#!/usr/bin/env python3
"""
Cleanup Old Signals

Removes signals older than the lookback window from signals-data.json.
This ensures the dashboard only shows recent, relevant signals.

Usage:
    python scripts/cleanup_old_signals.py [--dry-run] [--days 14]
"""

import json
import argparse
from datetime import datetime, timedelta
from pathlib import Path

# Paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
SIGNALS_PATH = PROJECT_ROOT / "signals-data.json"

DEFAULT_LOOKBACK_DAYS = 30  # 30 days to support monthly trend analysis


def cleanup_signals(lookback_days: int = DEFAULT_LOOKBACK_DAYS, dry_run: bool = False):
    """Remove signals older than lookback_days."""

    if not SIGNALS_PATH.exists():
        print(f"Signals file not found: {SIGNALS_PATH}")
        return

    # Load signals
    with open(SIGNALS_PATH) as f:
        signals = json.load(f)

    original_count = len(signals)

    # Calculate cutoff date
    cutoff_date = (datetime.utcnow() - timedelta(days=lookback_days)).strftime("%Y-%m-%d")

    print(f"Lookback window: {lookback_days} days")
    print(f"Cutoff date: {cutoff_date}")
    print(f"Original signal count: {original_count}")
    print()

    # Separate signals by date
    recent_signals = []
    old_signals = []

    for signal in signals:
        source_date = signal.get("source_date", "")

        # Handle partial dates like "2024-11" or "2025"
        if len(source_date) == 7:  # "2024-11" format
            source_date = source_date + "-01"
        elif len(source_date) == 4:  # "2025" format
            source_date = source_date + "-01-01"

        if source_date >= cutoff_date:
            recent_signals.append(signal)
        else:
            old_signals.append(signal)

    # Report what would be removed
    print(f"Signals to KEEP (within {lookback_days} days): {len(recent_signals)}")
    print(f"Signals to REMOVE (older than {lookback_days} days): {len(old_signals)}")
    print()

    if old_signals:
        print("=== SIGNALS TO BE REMOVED ===")
        # Group by month for readability
        by_month = {}
        for s in old_signals:
            month = s.get("source_date", "unknown")[:7]
            by_month[month] = by_month.get(month, 0) + 1

        for month, count in sorted(by_month.items()):
            print(f"  {month}: {count} signals")
        print()

    if dry_run:
        print("DRY RUN - No changes made")
        return

    # Save cleaned signals
    with open(SIGNALS_PATH, "w") as f:
        json.dump(recent_signals, f, indent=2)

    removed_count = original_count - len(recent_signals)
    print(f"✓ Removed {removed_count} old signals")
    print(f"✓ Saved {len(recent_signals)} signals to {SIGNALS_PATH}")


def main():
    parser = argparse.ArgumentParser(description="Cleanup old signals from signals-data.json")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be removed without making changes")
    parser.add_argument("--days", type=int, default=DEFAULT_LOOKBACK_DAYS, help=f"Lookback window in days (default: {DEFAULT_LOOKBACK_DAYS})")
    args = parser.parse_args()

    cleanup_signals(lookback_days=args.days, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
