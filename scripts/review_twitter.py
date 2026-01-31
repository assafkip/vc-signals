#!/usr/bin/env python3
"""
Twitter/X Manual Review Tool

Opens X/Twitter profiles in browser for manual review.
Supports daily rotation to cycle through all tracked profiles.

Usage:
    python review_twitter.py --open-tabs          # Open today's batch of profiles
    python review_twitter.py --open-tabs --all    # Open ALL profiles
    python review_twitter.py --list               # Show today's rotation list
    python review_twitter.py --list --all         # Show all X profiles
    python review_twitter.py --open-linkedin      # Open LinkedIn profiles instead
"""

import argparse
import json
import os
import sys
import webbrowser
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class ProfileEntry:
    """A profile to review."""
    name: str
    source: str  # 'vc' or 'media'
    firm_or_outlet: str
    x_url: str
    linkedin_url: str
    priority: Optional[int] = None


def load_data_files(data_dir: Path) -> tuple[list, list]:
    """Load VC watchlist and media voices data."""
    vc_path = data_dir / "vc_watchlist.json"
    media_path = data_dir / "cyber_media_voices.json"

    vcs = []
    media = []

    if vc_path.exists():
        with open(vc_path, 'r') as f:
            data = json.load(f)
            vcs = data.get('watchlist', [])

    if media_path.exists():
        with open(media_path, 'r') as f:
            data = json.load(f)
            media = data.get('voices', [])

    return vcs, media


def extract_profiles(vcs: list, media: list) -> list[ProfileEntry]:
    """Extract profiles with X or LinkedIn URLs."""
    profiles = []

    # Process VCs
    for vc in vcs:
        x_url = vc.get('x_url', '').strip()
        linkedin_url = vc.get('linkedin_url', '').strip()

        if x_url or linkedin_url:
            profiles.append(ProfileEntry(
                name=vc.get('person_name', 'Unknown'),
                source='vc',
                firm_or_outlet=vc.get('firm', ''),
                x_url=x_url,
                linkedin_url=linkedin_url,
                priority=vc.get('priority')
            ))

    # Process media voices
    for voice in media:
        x_url = voice.get('x_url', '').strip()
        linkedin_url = voice.get('linkedin_url', '').strip()

        # Skip placeholders
        if linkedin_url == '{{Unknown}}':
            linkedin_url = ''

        if x_url or linkedin_url:
            profiles.append(ProfileEntry(
                name=voice.get('person_name', 'Unknown'),
                source='media',
                firm_or_outlet=voice.get('outlet_or_primary_affiliation', ''),
                x_url=x_url,
                linkedin_url=linkedin_url
            ))

    return profiles


def get_rotation_state_path(data_dir: Path) -> Path:
    """Get path to rotation state file."""
    return data_dir / "review_rotation_state.json"


def load_rotation_state(data_dir: Path) -> dict:
    """Load rotation state from file."""
    state_path = get_rotation_state_path(data_dir)

    if state_path.exists():
        with open(state_path, 'r') as f:
            return json.load(f)

    return {
        "last_index": 0,
        "last_date": None,
        "batch_size": 10
    }


def save_rotation_state(data_dir: Path, state: dict):
    """Save rotation state to file."""
    state_path = get_rotation_state_path(data_dir)
    with open(state_path, 'w') as f:
        json.dump(state, f, indent=2)


def get_todays_batch(
    profiles: list[ProfileEntry],
    state: dict,
    platform: str = 'x',
    batch_size: int = 10
) -> list[ProfileEntry]:
    """Get today's batch of profiles to review."""
    # Filter by platform
    if platform == 'x':
        filtered = [p for p in profiles if p.x_url]
    else:
        filtered = [p for p in profiles if p.linkedin_url]

    if not filtered:
        return []

    # Check if we should advance the rotation
    today = datetime.now().strftime('%Y-%m-%d')
    last_date = state.get('last_date')
    last_index = state.get('last_index', 0)

    if last_date != today:
        # New day - advance the rotation
        last_index = (last_index + batch_size) % len(filtered)
        state['last_index'] = last_index
        state['last_date'] = today

    # Get batch
    end_index = min(last_index + batch_size, len(filtered))
    batch = filtered[last_index:end_index]

    # Wrap around if needed
    if len(batch) < batch_size and last_index > 0:
        remaining = batch_size - len(batch)
        batch.extend(filtered[:remaining])

    return batch


def format_profile_list(profiles: list[ProfileEntry], platform: str = 'x') -> str:
    """Format profiles for display."""
    lines = []

    for i, p in enumerate(profiles, 1):
        url = p.x_url if platform == 'x' else p.linkedin_url
        source_label = f"[{p.source.upper()}]"
        priority_label = f" P{p.priority}" if p.priority else ""

        lines.append(
            f"{i:2}. {source_label}{priority_label} {p.name} ({p.firm_or_outlet})"
        )
        lines.append(f"    {url}")

    return "\n".join(lines)


def open_in_browser(profiles: list[ProfileEntry], platform: str = 'x'):
    """Open profile URLs in browser."""
    count = 0
    for p in profiles:
        url = p.x_url if platform == 'x' else p.linkedin_url
        if url:
            webbrowser.open(url)
            count += 1

    return count


def main():
    parser = argparse.ArgumentParser(
        description='Manual X/Twitter and LinkedIn profile review tool'
    )

    parser.add_argument(
        '--open-tabs',
        action='store_true',
        help='Open profiles in browser tabs'
    )
    parser.add_argument(
        '--open-linkedin',
        action='store_true',
        help='Review LinkedIn profiles instead of X'
    )
    parser.add_argument(
        '--list',
        action='store_true',
        help='List profiles without opening'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Show/open all profiles instead of daily rotation'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=10,
        help='Number of profiles per daily batch (default: 10)'
    )
    parser.add_argument(
        '--data-dir',
        type=str,
        default=None,
        help='Path to data directory'
    )

    args = parser.parse_args()

    # Determine data directory
    if args.data_dir:
        data_dir = Path(args.data_dir)
    else:
        # Default: script is in scripts/, data is in data/
        script_dir = Path(__file__).parent
        data_dir = script_dir.parent / "data"

    if not data_dir.exists():
        print(f"Error: Data directory not found: {data_dir}")
        sys.exit(1)

    # Load data
    vcs, media = load_data_files(data_dir)
    profiles = extract_profiles(vcs, media)

    platform = 'linkedin' if args.open_linkedin else 'x'
    platform_label = 'LinkedIn' if platform == 'linkedin' else 'X/Twitter'

    # Filter by platform
    if platform == 'x':
        available = [p for p in profiles if p.x_url]
    else:
        available = [p for p in profiles if p.linkedin_url]

    if not available:
        print(f"No {platform_label} profiles found in data files.")
        sys.exit(0)

    print(f"\n📊 {platform_label} Profile Review Tool")
    print(f"   Total profiles with {platform_label}: {len(available)}")
    print(f"   (VCs: {len([p for p in available if p.source == 'vc'])}, "
          f"Media: {len([p for p in available if p.source == 'media'])})")
    print()

    if args.all:
        # Show/open all profiles
        to_review = available
        print(f"📋 All {len(to_review)} {platform_label} profiles:\n")
    else:
        # Get today's rotation batch
        state = load_rotation_state(data_dir)
        to_review = get_todays_batch(
            profiles, state, platform, args.batch_size
        )
        save_rotation_state(data_dir, state)

        # Calculate rotation info
        total = len(available)
        days_for_full_cycle = (total + args.batch_size - 1) // args.batch_size

        print(f"📅 Today's batch ({len(to_review)} profiles):")
        print(f"   Full cycle: {days_for_full_cycle} days\n")

    # Display profiles
    print(format_profile_list(to_review, platform))
    print()

    if args.open_tabs:
        print(f"🌐 Opening {len(to_review)} tabs...")
        count = open_in_browser(to_review, platform)
        print(f"✅ Opened {count} browser tabs")
    else:
        if not args.list:
            print(f"💡 Use --open-tabs to open in browser, or --list to just view")


if __name__ == "__main__":
    main()
