#!/usr/bin/env python3
"""
Retro-tag existing signals with environment tags.

This script reads signals from various JSON files and adds env_tags
using the keyword-based tagger. This allows the frontend filter to
work with pre-existing signals.

Usage:
    python scripts/retag_signals.py [--use-llm] [--verbose]
"""

import json
import argparse
from pathlib import Path
from env_tagger import tag_with_keywords, tag_with_llm, ANTHROPIC_AVAILABLE

# Signal files to process
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent

SIGNAL_FILES = [
    PROJECT_ROOT / "security-signals-data.json",
    PROJECT_ROOT / "signals-data.json",
    PROJECT_ROOT.parent / "data" / "signals-data.json",
]


def retag_signal(signal: dict, use_llm: bool = False) -> dict:
    """Add env_tags to a signal."""
    title = signal.get("title", "")
    summary = signal.get("summary", signal.get("excerpt", ""))
    content = signal.get("content", "")

    # Combine text for analysis
    full_text = f"{title} {summary} {content}"

    if use_llm and ANTHROPIC_AVAILABLE:
        tags = tag_with_llm(title, summary, content)
    else:
        tags = tag_with_keywords(full_text)

    signal["env_tags"] = tags
    return signal


def process_file(file_path: Path, use_llm: bool = False, verbose: bool = False) -> int:
    """Process a single signal file and add env_tags."""
    if not file_path.exists():
        if verbose:
            print(f"  Skipping {file_path} - file not found")
        return 0

    print(f"\nProcessing: {file_path}")

    with open(file_path) as f:
        signals = json.load(f)

    if not isinstance(signals, list):
        print(f"  Warning: Expected list, got {type(signals)}")
        return 0

    tagged_count = 0
    already_tagged = 0

    for i, signal in enumerate(signals):
        if signal.get("env_tags"):
            already_tagged += 1
            continue

        retag_signal(signal, use_llm=use_llm)
        tagged_count += 1

        if verbose and tagged_count % 20 == 0:
            print(f"  Tagged {tagged_count} signals...")

    # Save back
    with open(file_path, "w") as f:
        json.dump(signals, f, indent=2)

    print(f"  Tagged {tagged_count} new signals ({already_tagged} already had tags)")
    return tagged_count


def main():
    parser = argparse.ArgumentParser(description="Retro-tag existing signals with env_tags")
    parser.add_argument("--use-llm", action="store_true", help="Use LLM for tagging (requires ANTHROPIC_API_KEY)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--file", "-f", type=str, help="Process specific file only")
    args = parser.parse_args()

    if args.use_llm and not ANTHROPIC_AVAILABLE:
        print("Warning: --use-llm specified but anthropic package not installed. Using keyword matching.")
        args.use_llm = False

    print("Environment Signal Tagger")
    print("=" * 40)

    if args.use_llm:
        print("Mode: LLM-based tagging (Claude API)")
    else:
        print("Mode: Keyword-based tagging")

    total_tagged = 0

    if args.file:
        file_path = Path(args.file)
        total_tagged = process_file(file_path, use_llm=args.use_llm, verbose=args.verbose)
    else:
        for file_path in SIGNAL_FILES:
            tagged = process_file(file_path, use_llm=args.use_llm, verbose=args.verbose)
            total_tagged += tagged

    print(f"\n{'=' * 40}")
    print(f"Total signals tagged: {total_tagged}")


if __name__ == "__main__":
    main()
