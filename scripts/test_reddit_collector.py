#!/usr/bin/env python3
"""Offline test for Reddit source collection."""

import sys
import types

sys.modules.setdefault("feedparser", types.SimpleNamespace(parse=lambda _content: {"entries": []}))
sys.modules.setdefault("aiohttp", types.SimpleNamespace())

from live_monitor import reddit_feed_entries


def test_reddit_feed_entries_uses_arctic_then_pullpush():
    requested_urls = []

    def fake_fetch_json(url):
        requested_urls.append(url)
        if "arctic-shift.photon-reddit.com/api/posts/search" in url:
            raise RuntimeError("arctic blocked")
        assert "api.pullpush.io/reddit/search/submission" in url
        return {
            "data": [
                {
                    "id": "rd1",
                    "subreddit": "cybersecurity",
                    "author": "builder",
                    "title": "Detection engineering pain",
                    "selftext": "SOC teams still have detection gaps.",
                    "permalink": "/r/cybersecurity/comments/rd1/detection_engineering_pain/",
                    "score": 42,
                    "num_comments": 7,
                    "created_utc": 1782900000,
                }
            ]
        }

    entries = reddit_feed_entries("https://www.reddit.com/r/cybersecurity/.rss", fake_fetch_json)

    assert len(entries) == 1
    assert entries[0]["title"] == "Detection engineering pain"
    assert entries[0]["link"].endswith("/r/cybersecurity/comments/rd1/detection_engineering_pain/")
    assert requested_urls[0].startswith("https://arctic-shift.photon-reddit.com/api/posts/search?")
    assert requested_urls[1].startswith("https://api.pullpush.io/reddit/search/submission?")


if __name__ == "__main__":
    test_reddit_feed_entries_uses_arctic_then_pullpush()
    print("PASS")
