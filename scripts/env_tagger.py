#!/usr/bin/env python3
"""
Environment Tagger Module

Uses Claude API to analyze security signals and tag them with relevant
environment/infrastructure categories for filtering.

Categories:
- Cloud: aws, azure, gcp, on-prem
- Infrastructure: kubernetes, docker, vmware, terraform, linux, windows
- Security Stack: crowdstrike, sentinelone, microsoft_defender, splunk, elastic, palo_alto
- Identity: okta, azure_ad, office_365, google_workspace, slack
- Threat Focus: ransomware, apt, supply_chain, zero_day, phishing
"""

import os
import json
import re
from typing import List, Dict, Optional
from dataclasses import dataclass

# Try to import anthropic, but make it optional
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

# Environment tag categories with their valid values
ENV_TAG_SCHEMA = {
    "cloud": ["aws", "azure", "gcp", "on_prem"],
    "infrastructure": ["kubernetes", "docker", "vmware", "terraform", "linux", "windows"],
    "security_stack": ["crowdstrike", "sentinelone", "microsoft_defender", "splunk", "elastic", "palo_alto"],
    "identity": ["okta", "azure_ad", "office_365", "google_workspace", "slack"],
    "threat_focus": ["ransomware", "apt", "supply_chain", "zero_day", "phishing"]
}

# Flattened list of all valid tags
ALL_VALID_TAGS = []
for category, tags in ENV_TAG_SCHEMA.items():
    ALL_VALID_TAGS.extend(tags)

# Fallback keyword mapping for when API is unavailable
FALLBACK_KEYWORDS = {
    # Cloud
    "aws": ["aws", "amazon web services", "ec2", "s3", "lambda", "cloudfront", "rds", "eks", "ecs", "iam", "cloudwatch", "cloudtrail"],
    "azure": ["azure", "microsoft cloud", "entra", "intune", "sentinel", "defender for cloud", "azure ad"],
    "gcp": ["gcp", "google cloud", "bigquery", "gke", "cloud run", "compute engine"],
    "on_prem": ["on-premises", "on-prem", "data center", "physical server", "bare metal"],

    # Infrastructure
    "kubernetes": ["kubernetes", "k8s", "kubectl", "helm", "container orchestration", "eks", "aks", "gke", "pod", "deployment"],
    "docker": ["docker", "container", "dockerfile", "docker-compose", "containerized"],
    "vmware": ["vmware", "vsphere", "esxi", "vcenter", "vmware horizon"],
    "terraform": ["terraform", "infrastructure as code", "iac", "hashicorp"],
    "linux": ["linux", "ubuntu", "centos", "rhel", "debian", "fedora", "unix", "bash"],
    "windows": ["windows", "windows server", "active directory", "powershell", "microsoft windows", "win32", "win64"],

    # Security Stack
    "crowdstrike": ["crowdstrike", "falcon", "crowdstrike falcon"],
    "sentinelone": ["sentinelone", "sentinel one", "s1"],
    "microsoft_defender": ["microsoft defender", "defender for endpoint", "windows defender", "mde", "defender atp"],
    "splunk": ["splunk", "spl", "splunk enterprise", "splunk cloud"],
    "elastic": ["elastic", "elasticsearch", "kibana", "elastic security", "elk stack", "elastic siem"],
    "palo_alto": ["palo alto", "pan-os", "cortex", "prisma", "wildfire", "xsoar"],

    # Identity
    "okta": ["okta", "okta identity"],
    "azure_ad": ["azure ad", "azure active directory", "entra id", "entra"],
    "office_365": ["office 365", "o365", "microsoft 365", "m365", "exchange online", "sharepoint online"],
    "google_workspace": ["google workspace", "gsuite", "g suite", "gmail enterprise"],
    "slack": ["slack", "slack enterprise"],

    # Threat Focus
    "ransomware": ["ransomware", "lockbit", "blackcat", "alphv", "clop", "akira", "play ransomware", "royal ransomware", "rhysida", "extortion", "encrypted files", "ransom note"],
    "apt": ["apt", "apt28", "apt29", "apt41", "nation-state", "state-sponsored", "advanced persistent threat", "cozy bear", "fancy bear", "lazarus", "threat actor"],
    "supply_chain": ["supply chain", "supply-chain", "software supply chain", "solarwinds", "codecov", "dependency confusion", "typosquatting", "malicious package"],
    "zero_day": ["zero-day", "0-day", "zero day", "unpatched", "actively exploited", "in the wild"],
    "phishing": ["phishing", "spear-phishing", "credential theft", "social engineering", "business email compromise", "bec"]
}


def tag_with_keywords(text: str) -> List[str]:
    """
    Fallback tagging using keyword matching.
    Returns list of matching environment tags.
    """
    text_lower = text.lower()
    matched_tags = []

    for tag, keywords in FALLBACK_KEYWORDS.items():
        for keyword in keywords:
            if keyword.lower() in text_lower:
                matched_tags.append(tag)
                break  # Found match for this tag, move to next

    return list(set(matched_tags))


def tag_with_llm(title: str, summary: str, content: str = "") -> List[str]:
    """
    Use Claude API to analyze signal and return relevant environment tags.
    Falls back to keyword matching if API unavailable or fails.
    """
    if not ANTHROPIC_AVAILABLE:
        return tag_with_keywords(f"{title} {summary} {content}")

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return tag_with_keywords(f"{title} {summary} {content}")

    try:
        client = anthropic.Anthropic(api_key=api_key)

        prompt = f"""Analyze this security signal and identify which infrastructure/environment categories it's relevant to.

SIGNAL:
Title: {title}
Summary: {summary}
{f"Content: {content[:500]}" if content else ""}

CATEGORIES (only return tags from this list):
- Cloud: aws, azure, gcp, on_prem
- Infrastructure: kubernetes, docker, vmware, terraform, linux, windows
- Security Stack: crowdstrike, sentinelone, microsoft_defender, splunk, elastic, palo_alto
- Identity: okta, azure_ad, office_365, google_workspace, slack
- Threat Focus: ransomware, apt, supply_chain, zero_day, phishing

Return ONLY a JSON array of relevant tags. Be specific - only include tags if the signal directly relates to that technology or threat type.
Example: ["aws", "kubernetes", "ransomware"]
If no specific tags apply, return: []"""

        message = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=200,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        response_text = message.content[0].text.strip()

        # Parse JSON array from response
        # Handle potential markdown code blocks
        if "```" in response_text:
            response_text = re.search(r'\[.*?\]', response_text, re.DOTALL)
            if response_text:
                response_text = response_text.group()
            else:
                return tag_with_keywords(f"{title} {summary} {content}")

        tags = json.loads(response_text)

        # Validate tags are in our schema
        valid_tags = [t for t in tags if t in ALL_VALID_TAGS]

        return valid_tags

    except Exception as e:
        # Fall back to keyword matching on any error
        print(f"LLM tagging failed, using keywords: {e}")
        return tag_with_keywords(f"{title} {summary} {content}")


def tag_signal(signal: Dict) -> Dict:
    """
    Add env_tags to a signal dictionary.

    Args:
        signal: Signal dictionary with title, summary, etc.

    Returns:
        Signal dictionary with env_tags field added
    """
    title = signal.get("title", "")
    summary = signal.get("summary", signal.get("excerpt", ""))
    content = signal.get("content", "")

    # Check if already tagged
    if signal.get("env_tags"):
        return signal

    # Get tags
    tags = tag_with_llm(title, summary, content)

    # Add to signal
    signal["env_tags"] = tags

    return signal


def tag_signals_batch(signals: List[Dict], use_llm: bool = True) -> List[Dict]:
    """
    Tag a batch of signals with environment tags.

    Args:
        signals: List of signal dictionaries
        use_llm: Whether to use LLM (True) or just keywords (False)

    Returns:
        List of signals with env_tags added
    """
    tagged_signals = []

    for i, signal in enumerate(signals):
        if signal.get("env_tags"):
            # Already tagged
            tagged_signals.append(signal)
            continue

        title = signal.get("title", "")
        summary = signal.get("summary", signal.get("excerpt", ""))
        content = signal.get("content", "")

        if use_llm:
            tags = tag_with_llm(title, summary, content)
        else:
            tags = tag_with_keywords(f"{title} {summary} {content}")

        signal["env_tags"] = tags
        tagged_signals.append(signal)

        # Progress indicator for large batches
        if (i + 1) % 10 == 0:
            print(f"Tagged {i + 1}/{len(signals)} signals...")

    return tagged_signals


if __name__ == "__main__":
    # Test the tagger
    test_signals = [
        {
            "title": "CrowdStrike Falcon Detects New Ransomware Variant",
            "summary": "CrowdStrike's Falcon platform has identified a new LockBit variant targeting Windows servers in enterprise environments."
        },
        {
            "title": "Critical Kubernetes Vulnerability Allows Container Escape",
            "summary": "A zero-day vulnerability in Kubernetes allows attackers to escape containers and access the host node. Affects AWS EKS and Azure AKS."
        },
        {
            "title": "Phishing Campaign Targets Okta Users",
            "summary": "APT29 is conducting spear-phishing attacks against organizations using Okta for identity management."
        }
    ]

    print("Testing environment tagger...\n")

    for signal in test_signals:
        print(f"Title: {signal['title']}")
        tags = tag_with_keywords(f"{signal['title']} {signal['summary']}")
        print(f"Keyword Tags: {tags}")

        if ANTHROPIC_AVAILABLE and os.environ.get("ANTHROPIC_API_KEY"):
            llm_tags = tag_with_llm(signal['title'], signal['summary'])
            print(f"LLM Tags: {llm_tags}")

        print()
