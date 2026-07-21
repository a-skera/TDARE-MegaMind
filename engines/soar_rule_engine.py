"""
SOAR Rule Engine

Loads YAML rules and maps extracted features (ip, alert_level) to SSH commands.
No detection logic (as we depend on our detection_engines and smart agents) - only rule matching.
"""

from pathlib import Path
from typing import Dict, Any, Optional

# Optional YAML; fallback to empty rules if not installed
try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

from utils.soar_event_bus import publish_event


def _get_rules_path() -> Path:
    """Resolve config path relative to project root."""
    base = Path(__file__).resolve().parent.parent
    return base / "config" / "soar_rules.yaml"


def load_rules(rules_path: Optional[Path] = None) -> list:
    """
    Load SOAR rules from YAML file.
    Returns empty list if file missing or YAML not installed.
    """
    path = rules_path or _get_rules_path()
    if not path.exists() or not _HAS_YAML:
        return []

    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        rules = data.get("rules") if isinstance(data, dict) else []
        rules_list = rules if isinstance(rules, list) else []
        publish_event(
            "rules_loaded",
            {
                "rule_count": len(rules_list),
                "path": str(path),
            },
            source="rule_engine",
        )
        return rules_list
    except Exception:
        return []


def _normalize_level(level: Any) -> str:
    """Normalize alert_level for case-insensitive matching."""
    if level is None:
        return ""
    return str(level).lower().strip()


def _match_rule(rule: Dict[str, Any], features: Dict[str, Any]) -> bool:
    """
    Check if features match a single rule.
    Supports: alert_level, event_id (optional), ip (optional).
    """
    levels = rule.get("alert_level")
    if levels is not None:
        if isinstance(levels, str):
            levels = [levels]
        feat_level = _normalize_level(features.get("alert_level"))
        if feat_level not in [str(l).lower() for l in levels]:
            return False

    event_ids = rule.get("event_id")
    if event_ids is not None:
        if isinstance(event_ids, (int, str)):
            event_ids = [event_ids]
        feat_eid = features.get("event_id")
        if feat_eid is None:
            return False
        if int(feat_eid) not in [int(e) for e in event_ids]:
            return False

    return True


def decide_action_from_rules(features: Dict[str, Any], rules: Optional[list] = None) -> Optional[str]:
    """
    Match features against rules and return the SSH command to execute.
    First matching rule wins.

    Args:
        features: Dict from extract_soar_features, e.g. {ip, alert_level, event_id}.
        rules: Optional list of rules; if None, loads from config.

    Returns:
        SSH command string with {ip} substituted, or None for no_action.
    """
    if not features or not isinstance(features, dict):
        return None

    if rules is None:
        rules = load_rules()

    ip = str(features.get("ip") or "unknown")

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if not _match_rule(rule, features):
            continue

        action = rule.get("action", "")
        if action == "no_action":
            return None

        cmd = rule.get("command")
        if cmd and isinstance(cmd, str):
            return cmd.replace("{ip}", ip)

        return None

    return None
