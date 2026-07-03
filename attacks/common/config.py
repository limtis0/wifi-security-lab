from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AttackConfig:
    target_bssid: str = ""
    target_ssid: str = "DragonbloodLab"
    channel: int = 6


@dataclass(frozen=True)
class TimingAttackConfig(AttackConfig):
    samples_per_group: int = 1000
    inter_sample_delay_ms: float = 10.0
    timeout_seconds: float = 5.0
    password_groups: list[str] = field(
        default_factory=lambda: ["short_pw", "medium_password", "a_very_long_password_string"]
    )


@dataclass(frozen=True)
class PasswordRecoveryConfig(TimingAttackConfig):
    dictionary_path: str = ""
    dictionary_words: list[str] = field(default_factory=list)
    station_mac_prefix: str = "02:00:00:00:01"
    max_mac_addresses: int = 15


@dataclass(frozen=True)
class DowngradeAttackConfig(AttackConfig):
    beacon_injection_rate_ms: float = 50.0
    monitor_duration_seconds: float = 30.0
    target_key_mgmt: str = "WPA-PSK"
