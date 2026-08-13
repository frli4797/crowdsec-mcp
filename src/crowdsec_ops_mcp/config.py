from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Config:
    crowdsec_lapi_url: str | None
    crowdsec_lapi_key: str | None
    crowdsec_lapi_machine_id: str | None
    crowdsec_lapi_machine_password: str | None
    cscli_path: str
    default_window: str
    write_audit_log_path: str
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            crowdsec_lapi_url=os.getenv("CROWDSEC_LAPI_URL"),
            crowdsec_lapi_key=os.getenv("CROWDSEC_LAPI_KEY"),
            crowdsec_lapi_machine_id=os.getenv("CROWDSEC_LAPI_MACHINE_ID"),
            crowdsec_lapi_machine_password=os.getenv("CROWDSEC_LAPI_MACHINE_PASSWORD"),
            cscli_path=os.getenv("CSCLI_PATH", "cscli"),
            default_window=os.getenv("DEFAULT_WINDOW", "24h"),
            write_audit_log_path=os.getenv("WRITE_AUDIT_LOG_PATH", "crowdsec-write-audit.jsonl"),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        )
