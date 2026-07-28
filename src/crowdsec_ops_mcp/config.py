from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Config:
    crowdsec_lapi_url: str | None
    crowdsec_lapi_key: str | None
    cscli_path: str
    default_window: str
    write_execute_default: bool

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            crowdsec_lapi_url=os.getenv("CROWDSEC_LAPI_URL"),
            crowdsec_lapi_key=os.getenv("CROWDSEC_LAPI_KEY"),
            cscli_path=os.getenv("CSCLI_PATH", "cscli"),
            default_window=os.getenv("DEFAULT_WINDOW", "24h"),
            write_execute_default=os.getenv("WRITE_EXECUTE_DEFAULT", "false").lower() == "true",
        )
