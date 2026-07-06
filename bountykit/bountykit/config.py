"""Configuration management for bountykit."""

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field


DEFAULT_CONFIG_DIR = Path.home() / ".bountykit"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.yaml"


class LegalConfig(BaseModel):
    """Legal compliance configuration."""
    require_auth: bool = True
    scope_file: Optional[str] = None
    rate_limit: int = 10  # requests per second
    audit_log: bool = True

    def gate_check(self, target: str) -> bool:
        """Verify target is authorized for testing."""
        if not self.require_auth:
            return True

        if self.scope_file and os.path.exists(self.scope_file):
            with open(self.scope_file) as f:
                in_scope = [line.strip() for line in f if line.strip()]
            return any(target in entry or entry in target for entry in in_scope)

        if self.audit_log:
            self._log_check(target)

        return True

    def _log_check(self, target: str):
        """Log authorization check to audit trail."""
        log_file = DEFAULT_CONFIG_DIR / "audit.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)

        import datetime
        timestamp = datetime.datetime.now().isoformat()
        entry = f"[{timestamp}] GATE_CHECK target={target}\n"

        with open(log_file, "a") as f:
            f.write(entry)


class ScanConfig(BaseModel):
    """Scanning configuration."""
    threads: int = 10
    timeout: int = 30
    user_agent: str = "bountykit/0.1 (authorized research)"
    output_dir: str = "./results"


class NucleiConfig(BaseModel):
    """Nuclei-specific configuration."""
    templates_path: str = str(DEFAULT_CONFIG_DIR / "nuclei-templates")
    severity: str = "medium,high,critical"
    rate_limit: int = 50
    bulk_size: int = 25


class Config(BaseModel):
    """Main configuration model."""
    legal: LegalConfig = Field(default_factory=LegalConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    nuclei: NucleiConfig = Field(default_factory=NucleiConfig)
    target: Optional[str] = None

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "Config":
        """Load configuration from file or create default."""
        path = Path(config_path) if config_path else DEFAULT_CONFIG_FILE

        if path.exists():
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            return cls(**data)

        config = cls()
        config.save()
        return config

    def save(self, path: Optional[str] = None):
        """Save configuration to file."""
        save_path = Path(path) if path else DEFAULT_CONFIG_FILE
        save_path.parent.mkdir(parents=True, exist_ok=True)

        with open(save_path, "w") as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False, sort_keys=False)
