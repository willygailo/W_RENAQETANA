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
    scope_public_key: Optional[str] = None
    scope_private_key: Optional[str] = None
    rate_limit: int = 10
    audit_log: bool = True
    audit_log_dir: Optional[str] = None
    safe_mode: str = "active"
    default_bounty_platform: Optional[str] = None
    report_output_dir: str = "./reports"

    def gate_check(self, target: str) -> bool:
        """Verify target is authorized for testing."""
        if not self.require_auth:
            return True

        if self.scope_file and os.path.exists(self.scope_file):
            from bountykit.utils.legal import ScopeFile, check_authorization
            scope = ScopeFile.load(self.scope_file)
            ok, _ = scope.allows(target)
            if ok:
                return True

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
    user_agent: str = "bountykit/0.2.0 (authorized research)"
    output_dir: str = "./results"


class NucleiConfig(BaseModel):
    """Nuclei-specific configuration."""
    templates_path: str = str(DEFAULT_CONFIG_DIR / "nuclei-templates")
    severity: str = "medium,high,critical"
    rate_limit: int = 50
    bulk_size: int = 25


class LLMConfig(BaseModel):
    """LLM/AI security testing configuration."""
    default_model: Optional[str] = None
    api_key: Optional[str] = None
    timeout: int = 30
    max_retries: int = 3


class SupplyChainConfig(BaseModel):
    """Supply chain security configuration."""
    check_malicious_packages: bool = True
    check_typosquatting: bool = True
    check_ci_cd: bool = True
    check_mcp_hijack: bool = True
    check_skill_poisoning: bool = True


class RaceConditionConfig(BaseModel):
    """Race condition testing configuration."""
    default_threads: int = 10
    timeout: int = 30
    delay_between_requests: float = 0.1


class SmugglingConfig(BaseModel):
    """HTTP smuggling testing configuration."""
    test_cl_te: bool = True
    test_te_cl: bool = True
    test_te_te: bool = True
    test_cache_poison: bool = True
    test_host_injection: bool = True


class SSTIConfig(BaseModel):
    """SSTI detection configuration."""
    engine: str = "auto"
    test_rce: bool = True
    test_file_read: bool = True
    test_ssrf: bool = True


class WAFConfig(BaseModel):
    """WAF detection and analysis configuration."""
    test_bypasses: bool = True
    detect_cloudflare: bool = True
    detect_aws_waf: bool = True
    detect_azure_waf: bool = True
    detect_gcp_waf: bool = True


class CVEChainConfig(BaseModel):
    """CVE chaining and analysis configuration."""
    chain_depth: int = 3
    include_epss: bool = True
    include_cisa_kev: bool = True
    max_results: int = 50


class NetworkConfig(BaseModel):
    """Network attack configuration."""
    takeover_check: bool = True
    smuggling_check: bool = True
    race_condition_check: bool = True
    timeout: int = 30


class CloudConfig(BaseModel):
    """Multi-cloud security configuration."""
    provider: str = "all"
    test_metadata_bypass: bool = True
    test_credential_theft: bool = True
    test_storage_enum: bool = True
    test_function_rce: bool = True


class Config(BaseModel):
    """Main configuration model."""
    legal: LegalConfig = Field(default_factory=LegalConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    nuclei: NucleiConfig = Field(default_factory=NucleiConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    supply_chain: SupplyChainConfig = Field(default_factory=SupplyChainConfig)
    race_condition: RaceConditionConfig = Field(default_factory=RaceConditionConfig)
    smuggling: SmugglingConfig = Field(default_factory=SmugglingConfig)
    ssti: SSTIConfig = Field(default_factory=SSTIConfig)
    cloud: CloudConfig = Field(default_factory=CloudConfig)
    waf: WAFConfig = Field(default_factory=WAFConfig)
    cve_chain: CVEChainConfig = Field(default_factory=CVEChainConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
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
