# core/config.py
import os
import yaml
from typing import Optional
from pydantic import BaseModel, Field
from core.logger import logger


class ActiveDirectoryConfig(BaseModel):
    domain_controller: str = "dc01.domain.local"
    domain_name: str = "domain.local"
    ldap_port: int = 389
    use_ssl: bool = False
    username: Optional[str] = None
    password: Optional[str] = None


class EntraIdConfig(BaseModel):
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None


class SplunkConfig(BaseModel):
    host: str = "localhost"
    port: int = 8089
    username: str = "admin"
    password: str = "changeme"
    verify_ssl: bool = False
    index: str = "security"


class ElasticConfig(BaseModel):
    host: str = "http://localhost:9200"
    api_key: Optional[str] = None
    verify_ssl: bool = False
    index: str = "winlogbeat-*"


class SentinelConfig(BaseModel):
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    workspace_id: Optional[str] = None


class SiemConfig(BaseModel):
    provider: str = "mock"
    propagation_delay_seconds: int = 10
    splunk: SplunkConfig = Field(default_factory=SplunkConfig)
    elastic: ElasticConfig = Field(default_factory=ElasticConfig)
    sentinel: SentinelConfig = Field(default_factory=SentinelConfig)


class ReportingConfig(BaseModel):
    output_dir: str = "./reports/output"
    format: str = "html"


class ExecutionConfig(BaseModel):
    allow_live_actions: bool = False


class KronosConfig(BaseModel):
    active_directory: ActiveDirectoryConfig = Field(
        default_factory=ActiveDirectoryConfig
    )
    entra_id: EntraIdConfig = Field(default_factory=EntraIdConfig)
    siem: SiemConfig = Field(default_factory=SiemConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)


def load_config(config_path: str = "config.yaml") -> KronosConfig:
    """Loads and validates the configuration from yaml."""
    if not os.path.exists(config_path):
        logger.warning(
            f"Configuration file '{config_path}' not found. Using default mock configuration."
        )
        return KronosConfig()

    try:
        with open(config_path, "r") as f:
            data = yaml.safe_load(f) or {}
        logger.success(f"Configuration file '{config_path}' loaded successfully.")
        return KronosConfig(**data)
    except Exception as e:
        logger.error(
            f"Configuration validation failed: {e}. Falling back to default mock configuration."
        )
        return KronosConfig()
