"""
Configuration management for CaaS Prototype.

This module provides centralized configuration using Pydantic BaseSettings,
loading values from environment variables and .env file.
"""

from typing import List
from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import field_validator
import json


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_name: str = "CaaS-Prototype"
    app_version: str = "1.0.0"
    environment: str = "development"
    debug: bool = False

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4

    # Security
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # Master Key (for encrypting stored keys)
    master_key_secret: str
    master_key_salt: str

    # Database
    database_url: str = "sqlite:///./data/caas.db"
    database_echo: bool = False

    # Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 100

    # CORS
    cors_origins: str = '["http://localhost:3000"]'

    # Logging
    log_level: str = "INFO"
    log_file: str = "./logs/app.log"
    log_rotation: str = "10MB"
    log_retention: str = "30 days"

    # SSL/TLS
    ssl_enabled: bool = False
    ssl_keyfile: str = "./certs/key.pem"
    ssl_certfile: str = "./certs/cert.pem"

    # Audit
    audit_enabled: bool = True
    audit_log_sensitive_data: bool = False

    @field_validator('cors_origins')
    @classmethod
    def parse_cors_origins(cls, v):
        """Parse CORS origins from string to list."""
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                # If it's a single origin without brackets, return as list
                return [v.strip()]
        return v

    class Config:
        """Pydantic configuration."""
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.

    This function uses lru_cache to ensure Settings is instantiated only once,
    providing a singleton pattern for configuration access.

    Returns:
        Settings: The application settings instance
    """
    return Settings()


# Convenience access to settings
settings = get_settings()
