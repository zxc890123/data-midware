from pydantic import BaseModel
from uuid import UUID


class NewUserModel(BaseModel):
    email: str
    password: str
    admin: bool = False
    email2: str = None
    name: str = None
    allow_ip: list[str] = ['0.0.0.0/0', '::/0']
    deny_ip: list[str] = []
    protect: bool = False


class UpdateUserModel(BaseModel):
    user_id: UUID
    password: str = None
    status: int = None
    email2: str = None
    name: str = None
    allow_ip: list[str] = None
    deny_ip: list[str] = None
    protect: bool = None


class HistoryConfigModel(BaseModel):
    email_mask: str = None
    password: int = None
    email2_mask: str = None
    name: str = None
    allow_ip: list[str] = None
    deny_ip: list[str] = None
    protect: bool = None
    locked: bool = None


class SystemCommonConfigModel(BaseModel):
    system_allow_register: bool = None
    user_passwd_require_digit: bool = None
    user_passwd_require_upper: bool = None
    user_passwd_require_lower: bool = None
    user_passwd_require_special: bool = None
    user_passwd_require_unicode: bool = None
    user_passwd_require_length: int = None
    user_passwd_expire: float = None
    user_history_login_number: int = None
    user_history_passwd_number: int = None
    user_history_config_number: int = None
    user_history_delete_number: int = None
    user_delete_retain_period: float = None
    user_session_expire: float = None
    user_session_token_fallback: int = None
    user_session_number: int = None
    user_lock_period: float = None
    user_lock_ip_only: bool = None
    login_fail_count: int = None
    login_fail_count_expire: float = None
    email_verify_expire: int = None
    system_allow_ip: list[str] = None
    system_deny_ip: list[str] = None


class SystemInternalConfigModel(BaseModel):
    internal_data_clear_interval: str = None
    internal_session_refresh_interval: str = None
    internal_login_nonce_ttl: str = None
    internal_old_nonce_timeout: str = None
    internal_func_cache_ttl: str = None
    internal_signature_private_key: str = None
    internal_elasticsearch_url: str = None
    internal_elasticsearch_index: str = None
    internal_elasticsearch_apikey: str = None
    internal_influxdb_url: str = None
    internal_influxdb_org: str = None
    internal_influxdb_token: str = None
    internal_influxdb_bucket: str = None


class UserOtherConfigModel(BaseModel):
    name: str = None
    allow_ip: list[str] = None
    deny_ip: list[str] = None
    protect: bool = None
