import logging
_logger = logging.getLogger(__name__)

from json import load, dump
from os import getenv, path
from .. import root_dir

system_config_file_path = getenv('SYSTEM_CONFIG_FILE') or path.join(root_dir, 'system_config.json')
if not path.isabs(system_config_file_path):
    system_config_file_path = path.join(root_dir, system_config_file_path)


class SystemConfig(object):
    __slots__ = (
        'system_allow_register',
        'user_passwd_require_digit',
        'user_passwd_require_upper',
        'user_passwd_require_lower',
        'user_passwd_require_special',
        'user_passwd_require_unicode',
        'user_passwd_require_length',
        'user_passwd_expire',
        'user_history_login_number',
        'user_history_passwd_number',
        'user_history_config_number',
        'user_history_delete_number',
        'user_delete_retain_period',
        'user_session_expire',
        'user_session_token_fallback',
        'user_session_number',
        'user_lock_period',
        'user_lock_ip_only',
        'login_fail_count',
        'login_fail_count_expire',
        'email_verify_expire',
        'system_allow_ip',
        'system_deny_ip',
        'system_acl_serial',
        'internal_data_clear_interval',
        'internal_session_refresh_interval',
        'internal_login_nonce_ttl',
        'internal_old_nonce_timeout',
        'internal_func_cache_ttl',
        'internal_signature_private_key',
        'internal_elasticsearch_url',
        'internal_elasticsearch_index',
        'internal_elasticsearch_apikey',
        'internal_influxdb_url',
        'internal_influxdb_org',
        'internal_influxdb_token',
        'internal_influxdb_bucket',
    )

    def __init__(self):
        self.system_allow_register = False
        self.user_passwd_require_digit = False
        self.user_passwd_require_upper = False
        self.user_passwd_require_lower = False
        self.user_passwd_require_special = False
        self.user_passwd_require_unicode = False
        self.user_passwd_require_length = 0
        self.user_passwd_expire = -1.0
        self.user_history_login_number = 10000
        self.user_history_passwd_number = 0
        self.user_history_config_number = 2000
        self.user_history_delete_number = 1000
        self.user_delete_retain_period = 30.0
        self.user_session_expire = 10080.0
        self.user_session_token_fallback = 1
        self.user_session_number = 3
        self.user_lock_period = 60.0
        self.user_lock_ip_only = True
        self.login_fail_count = 5
        self.login_fail_count_expire = 30.0
        self.email_verify_expire = 600
        self.system_allow_ip = ['0.0.0.0/0', '::/0']
        self.system_deny_ip = []
        self.system_acl_serial = 0
        self.internal_data_clear_interval = 3600
        self.internal_session_refresh_interval = 600
        self.internal_login_nonce_ttl = 10
        self.internal_old_nonce_timeout = 10
        self.internal_func_cache_ttl = 3600
        self.internal_signature_private_key = 'private_key.pem'
        self.internal_elasticsearch_url = ''
        self.internal_elasticsearch_index = ''
        self.internal_elasticsearch_apikey = ''
        self.internal_influxdb_url = ''
        self.internal_influxdb_org = ''
        self.internal_influxdb_token = ''
        self.internal_influxdb_bucket = ''

    def load(self) -> bool:
        try:
            with open(system_config_file_path) as system_config_file:
                _data = load(system_config_file)
            for key, value in _data.items():
                if key not in self.__slots__:
                    _logger.warning(f'System: Unknown system config key: "{key}", ignored.')
                    continue
                if type(getattr(self, key)) is not type(value):
                    _logger.warning((
                        f'System: System config key "{key}" '
                        f'should be type of "{type(getattr(self, key)).__name__}", '
                        f'but got "{type(value).__name__}", ignored.'
                    ))
                    continue
                setattr(self, key, value)
            self.system_acl_serial = self.system_acl_serial & 0xffffffff
            self.user_session_expire = max(
                self.internal_session_refresh_interval * 2 / 60,
                self.user_session_expire
            )
            _logger.info('System: Loaded system config.')
            return True
        except Exception as identifier:
            _logger.error(f'System: Load system config failed: {identifier}')
            _logger.warning('System: Using default system config.')
            return False

    def save(self) -> None:
        # 在API中处理错误
        _data = {key: getattr(self, key) for key in self.__slots__}
        with open(system_config_file_path, 'w') as system_config_file:
            dump(_data, system_config_file, ensure_ascii=False, indent=2)
