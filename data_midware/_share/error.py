from enum import Enum


class ErrorCode(Enum):
    OK = (-1, 200, '-', '-')  # Code, Status, Error, Message

    SERVER_INTERNAL_ERROR = (9, 500, 'Server', 'Internal error.')

    ENCRYPTION_INVALID_DATA = (101, 400, 'Encryption', 'Invalid data encryption.')
    ENCRYPTION_INVALID_KEY = (102, 406, 'Encryption', 'Invalid encryption key.')
    ENCRYPTION_INVALID_SIGNATURE = (199, 403, 'Signature', 'Invalid signature.')

    NONCE_GET_NEW = (20, 303, 'Nonce', 'Get a new nonce.')
    NONCE_INVALID = (20000, 400, 'Nonce', 'Invalid nonce.')

    SESSION_NOT_FOUND = (301, 401, 'Session', 'Not found.')
    SESSION_REPLACED = (302, 401, 'Session', 'Replaced by new login.')
    SESSION_TOKEN_WRONG = (303, 401, 'Session', 'Session token wrong.')
    SESSION_EXPIRED = (304, 401, 'Session', 'Expired.')
    TARGET_SESSION_NOT_FOUND = (305, 404, 'Session', 'Not found.')
    TARGET_LOCK_NOT_FOUND = (306, 404, 'Lock', 'Not found.')

    PASSWORD_EXPIRED = (41, 303, 'Password', 'Expired.')
    PASSWORD_WEAK = (42, 303, 'Password', 'Too weak.')
    USER_DELETED = (43, 404, 'User', 'Deleted.')
    USER_NOT_FOUND = (401, 404, 'User', 'Not found.')
    EMAIL_NOT_FOUND = (402, 404, 'Email', 'Not found.')
    EMAIL_ALREADY_EXISTS = (403, 409, 'Email', 'Already exists.')
    PASSWORD_WRONG = (404, 401, 'Password', 'Wrong.')
    EMAIL_WRONG = (405, 403, 'Email', 'Wrong.')
    EMAIL2_WRONG = (406, 403, 'Email2', 'Wrong.')
    NEW_PASSWORD_WEAK = (407, 406, 'Password', 'New password too weak.')
    NEW_PASSWORD_USED = (408, 406, 'Password', 'New password used before.')

    APP_ID_NOT_FOUND = (501, 404, 'ID', 'Not found.')
    APP_MFA_SECRET_INVALID = (50001, 406, 'Secret', 'Invalid secret.')

    IP_FORBIDDEN = (6001, 403, 'IP', 'Client IP is not allowed.')
    USER_LOCKED = (6002, 403, 'Lock', 'User locked.')
    SYSTEM_NEED_ADMIN = (6003, 403, 'System', 'Require admin.')

    VERIFY_EMAIL_NOT_FOUND = (700, 404, 'Verify', 'Verify email not found.')

    SYSTEM_LOAD_DATA_FAILED = (801, 503, 'System', 'Load data failed.')
    SYSTEM_SAVE_DATA_FAILED = (802, 503, 'System', 'Save data failed.')
    SYSTEM_BOTH_DATA_FAILED = (803, 503, 'System', 'Load and save data failed.')
    SYSTEM_REGISTER_FORBIDDEN = (8001, 403, 'System', 'Register is not allowed.')
    SYSTEM_LAST_ADMIN = (8002, 406, 'System', 'Last admin user.')
    SYSTEM_DELETED_USER = (8003, 406, 'System', 'Only delete only trashed user.')
    ADMIN_NOT_MANAGE_ADMIN = (8004, 406, 'Admin', 'Target user is admin.')
    APP_NOT_FOR_ADMIN = (8005, 406, 'App', 'Not for admin.')

    OTHER_INVALID_DATA = (90001, 406, 'DATA', 'Invalid request data.')
    OTHER_PARAMETER_REQUIRED = (90002, 406, 'Parameter', 'Parameter required.')
    OTHER_WS_TIMEOUT = (90003, 101, 'WS', 'Connection timeout.')
    OTHER_WS_TERMINATED = (90004, 101, 'WS', 'Connection terminated.')

    def __init__(self, error_code: int, http_status: int, error_type: str, error_message: str):
        self.error_code = error_code
        self.http_status = http_status
        self.error_type = error_type
        self.error_message = error_message
