from fastapi import Depends

from .._share.log import Log_Fields
from .._share.error import ErrorCode
from .._share.crypto import CryptoAES
from .._share.api import log_with_user_info


def user_not_admin(
    log: Log_Fields = Depends(log_with_user_info)
) -> Log_Fields:
    if log.res_error != ErrorCode.OK:
        return log

    if log.user_info['admin']:
        log.res_error = ErrorCode.APP_NOT_FOR_ADMIN
    return log


def user_with_data_key(
    log: Log_Fields = Depends(user_not_admin)
) -> Log_Fields:
    if log.res_error != ErrorCode.OK:
        return log

    if 'data_key' not in log.session_info:
        log.session_info['data_key'] = CryptoAES(log.session_info['token']).decrypt(
            log.session_info['session_data_key'][log.session_info['token_index']]
        )
    return log
