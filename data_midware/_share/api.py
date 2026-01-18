from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Coroutine, Any

from time import time
from asyncio import sleep, wait_for
from os import urandom
from random import random
from uuid import UUID
from base64 import b64decode
from urllib.parse import urlencode

from fastapi import (
    APIRouter,
    Body,
    BackgroundTasks,
    Cookie,
    Depends,
    Header,
    Request,
    WebSocket
)
from fastapi.responses import JSONResponse

from .db import session_factory
from .crypto import CryptoAES
from .instance import (
    system_config,
    default_rsa,
    verify_rsa,
    default_cache
)
from .log import Log_Fields, default_logger
from .batch import (
    match_ip,
    get_hash,
    update_user_session,
    delete_expired_users_session,
    delete_redundant_users_session,
    check_session_nonce
)
from .sql import simple_select_one, select_multi, get_one_user
from .._main.table import TB_USERS_SESSION
from .error import ErrorCode

router = APIRouter()


async def init_log(
    request: Request,
    x_forwarded_for: str | None = Header(None)
) -> Log_Fields:
    if x_forwarded_for:
        ip = [x.strip() for x in x_forwarded_for.split(',')][-1]
    else:
        ip = request.client.host
    log = Log_Fields(
        ip=ip,
        method=request.method,
        path=request.url.path,
        start_time=time()
    )
    if request.url.query:
        log.query = request.url.query

    try:
        if not await match_ip(
            ip,
            system_config.system_allow_ip,
            system_config.system_deny_ip,
            system_config.system_acl_serial.to_bytes(4),
            aiocache_wait_for_write=False
        ):
            log.res_error = ErrorCode.IP_FORBIDDEN
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = 'match_ip'
        log.debug_error = str(identifier)

    return log


def log_with_key(
    x_custom_encryption_key: str = Header(),
    log: Log_Fields = Depends(init_log)
) -> Log_Fields:
    if log.res_error != ErrorCode.OK:
        return log

    try:
        log.key = default_rsa.decrypt(x_custom_encryption_key)
        log.aes = CryptoAES(log.key)
    except Exception as identifier:
        log.res_error = ErrorCode.ENCRYPTION_INVALID_KEY
        log.internal_error = 'decrypt(x_custom_encryption_key)'
        log.debug_error = str(identifier)
    return log


async def log_with_user_info_before_nonce_check(
    session_id: UUID = Cookie(),
    x_custom_session_token: str = Header(),
    log: Log_Fields = Depends(log_with_key)
) -> Log_Fields:
    log.session_id = session_id
    if log.res_error != ErrorCode.OK:
        return log

    try:
        session_token = log.aes.decrypt(x_custom_session_token)
    except Exception as identifier:
        log.res_error = ErrorCode.ENCRYPTION_INVALID_DATA
        log.internal_error = 'decrypt(x_custom_session_token)'
        log.debug_error = str(identifier)
        return log

    session = session_factory()
    try:
        _mark = 'simple_select_one(TB_USERS_SESSION)'
        _session = await simple_select_one(session, TB_USERS_SESSION, {'session_id': session_id})
        if not _session:
            log.res_error = ErrorCode.SESSION_NOT_FOUND
            return log
        log.user_id = _session['user_id']
        hashed_session_token = get_hash(session_token, algorithm='md5').decode()
        if hashed_session_token not in _session['session_token']:
            log.res_error = ErrorCode.SESSION_TOKEN_WRONG
            return log
        _session['token'] = session_token
        _session['token_index'] = _session['session_token'].index(hashed_session_token)
        log.session_info = _session

        if log.start_time - _session['refresh_time'] > system_config.user_session_expire * 60:
            log.res_error = ErrorCode.SESSION_EXPIRED
            return log

        _mark = 'select_multi(TB_USERS_SESSION)'
        _valid_sessions = await select_multi(
            session,
            TB_USERS_SESSION,
            ['session_id'],
            in_={'user_id': [log.user_id]},
            order={'id': True},
            limit=system_config.user_session_number
        )
        if session_id not in [r['session_id'] for r in _valid_sessions]:
            log.res_error = ErrorCode.SESSION_REPLACED
            return log

        _mark = 'get_one_user'
        _user = await get_one_user(session, user_id=log.user_id)
        if not _user:  # 不可能，session.user_id是外键
            log.res_error = ErrorCode.USER_NOT_FOUND
            return log
        log.user_info = _user
        if _user['trashed_time'] >= 0:
            log.res_error = ErrorCode.USER_DELETED
            return log

        if log.ip != _session['ip']:
            _mark = 'match_ip'
            if not await match_ip(
                log.ip,
                _user['allow_ip'],
                _user['deny_ip'],
                _user['acl_serial'] + b'\xff' + _user['user_id'].bytes,
                aiocache_wait_for_write=False
            ):
                log.res_error = ErrorCode.IP_FORBIDDEN
                return log

        _mark = 'update_user_session'
        _session_token = await update_user_session(
            session,
            session_id,
            log.session_info,
            log.ip,
            log.start_time,
            aiocache_wait_for_write=False
        )
        if 'data_key' in log.session_info:
            log.new_session_token = _session_token
            _mark = 'session.commit'
            await session.commit()
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return log
    finally:
        await session.close()

    return log


async def log_with_user_info(
    log: Log_Fields = Depends(log_with_user_info_before_nonce_check)
) -> Log_Fields:
    if log.res_error != ErrorCode.OK:
        return log

    nonce = int.from_bytes(log.key[56:])
    try:
        _result = await check_session_nonce(log.session_id.bytes, nonce)
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = 'check_session_nonce'
        log.debug_error = str(identifier)
        return log
    if _result == 0:
        log.res_error = ErrorCode.NONCE_INVALID
        return log
    if _result == 2:
        log.res_error = ErrorCode.NONCE_GET_NEW
        return log
    if log.user_info['status'] & 1:
        log.res_error = ErrorCode.PASSWORD_EXPIRED
        return log
    if log.user_info['status'] & 2:
        log.res_error = ErrorCode.PASSWORD_WEAK
    return log


async def background_run(log: Log_Fields, func: 'Coroutine', *args, **kwargs) -> None:
    '''
    Run a database batch in the background_tasks.
    Provide independent database session as the first argument to the function.
    '''
    session = session_factory()
    try:
        _mark = func.__name__
        await func(session, *args, **kwargs)
        _mark = 'session.commit'
        await session.commit()
    except Exception as identifier:
        await default_logger.log('ERROR', log, server_error=_mark)
        await default_logger.log('DEBUG', log, server_error=str(identifier))
    await session.close()


def response_200(
    background_tasks: BackgroundTasks,
    log: Log_Fields,
    return_sid: bool | None = False,
    data: 'Any' = None,
    total: int | None = None
) -> JSONResponse:
    background_tasks.add_task(default_logger.log, 'INFO', log)
    background_tasks.add_task(
        background_run,
        log,
        delete_expired_users_session,
        log.start_time,
        aiocache_wait_for_write=False
    )
    background_tasks.add_task(
        background_run,
        log,
        delete_redundant_users_session,
        cache_read=return_sid is not None,
        aiocache_wait_for_write=False
    )

    _body = {'isOK': True}
    if data is not None:
        _body['data'] = data
    if total is not None:
        _body['total'] = total
    response = JSONResponse(_body)
    if return_sid:
        response.set_cookie(
            'session_id',
            value=log.session_id.hex,
            expires='Fri, 31 Dec 9999 23:59:59 GMT',
            path='/api',
            samesite='strict'
        )
    elif return_sid is None:
        response.set_cookie(
            'session_id',
            value='',
            expires='Thu, 01 Jan 1970 00:00:00 GMT',
            path='/api',
            samesite='strict'
        )
    if log.new_session_token and return_sid is not None:
        response.headers['x-custom-session-token'] = log.aes.encrypt(log.new_session_token)
    log.proc_time = time() - log.start_time
    return response


def response_err(
    background_tasks: BackgroundTasks,
    log: Log_Fields,
    data: 'Any' = None
) -> JSONResponse:
    if log.res_error.http_status == 500:
        background_tasks.add_task(default_logger.log, 'ERROR', log)
    else:
        background_tasks.add_task(default_logger.log, 'INFO', log)
    if log.debug_error != '-':
        background_tasks.add_task(default_logger.log, 'DEBUG', log)
    background_tasks.add_task(
        background_run,
        log,
        delete_expired_users_session,
        log.start_time,
        aiocache_wait_for_write=False
    )
    background_tasks.add_task(
        background_run,
        log,
        delete_redundant_users_session,
        aiocache_wait_for_write=False
    )

    _body = {
        'isOK': False,
        'error': log.res_error.error_type,
        'errorCode': log.res_error.error_code,
        'errorMessage': log.res_error.error_message
    }
    if data is not None:
        _body['data'] = data
    response = JSONResponse(
        _body,
        log.res_error.http_status
    )
    if log.new_session_token:
        response.headers['x-custom-session-token'] = log.aes.encrypt(log.new_session_token)
    if log.res_error.http_status in (400, 403):
        response.headers['connection'] = 'close'
    log.proc_time = time() - log.start_time
    return response


@router.get('/crypto/public')
async def crypto_public(
    background_tasks: BackgroundTasks,
    log: Log_Fields = Depends(init_log)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    return response_200(background_tasks, log, data=default_rsa.public_pem())


@router.get('/crypto/nonce1')
async def crypto_nonce1(
    background_tasks: BackgroundTasks,
    log: Log_Fields = Depends(init_log)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    nonce = b'\x00' * 4 + urandom(4)
    await sleep(1 - random() / 2)
    try:
        await default_cache.set(b'login_nonce\xff' + nonce, True, ttl=system_config.internal_login_nonce_ttl)
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = 'default_cache.set'
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    return response_200(background_tasks, log, data=list(nonce))


@router.get('/crypto/nonce2')
async def crypto_nonce2(
    background_tasks: BackgroundTasks,
    log: Log_Fields = Depends(log_with_user_info_before_nonce_check)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    nonce = b'\x00' * 4 + urandom(4)
    try:
        await default_cache.set(
            b'session_nonce\xff' + log.session_id.bytes,
            [int.from_bytes(nonce) - 1],
            ttl=system_config.user_session_expire * 60
        )
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = 'default_cache.set'
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    return response_200(background_tasks, log, data=list(nonce))


@router.get('/system/settings')
async def list_system_config(
    background_tasks: BackgroundTasks,
    log: Log_Fields = Depends(init_log)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    data = {
        key: getattr(system_config, key)
        for key in system_config.__slots__
        if not key.startswith('internal_') and not key.endswith('_serial')
    }
    return response_200(background_tasks, log, data=data)


@router.post('/email/verify')
async def email_verify(
    background_tasks: BackgroundTasks,
    from_: str = Body(),
    to: str = Body(),
    signature: str = Body(),
    log: Log_Fields = Depends(log_with_key)
) -> JSONResponse:
    log.req_params = urlencode({'to': to}, True)
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    try:
        _mark = 'email'
        email = log.aes.decrypt(from_)
        email.decode()
    except UnicodeDecodeError:
        log.res_error = ErrorCode.OTHER_INVALID_DATA
        log.internal_error = f'{_mark}.decode()'
        res = response_err(background_tasks, log, data=_mark)
        await sleep(2 + random() * 2)
        return res
    except Exception as identifier:
        log.res_error = ErrorCode.ENCRYPTION_INVALID_DATA
        log.internal_error = f'decrypt({_mark})'
        log.debug_error = str(identifier)
        res = response_err(background_tasks, log, data=_mark)
        await sleep(2 + random() * 2)
        return res

    if not verify_rsa.verify_signature(b64decode(signature), email + f'.{to}'.encode()):
        log.res_error = ErrorCode.ENCRYPTION_INVALID_SIGNATURE
        log.internal_error = 'public_key.verify'
        res = response_err(background_tasks, log)
        await sleep(2 + random() * 2)
        return res

    try:
        await default_cache.set(
            b'email_verify\xff' + get_hash(email),
            to.encode(),
            ttl=system_config.email_verify_expire
        )
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = 'default_cache.set'
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    return response_200(background_tasks, log)


@router.websocket('/system/ping')
async def system_ping(
    ws: WebSocket,
    x_forwarded_for: str | None = Header(None)
) -> None:
    if x_forwarded_for:
        ip = [x.strip() for x in x_forwarded_for.split(',')][-1]
    else:
        ip = ws.client.host
    log = Log_Fields(
        ip=ip,
        method='WEBSOCKET',
        path=ws.url.path,
        start_time=time()
    )
    if ws.url.query:
        log.query = ws.url.query

    try:
        if not await match_ip(
            ip,
            system_config.system_allow_ip,
            system_config.system_deny_ip,
            system_config.system_acl_serial.to_bytes(4),
            aiocache_wait_for_write=False
        ):
            log.res_error = ErrorCode.IP_FORBIDDEN
            await sleep(2 + random() * 2)
            await ws.close()
            log.proc_time = time() - log.start_time
            await default_logger.log('INFO', log)
            return
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = 'match_ip'
        log.debug_error = str(identifier)

    count = 0
    try:
        await wait_for(ws.accept(), timeout=10)

        if log.res_error != ErrorCode.OK:
            await ws.close(1011)
            log.proc_time = time() - log.start_time
            await default_logger.log('ERROR', log)
            await default_logger.log('DEBUG', log)
            return

        while count < 10:
            msg = await wait_for(ws.receive(), timeout=10)
            msg['type'] = 'websocket.send'
            await wait_for(ws.send(msg), timeout=10)
            count += 1
    except TimeoutError:
        log.res_error = ErrorCode.OTHER_WS_TIMEOUT
        await ws.close(1008)
    except Exception:
        log.res_error = ErrorCode.OTHER_WS_TERMINATED
        await ws.close(1001)
    else:
        await ws.close()

    log.proc_time = time() - log.start_time
    await default_logger.log('INFO', log)


from .. import __version__


@router.get('/system/version')
async def system_version(
    background_tasks: BackgroundTasks,
    log: Log_Fields = Depends(init_log)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    return response_200(background_tasks, log, data={'version': __version__})
