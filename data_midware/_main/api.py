from time import time
from uuid import UUID, uuid4
from urllib.parse import urlencode
from os import urandom, path
from asyncio import sleep
from random import random

from fastapi import APIRouter, Body, BackgroundTasks, Depends, Query
from fastapi.responses import JSONResponse

from .batch import (
    check_password_compliance,
    check_password_used,
    generate_random_string,
    add_user,
    insert_history_login,
    insert_history_passwd,
    insert_history_config,
    insert_history_delete,
    delete_expired_users_lock
)
from .table import (
    TB_USERS_MAIN,
    TB_USERS_OTHER,
    TB_USERS_LOCK,
    TB_USERS_LOGIN_FAIL,
    TB_USERS_SESSION,
    TB_USERS_HISTORY_PASSWD,
    TB_USERS_HISTORY_LOGIN,
    TB_USERS_HISTORY_CONFIG,
    TB_USERS_HISTORY_DELETE,
)
from .param import (
    NewUserModel,
    UpdateUserModel,
    SystemCommonConfigModel,
    SystemInternalConfigModel,
    UserOtherConfigModel
)

from .._share.log import default_logger
from .._share.instance import (
    system_config,
    verify_rsa,
    default_cache,
    func_caches_data_clear,
    func_caches_session_update,
    func_caches_auto_refresh,
)
from .._share.db import session_factory
from .._share.crypto import CryptoAES
from .._share.sql import (
    get_all_users,
    get_one_user,
    simple_select_one,
    select_multi,
    simple_insert_one,
    simple_update_one,
    simple_upsert_one,
    delete_multi,
    get_count
)
from .._share.batch import get_hash, check_cidr, match_ip, check_email_verify
from .._share.log import Log_Fields
from .._share.api import (
    log_with_key,
    log_with_user_info,
    background_run,
    response_200,
    response_err
)
from .._share.error import ErrorCode
from .. import root_dir

router = APIRouter()


@router.post('/user')
# content-type: application/json required (and all others)
async def register(
    background_tasks: BackgroundTasks,
    config: NewUserModel = Body(),
    log: Log_Fields = Depends(log_with_key)
) -> JSONResponse:
    _params = {
        'name': config.name,
        'email2': '_' if config.email2 else config.email2,
        'allow_ip': config.allow_ip,
        'deny_ip': config.deny_ip,
        'protect': config.protect
    }
    log.req_params = urlencode({key: value for key, value in _params.items() if value is not None}, True)

    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    if not system_config.system_allow_register:
        log.res_error = ErrorCode.SYSTEM_REGISTER_FORBIDDEN
        res = response_err(background_tasks, log)
        await sleep(2 + random() * 2)
        return res

    for _cidr in config.allow_ip + config.deny_ip:
        if not check_cidr(_cidr):
            log.res_error = ErrorCode.OTHER_INVALID_DATA
            return response_err(background_tasks, log, data=_cidr)

    try:
        _mark = 'email'
        email = log.aes.decrypt(config.email)
        email.decode()
        _mark = 'password'
        password = log.aes.decrypt(config.password)
        password.decode()
        email2 = b''
        if config.email2:
            _mark = 'email2'
            email2 = log.aes.decrypt(config.email2)
            email2.decode()
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

    session = session_factory()
    try:
        hashed_email = get_hash(email)
        log.user_info['email'] = hashed_email
        _mark = 'check_email_verify'
        if not await check_email_verify(b'POST /api/user', hashed_email):
            log.res_error = ErrorCode.VERIFY_EMAIL_NOT_FOUND
            res = response_err(background_tasks, log)
            await sleep(2 + random() * 2)
            return res
        if not check_password_compliance(password.decode()):
            log.res_error = ErrorCode.PASSWORD_WEAK
            return response_err(background_tasks, log)
        _mark = 'simple_select_one(TB_USERS_MAIN)'
        target_user = await simple_select_one(session, TB_USERS_MAIN, {'email': hashed_email})
        if target_user:
            if (
                target_user['trashed_time'] >= 0 and
                target_user['trashed_time'] < log.start_time - system_config.user_delete_retain_period * 24 * 60 * 60
            ):
                _mark = 'delete_multi(TB_USERS_MAIN)'
                result = await delete_multi(
                    session,
                    TB_USERS_MAIN,
                    {'email': [hashed_email]},
                    returning=['email', 'email_mask', 'user_id', 'trashed_time', 'trashed_ip']
                )
                _mark = 'insert_history_delete'
                await insert_history_delete(session, **result[0], deleted_time=log.start_time)
            else:
                log.res_error = ErrorCode.EMAIL_ALREADY_EXISTS
                res = response_err(background_tasks, log)
                await sleep(2 + random() * 2)
                return res
        _mark = 'add_user'
        await add_user(
            session,
            email,
            password,
            admin=False,
            email2=email2,
            name=config.name or f'user_{generate_random_string()}',
            allow_ip=config.allow_ip,
            deny_ip=config.deny_ip,
            protect=config.protect,
            time_=log.start_time,
            ip=log.ip
        )
        _mark = 'session.commit'
        await session.commit()
        _mark = 'default_cache.delete'
        await default_cache.delete(b'email_verify\xff' + hashed_email)
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log)


@router.delete('/user')
async def unregister(
    background_tasks: BackgroundTasks,
    log: Log_Fields = Depends(log_with_user_info)
) -> JSONResponse:
    if log.res_error not in (ErrorCode.OK, ErrorCode.PASSWORD_EXPIRED, ErrorCode.PASSWORD_WEAK):
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res
    log.res_error = ErrorCode.OK

    session = session_factory()
    try:
        _email = b''
        if log.user_info['protect']:
            _mark = 'check_email_verify'
            _email = log.user_info['email2'] if log.user_info['email2'] else log.user_info['email']
            if not await check_email_verify(b'DELETE /api/user', _email):
                log.res_error = ErrorCode.VERIFY_EMAIL_NOT_FOUND
                res = response_err(background_tasks, log)
                await sleep(2 + random() * 2)
                return res
        if log.user_info['admin']:
            _mark = 'get_count(TB_USERS_MAIN)'
            if await get_count(session, TB_USERS_MAIN, {'admin': [True]}) <= 1:
                log.res_error = ErrorCode.SYSTEM_LAST_ADMIN
                return response_err(background_tasks, log)
        _mark = 'simple_update_one(TB_USERS_MAIN)'
        await simple_update_one(
            session,
            TB_USERS_MAIN,
            filter={'user_id': log.user_id},
            value={'trashed_time': log.start_time, 'trashed_ip': log.ip}
        )
        _mark = 'insert_history_config'
        await insert_history_config(session, log.user_id, log.start_time, log.ip, password=3)

        _mark = 'delete_multi(TB_USERS_SESSION)'
        await delete_multi(session, TB_USERS_SESSION, {'user_id': [log.user_id], 'session_id': [log.session_id]})

        _mark = 'session.commit'
        await session.commit()
        _mark = 'default_cache.delete'
        await default_cache.delete(b'session_nonce\xff' + log.session_id.bytes)
        if _email:
            await default_cache.delete(b'email_verify\xff' + _email)
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log, None)


# 已在/crypto/nonce1中sleep(0.5~1s)
@router.post('/user/session')
async def login(
    background_tasks: BackgroundTasks,
    email: str = Body(),
    password: str = Body(),
    log: Log_Fields = Depends(log_with_key)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    background_tasks.add_task(
        background_run,
        log,
        delete_expired_users_lock,
        time_=log.start_time,
        aiocache_wait_for_write=False
    )

    try:
        _mark = 'email'
        email = log.aes.decrypt(email)
        email.decode()
        _mark = 'password'
        password = log.aes.decrypt(password)
        password.decode()
    except UnicodeDecodeError:
        log.res_error = ErrorCode.OTHER_INVALID_DATA
        log.internal_error = f'{_mark}.decode'
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

    session = session_factory()
    try:
        nonce = log.key[56:]
        _mark = 'default_cache.get'
        if not await default_cache.get(b'login_nonce\xff' + nonce):
            log.res_error = ErrorCode.NONCE_INVALID
            res = response_err(background_tasks, log)
            await sleep(2 + random() * 2)
            return res
        _mark = 'default_cache.delete'
        await default_cache.delete(b'login_nonce\xff' + nonce)

        hashed_email = get_hash(email)
        _mark = 'get_one_user'
        _user = await get_one_user(session, hashed_email)
        if not _user:
            log.res_error = ErrorCode.EMAIL_NOT_FOUND
            res = response_err(background_tasks, log)
            await sleep(2 + random() * 2)
            return res
        log.user_id = _user['user_id']
        _mark = 'match_ip'
        if not await match_ip(
            log.ip,
            _user['allow_ip'],
            _user['deny_ip'],
            _user['acl_serial'] + b'\xff' + _user['user_id'].bytes,
            aiocache_wait_for_write=False
        ):
            log.res_error = ErrorCode.IP_FORBIDDEN
            _mark = 'insert_history_login'
            await insert_history_login(session, _user['user_id'], log.start_time, log.ip, 4)
            _mark = 'session.commit'
            await session.commit()
            res = response_err(background_tasks, log)
            await sleep(2 + random() * 2)
            return res

        _mark = 'select_multi(TB_USERS_LOCK)'
        if system_config.user_lock_ip_only:
            lock = await select_multi(
                session,
                TB_USERS_LOCK,
                ['time'],
                in_={'user_id': [_user['user_id']], 'ip': [log.ip]},
                gt={'time': log.start_time - system_config.user_lock_period * 60}
            )
        else:
            lock = await select_multi(
                session,
                TB_USERS_LOCK,
                ['time'],
                in_={'user_id': [_user['user_id']]},
                gt={'time': log.start_time - system_config.user_lock_period * 60}
            )
        if len(lock) > 0:
            log.res_error = ErrorCode.USER_LOCKED
            _mark = 'insert_history_login'
            await insert_history_login(session, _user['user_id'], log.start_time, log.ip, 3)
            _mark = 'session.commit'
            await session.commit()
            res = response_err(background_tasks, log, data=lock[0]['time'])
            await sleep(2 + random() * 2)
            return res

        if _user['trashed_time'] >= 0:
            _mark = 'check_email_verify'
            if not await check_email_verify(b'POST /api/user/session', hashed_email):
                log.res_error = ErrorCode.USER_DELETED
                res = response_err(background_tasks, log)
                await sleep(2 + random() * 2)
                return res

        if get_hash(password, _user['password_salt']) == _user['password']:
            if _user['trashed_time'] >= 0:
                _mark = 'simple_update_one(TB_USERS_MAIN)'
                await simple_update_one(
                    session,
                    TB_USERS_MAIN,
                    filter={'user_id': _user['user_id']},
                    value={'trashed_time': -1, 'trashed_ip': None}
                )
                _mark = 'insert_history_config'
                await insert_history_config(session, _user['user_id'], log.start_time, log.ip, password=0)
                _mark = 'default_cache.delete'
                await default_cache.delete(b'email_verify\xff' + hashed_email)
            if _user['status'] == 0:
                background_tasks.add_task(
                    background_update_user_status,
                    log,
                    _user['user_id'],
                    password.decode()
                )
            background_tasks.add_task(
                background_run,
                log,
                delete_multi,
                table=TB_USERS_LOGIN_FAIL,
                in_={'user_id': [_user['user_id']], 'ip': [log.ip]}
            )
            _mark = 'insert_history_login'
            await insert_history_login(session, _user['user_id'], log.start_time, log.ip, 0)
            session_token = urandom(64)
            hashed_session_token = get_hash(session_token, algorithm='md5')
            new_session_id = uuid4()
            while await simple_select_one(session, TB_USERS_SESSION, {'session_id': new_session_id}):
                new_session_id = uuid4()
            _mark = 'simple_insert_one(TB_USERS_SESSION)'
            _r = await simple_insert_one(
                session,
                TB_USERS_SESSION,
                {
                    'session_id': new_session_id,
                    'session_token': [hashed_session_token.decode()],
                    'session_data_key': [CryptoAES(session_token).encrypt(
                        CryptoAES(email, _user['password_salt'][::-1]).decrypt(_user['data_key'])
                    )],
                    'user_id': _user['user_id'],
                    'ip': log.ip,
                    'login_time': log.start_time,
                    'refresh_time': log.start_time
                },
                returning=['session_id']
            )
            session_id = _r['session_id']
            log.session_id = session_id
            log.new_session_token = session_token
            _mark = 'session.commit'
            await session.commit()
            _mark = 'default_cache.set'
            await default_cache.set(
                b'session_nonce\xff' + session_id.bytes,
                [int.from_bytes(nonce)],
                ttl=system_config.user_session_expire * 60
            )
        else:
            _mark = 'select_multi(TB_USERS_LOGIN_FAIL)'
            count = await select_multi(
                session,
                TB_USERS_LOGIN_FAIL,
                ['count'],
                in_={'user_id': [_user['user_id']], 'ip': [log.ip]},
                gt={'time': log.start_time - system_config.login_fail_count_expire * 60}
            )
            if len(count) == 0:
                count = 1
            else:
                count = count[0]['count']
                count += 1
            if count > system_config.login_fail_count:
                _mark = 'simple_upsert_one(TB_USERS_LOCK)'
                await simple_upsert_one(
                    session,
                    TB_USERS_LOCK,
                    {'user_id': _user['user_id'], 'ip': log.ip, 'time': log.start_time},
                    ['user_id', 'ip']
                )
                _mark = 'delete_multi(TB_USERS_LOGIN_FAIL)'
                await delete_multi(
                    session,
                    TB_USERS_LOGIN_FAIL,
                    in_={'user_id': [_user['user_id']], 'ip': [log.ip]}
                )
                _mark = 'insert_history_login'
                await insert_history_login(session, _user['user_id'], log.start_time, log.ip, 2)
                _mark = 'insert_history_config'
                await insert_history_config(session, _user['user_id'], log.start_time, log.ip, locked=True)
                _mark = 'session.commit'
                await session.commit()
                log.res_error = ErrorCode.USER_LOCKED
                res = response_err(background_tasks, log, data=log.start_time)
                await sleep(2 + random() * 2)
                return res
            else:
                _mark = 'simple_upsert_one(TB_USERS_LOGIN_FAIL)'
                await simple_upsert_one(
                    session,
                    TB_USERS_LOGIN_FAIL,
                    {'user_id': _user['user_id'], 'ip': log.ip, 'count': count, 'time': log.start_time},
                    ['user_id', 'ip']
                )
                _mark = 'insert_history_login'
                await insert_history_login(session, _user['user_id'], log.start_time, log.ip, 1)
                _mark = 'session.commit'
                await session.commit()
                log.res_error = ErrorCode.PASSWORD_WRONG
                res = response_err(
                    background_tasks,
                    log,
                    data=system_config.login_fail_count - count
                )
                await sleep(2 + random() * 2)
                return res
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log, True)


# 只在用户登录时调用，降低开销，保护用户体验
async def background_update_user_status(log: Log_Fields, user_id: UUID, password: str) -> None:
    session = session_factory()
    try:
        _mark = 'select_multi(TB_USERS_HISTORY_PASSWD)'
        _time = await select_multi(
            session,
            TB_USERS_HISTORY_PASSWD,
            ['time'],
            in_={'user_id': [user_id]},
            order={'id': True},
            limit=1
        )
        new_status = 0
        if (
            system_config.user_passwd_expire > 0
            and _time[0]['time'] < time() - system_config.user_passwd_expire * 24 * 60 * 60
        ):
            new_status = 1
        if not check_password_compliance(password):
            new_status = 2 | new_status
        _mark = 'simple_update_one(TB_USERS_MAIN)'
        await simple_update_one(
            session,
            TB_USERS_MAIN,
            filter={'user_id': user_id},
            value={'status': new_status}
        )
        _mark = 'session.commit'
        await session.commit()
    except Exception as identifier:
        await default_logger.log('ERROR', log, server_error=_mark)
        await default_logger.log('DEBUG', log, server_error=str(identifier))
    await session.close()


@router.delete('/user/sessions')
async def logout(
    background_tasks: BackgroundTasks,
    sids: list[UUID] | None = Body(None, embed=True),
    log: Log_Fields = Depends(log_with_user_info)
) -> JSONResponse:
    if sids is not None:
        log.req_params = urlencode({'sids': sids}, True)
    if log.res_error not in (ErrorCode.OK, ErrorCode.PASSWORD_EXPIRED, ErrorCode.PASSWORD_WEAK):
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res
    log.res_error = ErrorCode.OK

    session = session_factory()
    try:
        target_session = [log.session_id]
        if sids:
            target_session = sids
            _mark = 'select_multi(TB_USERS_SESSION)'
            result = await select_multi(
                session,
                TB_USERS_SESSION,
                ['session_id'],
                in_={'user_id': [log.user_id]}
            )
            non_exist = [x for x in target_session if x not in [r['session_id'] for r in result]]
            if non_exist:
                log.res_error = ErrorCode.TARGET_SESSION_NOT_FOUND
                return response_err(background_tasks, log, data=[x.hex for x in non_exist])

        _mark = 'delete_multi(TB_USERS_SESSION)'
        await delete_multi(
            session,
            TB_USERS_SESSION,
            in_={'session_id': target_session}
        )
        _mark = 'session.commit'
        await session.commit()
        _mark = 'default_cache.delete'
        for sid in target_session:
            await default_cache.delete(b'session_nonce\xff' + sid.bytes)
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(
        background_tasks,
        log,
        False if log.session_id not in target_session else None
    )


@router.get('/user/sessions')
async def user_list_sessions(
    background_tasks: BackgroundTasks,
    log: Log_Fields = Depends(log_with_user_info)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    session = session_factory()
    try:
        _mark = 'select_multi(TB_USERS_SESSION)'
        full_data = await select_multi(
            session,
            TB_USERS_SESSION,
            ['session_id', 'ip', 'login_time'],
            in_={'user_id': [log.user_id]},
            gt={'refresh_time': log.start_time - system_config.user_session_expire * 60},
            order={'id': True}
        )
        data = full_data[:system_config.user_session_number]
        for _r in data:
            _r['session_id'] = _r['session_id'].hex
        if len(full_data) > system_config.user_session_number:
            background_tasks.add_task(
                background_run,
                log,
                delete_multi,
                table=TB_USERS_SESSION,
                in_={
                    'user_id': [log.user_id],
                    'session_id': [r['session_id'] for r in full_data[system_config.user_session_number:]]
                }
            )
            _mark = 'default_cache.delete'
            for _row in full_data[system_config.user_session_number:]:
                await default_cache.delete(b'session_nonce\xff' + _row['session_id'].bytes)
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log, data=data)


@router.get('/user/settings')
async def user_list_config(
    background_tasks: BackgroundTasks,
    log: Log_Fields = Depends(log_with_user_info)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    data = {
        'user_id': log.user_id.hex,
        'email_mask': log.user_info['email_mask'],
        'created_time': log.user_info['created_time'],
        'created_ip': log.user_info['created_ip'],
        'email2_mask': log.user_info['email2_mask'],
        'name': log.user_info['name'],
        'allow_ip': log.user_info['allow_ip'],
        'deny_ip': log.user_info['deny_ip'],
        'protect': log.user_info['protect']
    }
    # session = session_factory()
    # try:
    #     await session.commit()
    # except Exception as identifier:
    #     log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
    #     log.debug_error = str(identifier)
    #     return response_err(background_tasks, log)
    # finally:
    #     await session.close()

    return response_200(background_tasks, log, data=data)


@router.put('/user/settings')
async def user_update_config(
    background_tasks: BackgroundTasks,
    config: UserOtherConfigModel = Body(),
    log: Log_Fields = Depends(log_with_user_info)
) -> JSONResponse:
    _new_config = {key: value for key, value in config if value is not None}
    log.req_params = urlencode(_new_config, True)
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    if not _new_config:
        log.res_error = ErrorCode.OTHER_PARAMETER_REQUIRED
        return response_err(background_tasks, log)

    _ips = _new_config.get('allow_ip', []) + _new_config.get('deny_ip', [])
    for _cidr in _ips:
        if not check_cidr(_cidr):
            log.res_error = ErrorCode.OTHER_INVALID_DATA
            return response_err(background_tasks, log, data=_cidr)
    if _ips:
        _new_serial = urandom(4)
        while _new_serial == log.user_info['acl_serial']:
            _new_serial = urandom(4)
        _new_config['acl_serial'] = _new_serial

    session = session_factory()
    try:
        _email = b''
        if log.user_info['protect']:
            _mark = 'check_email_verify'
            _email = log.user_info['email2'] if log.user_info['email2'] else log.user_info['email']
            if not await check_email_verify(b'PUT /api/user/settings', _email):
                log.res_error = ErrorCode.VERIFY_EMAIL_NOT_FOUND
                res = response_err(background_tasks, log)
                await sleep(2 + random() * 2)
                return res
        _mark = 'simple_update_one(TB_USERS_OTHER)'
        await simple_update_one(
            session,
            TB_USERS_OTHER,
            filter={'user_id': log.user_id},
            value=_new_config
        )
        _mark = 'insert_history_config'
        await insert_history_config(
            session,
            log.user_id,
            log.start_time,
            log.ip,
            **_new_config
        )
        _mark = 'session.commit'
        await session.commit()
        if _email:
            _mark = 'default_cache.delete'
            await default_cache.delete(b'email_verify\xff' + _email)
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log)


@router.put('/user/settings/email')
async def user_change_email(
    background_tasks: BackgroundTasks,
    cur: str = Body(),
    new: str = Body(),
    log: Log_Fields = Depends(log_with_user_info)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    try:
        _mark = 'cur_email'
        cur_email = log.aes.decrypt(cur)
        cur_email.decode()
        _mark = 'new_email'
        new_email = log.aes.decrypt(new)
        new_email_mask = new_email.decode()[:3]
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

    session = session_factory()
    try:
        _email = b''
        if log.user_info['protect']:
            _mark = 'check_email_verify'
            _email = log.user_info['email2'] if log.user_info['email2'] else log.user_info['email']
            if not await check_email_verify(b'PUT /api/user/settings/email', _email):
                log.res_error = ErrorCode.VERIFY_EMAIL_NOT_FOUND
                res = response_err(background_tasks, log)
                await sleep(2 + random() * 2)
                return res
        if get_hash(cur_email) != log.user_info['email']:
            log.res_error = ErrorCode.EMAIL_WRONG
            res = response_err(background_tasks, log)
            await sleep(2 + random() * 2)
            return res
        if cur_email == new_email:
            return response_200(background_tasks, log)

        hashed_new_email = get_hash(new_email)
        _mark = 'simple_select_one(TB_USERS_MAIN)'
        target_user = await simple_select_one(session, TB_USERS_MAIN, {'email': hashed_new_email})
        if target_user:
            if (
                target_user['trashed_time'] >= 0 and
                target_user['trashed_time'] < log.start_time - system_config.user_delete_retain_period * 24 * 60 * 60
            ):
                _mark = 'delete_multi(TB_USERS_MAIN)'
                result = await delete_multi(
                    session,
                    TB_USERS_MAIN,
                    {'email': [hashed_new_email]},
                    returning=['email', 'email_mask', 'user_id', 'trashed_time', 'trashed_ip']
                )
                _mark = 'insert_history_delete'
                await insert_history_delete(session, **result[0], deleted_time=log.start_time)
            else:
                log.res_error = ErrorCode.EMAIL_ALREADY_EXISTS
                res = response_err(background_tasks, log)
                await sleep(2 + random() * 2)
                return res
        _mark = 'simple_update_one(TB_USERS_MAIN)'
        _tlas_drowssap = log.user_info['password_salt'][::-1]
        await simple_update_one(
            session,
            TB_USERS_MAIN,
            filter={'user_id': log.user_id},
            value={
                'email': hashed_new_email,
                'email_mask': new_email_mask,
                'data_key': CryptoAES(new_email, _tlas_drowssap).encrypt(
                    CryptoAES(cur_email, _tlas_drowssap).decrypt(log.user_info['data_key'])
                )
            }
        )
        _mark = 'insert_history_config'
        await insert_history_config(
            session,
            log.user_id,
            log.start_time,
            log.ip,
            email_mask=new_email_mask
        )
        _mark = 'session.commit'
        await session.commit()
        if _email:
            _mark = 'default_cache.delete'
            await default_cache.delete(b'email_verify\xff' + _email)
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log)


@router.put('/user/settings/email2')
async def user_change_email2(
    background_tasks: BackgroundTasks,
    cur: str = Body(),
    new: str = Body(),
    log: Log_Fields = Depends(log_with_user_info)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    try:
        _mark = 'cur_email2'
        cur_email2 = log.aes.decrypt(cur)
        cur_email2.decode()
        _mark = 'new_email2'
        new_email2 = log.aes.decrypt(new)
        new_email2_mask = new_email2.decode()[:3]
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

    session = session_factory()
    try:
        _mark = 'check_email_verify'
        _email = log.user_info['email2'] if log.user_info['email2'] else log.user_info['email']
        if not await check_email_verify(b'PUT /api/user/settings/email2', _email):
            log.res_error = ErrorCode.VERIFY_EMAIL_NOT_FOUND
            res = response_err(background_tasks, log)
            await sleep(2 + random() * 2)
            return res
        if log.user_info['email2']:
            if get_hash(cur_email2) != log.user_info['email2']:
                log.res_error = ErrorCode.EMAIL_WRONG
                res = response_err(background_tasks, log)
                await sleep(2 + random() * 2)
                return res
        else:
            if cur_email2:
                log.res_error = ErrorCode.EMAIL_WRONG
                res = response_err(background_tasks, log)
                await sleep(2 + random() * 2)
                return res
        if cur_email2 == new_email2:
            return response_200(background_tasks, log)

        _mark = 'simple_update_one(TB_USERS_OTHER)'
        await simple_update_one(
            session,
            TB_USERS_OTHER,
            filter={'user_id': log.user_id},
            value={'email2': get_hash(new_email2), 'email2_mask': new_email2_mask}
        )
        _mark = 'insert_history_config'
        await insert_history_config(
            session,
            log.user_id,
            log.start_time,
            log.ip,
            email2_mask=new_email2_mask
        )
        _mark = 'session.commit'
        await session.commit()
        if _email:
            _mark = 'default_cache.delete'
            await default_cache.delete(b'email_verify\xff' + _email)
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log)


@router.put('/user/settings/password')
async def user_change_password(
    background_tasks: BackgroundTasks,
    cur: str = Body(),
    new: str = Body(),
    log: Log_Fields = Depends(log_with_user_info)
) -> JSONResponse:
    if log.res_error not in (ErrorCode.OK, ErrorCode.PASSWORD_EXPIRED, ErrorCode.PASSWORD_WEAK):
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res
    log.res_error = ErrorCode.OK

    try:
        _mark = 'cur_password'
        cur_password = log.aes.decrypt(cur)
        cur_password.decode()
        _mark = 'new_password'
        new_password = log.aes.decrypt(new)
        new_password.decode()
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

    session = session_factory()
    try:
        _email = b''
        if log.user_info['protect']:
            _mark = 'check_email_verify'
            _email = log.user_info['email2'] if log.user_info['email2'] else log.user_info['email']
            if not await check_email_verify(b'PUT /api/user/settings/password', _email):
                log.res_error = ErrorCode.VERIFY_EMAIL_NOT_FOUND
                res = response_err(background_tasks, log)
                await sleep(2 + random() * 2)
                return res
        if get_hash(cur_password, log.user_info['password_salt']) != log.user_info['password']:
            log.res_error = ErrorCode.PASSWORD_WRONG
            res = response_err(background_tasks, log)
            await sleep(2 + random() * 2)
            return res
        if cur_password == new_password:
            return response_200(background_tasks, log)

        if not check_password_compliance(new_password):
            log.res_error = ErrorCode.NEW_PASSWORD_WEAK
            return response_err(background_tasks, log)
        new_password_hash = get_hash(new_password, log.user_info['password_salt'])
        _mark = 'check_password_used'
        if await check_password_used(session, log.user_id, new_password_hash):
            log.res_error = ErrorCode.NEW_PASSWORD_USED
            return response_err(background_tasks, log)

        _mark = 'simple_update_one(TB_USERS_MAIN)'
        await simple_update_one(
            session,
            TB_USERS_MAIN,
            filter={'user_id': log.user_id},
            value={'password': new_password_hash, 'status': 0}
        )
        _mark = 'insert_history_passwd'
        await insert_history_passwd(session, log.user_id, new_password_hash, log.start_time)
        _mark = 'insert_history_config'
        await insert_history_config(session, log.user_id, log.start_time, log.ip, password=1)
        _mark = 'session.commit'
        await session.commit()
        if _email:
            _mark = 'default_cache.delete'
            await default_cache.delete(b'email_verify\xff' + _email)
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log)


@router.post('/user/settings/password')
async def user_reset_password(
    background_tasks: BackgroundTasks,
    email: str = Body(),
    password: str = Body(),
    log: Log_Fields = Depends(log_with_key)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    try:
        _mark = 'email'
        email = log.aes.decrypt(email)
        email.decode()
        _mark = 'new_password'
        new_password = log.aes.decrypt(password)
        new_password.decode()
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

    session = session_factory()
    try:
        _mark = 'get_one_user'
        _user = await get_one_user(session, get_hash(email))
        if not _user:
            log.res_error = ErrorCode.EMAIL_NOT_FOUND
            res = response_err(background_tasks, log)
            await sleep(2 + random() * 2)
            return res
        log.user_id = _user['user_id']

        _mark = 'match_ip'
        if not await match_ip(
            log.ip,
            _user['allow_ip'],
            _user['deny_ip'],
            _user['acl_serial'] + b'\xff' + _user['user_id'].bytes,
            aiocache_wait_for_write=False
        ):
            log.res_error = ErrorCode.IP_FORBIDDEN
            res = response_err(background_tasks, log)
            await sleep(2 + random() * 2)
            return res

        if _user['trashed_time'] >= 0:
            log.res_error = ErrorCode.USER_DELETED
            res = response_err(background_tasks, log)
            await sleep(2 + random() * 2)
            return res

        _mark = 'check_email_verify'
        _email = _user['email2'] if _user['email2'] else _user['email']
        if not await check_email_verify(b'POST /api/user/settings/password', _email):
            log.res_error = ErrorCode.VERIFY_EMAIL_NOT_FOUND
            res = response_err(background_tasks, log)
            await sleep(2 + random() * 2)
            return res
        if not check_password_compliance(new_password):
            log.res_error = ErrorCode.NEW_PASSWORD_WEAK
            return response_err(background_tasks, log)
        if get_hash(new_password, _user['password_salt']) == _user['password']:
            log.res_error = ErrorCode.NEW_PASSWORD_USED
            return response_err(background_tasks, log)

        new_password_hash = get_hash(new_password, _user['password_salt'])
        _mark = 'check_password_used'
        if await check_password_used(session, _user['user_id'], new_password_hash):
            log.res_error = ErrorCode.NEW_PASSWORD_USED
            return response_err(background_tasks, log)

        _mark = 'simple_update_one(TB_USERS_MAIN)'
        await simple_update_one(
            session,
            TB_USERS_MAIN,
            filter={'user_id': _user['user_id']},
            value={'password': new_password_hash, 'status': 0}
        )
        _mark = 'insert_history_passwd'
        await insert_history_passwd(session, _user['user_id'], new_password_hash, log.start_time)
        _mark = 'insert_history_config'
        await insert_history_config(session, _user['user_id'], log.start_time, log.ip, password=2)
        _mark = 'session.commit'
        await session.commit()
        _mark = 'default_cache.delete'
        await default_cache.delete(b'email_verify\xff' + _email)
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log)


@router.get('/user/locks')
async def user_list_locks(
    background_tasks: BackgroundTasks,
    start: int = Query(1),
    end: int = Query(10),
    log: Log_Fields = Depends(log_with_user_info)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    session = session_factory()
    try:
        _mark = 'select_multi(TB_USERS_LOCK)'
        data = await select_multi(
            session,
            TB_USERS_LOCK,
            ['ip', 'time'],
            in_={'user_id': [log.user_id]},
            order={'id': True},
            offset=max(start - 1, 0),
            limit=max(end - start + 1, 0)
        )
        _mark = 'get_count(TB_USERS_LOCK)'
        count = await get_count(session, TB_USERS_LOCK, {'user_id': [log.user_id]})
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log, data=data, total=count)


@router.delete('/user/locks')
async def user_delete_locks(
    background_tasks: BackgroundTasks,
    ips: list[str] = Body(embed=True),
    log: Log_Fields = Depends(log_with_user_info)
) -> JSONResponse:
    log.req_params = urlencode({'ips': ips}, True)
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    session = session_factory()
    try:
        _mark = 'select_multi(TB_USERS_LOCK)'
        result = await select_multi(
            session,
            TB_USERS_LOCK,
            ['ip'],
            in_={'user_id': [log.user_id]}
        )
        non_exist = [x for x in ips if x not in [r['ip'] for r in result]]
        if non_exist:
            log.res_error = ErrorCode.TARGET_LOCK_NOT_FOUND
            return response_err(background_tasks, log, data=non_exist)
        _mark = 'delete_multi(TB_USERS_LOCK)'
        await delete_multi(session, TB_USERS_LOCK, {'user_id': [log.user_id], 'ip': ips})
        _mark = 'session.commit'
        await session.commit()
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log)


@router.get('/user/history/logins')
async def user_list_login_history(
    background_tasks: BackgroundTasks,
    start: int = Query(1),
    end: int = Query(10),
    log: Log_Fields = Depends(log_with_user_info)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    session = session_factory()
    try:
        _mark = 'select_multi(TB_USERS_HISTORY_LOGIN)'
        data = await select_multi(
            session,
            TB_USERS_HISTORY_LOGIN,
            ['time', 'ip', 'result'],
            in_={'user_id': [log.user_id]},
            order={'id': True},
            offset=max(start - 1, 0),
            limit=max(end - start + 1, 0)
        )
        _mark = 'get_count(TB_USERS_HISTORY_LOGIN)'
        count = await get_count(session, TB_USERS_HISTORY_LOGIN, {'user_id': [log.user_id]})
        # _mark = 'session.commit'
        # await session.commit()
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log, data=data, total=count)


@router.get('/user/history/settings')
async def user_list_config_history(
    background_tasks: BackgroundTasks,
    start: int = Query(1),
    end: int = Query(10),
    log: Log_Fields = Depends(log_with_user_info)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    session = session_factory()
    try:
        _mark = 'select_multi(TB_USERS_HISTORY_CONFIG)'
        data = await select_multi(
            session,
            TB_USERS_HISTORY_CONFIG,
            ['time', 'ip', 'email_mask', 'password', 'email2_mask', 'name', 'allow_ip', 'deny_ip', 'protect', 'locked'],
            in_={'user_id': [log.user_id]},
            order={'id': True},
            offset=max(start - 1, 0),
            limit=max(end - start + 1, 0)
        )
        _mark = 'get_count(TB_USERS_HISTORY_CONFIG)'
        count = await get_count(session, TB_USERS_HISTORY_CONFIG, {'user_id': [log.user_id]})
        # _mark = 'session.commit'
        # await session.commit()
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    for row in data:
        for key, value in list(row.items()):
            if value is None:
                row.pop(key)

    return response_200(background_tasks, log, data=data, total=count)


def user_is_admin(
    log: Log_Fields = Depends(log_with_user_info)
) -> Log_Fields:
    if log.res_error != ErrorCode.OK:
        return log

    if not log.user_info['admin']:
        log.res_error = ErrorCode.SYSTEM_NEED_ADMIN
    return log


@router.get('/admin/users')
async def admin_list_users(
    background_tasks: BackgroundTasks,
    start: int = Query(1),
    end: int = Query(10),
    log: Log_Fields = Depends(user_is_admin)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    session = session_factory()
    try:
        _mark = 'get_all_users'
        data = await get_all_users(
            session,
            offset=max(start - 1, 0),
            limit=max(end - start + 1, 0)
        )
        for row in data:
            row['user_id'] = row['user_id'].hex
            row['trashed'] = row.pop('trashed_time') > 0
            row.pop('trashed_ip')
        _mark = 'get_count(TB_USERS_MAIN)'
        count = await get_count(session, TB_USERS_MAIN, {})
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log, data=data, total=count)


@router.get('/admin/user/history/delete')
async def admin_list_user_delete_history(
    background_tasks: BackgroundTasks,
    email: str | None = Query(None),
    start: int = Query(1),
    end: int = Query(10),
    log: Log_Fields = Depends(user_is_admin)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    _in = {}
    if email:
        try:
            email = log.aes.decrypt(email)
            email.decode()
        except UnicodeDecodeError:
            log.res_error = ErrorCode.OTHER_INVALID_DATA
            log.internal_error = 'email.decode()'
            res = response_err(background_tasks, log, data='email')
            await sleep(2 + random() * 2)
            return res
        except Exception as identifier:
            log.res_error = ErrorCode.ENCRYPTION_INVALID_DATA
            log.internal_error = 'decrypt(email)'
            log.debug_error = str(identifier)
            return response_err(background_tasks, log, data='email')
        _in['email'] = [get_hash(email)]

    session = session_factory()
    try:
        _mark = 'select_multi(TB_USERS_HISTORY_DELETE)'
        data = await select_multi(
            session,
            TB_USERS_HISTORY_DELETE,
            ['email', 'email_mask', 'user_id', 'trashed_time', 'trashed_ip', 'deleted_time', 'deleted_by'],
            in_=_in,
            order={'id': True},
            offset=max(start - 1, 0),
            limit=max(end - start + 1, 0)
        )
        _mark = 'get_count(TB_USERS_HISTORY_DELETE)'
        count = await get_count(session, TB_USERS_HISTORY_DELETE, _in)
        # _mark = 'session.commit'
        # await session.commit()
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    for row in data:
        row['email'] = log.aes.encrypt(row['email'])
        row['user_id'] = row['user_id'].hex

    return response_200(background_tasks, log, data=data, total=count)


@router.post('/admin/user')
async def admin_create_user(
    background_tasks: BackgroundTasks,
    config: NewUserModel = Body(),
    log: Log_Fields = Depends(user_is_admin)
) -> JSONResponse:
    _params = {
        'admin': config.admin,
        'email2': '_' if config.email2 else config.email2,
        'name': config.name,
        'allow_ip': config.allow_ip,
        'deny_ip': config.deny_ip,
        'protect': config.protect
    }
    log.req_params = urlencode({key: value for key, value in _params.items() if value is not None}, True)

    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    for _cidr in config.allow_ip + config.deny_ip:
        if not check_cidr(_cidr):
            log.res_error = ErrorCode.OTHER_INVALID_DATA
            return response_err(background_tasks, log, data=_cidr)

    try:
        _mark = 'email'
        email = log.aes.decrypt(config.email)
        email.decode()
        _mark = 'password'
        password = log.aes.decrypt(config.password)
        password.decode()
        if config.email2:
            _mark = 'email2'
            email2 = log.aes.decrypt(config.email2)
            email2.decode()
        else:
            email2 = b''
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

    session = session_factory()
    try:
        _mark = 'simple_select_one(TB_USERS_MAIN)'
        target_user = await simple_select_one(session, TB_USERS_MAIN, {'email': get_hash(email)})
        if target_user:
            log.res_error = ErrorCode.EMAIL_ALREADY_EXISTS
            res = response_err(background_tasks, log)
            await sleep(2 + random() * 2)
            return res
        _mark = 'add_user'
        await add_user(
            session,
            email,
            password,
            config.admin,
            email2,
            config.name or f'user_{generate_random_string()}',
            config.allow_ip,
            config.deny_ip,
            config.protect,
            time_=log.start_time,
            ip='admin'
        )
        _mark = 'session.commit'
        await session.commit()
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log)


@router.put('/admin/user/config')
async def admin_update_user_config(
    background_tasks: BackgroundTasks,
    config: UpdateUserModel = Body(),
    log: Log_Fields = Depends(user_is_admin)
) -> JSONResponse:
    _main_data = {}
    for key in ('password', 'status'):
        if getattr(config, key) is not None:
            _main_data[key] = getattr(config, key)
    _other_data = {}
    for key, value in config:
        if key not in _main_data and value is not None:
            _other_data[key] = value

    log.req_params = urlencode({
        **_main_data,
        **_other_data,
        **({'password': '_'} if config.password else {}),
        **({'email2': '_' if config.email2 else config.email2} if config.email2 is not None else {})
    }, True)
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    if not _main_data and not _other_data:
        log.res_error = ErrorCode.OTHER_PARAMETER_REQUIRED
        return response_err(background_tasks, log)

    _history_data = {}

    try:
        if 'password' in _main_data:
            _mark = 'password'
            password = log.aes.decrypt(_main_data['password'])
            password.decode()
            _main_data['password'] = password
        if 'email2' in _other_data:
            email2 = b''
            if _other_data['email2']:
                _mark = 'email2'
                email2 = log.aes.decrypt(_other_data['email2'])
            email2_mask = email2.decode()[:3]
            _other_data['email2'] = email2 and get_hash(email2)
            _other_data['email2_mask'] = email2_mask
            _history_data['email2_mask'] = email2_mask
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

    if 'status' in _main_data:
        _main_data['status'] = _main_data['status']
    if 'name' in _other_data:
        _other_data['name'] = _other_data['name']
        _history_data['name'] = _other_data['name']
    if 'allow_ip' in _other_data:
        for _cidr in _other_data['allow_ip']:
            if not check_cidr(_cidr):
                log.res_error = ErrorCode.OTHER_INVALID_DATA
                return response_err(background_tasks, log, data=_cidr)
        _other_data['allow_ip'] = _other_data['allow_ip']
        _other_data['acl_serial'] = urandom(4)
        _history_data['allow_ip'] = _other_data['allow_ip']
    if 'deny_ip' in _other_data:
        for _cidr in _other_data['deny_ip']:
            if not check_cidr(_cidr):
                log.res_error = ErrorCode.OTHER_INVALID_DATA
                return response_err(background_tasks, log, data=_cidr)
        _other_data['deny_ip'] = _other_data['deny_ip']
        _other_data['acl_serial'] = urandom(4)
        _history_data['deny_ip'] = _other_data['deny_ip']
    if 'protect' in _other_data:
        _other_data['protect'] = _other_data['protect']
        _history_data['protect'] = _other_data['protect']

    session = session_factory()
    try:
        _mark = 'simple_select_one(TB_USERS_MAIN)'
        target_user = await simple_select_one(session, TB_USERS_MAIN, {'user_id': config.user_id})
        if not target_user:
            log.res_error = ErrorCode.USER_NOT_FOUND
            return response_err(background_tasks, log)
        if target_user['admin'] and config.user_id != log.user_id:
            log.res_error = ErrorCode.ADMIN_NOT_MANAGE_ADMIN
            return response_err(background_tasks, log)
        if target_user['trashed_time'] >= 0:
            log.res_error = ErrorCode.SYSTEM_DELETED_USER
            return response_err(background_tasks, log)

        if 'password' in _main_data:
            _main_data['password'] = get_hash(_main_data['password'], target_user['password_salt'])
            _history_data['password'] = 2
            _mark = 'insert_history_passwd'
            await insert_history_passwd(session, config.user_id, _main_data['password'], log.start_time)

        if _main_data:
            _mark = 'simple_update_one(TB_USERS_MAIN)'
            await simple_update_one(
                session,
                TB_USERS_MAIN,
                filter={'user_id': config.user_id},
                value=_main_data
            )
        if _other_data:
            _mark = 'simple_update_one(TB_USERS_OTHER)'
            await simple_update_one(
                session,
                TB_USERS_OTHER,
                filter={'user_id': config.user_id},
                value=_other_data
            )
        _self = config.user_id == log.user_id
        if _history_data:
            _mark = 'insert_history_config'
            await insert_history_config(
                session,
                config.user_id,
                log.start_time,
                log.ip if _self else 'admin',
                **_history_data
            )
        _mark = 'session.commit'
        await session.commit()
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log)


@router.put('/admin/user/trash')
async def admin_trash_user(
    background_tasks: BackgroundTasks,
    user_id: UUID = Body(),
    undo: bool = Body(False),
    log: Log_Fields = Depends(user_is_admin)
) -> JSONResponse:
    log.req_params = urlencode({'user_id': user_id.hex, 'undo': undo}, True)
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    session = session_factory()
    try:
        _mark = 'simple_select_one(TB_USERS_MAIN)'
        target_user = await simple_select_one(session, TB_USERS_MAIN, {'user_id': user_id})
        if not target_user:
            log.res_error = ErrorCode.USER_NOT_FOUND
            return response_err(background_tasks, log)
        if target_user['admin'] and user_id != log.user_id:
            log.res_error = ErrorCode.ADMIN_NOT_MANAGE_ADMIN
            return response_err(background_tasks, log)
        if target_user['trashed_time'] >= 0 and not undo:
            log.res_error = ErrorCode.SYSTEM_DELETED_USER
            return response_err(background_tasks, log)
        if target_user['trashed_time'] < 0 and undo:
            return response_200(background_tasks, log)

        _self = user_id == log.user_id

        _mark = 'simple_update_one(TB_USERS_MAIN)'
        await simple_update_one(
            session,
            TB_USERS_MAIN,
            filter={'user_id': user_id},
            value={
                'trashed_time': -1 if undo else log.start_time,
                'trashed_ip': None if undo else log.ip if _self else 'admin'
            }
        )
        _mark = 'insert_history_config'
        await insert_history_config(
            session,
            user_id,
            log.start_time,
            log.ip if _self else 'admin',
            password=0 if undo else 3
        )
        if _self:
            _mark = 'delete_multi(TB_USERS_SESSION)'
            await delete_multi(session, TB_USERS_SESSION, {'user_id': [user_id], 'session_id': [log.session_id]})
            _mark = 'default_cache.delete'
            await default_cache.delete(b'session_nonce\xff' + log.session_id.bytes)
        _mark = 'session.commit'
        await session.commit()
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log, None if _self else False)


@router.delete('/admin/user')
async def admin_delete_user(
    background_tasks: BackgroundTasks,
    user_id: UUID = Body(embed=True),
    log: Log_Fields = Depends(user_is_admin)
) -> JSONResponse:
    log.req_params = urlencode({'user_id': user_id.hex}, True)
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    session = session_factory()
    try:
        _mark = 'simple_select_one(TB_USERS_MAIN)'
        target_user = await simple_select_one(session, TB_USERS_MAIN, {'user_id': user_id})
        if not target_user:
            log.res_error = ErrorCode.USER_NOT_FOUND
            return response_err(background_tasks, log)
        if target_user['admin'] and user_id != log.user_id:
            log.res_error = ErrorCode.ADMIN_NOT_MANAGE_ADMIN
            return response_err(background_tasks, log)
        if target_user['trashed_time'] < 0:
            log.res_error = ErrorCode.SYSTEM_DELETED_USER
            return response_err(background_tasks, log)

        if target_user['admin']:
            _mark = 'get_count(TB_USERS_MAIN)'
            if await get_count(session, TB_USERS_MAIN, {'admin': [True]}) <= 1:
                log.res_error = ErrorCode.SYSTEM_LAST_ADMIN
                return response_err(background_tasks, log)

        _self = user_id == log.user_id

        _mark = 'delete_multi(TB_USERS_MAIN)'
        result = await delete_multi(
            session,
            TB_USERS_MAIN,
            {'user_id': [user_id]},
            returning=['email', 'email_mask', 'user_id', 'trashed_time', 'trashed_ip']
        )
        _mark = 'insert_history_delete'
        await insert_history_delete(
            session,
            **result[0],
            deleted_time=log.start_time,
            deleted_by=log.ip if _self else 'admin'
        )
        if _self:
            _mark = 'delete_multi(TB_USERS_SESSION)'
            await delete_multi(session, TB_USERS_SESSION, {'user_id': [user_id], 'session_id': [log.session_id]})
            _mark = 'default_cache.delete'
            await default_cache.delete(b'session_nonce\xff' + log.session_id.bytes)
        _mark = 'session.commit'
        await session.commit()
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log, None if _self else False)


@router.put('/admin/system/settings/common')
async def admin_update_system_common_config(
    background_tasks: BackgroundTasks,
    config: SystemCommonConfigModel = Body(),
    log: Log_Fields = Depends(user_is_admin)
) -> JSONResponse:
    _new_config = {key: value for key, value in config if value is not None}
    log.req_params = urlencode(_new_config, True)
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    if not _new_config:
        log.res_error = ErrorCode.OTHER_PARAMETER_REQUIRED
        return response_err(background_tasks, log)

    _ips = _new_config.get('system_allow_ip', []) + _new_config.get('system_deny_ip', [])
    for _cidr in _ips:
        if not check_cidr(_cidr):
            log.res_error = ErrorCode.OTHER_INVALID_DATA
            return response_err(background_tasks, log, data=_cidr)
    if _ips:
        _new_serial = int.from_bytes(urandom(4))
        while _new_serial == system_config.system_acl_serial:
            _new_serial = int.from_bytes(urandom(4))
        _new_config['system_acl_serial'] = _new_serial

    for key, value in _new_config.items():
        setattr(system_config, key, value)

    system_config.user_session_expire = max(
        system_config.internal_session_refresh_interval * 2 / 60,
        system_config.user_session_expire
    )

    try:
        system_config.save()
    except Exception as identifier:
        log.res_error = ErrorCode.SYSTEM_SAVE_DATA_FAILED
        log.internal_error = 'system_config.save()'
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)

    return response_200(background_tasks, log)


@router.get('/admin/system/settings/internal')
async def admin_list_system_internal_config(
    background_tasks: BackgroundTasks,
    log: Log_Fields = Depends(user_is_admin)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    data = {}
    for key in system_config.__slots__:
        if key.startswith('internal_'):
            _value = getattr(system_config, key)
            data[key] = log.aes.encrypt(str(_value).encode())

    return response_200(background_tasks, log, data=data)


@router.put('/admin/system/settings/internal')
async def admin_update_system_internal_config(
    background_tasks: BackgroundTasks,
    config: SystemInternalConfigModel = Body(),
    log: Log_Fields = Depends(user_is_admin)
) -> JSONResponse:
    log.req_params = urlencode({key: '_' for key, value in config if value is not None}, True)
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    _new_config = {}
    try:
        for key, value in config:
            if value is not None:
                _value = log.aes.decrypt(value).decode()
                if type(getattr(system_config, key)) is int:
                    _value = int(_value)
                _new_config[key] = _value
                setattr(system_config, key, _value)
    except ValueError:
        log.res_error = ErrorCode.OTHER_INVALID_DATA
        log.internal_error = f'int({key})'
        return response_err(background_tasks, log, data=key)
    except UnicodeDecodeError:
        log.res_error = ErrorCode.OTHER_INVALID_DATA
        log.internal_error = f'{key}.decode()'
        res = response_err(background_tasks, log, data=key)
        await sleep(2 + random() * 2)
        return res
    except Exception as identifier:
        log.res_error = ErrorCode.ENCRYPTION_INVALID_DATA
        log.internal_error = f'decrypt({key})'
        log.debug_error = str(identifier)
        return response_err(background_tasks, log, data=key)
    if not _new_config:
        log.res_error = ErrorCode.OTHER_PARAMETER_REQUIRED
        return response_err(background_tasks, log)

    if 'internal_data_clear_interval' in _new_config:
        for cache in func_caches_data_clear:
            cache.ttl = system_config.internal_data_clear_interval
    if 'internal_session_refresh_interval' in _new_config:
        for cache in func_caches_session_update:
            cache.ttl = system_config.internal_session_refresh_interval
    if 'internal_func_cache_ttl' in _new_config:
        for cache in func_caches_auto_refresh:
            cache.ttl = system_config.internal_func_cache_ttl

    data = None
    try:
        if 'internal_signature_private_key' in _new_config:
            _path = system_config.internal_signature_private_key
            if not path.isabs(_path):
                _path = path.join(root_dir, _path)
            verify_rsa.load_private_key(_path)
    except Exception as identifier:
        log.res_error = ErrorCode.SYSTEM_LOAD_DATA_FAILED
        log.internal_error = 'verify_rsa.load_private_key()'
        log.debug_error = str(identifier)
        data = 'key'

    if any(key.startswith('internal_elasticsearch_') for key in _new_config):
        if not await default_logger.set_elasticsearch_client():
            if log.res_error != ErrorCode.OK:
                log.internal_error = log.internal_error + ', default_logger.set_elasticsearch_client()'
                data = data + ', elasticsearch'
            else:
                log.res_error = ErrorCode.SYSTEM_LOAD_DATA_FAILED
                log.internal_error = 'default_logger.set_elasticsearch_client()'
                data = 'elasticsearch'
    if any(key.startswith('internal_influxdb_') for key in _new_config):
        if not await default_logger.set_influxdb_client():
            if log.res_error != ErrorCode.OK:
                log.internal_error = log.internal_error + ', default_logger.set_influxdb_client()'
                data = data + ', influxdb'
            else:
                log.res_error = ErrorCode.SYSTEM_LOAD_DATA_FAILED
                log.internal_error = 'default_logger.set_influxdb_client()'
                data = 'influxdb'

    try:
        system_config.save()
    except Exception as identifier:
        if log.res_error != ErrorCode.OK:
            log.res_error = ErrorCode.SYSTEM_BOTH_DATA_FAILED
            log.internal_error = log.internal_error + ', system_config.save()'
            log.debug_error = log.debug_error + ', ' + str(identifier)
            data = data + ', save'
        else:
            log.res_error = ErrorCode.SYSTEM_SAVE_DATA_FAILED
            log.internal_error = 'system_config.save()'
            log.debug_error = str(identifier)
            data = 'save'

    if log.res_error != ErrorCode.OK:
        return response_err(background_tasks, log, data=data)

    return response_200(background_tasks, log)
