from uuid import UUID
from urllib.parse import urlencode
from asyncio import sleep
from random import random

from fastapi import APIRouter, Body, BackgroundTasks, Depends, Query
from fastapi.responses import JSONResponse

from .table import (
    TB_APPS_MFA_MAIN,
    TB_APPS_MFA_OTHER
)
from .param import (
    MFAConfigModel,
    MFANewDataModel,
    MFAUpdateDataModel
)

from ..._share.db import session_factory
from ..._share.crypto import CryptoAES
from ..._share.sql import (
    simple_select_one,
    select_multi,
    simple_insert_one,
    simple_update_one,
    simple_upsert_one,
    delete_multi,
    get_count
)
from ..batch import check_email_verify
from ..._share.log import Log_Fields
from ..._share.api import (
    response_200,
    response_err
)
from ..._share.error import ErrorCode

from ..api import user_not_admin, user_with_data_key
from .totp import Totp

router = APIRouter()


@router.get('/app/mfas')
async def app_list_mfas(
    background_tasks: BackgroundTasks,
    start: int = Query(1),
    end: int = Query(10),
    log: Log_Fields = Depends(user_with_data_key)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    _aes = CryptoAES(log.session_info['data_key'])
    session = session_factory()
    try:
        _mark = 'select_multi(TB_APPS_MFA_MAIN)'
        data = await select_multi(
            session,
            TB_APPS_MFA_MAIN,
            [
                'id',
                'name',
                'comment',
                'secret',
                'position',
                'algorithm',
                'interval',
                'digits',
                'created_time',
                'updated_time'
            ],
            in_={'user_id': [log.user_id]},
            order={'position': False},
            offset=max(start - 1, 0),
            limit=max(end - start + 1, 0)
        )
        for row in data:
            _codes = Totp(
                _aes.decrypt(row.pop('secret')),
                row['algorithm'],
                row['interval'],
                row['digits']
            ).codes(log.start_time)
            row['time'] = log.start_time
            row['codes'] = log.aes.encrypt(','.join(_codes).encode())
            row['id'] = row['id'].hex
        _mark = 'get_count(TB_APPS_MFA_MAIN)'
        count = await get_count(session, TB_APPS_MFA_MAIN, {'user_id': [log.user_id]})
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log, data=data, total=count)


@router.post('/app/mfa')
async def app_add_mfa(
    background_tasks: BackgroundTasks,
    data: MFANewDataModel = Body(),
    log: Log_Fields = Depends(user_with_data_key)
) -> JSONResponse:
    log.req_params = urlencode({
        'name': data.name,
        'comment': data.comment,
        'position': data.position,
        'algorithm': data.algorithm,
        'interval': data.interval,
        'digits': data.digits
    }, True)
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    _aes = CryptoAES(log.session_info['data_key'])
    session = session_factory()
    try:
        _mark = 'check_secret'
        _secret = log.aes.decrypt(data.secret)
        _codes = Totp(
            _secret,
            data.algorithm,
            data.interval,
            data.digits
        ).codes()
        _codes.send(None)
        _codes.close()

        _mark = 'simple_insert_one(TB_APPS_MFA_MAIN)'
        await simple_insert_one(
            session,
            TB_APPS_MFA_MAIN,
            {
                'user_id': log.user_id,
                'created_time': log.start_time,
                'updated_time': log.start_time,
                **data.model_dump(),
                'secret': _aes.encrypt(_secret)
            }
        )
        _mark = 'session.commit'
        await session.commit()
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        if _mark == 'check_secret':
            log.res_error = ErrorCode.APP_MFA_SECRET_INVALID
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log)


@router.put('/app/mfa')
async def app_update_mfa(
    background_tasks: BackgroundTasks,
    data: MFAUpdateDataModel = Body(),
    log: Log_Fields = Depends(user_with_data_key)
) -> JSONResponse:
    _new_data = {key: value for key, value in data if value is not None}
    log.req_params = urlencode({
        **_new_data,
        'id': data.id.hex,
        **({'secret': '_'} if data.secret is not None else {})
    }, True)
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    if len(_new_data) == 1:
        log.res_error = ErrorCode.OTHER_PARAMETER_REQUIRED
        return response_err(background_tasks, log)

    _aes = CryptoAES(log.session_info['data_key'])
    session = session_factory()
    try:
        _mark = 'check_email_verify'
        _email = await check_email_verify(
            session,
            TB_APPS_MFA_OTHER,
            log.user_info,
            'PUT /api/app/mfa',
            log.session_id
        )
        if _email == b'':
            log.res_error = ErrorCode.VERIFY_EMAIL_NOT_FOUND
            res = response_err(background_tasks, log)
            await sleep(2 + random() * 2)
            return res

        _mark = 'simple_select_one(TB_APPS_MFA_MAIN)'
        result = await simple_select_one(
            session,
            TB_APPS_MFA_MAIN,
            filter={'id': data.id, 'user_id': log.user_id}
        )
        if not result:
            log.res_error = ErrorCode.APP_ID_NOT_FOUND
            return response_err(background_tasks, log)

        if 'secret' in _new_data:
            _mark = 'check_secret'
            _secret = log.aes.decrypt(_new_data['secret'])
            _codes = Totp(
                _secret,
                _new_data.get('algorithm', result['algorithm']),
                _new_data.get('interval', result['interval']),
                _new_data.get('digits', result['digits'])
            ).codes()
            _codes.send(None)
            _codes.close()
            _new_data['secret'] = _aes.encrypt(_secret)

        _new_data['updated_time'] = log.start_time
        _mark = 'simple_update_one(TB_APPS_MFA_MAIN)'
        await simple_update_one(
            session,
            TB_APPS_MFA_MAIN,
            filter={'id': data.id, 'user_id': log.user_id},
            value=_new_data
        )
        _mark = 'session.commit'
        await session.commit()
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        if _mark == 'check_secret':
            log.res_error = ErrorCode.APP_MFA_SECRET_INVALID
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log)


@router.get('/app/mfa')
async def app_export_mfa(
    background_tasks: BackgroundTasks,
    id: UUID = Query(),
    log: Log_Fields = Depends(user_with_data_key)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    _aes = CryptoAES(log.session_info['data_key'])
    session = session_factory()
    try:
        _mark = 'check_email_verify'
        _email = await check_email_verify(
            session,
            TB_APPS_MFA_OTHER,
            log.user_info,
            'GET /api/app/mfa',
            log.session_id
        )
        if _email == b'':
            log.res_error = ErrorCode.VERIFY_EMAIL_NOT_FOUND
            res = response_err(background_tasks, log)
            await sleep(2 + random() * 2)
            return res

        _mark = 'select_multi(TB_APPS_MFA_MAIN)'
        results = await select_multi(
            session,
            TB_APPS_MFA_MAIN,
            ['secret'],
            in_={'user_id': [log.user_id], 'id': [id]}
        )
        data = {'secret': log.aes.encrypt(_aes.decrypt(results[0]['secret']))}
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log, data=data)


@router.delete('/app/mfa')
async def app_delete_mfa(
    background_tasks: BackgroundTasks,
    ids: list[UUID] | None = Body(None, embed=True),
    log: Log_Fields = Depends(user_not_admin)
) -> JSONResponse:
    log.req_params = urlencode({'ids': [id.hex for id in ids] if ids else ids}, True)
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    session = session_factory()
    try:
        _mark = 'check_email_verify'
        _email = await check_email_verify(
            session,
            TB_APPS_MFA_OTHER,
            log.user_info,
            'DELETE /api/app/mfa',
            log.session_id
        )
        if _email == b'':
            log.res_error = ErrorCode.VERIFY_EMAIL_NOT_FOUND
            res = response_err(background_tasks, log)
            await sleep(2 + random() * 2)
            return res

        if ids:
            _mark = 'delete_multi(TB_APPS_MFA_MAIN)'
            await delete_multi(
                session,
                TB_APPS_MFA_MAIN,
                in_={'user_id': [log.user_id], 'id': ids}
            )
        else:
            _mark = 'delete_multi(TB_APPS_MFA_MAIN)'
            await delete_multi(
                session,
                TB_APPS_MFA_MAIN,
                in_={'user_id': [log.user_id]}
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


@router.get('/app/mfa/settings')
async def app_list_mfa_settings(
    background_tasks: BackgroundTasks,
    log: Log_Fields = Depends(user_not_admin)
) -> JSONResponse:
    if log.res_error != ErrorCode.OK:
        res = response_err(background_tasks, log)
        if log.res_error.http_status in (400, 403):
            await sleep(2 + random() * 2)
        return res

    session = session_factory()
    try:
        _mark = 'select_multi(TB_APPS_MFA_OTHER)'
        data = await select_multi(
            session,
            TB_APPS_MFA_OTHER,
            ['protect'],
            in_={'user_id': [log.user_id]}
        )
        if not data:
            data = await simple_insert_one(
                session,
                TB_APPS_MFA_OTHER,
                value={'user_id': log.user_id},
                returning=['protect']
            )
            _mark = 'session.commit'
            await session.commit()
        else:
            data = data[0]
    except Exception as identifier:
        log.res_error = ErrorCode.SERVER_INTERNAL_ERROR
        log.internal_error = _mark
        log.debug_error = str(identifier)
        return response_err(background_tasks, log)
    finally:
        await session.close()

    return response_200(background_tasks, log, data=data)


@router.put('/app/mfa/settings')
async def app_update_mfa_settings(
    background_tasks: BackgroundTasks,
    config: MFAConfigModel = Body(),
    log: Log_Fields = Depends(user_not_admin)
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

    session = session_factory()
    try:
        _mark = 'check_email_verify'
        _email = await check_email_verify(
            session,
            TB_APPS_MFA_OTHER,
            log.user_info,
            'PUT /api/app/mfa/settings',
            log.session_id
        )
        if _email == b'':
            log.res_error = ErrorCode.VERIFY_EMAIL_NOT_FOUND
            res = response_err(background_tasks, log)
            await sleep(2 + random() * 2)
            return res

        _mark = 'simple_upsert_one(TB_APPS_MFA_OTHER)'
        await simple_upsert_one(
            session,
            TB_APPS_MFA_OTHER,
            {'user_id': log.user_id, **_new_config},
            ['user_id']
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
