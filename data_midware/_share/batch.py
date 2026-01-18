from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from sqlalchemy.orm import Session
    from uuid import UUID
    from typing import Callable

from ipaddress import ip_network, ip_address, IPv4Network, IPv6Network

from hashlib import new
from base64 import b64encode

from aiocache import cached
from os import urandom
from time import time
from asyncio import sleep, create_task

from .._main.table import TB_USERS_MAIN, TB_USERS_SESSION
from .instance import (
    system_config,
    default_cache,
    func_caches_data_clear,
    func_caches_session_update,
    func_caches_auto_refresh,
    cache_alias
)
from .sql import (
    get_all_user_ids_in_session,
    select_multi,
    simple_update_one,
    delete_multi,
    delete_multi_with_subquery
)
from .crypto import CryptoAES


def get_hash(data: bytes, salt: bytes = b'', algorithm: str = 'shake_256') -> bytes:
    hasher = new(algorithm)
    hasher.update(data)
    if salt:
        hasher.update(salt)
    if algorithm == 'shake_256':
        result = hasher.digest(64)
    elif algorithm == 'shake_128':
        result = hasher.digest(32)
    else:
        result = hasher.digest()
    return b64encode(result).rstrip(b'=')


def check_cidr(cidr: str) -> IPv4Network | IPv6Network | None:
    try:
        return ip_network(cidr, strict=False)
    except Exception:
        return None


def cache_key_builder_match_ip(func: 'Callable', *args, **kwargs) -> bytes:
    if 'ip' in kwargs:
        _ip = kwargs['ip']
    else:
        _ip = args[0]
    if 'acl_serial' in kwargs:
        _acl_serial = kwargs['acl_serial']
    else:
        _acl_serial = args[3]
    return func.__name__.encode() + b'\xff' + _ip.encode() + b'\xff' + _acl_serial


match_ip_cache = cached(
    ttl=system_config.internal_func_cache_ttl,
    key_builder=cache_key_builder_match_ip,
    alias=cache_alias
)
func_caches_auto_refresh.append(match_ip_cache)


@match_ip_cache
async def match_ip(
    ip: str,
    allow: list[str],
    deny: list[str],
    acl_serial: bytes,
    **cached_kwargs
) -> bool:
    try:
        _ip = ip_address(ip)
    except Exception:
        return False
    for _cidr in deny:
        if _ip in check_cidr(_cidr):
            return False
    for _cidr in allow:
        if _ip in check_cidr(_cidr):
            return True
    return False


def cache_key_builder(uuid_name: str = None) -> 'Callable':
    def _builder(func, *args, **kwargs) -> bytes:
        if uuid_name:
            if uuid_name in kwargs:
                return func.__name__.encode() + b'\xff' + kwargs[uuid_name].bytes
            return func.__name__.encode() + b'\xff' + args[1].bytes
        return func.__name__.encode()
    return _builder


update_user_session_cache = cached(
    ttl=system_config.internal_session_refresh_interval,
    key_builder=cache_key_builder('session_id'),
    alias=cache_alias
)
func_caches_session_update.append(update_user_session_cache)


@update_user_session_cache
async def update_user_session(
    session: 'Session',
    session_id: 'UUID',
    session_info: dict,
    ip: str,
    time_: float = None,
    **cached_kwargs
) -> bytes:
    if time_ is None:
        time_ = time()
    session_tokens = session_info['session_token']
    data_keys = session_info['session_data_key']
    session_info['data_key'] = CryptoAES(session_info['token']).decrypt(
        session_info['session_data_key'][session_info['token_index']]
    )

    new_session_token = urandom(64)
    hashed_new_session_token = get_hash(new_session_token, algorithm='md5').decode()
    while hashed_new_session_token in session_tokens:
        new_session_token = urandom(64)
        hashed_new_session_token = get_hash(new_session_token, algorithm='md5').decode()
    session_tokens.insert(0, hashed_new_session_token)
    data_keys.insert(0, CryptoAES(new_session_token).encrypt(session_info['data_key']))
    while len(session_tokens) > max(system_config.user_session_token_fallback + 1, 1):
        session_tokens.pop()
        data_keys.pop()
    await simple_update_one(
        session,
        TB_USERS_SESSION,
        {'session_id': session_id},
        {'session_token': session_tokens, 'session_data_key': data_keys, 'ip': ip, 'refresh_time': time_}
    )
    return new_session_token


delete_expired_users_session_cache = cached(
    ttl=system_config.internal_data_clear_interval,
    key_builder=cache_key_builder(),
    alias=cache_alias
)
func_caches_data_clear.append(delete_expired_users_session_cache)


@delete_expired_users_session_cache
async def delete_expired_users_session(
    session: 'Session',
    time_: float = None,
    **cached_kwargs
) -> bool:
    if time_ is None:
        time_ = time()
    await delete_multi(
        session,
        TB_USERS_SESSION,
        lt={'refresh_time': time_ - system_config.user_session_expire * 60}
    )
    return True


delete_redundant_users_session_cache = cached(
    ttl=system_config.internal_data_clear_interval,
    key_builder=cache_key_builder(),
    alias=cache_alias
)
func_caches_data_clear.append(delete_redundant_users_session_cache)


@delete_redundant_users_session_cache
async def delete_redundant_users_session(
    session: 'Session',
    **cached_kwargs
) -> bool:
    all_uids = await get_all_user_ids_in_session(session)
    results = await select_multi(
        session,
        TB_USERS_MAIN,
        ['user_id'],
        gt={'trashed_time': 0}
    )
    deleted_uids = [row['user_id'] for row in results]
    sids = []
    if deleted_uids:
        results = await delete_multi(session, TB_USERS_SESSION, in_={'user_id': deleted_uids}, returning=['session_id'])
        sids.extend([row['session_id'] for row in results])

    remain_uids = [x for x in all_uids if x not in deleted_uids]
    for user_id in remain_uids:
        results = await delete_multi_with_subquery(
            session,
            TB_USERS_SESSION,
            in_={'user_id': [user_id]},
            order={'id': True},
            offset=system_config.user_session_number,
            returning=['session_id']
        )
        sids.extend([row['session_id'] for row in results])

    if not sids:
        return False
    for session_id in sids:
        await default_cache.delete(b'session_nonce\xff' + session_id.bytes)
    return True


async def check_session_nonce(
    session_id: bytes,
    nonce: int
) -> int:
    _nonce = await default_cache.get(b'session_nonce\xff' + session_id)
    if not _nonce:
        return 2
    if nonce in _nonce:
        return 0
    if nonce < min(_nonce):
        return 0
    if nonce >= 0xffff_ffff_ffff_ffff:
        await default_cache.delete(b'session_nonce\xff' + session_id)
    else:
        await default_cache.set(
            b'session_nonce\xff' + session_id,
            _nonce + [nonce],
            ttl=system_config.user_session_expire * 60
        )
    create_task(delete_old_nonce(session_id, nonce))
    return 1


async def delete_old_nonce(
    session_id: bytes,
    nonce: int
) -> None:
    await sleep(system_config.internal_old_nonce_timeout)
    _nonce = await default_cache.get(b'session_nonce\xff' + session_id)
    if _nonce:
        await default_cache.set(
            b'session_nonce\xff' + session_id,
            [x for x in _nonce if x >= nonce],
            ttl=system_config.user_session_expire * 60
        )
