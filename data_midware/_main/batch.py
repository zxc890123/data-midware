from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from sqlalchemy.orm import Session
    from uuid import UUID

from re import escape, search
from string import ascii_lowercase, ascii_uppercase, digits, punctuation, printable, whitespace
from random import choice
from time import time

from aiocache import cached
from os import urandom

from uuid import uuid4

from .table import (
    TB_USERS_MAIN,
    TB_USERS_OTHER,
    TB_USERS_LOCK,
    TB_USERS_HISTORY_LOGIN,
    TB_USERS_HISTORY_PASSWD,
    TB_USERS_HISTORY_CONFIG,
    TB_USERS_HISTORY_DELETE,
    TB_USERS_LOGIN_FAIL
)
from .param import HistoryConfigModel
from .._share.instance import system_config, func_caches_data_clear, cache_alias
from .._share.sql import simple_select_one, select_multi, simple_insert_one, insert_multi, delete_multi, delete_multi_with_subquery
from .._share.crypto import CryptoAES
from .._share.batch import get_hash, cache_key_builder


def check_password_compliance(password: str) -> bool:
    if system_config.user_passwd_require_digit:
        if not search(rf'[{digits}]', password):
            return False
    if system_config.user_passwd_require_upper:
        if not search(rf'[{ascii_uppercase}]', password):
            return False
    if system_config.user_passwd_require_lower:
        if not search(rf'[{ascii_lowercase}]', password):
            return False
    if system_config.user_passwd_require_special:
        if not search(rf'[{escape(punctuation + whitespace)}]', password):
            return False
    if system_config.user_passwd_require_unicode:
        if not search(rf'[^{escape(printable)}]', password):
            return False
    if len(password) < system_config.user_passwd_require_length:
        return False
    return True


async def check_password_used(
    session: 'Session',
    user_id: 'UUID',
    hashed_password: bytes
) -> bool:
    if system_config.user_history_passwd_number > 0:
        _r = await select_multi(
            session,
            TB_USERS_HISTORY_PASSWD,
            ['password'],
            in_={'user_id': [user_id]},
            order={'id': True},
            limit=system_config.user_history_passwd_number
        )
        if hashed_password in [row['password'] for row in _r]:
            return True
    elif system_config.user_history_passwd_number < 0:
        if await select_multi(
            session,
            TB_USERS_HISTORY_PASSWD,
            ['password'],
            in_={'user_id': [user_id], 'password': [hashed_password]}
        ):
            return True
    return False


def generate_random_string(
    length: int = 4,
    digit: bool = True,
    upper: bool = True,
    lower: bool = True,
    special: bool = False
) -> str:
    _dict = ''
    if digit:
        _dict += digits
    if upper:
        _dict += ascii_uppercase
    if lower:
        _dict += ascii_lowercase
    if special:
        _dict += punctuation
    if not _dict:
        return ''
    return ''.join(choice(_dict) for _ in range(length))


async def add_user(
    session: 'Session',
    email: bytes,
    password: bytes,
    admin: bool,
    email2: bytes,
    name: str,
    allow_ip: list[str],
    deny_ip: list[str],
    protect: bool,
    time_: float = None,
    ip: str = 'system'
) -> None:
    if time_ is None:
        time_ = time()
    email_mask = email.decode()[:3]
    password_salt = urandom(32)
    new_user_id = uuid4()
    while await simple_select_one(session, TB_USERS_MAIN, {'user_id': new_user_id}):
        new_user_id = uuid4()
    _r = await simple_insert_one(
        session,
        TB_USERS_MAIN,
        {
            'user_id': new_user_id,
            'email': get_hash(email),
            'email_mask': email_mask,
            'password': get_hash(password, password_salt),
            'password_salt': password_salt,
            'data_key': CryptoAES(email, password_salt[::-1]).encrypt(urandom(80)),
            'admin': admin,
            'status': 0,
            'created_time': time_,
            'created_ip': ip,
        },
        returning=['user_id']
    )
    user_id = _r['user_id']
    email2_mask = email2.decode()[:3]
    await simple_insert_one(
        session,
        TB_USERS_OTHER,
        {
            'user_id': user_id,
            'email2': email2 and get_hash(email2),
            'email2_mask': email2_mask,
            'name': name,
            'allow_ip': allow_ip,
            'deny_ip': deny_ip,
            'protect': protect
        }
    )
    await insert_history_passwd(
        session,
        user_id,
        get_hash(password, password_salt),
        time_
    )


delete_old_users_history_login_cache = cached(
    ttl=system_config.internal_data_clear_interval,
    key_builder=cache_key_builder('user_id'),
    alias=cache_alias
)
func_caches_data_clear.append(delete_old_users_history_login_cache)


@delete_old_users_history_login_cache
async def delete_old_users_history_login(
    session: 'Session',
    user_id: 'UUID',
    **cached_kwargs
) -> bool:
    if system_config.user_history_login_number < 0:
        return False
    await delete_multi_with_subquery(
        session,
        TB_USERS_HISTORY_LOGIN,
        in_={'user_id': [user_id]},
        order={'id': True},
        offset=system_config.user_history_login_number
    )
    return True


async def insert_history_login(
    session: 'Session',
    user_id: 'UUID',
    time_: float,
    ip: str,
    result: int
) -> None:
    if system_config.user_history_login_number != 0:
        await simple_insert_one(
            session,
            TB_USERS_HISTORY_LOGIN,
            {'user_id': user_id, 'time': time_, 'ip': ip, 'result': result}
        )
    await delete_old_users_history_login(session, user_id, aiocache_wait_for_write=False)


delete_old_users_history_passwd_cache = cached(
    ttl=system_config.internal_data_clear_interval,
    key_builder=cache_key_builder('user_id'),
    alias=cache_alias
)
func_caches_data_clear.append(delete_old_users_history_passwd_cache)


@delete_old_users_history_passwd_cache
async def delete_old_users_history_passwd(
    session: 'Session',
    user_id: 'UUID',
    **cached_kwargs
) -> bool:
    if system_config.user_history_passwd_number < 0:
        return False
    await delete_multi_with_subquery(
        session,
        TB_USERS_HISTORY_PASSWD,
        in_={'user_id': [user_id]},
        order={'id': True},
        offset=system_config.user_history_passwd_number
    )
    return True


async def insert_history_passwd(
    session: 'Session',
    user_id: 'UUID',
    password_hash: int,
    time_: float
) -> None:
    if system_config.user_history_passwd_number != 0:
        await simple_insert_one(
            session,
            TB_USERS_HISTORY_PASSWD,
            {'user_id': user_id, 'password': password_hash, 'time': time_}
        )
    await delete_old_users_history_passwd(session, user_id, aiocache_wait_for_write=False)


delete_old_users_history_config_cache = cached(
    ttl=system_config.internal_data_clear_interval,
    key_builder=cache_key_builder('user_id'),
    alias=cache_alias
)
func_caches_data_clear.append(delete_old_users_history_config_cache)


@delete_old_users_history_config_cache
async def delete_old_users_history_config(
    session: 'Session',
    user_id: 'UUID',
    **cached_kwargs
) -> bool:
    if system_config.user_history_config_number < 0:
        return False
    await delete_multi_with_subquery(
        session,
        TB_USERS_HISTORY_CONFIG,
        in_={'user_id': [user_id]},
        order={'id': True},
        offset=system_config.user_history_config_number
    )
    return True


async def insert_history_config(
    session: 'Session',
    user_id: 'UUID',
    time_: float,
    ip: str,
    **value: HistoryConfigModel
) -> None:
    if system_config.user_history_config_number != 0:
        await simple_insert_one(
            session,
            TB_USERS_HISTORY_CONFIG,
            {'user_id': user_id, 'time': time_, 'ip': ip, **value}
        )
    await delete_old_users_history_config(session, user_id, aiocache_wait_for_write=False)


delete_old_users_history_delete_cache = cached(
    ttl=system_config.internal_data_clear_interval,
    key_builder=cache_key_builder(),
    alias=cache_alias
)
func_caches_data_clear.append(delete_old_users_history_delete_cache)


@delete_old_users_history_delete_cache
async def delete_old_users_history_delete(
    session: 'Session',
    **cached_kwargs
) -> bool:
    if system_config.user_history_delete_number < 0:
        return False
    await delete_multi_with_subquery(
        session,
        TB_USERS_HISTORY_DELETE,
        order={'id': True},
        offset=system_config.user_history_delete_number
    )
    return True


async def insert_history_delete(
    session: 'Session',
    email: bytes,
    email_mask: str,
    user_id: 'UUID',
    trashed_time: float,
    trashed_ip: str,
    deleted_time: float = None,
    deleted_by: str = 'system'
) -> None:
    if deleted_time is None:
        deleted_time = time()
    if system_config.user_history_delete_number != 0:
        await simple_insert_one(
            session,
            TB_USERS_HISTORY_DELETE,
            {
                'email': email,
                'email_mask': email_mask,
                'user_id': user_id,
                'trashed_time': trashed_time,
                'trashed_ip': trashed_ip,
                'deleted_time': deleted_time,
                'deleted_by': deleted_by
            }
        )
    await delete_old_users_history_delete(session, aiocache_wait_for_write=False)


delete_expired_users_lock_cache = cached(
    ttl=system_config.internal_data_clear_interval,
    key_builder=cache_key_builder(),
    alias=cache_alias
)
func_caches_data_clear.append(delete_expired_users_lock_cache)


@delete_expired_users_lock_cache
async def delete_expired_users_lock(
    session: 'Session',
    time_: float,
    **cached_kwargs
) -> bool:
    if system_config.user_lock_period >= 0:
        await delete_multi(
            session,
            TB_USERS_LOCK,
            lt={'time': time_ - system_config.user_lock_period * 60}
        )
    await delete_multi(
        session,
        TB_USERS_LOGIN_FAIL,
        lt={'time': time_ - system_config.login_fail_count_expire * 60}
    )
    return True


delete_old_users_cache = cached(
    ttl=system_config.internal_data_clear_interval,
    key_builder=cache_key_builder(),
    alias=cache_alias
)
func_caches_data_clear.append(delete_old_users_cache)


@delete_old_users_cache
async def delete_old_users(
    session: 'Session',
    time_: float = None,
    **cached_kwargs
) -> bool:
    if time_ is None:
        time_ = time()
    if system_config.user_delete_retain_period < 0:
        return False
    results = await delete_multi(
        session,
        TB_USERS_MAIN,
        gt={'trashed_time': 0},
        lt={'trashed_time': time_ - system_config.user_delete_retain_period * 24 * 60 * 60},
        returning=['user_id', 'email', 'email_mask', 'trashed_time', 'trashed_ip']
    )
    if results and system_config.user_history_delete_number != 0:
        await insert_multi(
            session,
            TB_USERS_HISTORY_DELETE,
            [{**row, 'deleted_time': time_, 'deleted_by': 'system'} for row in results]
        )
    await delete_old_users_history_delete(session, cache_read=False, aiocache_wait_for_write=False)
    return True
