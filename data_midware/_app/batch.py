from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from uuid import UUID
    from sqlalchemy.orm import Session, DeclarativeBase

from .._share.sql import select_multi
from .._share.batch import get_hash
from .._share.instance import default_cache


async def check_email_verify(
    session: 'Session',
    table: 'DeclarativeBase',
    user_info: dict,
    api: str,
    session_id: 'UUID'
) -> bytes | None:
    _protect = await select_multi(
        session,
        table,
        ['protect'],
        in_={'user_id': [user_info['user_id']]}
    )
    if _protect and _protect[0]['protect']:
        _email = user_info['email2'] if user_info['email2'] else user_info['email']
        hashed_to = get_hash(api.encode(), session_id.hex.encode(), algorithm='md5')
        if await default_cache.get(b'email_verify\xff' + _email) != hashed_to:
            return b''
        return _email
    return None
