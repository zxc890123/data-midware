from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from sqlalchemy.orm import Session, DeclarativeBase
    from uuid import UUID

from sqlalchemy import select, update, delete, func
from sqlalchemy.dialects.sqlite import insert

from .._main.table import TB_USERS_MAIN, TB_USERS_OTHER, TB_USERS_SESSION


async def get_all_users(
    session: 'Session',
    no_column_main: list[str] = ['email', 'password', 'password_salt', 'data_key'],
    no_column_other: list[str] = ['email2', 'acl_serial'],
    email_hash: list[bytes] = None,
    user_id: list['UUID'] = None,
    admin: bool = None,
    status: list[int] = None,
    name: str = None,
    protect: bool = None,
    offset: int = None,
    limit: int = None
) -> list[dict]:
    _cols = [*TB_USERS_MAIN.__table__.columns] + [*TB_USERS_OTHER.__table__.columns]
    _cols.remove(TB_USERS_MAIN.id)
    _cols.remove(TB_USERS_OTHER.id)
    _cols.remove(TB_USERS_OTHER.user_id)
    for col in no_column_main:
        _cols.remove(getattr(TB_USERS_MAIN, col))
    for col in no_column_other:
        _cols.remove(getattr(TB_USERS_OTHER, col))
    stmt = select(*_cols).join(TB_USERS_OTHER)
    if email_hash:
        stmt = stmt.where(TB_USERS_MAIN.email.in_(email_hash))
    if user_id:
        stmt = stmt.where(TB_USERS_MAIN.user_id.in_(user_id))
    if admin is not None:
        stmt = stmt.where(TB_USERS_MAIN.admin == admin)
    if status:
        stmt = stmt.where(TB_USERS_MAIN.status.in_(status))
    if name:
        stmt = stmt.where(TB_USERS_OTHER.name.like(f'%{name}%'))
    if protect is not None:
        stmt = stmt.where(TB_USERS_OTHER.protect == protect)
    if offset:
        stmt = stmt.offset(offset)
    if limit is not None:
        stmt = stmt.limit(limit)
    results = await session.execute(stmt)
    return [row._asdict() for row in results]


async def get_one_user(
    session: 'Session',
    email: bytes = None,
    user_id: 'UUID' = None
) -> dict | None:
    _cols = [*TB_USERS_MAIN.__table__.columns] + [*TB_USERS_OTHER.__table__.columns]
    _cols.remove(TB_USERS_MAIN.id)
    _cols.remove(TB_USERS_OTHER.id)
    _cols.remove(TB_USERS_OTHER.user_id)
    stmt = select(*_cols).join(TB_USERS_OTHER)
    if email:
        stmt = stmt.where(TB_USERS_MAIN.email == email)
    elif user_id:
        stmt = stmt.where(TB_USERS_MAIN.user_id == user_id)
    else:
        return None
    result = (await session.execute(stmt)).first()
    return result._asdict() if result else None


async def get_all_user_ids_in_session(session: 'Session') -> list['UUID']:
    stmt = select(TB_USERS_SESSION.user_id).distinct()
    return await session.scalars(stmt)


async def simple_select_one(
    session: 'Session',
    table: 'DeclarativeBase',
    filter: dict
) -> dict | None:
    stmt = select(*table.__table__.columns)
    for k, v in filter.items():
        stmt = stmt.where(getattr(table, k) == v)
    result = (await session.execute(stmt)).first()
    return result._asdict() if result else None


async def select_multi(
    session: 'Session',
    table: 'DeclarativeBase',
    column: list[str],
    in_: dict[str, list] = None,
    gt: dict = None,
    lt: dict = None,
    order: dict[str, bool] = None,
    offset: int = None,
    limit: int = None
) -> list[dict]:
    _cols = []
    if len(column) == 0:
        column = table.__table__.columns.keys()
    for _col in column:
        _cols.append(getattr(table, _col))
    stmt = select(*_cols)
    if in_:
        for k, v in in_.items():
            stmt = stmt.where(getattr(table, k).in_(v))
    if gt:
        for k, v in gt.items():
            stmt = stmt.where(getattr(table, k) > v)
    if lt:
        for k, v in lt.items():
            stmt = stmt.where(getattr(table, k) < v)
    if order:
        for k, v in order.items():
            stmt = stmt.order_by(getattr(table, k).desc() if v else getattr(table, k))
    if offset:
        stmt = stmt.offset(offset)
    if limit is not None:
        stmt = stmt.limit(limit)
    results = await session.execute(stmt)
    return [row._asdict() for row in results]


async def get_count(
    session: 'Session',
    table: 'DeclarativeBase',
    in_: dict[str, list]
) -> int:
    stmt = select(func.count()).select_from(table)
    for k, v in in_.items():
        stmt = stmt.where(getattr(table, k).in_(v))
    return await session.scalar(stmt)


async def simple_insert_one(
    session: 'Session',
    table: 'DeclarativeBase',
    value: dict,
    returning: list[str] = None
) -> dict | None:
    stmt = insert(table).values(value)
    if returning:
        _cols = []
        for key in returning:
            _cols.append(getattr(table, key))
        stmt = stmt.returning(*_cols)
    result = await session.execute(stmt)
    return result.first()._asdict() if returning else None


async def insert_multi(
    session: 'Session',
    table: 'DeclarativeBase',
    value: list[dict],
    returning: list[str] = None
) -> list[dict] | None:
    stmt = insert(table).values(value)
    if returning:
        _cols = []
        for key in returning:
            _cols.append(getattr(table, key))
        stmt = stmt.returning(*_cols)
    results = await session.execute(stmt)
    return [row._asdict() for row in results] if returning else None


async def simple_update_one(
    session: 'Session',
    table: 'DeclarativeBase',
    filter: dict,
    value: dict,
    returning: list[str] = None
) -> dict | None:
    stmt = update(table).values(value)
    for k, v in filter.items():
        stmt = stmt.where(getattr(table, k) == v)
    if returning:
        _cols = []
        for key in returning:
            _cols.append(getattr(table, key))
        stmt = stmt.returning(*_cols)
    result = await session.execute(stmt)
    return result.first()._asdict() if returning else None


async def simple_upsert_one(
    session: 'Session',
    table: 'DeclarativeBase',
    value: dict,
    index: list[str]
) -> None:
    '''
    :param index: MUST be the UNIQUE constraint columns
    :type index: list[str]
    '''
    stmt = insert(table).values(value).on_conflict_do_update(
        index_elements=index,
        set_=value
    )
    await session.execute(stmt)


async def delete_multi(
    session: 'Session',
    table: 'DeclarativeBase',
    in_: dict[str, list] = None,
    gt: dict = None,
    lt: dict = None,
    returning: list[str] = None
) -> list[dict] | None:
    stmt = delete(table)
    if in_:
        for k, v in in_.items():
            stmt = stmt.where(getattr(table, k).in_(v))
    if gt:
        for k, v in gt.items():
            stmt = stmt.where(getattr(table, k) > v)
    if lt:
        for k, v in lt.items():
            stmt = stmt.where(getattr(table, k) < v)
    if returning:
        _cols = []
        for key in returning:
            _cols.append(getattr(table, key))
        stmt = stmt.returning(*_cols)
    results = await session.execute(stmt)
    return [row._asdict() for row in results] if returning else None


async def delete_multi_with_subquery(
    session: 'Session',
    table: 'DeclarativeBase',
    in_: dict[str, list] = None,
    gt: dict = None,
    lt: dict = None,
    order: dict[str, bool] = None,
    offset: int = None,
    limit: int = None,
    returning: list[str] = None
) -> list[dict] | None:
    stmt = delete(table)
    subq = select(table.id)
    subq_snap = subq
    if in_:
        for k, v in in_.items():
            subq = subq.where(getattr(table, k).in_(v))
    if gt:
        for k, v in gt.items():
            subq = subq.where(getattr(table, k) > v)
    if lt:
        for k, v in lt.items():
            subq = subq.where(getattr(table, k) < v)
    if order:
        for k, v in order.items():
            subq = subq.order_by(getattr(table, k).desc() if v else getattr(table, k))
    if offset:
        subq = subq.offset(offset)
    if limit is not None:
        subq = subq.limit(limit)
    if subq_snap != subq:
        stmt = stmt.where(table.id.in_(subq))
    if returning:
        _cols = []
        for key in returning:
            _cols.append(getattr(table, key))
        stmt = stmt.returning(*_cols)
    results = await session.execute(stmt)
    return [row._asdict() for row in results] if returning else None
