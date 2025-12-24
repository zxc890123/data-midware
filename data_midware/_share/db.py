from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import registry, sessionmaker
from sqlalchemy.event import listens_for
from sqlalchemy import text

from os import getenv, path
from .. import root_dir

db_file_path = getenv('SQLITE_DB_FILE') or path.join(root_dir, 'data.sqlite')
if not path.isabs(db_file_path):
    db_file_path = path.join(root_dir, db_file_path)

engine = create_async_engine(f'sqlite+aiosqlite:///{db_file_path}')
sync_session_factory = sessionmaker(engine.sync_engine)
session_factory = async_sessionmaker(engine, expire_on_commit=False, sync_session_class=sync_session_factory)
Base = registry().generate_base()


@listens_for(engine.sync_engine, 'connect')
def set_sqlite_pragma(conn, _) -> None:
    cursor = conn.cursor()
    cursor.execute('PRAGMA synchronous = OFF')
    cursor.execute('PRAGMA foreign_keys = ON')
    cursor.execute('PRAGMA temp_store = MEMORY')
    cursor.execute('PRAGMA cache_size = -1048576')
    cursor.execute('PRAGMA optimize(0x10002)')
    cursor.close()


from time import time
optimize_timer = {'time': 0}


@listens_for(sync_session_factory, 'after_commit')
def optimize_after_commit(*_) -> None:
    now = time()
    if now > optimize_timer['time'] + 86400:
        session = sync_session_factory()
        session.execute(text('PRAGMA optimize'))
        session.close()
        optimize_timer['time'] = now
