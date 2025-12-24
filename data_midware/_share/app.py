import logging
_logger = logging.getLogger(__name__)

from .db import engine, session_factory, Base
from .._main.table import *  # noqa
from .._app.mfa.table import *  # noqa

from .instance import system_config, verify_rsa
from .log import default_logger
system_config.load()

from .sql import simple_select_one, select_multi
from .batch import delete_expired_users_session, delete_redundant_users_session
from .._main.batch import (
    add_user,
    delete_old_users_history_login,
    delete_old_users_history_passwd,
    delete_old_users_history_config,
    delete_old_users
)
from .. import root_dir

from os import getenv, path
debug = bool(getenv('DEBUG'))

from contextlib import asynccontextmanager


async def after_startup():
    conn = await engine.connect()
    await conn.run_sync(Base.metadata.create_all)
    await conn.commit()
    await conn.close()

    session = session_factory()
    await delete_old_users(session, cache_read=False, aiocache_wait_for_write=False)
    all_uids = await select_multi(
        session,
        TB_USERS_MAIN,  # noqa
        ['user_id']
    )
    for row in all_uids:
        await delete_old_users_history_login(session, row['user_id'], cache_read=False, aiocache_wait_for_write=False)
        await delete_old_users_history_passwd(session, row['user_id'], cache_read=False, aiocache_wait_for_write=False)
        await delete_old_users_history_config(session, row['user_id'], cache_read=False, aiocache_wait_for_write=False)

    await delete_expired_users_session(session, cache_read=False, aiocache_wait_for_write=False)
    await delete_redundant_users_session(session, cache_read=False, aiocache_wait_for_write=False)

    admin = await simple_select_one(
        session,
        TB_USERS_MAIN,  # noqa
        {'admin': True}
    )
    if not admin:
        await add_user(
            session,
            b'admin@local',
            b'admin',
            admin=True,
            email2=b'',
            name='admin',
            allow_ip=['0.0.0.0/0', '::/0'],
            deny_ip=[],
            protect=False
        )
        _logger.info('System: Created first admin user: admin@local, password: admin')
        _logger.warning('System: Secure this user ASAP.')

    await session.commit()
    await session.close()

    try:
        email_verify_key_path = system_config.internal_signature_private_key
        if not path.isabs(email_verify_key_path):
            email_verify_key_path = path.join(root_dir, email_verify_key_path)
        verify_rsa.load_private_key(email_verify_key_path)
    except FileNotFoundError:
        try:
            with open(email_verify_key_path, 'w') as f:
                f.write(verify_rsa.private_pem())
            _logger.info(f'System: Created email verify private key: {email_verify_key_path}')
            _logger.warning('System: Email verify requests relayed by the "repeater" need to be signed with this key.')
        except Exception as identifier:
            _logger.error(f'System: Create email verify private key failed: {identifier}')
            _logger.warning('System: Email verification will always fail.')
    except Exception as identifier:
        _logger.error(f'System: Load email verify private key failed: {identifier}')
        _logger.warning('System: Email verification will always fail.')
    await default_logger.set_elasticsearch_client()
    await default_logger.set_influxdb_client()
    _logger.info('System: Started.')


async def before_shutdown():
    if default_logger.influxdb_client:
        await default_logger.influxdb_client.close()
    if default_logger.elasticsearch_client:
        await default_logger.elasticsearch_client.close()
    await engine.dispose()
    engine.sync_engine.dispose()
    _logger.info('System: Stopped.')


@asynccontextmanager
async def lifespan(_):
    await after_startup()
    yield
    await before_shutdown()


from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import PlainTextResponse
from starlette.exceptions import HTTPException

from .. import __version__

app = FastAPI(
    title="Data Middleware",
    description="A API server.",
    version=__version__,
    openapi_url='/api/openapi.json' if debug else None,
    redirect_slashes=False,
    docs_url='/api/docs' if debug else None,
    redoc_url=None,
    lifespan=lifespan
)


@app.exception_handler(HTTPException)
def http_error(request: Request, exc: HTTPException) -> PlainTextResponse:
    response = PlainTextResponse(str(exc.detail), exc.status_code)
    if exc.status_code < 500:
        response.headers['connection'] = 'close'
    return response


@app.exception_handler(RequestValidationError)
def validation_error(request: Request, exc: RequestValidationError) -> PlainTextResponse:
    return PlainTextResponse('Bad Request', 400, {'connection': 'close'})


from .api import router as router_share
from .._main.api import router as router_main
from .._app.mfa.api import router as router_mfa

app.include_router(router_share, prefix='/api', tags=['share'])
app.include_router(router_main, prefix='/api', tags=['main'])
app.include_router(router_mfa, prefix='/api', tags=['mfa'])
