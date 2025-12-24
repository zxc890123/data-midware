import logging
from uvicorn import run
from os import getenv

debug = bool(getenv('DEBUG'))

logging.basicConfig(
    format='%(asctime)s %(levelname)s %(name)s %(message)s' if debug else '%(asctime)s %(levelname)s %(message)s',
    # datefmt=r'%Y-%m-%dT%H:%M:%S%z',  only get worst
    level=logging.DEBUG if debug else logging.INFO
)

if debug:
    logging.getLogger('aiosqlite').setLevel(logging.INFO)
    logging.getLogger('sqlalchemy.engine.Engine').setLevel(logging.DEBUG)

from ._share.app import app

if __name__ == '__main__':
    run(
        app,
        host='0.0.0.0',
        port=4000,
        log_level='debug' if debug else 'error',
        access_log=debug,
        timeout_keep_alive=60
    )
