import logging
_logger = logging.getLogger(__name__)

from os import getenv
from aiocache.plugins import BasePlugin
from aiocache.factory import caches

from .crypto import CryptoRSA
from .config import SystemConfig

system_config = SystemConfig()

default_rsa = CryptoRSA()
verify_rsa = CryptoRSA()


class CACHE_AUTO_REFRESH(BasePlugin):
    async def post_get(self, cache, key, **_):
        if any(key.startswith(func) for func in (b'match_ip\xff',)):
            await cache.expire(key, system_config.internal_func_cache_ttl)


caches.add('default', {
    'cache': 'aiocache.SimpleMemoryCache',
    'serializer': {'class': 'aiocache.serializers.NullSerializer'},
    'timeout': 1,
    'plugins': [{'class': CACHE_AUTO_REFRESH}]
})
cache_alias = 'default'

if getenv('REDIS_HOST'):
    from redis import Redis

    try:
        _test = Redis(
            host=getenv('REDIS_HOST'),
            port=int(getenv('REDIS_PORT', 6379)),
            socket_timeout=1,
            retry=0
        )
        if _test.set('test', 0, ex=1):
            caches.add('redis', {
                'cache': 'aiocache.RedisCache',
                'serializer': {'class': 'aiocache.serializers.PickleSerializer'},
                'endpoint': getenv('REDIS_HOST'),
                'port': int(getenv('REDIS_PORT', 6379)),
                'timeout': 1,
                'plugins': [{'class': CACHE_AUTO_REFRESH}]
            })
            cache_alias = 'redis'
            _logger.info('System: Redis cache enabled.')
        else:
            _logger.warning('System: Unable to access redis, using local memory cache.')
    except ValueError:
        _logger.warning('System: Invalid redis port, using local memory cache.')
    except Exception:
        _logger.warning('System: Unable to connect redis, using local memory cache.')
    finally:
        _test.close()
else:
    _logger.info('System: Redis not configured, using local memory cache.')

default_cache = caches.get(cache_alias)

func_caches_data_clear = []
func_caches_session_update = []
func_caches_auto_refresh = []
