import logging
from os import getenv
from uuid import UUID
from urllib.parse import quote_plus

debug = bool(getenv('DEBUG'))

from pydantic import BaseModel
from .error import ErrorCode
from .instance import system_config
from .crypto import CryptoAES


class Log_Fields(BaseModel):
    ip: str
    method: str
    path: str
    key: bytes = b''
    aes: CryptoAES = None
    session_id: UUID = None
    session_info: dict = {}
    new_session_token: bytes = b''
    user_id: UUID | str = '-'
    user_info: dict = {}
    start_time: float = 0.0
    proc_time: float = 0.0
    query: str = '-'
    req_params: str = '-'
    res_error: ErrorCode = ErrorCode.OK
    internal_error: str = '-'
    debug_error: str = '-'


from influxdb_client.client.influxdb_client_async import InfluxDBClientAsync
from elasticsearch import AsyncElasticsearch
from time import time, strftime, gmtime


class Logger(object):
    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self.influxdb_client = None
        self.influxdb_bucket = None
        self.elasticsearch_client = None
        self.elasticsearch_index = None

    async def set_elasticsearch_client(self) -> bool:
        if self.elasticsearch_client:
            await self.elasticsearch_client.close()
            self.elasticsearch_client = None
            self.elasticsearch_index = None
        if (
            not system_config.internal_elasticsearch_url or
            not system_config.internal_elasticsearch_index or
            not system_config.internal_elasticsearch_apikey
        ):
            self.logger.info('System: Elasticsearch not configured, ignored.')
            return False
        if debug:
            _handler = logging.StreamHandler()
            _handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
            _logger = logging.getLogger('elastic_transport.node')
            _logger.addHandler(_handler)
            _logger.setLevel(logging.DEBUG)
        else:
            logging.getLogger('elastic_transport.transport').propagate = False
        _client = AsyncElasticsearch(
            system_config.internal_elasticsearch_url,
            api_key=system_config.internal_elasticsearch_apikey,
            verify_certs=False,
            request_timeout=1
        )
        try:
            _now = time()
            await _client.index(
                index=system_config.internal_elasticsearch_index,
                document={
                    '@timestamp': strftime(r'%FT%T', gmtime(_now)) + f'{_now:.9f}'[-10:],
                    'app': 'data-midware',
                    'type': 'test'
                }
            )
        except Exception:
            self.logger.warning('System: Unabled to access elasticsearch, ignored.')
            await _client.close()
            return False
        self.logger.info('System: Elasticsearch logging enabled.')
        self.elasticsearch_client = _client
        self.elasticsearch_index = system_config.internal_elasticsearch_index
        return True

    async def set_influxdb_client(self) -> bool:
        if self.influxdb_client:
            await self.influxdb_client.close()
            self.influxdb_client = None
            self.influxdb_bucket = None
        if (
            not system_config.internal_influxdb_url or
            not system_config.internal_influxdb_org or
            not system_config.internal_influxdb_token or
            not system_config.internal_influxdb_bucket
        ):
            self.logger.info('System: Influxdb not configured, ignored.')
            return False
        _client = InfluxDBClientAsync(
            system_config.internal_influxdb_url,
            system_config.internal_influxdb_token,
            debug=debug,
            timeout=1000,
            org=system_config.internal_influxdb_org,
            default_tags={'app': 'data-midware'}
        )
        _writter = _client.write_api()
        try:
            await _writter.write(system_config.internal_influxdb_bucket, record={
                'measurement': 'data-midware',
                'tags': {},
                'fields': {}
            })
        except Exception:
            self.logger.warning(f'System: Unabled to access influxdb bucket: {system_config.internal_influxdb_bucket}, ignored.')
            await _client.close()
            return False
        self.logger.info('System: Influxdb logging enabled.')
        self.influxdb_client = _client
        self.influxdb_bucket = system_config.internal_influxdb_bucket
        return True

    async def log(self, level: str, log: Log_Fields, server_error: str = None) -> None:
        level = level.upper()
        _error = log.debug_error if level == 'DEBUG' else log.internal_error
        if server_error:
            _error = server_error

        if isinstance(log.user_id, UUID):
            log.user_id = log.user_id.hex
        if level in logging._nameToLevel:
            self.logger.log(
                logging._nameToLevel[level],
                '%s "%s %s" %s %s %s %s "%s" "%s" %s "%s"',
                log.ip,
                log.method,
                log.path,
                log.user_id,
                log.res_error.http_status,
                log.start_time,
                log.proc_time,
                log.query,
                log.req_params,
                log.res_error.name,
                quote_plus(_error)
            )

        if self.elasticsearch_client:
            try:
                _now = time()
                await self.elasticsearch_client.index(
                    index=self.elasticsearch_index,
                    document={
                        '@timestamp': strftime(r'%FT%T', gmtime(_now)) + f'{_now:.9f}'[-10:],
                        'app': 'data-midware',
                        'type': 'log',
                        'level': level,
                        'method': log.method,
                        'path': log.path,
                        'ip': log.ip,
                        'user_id': log.user_id,
                        'status': log.res_error.http_status,
                        'start_time': log.start_time,
                        'proc_time': log.proc_time,
                        'query': log.query,
                        'req_params': log.req_params,
                        'res_error': log.res_error.name,
                        'server_error': _error
                    }
                )
            except Exception as identifier:
                self.logger.error(f'System: Write elasticsearch failed: {identifier.message}')
                self.logger.debug(f'System: Write elasticsearch failed: {identifier}')

        if self.influxdb_client:
            _writter = self.influxdb_client.write_api()
            try:
                await _writter.write(self.influxdb_bucket, record={
                    'measurement': 'data-midware',
                    'tags': {'level': level, 'method': log.method, 'path': log.path},
                    'fields': {
                        'ip': log.ip,
                        'user_id': log.user_id,
                        'status': log.res_error.http_status,
                        'start_time': log.start_time,
                        'proc_time': log.proc_time,
                        'query': log.query,
                        'req_params': log.req_params,
                        'res_error': log.res_error.name,
                        'server_error': _error
                    }
                })
            except Exception as identifier:
                self.logger.error(f'System: Write influxdb failed: {identifier.status}')
                self.logger.debug(f'System: Write influxdb failed: {identifier.message}')


default_logger = Logger()
