# 设计

与实际代码有出入。

目录
- [1 功能](#1-功能)
  - [1.1 数据安全](#11-数据安全)
    - [1.1.1 传输](#111-传输)
      - [1.1.1.1 防重放](#1111-防重放)
      - [1.1.1.2 加密](#1112-加密)
      - [1.1.1.3 包含email的请求](#1113-包含email的请求)
    - [1.1.2 数据格式](#112-数据格式)
      - [1.1.2.1 哈希值](#1121-哈希值)
      - [1.1.2.2 UUID](#1122-uuid)
    - [1.1.3 数据保存](#113-数据保存)
      - [1.1.3.1 用户信息](#1131-用户信息)
      - [1.1.3.2 应用数据](#1132-应用数据)
  - [1.2 访问控制](#12-访问控制)
  - [1.3 会话](#13-会话)
  - [1.4 用户配置](#14-用户配置)
  - [1.5 系统配置](#15-系统配置)
  - [1.6 环境变量](#16-环境变量)
- [2 外部库](#2-外部库)
- [3 内部库](#3-内部库)
  - [3.1 数据模型](#31-数据模型)
  - [3.2 通用](#32-通用)
    - [3.2.1 类](#321-类)
      - [3.2.1.1 系统设置](#3211-系统设置)
      - [3.2.1.2 加解密](#3212-加解密)
      - [3.2.1.3 错误码](#3213-错误码)
      - [3.2.1.4 缓存](#3214-缓存)
        - [3.2.1.4.1 函数缓存](#32141-函数缓存)
    - [3.2.2 SQL](#322-sql)
      - [3.2.2.1 读](#3221-读)
      - [3.2.2.2 写](#3222-写)
    - [3.2.3 批处理](#323-批处理)
  - [3.3 本体](#33-本体)
    - [3.3.1 类](#331-类)
    - [3.3.2 SQL](#332-sql)
    - [3.3.3 批处理](#333-批处理)
    - [3.3.4 参数模型](#334-参数模型)
  - [3.4 应用](#34-应用)
    - [3.4.1 类](#341-类)
    - [3.4.2 SQL](#342-sql)
    - [3.4.3 批处理](#343-批处理)
    - [3.4.4 参数模型](#344-参数模型)
- [4 API](#4-api)
  - [4.1 共通](#41-共通)
    - [4.1.1 响应](#411-响应)
    - [4.1.2 前置处理](#412-前置处理)
    - [4.1.3 有“副作用”的API](#413-有副作用的api)
  - [4.2 /api/crypto](#42-apicrypto)
    - [4.2.1 GET /api/crypto/public](#421-get-apicryptopublic)
    - [4.2.2 GET /api/crypto/nonce1](#422-get-apicryptononce1)
    - [4.2.3 GET /api/crypto/nonce2](#423-get-apicryptononce2)
  - [4.3 /api/user](#43-apiuser)
    - [4.3.1 POST /api/user](#431-post-apiuser)
    - [4.3.2 DELETE /api/user](#432-delete-apiuser)
    - [4.3.3 POST /api/user/session](#433-post-apiusersession)
    - [4.3.4 DELETE /api/user/session](#434-delete-apiusersession)
    - [4.3.5 GET /api/user/sessions](#435-get-apiusersessions)
    - [4.3.6 GET /api/user/settings](#436-get-apiusersettings)
    - [4.3.7 PUT /api/user/settings](#437-put-apiusersettings)
    - [4.3.8 PUT /api/user/settings/email](#438-put-apiusersettingsemail)
    - [4.3.9 PUT /api/user/settings/email2](#439-put-apiusersettingsemail2)
    - [4.3.10 PUT /api/user/settings/password](#4310-put-apiusersettingspassword)
    - [4.3.11 POST /api/user/settings/password](#4311-post-apiusersettingspassword)
    - [4.3.12 GET /api/user/locks](#4312-get-apiuserlocks)
    - [4.3.13 DELETE /api/user/locks](#4313-delete-apiuserlocks)
    - [4.3.14 GET /api/user/history/logins](#4314-get-apiuserhistorylogins)
    - [4.3.15 GET /api/user/history/settings](#4315-get-apiuserhistorysettings)
  - [4.4 /api/email](#44-apiemail)
    - [4.4.1 POST /api/email/verify](#441-post-apiemailverify)
  - [4.5 /api/system](#45-apisystem)
    - [4.5.1 GET /api/system/settings](#451-get-apisystemsettings)
    - [4.5.2 WebSocket /api/system/ping](#452-websocket-apisystemping)
  - [4.6 /api/admin](#46-apiadmin)
    - [4.6.1 GET /api/admin/users](#461-get-apiadminusers)
    - [4.6.2 GET /api/admin/user/history/delete](#462-get-apiadminuserhistorydelete)
    - [4.6.3 POST /api/admin/user](#463-post-apiadminuser)
    - [4.6.4 PUT /api/admin/user/config](#464-put-apiadminuserconfig)
    - [4.6.5 PUT /api/admin/user/trash](#465-put-apiadminusertrash)
    - [4.6.6 DELETE /api/admin/user](#466-delete-apiadminuser)
    - [4.6.7 PUT /api/admin/system/settings/common](#467-put-apiadminsystemsettingscommon)
    - [4.6.8 GET /api/admin/system/settings/internals](#468-get-apiadminsystemsettingsinternals)
    - [4.6.9 PUT /api/admin/system/settings/internals](#469-put-apiadminsystemsettingsinternals)
  - [4.7 /api/app](#47-apiapp)
    - [4.7.1 GET /api/app/mfas](#471-get-apiappmfas)
    - [4.7.2 POST /api/app/mfa](#472-post-apiappmfa)
    - [4.7.3 PUT /api/app/mfa](#473-put-apiappmfa)
    - [4.7.4 GET /api/app/mfa](#474-get-apiappmfa)
    - [4.7.5 DELETE /api/app/mfa](#475-delete-apiappmfa)
    - [4.7.6 GET /api/app/mfa/settings](#476-get-apiappmfasettings)
    - [4.7.7 PUT /api/app/mfa/settings](#477-put-apiappmfasettings)
- [5 数据库](#5-数据库)
- [6 表结构](#6-表结构)
  - [6.1 本体](#61-本体)
  - [6.2 应用](#62-应用)
    - [6.2.1 MFA](#621-mfa)
- [7 日志](#7-日志)
  - [7.1 类](#71-类)
  - [7.2 参数模型](#72-参数模型)

## 1 功能

- 中间件指的是运行在应用和数据库之间，以API的形式提供数据操作。
  - 虽然暂无计划使用独立数据库。
- 数据包含[用户信息](#1131-用户信息)，[应用数据](#1132-应用数据)。
- 数据操作包括数据增删改查和数据转换。
- 考虑成本等问题暂不考虑任何邮件外发功能。

### 1.1 数据安全

- 目标：服务器（数据库）中保存的数据可（人为）泄露，但是不能被理解。
  - 目前保护数据的核心就是用户邮箱。
  - 假定服务器不会运行被篡改的代码或其他恶意程序。

#### 1.1.1 传输

- 考虑到客户端和服务器所在网络可能不安全，所有敏感数据的传输需要加密，并且防重放攻击。
  - 客户端（如公司网络）使用的代理可能使用专用的证书并解密https。
  - 服务端网络不使用https，存在被监听的风险。
- 敏感数据包括：
  - session_token
  - email
  - password
  - email2
  - 应用数据

##### 1.1.1.1 防重放

- 没有nonce或nonce失效或丢失时：
  - 需要先从服务器获取nonce值
    - 随机数
    - 和会话绑定
    - 保存在内存
  - 登录请求必须使用相同nonce
  - 其他请求每次需要nonce + 1
    - 只要不一样即可
      - 但要防止过去的nonce出现，所以要增长
    - 当达到最大值时需要重新获取nonce，而不是归零
      - 降低到达最大值的可能性
- 需要考虑并发请求的情况。
  - 以及任何问题导致接收nonce的顺序被打乱的情况。
- 无需登录的功能无需nonce。

##### 1.1.1.2 加密

- 使用公钥加密*通信密钥*。
  - *通信密钥* = 随机数 + nonce
  - 使用*通信密钥*加密传输敏感数据。
- 使用用户邮箱加密数据密钥。
  - 使用数据密钥加密应用数据。
- 各随机数长度（字节）：
  - 通信密钥：56 + 8(nonce，最大值18446744073709551615)
  - 密码盐：32
  - 会话令牌：64
  - 数据密钥：80（足够长，密文没有等号）

##### 1.1.1.3 包含email的请求

- [4.3.1 POST /api/user](#431-post-apiuser)
- [4.3.3 POST /api/user/session](#433-post-apiusersession)
- [4.3.8 PUT /api/user/settings/email](#438-put-apiusersettingsemail)
- [4.3.11 POST /api/user/settings/password](#4311-post-apiusersettingspassword)
- [4.4.1 POST /api/email/verify](#441-post-apiemailverify)
- [4.6.4 PUT /api/admin/user/config](#464-put-apiadminuserconfig)

#### 1.1.2 数据格式

##### 1.1.2.1 哈希值

所有哈希值以base64**字节**形式处理和保存，以base64**字符串**形式传输。
session_token除外，因为是JSON，不能以字节形式保存。

因为长度问题不能以整数形式保存。

不保留等号。（密文的base64字符串依旧保留，因为需要解码）

- SHAKE256
  - email
  - password
  - email2
- MD5
  - session_token
  - email_verify -> api

##### 1.1.2.2 UUID

所有UUID以UUID对象进行处理，以UUID字符串形式保存，以hex字符串形式传输。

#### 1.1.3 数据保存

##### 1.1.3.1 用户信息

- 需要使用邮箱和密码登录，用户名仅用作昵称。
- 邮箱和密码都以哈希的形式保存，既能用于验证，又能保证安全。
- 在涉及敏感数据操作时可以进行**邮箱验证**。
  - 验证时需要用户使用该邮箱发送特定邮件，以证明用户拥有该邮箱。
  - 验证成功后一定时间内可以**完成一次**操作数据。
  - 此邮箱可以是另一个邮箱，保存哈希值，不公开，进一步增加账号以及**主**邮箱都被盗后的安全性。
    - 命名为安全邮箱。
    - 如果忘记（理论上）可以通过管理员重置。
- 建议用户使用巨复杂的~~不存在的~~邮箱作为主邮箱，并设置可以用的安全邮箱，并开启**邮箱验证**。

##### 1.1.3.2 应用数据

- 应用数据必须加密。
- 因为用户可以忘记密码，所以不考虑使用用户密码加密任何数据。
- 但是用户不可以忘记登陆邮箱，并且服务器并不保存真正的邮箱地址，所以可以利用邮箱地址加密数据。
  - 在创建用户时生成随机的密钥，并使用邮箱地址进行加密。
  - 修改邮箱时仅需重新对密钥进行加密。
  - 使用密钥加解密数据。
  - 真正的密钥也就是邮箱地址由客户端保管，在需要的请求中附加加密后的邮箱地址。

### 1.2 访问控制

- 分为用户设置和系统设置，都有白名单和黑名单。
- 所有访问（API）的IP必须在用户**以及**系统的**任何**白名单内，并且不在**所有**黑名单内。
- 所有涉及用户的访问必须**同时**满足用户设置和系统设置，其他访问只须满足系统设置。
- IP信息从`x-forwarded-for`头或者socket获取。

### 1.3 会话

- IP变化后依旧受访问控制限制。
  - 不考虑绑定国家。
- 会话令牌
  - 使用`x-custom-session-token`头传递。
  - 在数据库中只保存哈希值

### 1.4 用户配置

- 邮箱
- 密码
- 安全邮箱
- 用户名
- IP白名单
- IP黑名单
- 是否开启邮箱保护
- 锁定状态

### 1.5 系统配置

- 是否开放注册
- 密码复杂度
- 密码有效期
- 保留密码个数
- 历史记录保留个数
- 用户删除记录个数
- 用户删除保留期
- 会话超时时间
- 有效的旧会话令牌个数
- 每个用户最大会话个数
- 全局IP白名单
- 全局IP黑名单
- 锁定前的登录失败次数
- 登录失败次数重置时间
- 账户锁定时间
- 是否仅锁定IP

### 1.6 环境变量

底层设置，不能在线修改。

- DEBUG
- SQLITE_DB_FILE
  - 路径
  - 默认：`data.db`
  - 相对路径相对于模块根目录，下同
- SYSTEM_CONFIG_FILE
  - 路径
  - 默认：`system_config.json`
- REDIS_HOST
  - IP地址
  - 默认：`''`, 使用内存缓存
- REDIS_PORT
  - 整数
  - 默认：`6379`

## 2 外部库

- uvicorn[standard]
  - Web服务器，负责接收和返回请求
  - 支持uvloop
- fastapi
  - API框架，负责处理请求
  - 现在不加`[standard]`相当于过去的fastapi-slim
  - 基于starlette和pydantic
- sqlalchemy
  - SQL数据库工具，ORM框架，简化数据库操作，免去SQL语句
  - 支持异步，需要额外的异步数据库驱动
- aiosqlite
  - 异步SQLite数据库驱动
- uuid7
  - 生成UUIDv7
- aiocache[redis]
  - 异步函数缓存，减少数据库访问
  - 支持Redis，Memcached，Memory
- cryptography
  - 用于数据哈希，加解密
- python-dotenv
  - 读取.env文件
- elasticsearch[async]
  - 用于上传日志到Elasticsearch
  - 官方库
  - 支持异步
- influxdb-client[async]
  - 用于上传日志到InfluxDB
  - 官方库
  - 支持异步

## 3 内部库

### 3.1 数据模型

见[表结构](#6-表结构)。

### 3.2 通用

#### 3.2.1 类

##### 3.2.1.1 系统设置

- SystemConfig: object
  - 属性
    - system_allow_register: bool
      - 默认：`false`
    - user_passwd_require_digit: bool
      - 默认：`false`
    - user_passwd_require_upper: bool
      - 默认：`false`
    - user_passwd_require_lower: bool
      - 默认：`false`
    - user_passwd_require_special: bool
      - 默认：`false`
    - user_passwd_require_unicode: bool
      - 默认：`false`
    - user_passwd_require_length: int
      - 默认：`0`, 任意
    - user_passwd_expire: float
      - 天数
      - 默认：`-1.0`, 永久
    - user_history_login_number: int
      - 默认：`10000`
      - `-1`: 无限
    - user_history_passwd_number: int
      - 默认：`0`
      - `-1`: 无限
    - user_history_config_number: int
      - 默认：`2000`
      - `-1`: 无限
    - user_history_delete_number: int
      - 默认：`1000`
      - `-1`: 无限
    - user_delete_retain_period: float
      - 天数
      - 默认：`30.0`
      - `-1.0`: 无限
    - user_session_expire: float
      - 分钟
      - 默认：`10080.0`, 7天
    - user_session_token_fallback: int
      - 默认：`1`
    - user_session_number: int
      - 默认：`3`
    - user_lock_period: float
      - 分钟
      - 默认：`60.0`
      - `-1.0`: 永久
    - user_lock_ip_only: bool
      - 默认：`true`
    - login_fail_count: int
      - 允许输错密码的次数，包括第一次
      - 默认：`5`
    - login_fail_count_expire: float
      - 分钟
      - 默认：`30.0`
    - email_verify_expire: int
      - 秒
      - 默认：`600`
    - system_allow_ip: [string]
      - 默认：`['0.0.0.0/0', '::/0']`
    - system_deny_ip: [string]
      - 默认：`[]`
    - system_acl_serial: int
      - 4字节随机数
      - 默认：`0`
      - 用于match_ip缓存
    - internal_data_clear_interval: int
      - 秒
      - 默认：`3600`
    - internal_session_refresh_interval: int
      - 秒
      - 默认：`600`
    - internal_login_nonce_ttl: int
      - 秒
      - 默认：`10`
    - internal_old_nonce_timeout: int
      - 秒
      - 默认：`10`
    - internal_func_cache_ttl: int
      - 秒
      - 默认：`3600`
    - internal_signature_private_key: str
      - 路径
      - 默认：`private_key.pem`
    - internal_elasticsearch_url: str
    - internal_elasticsearch_apikey: str
    - internal_elasticsearch_index: str
    - internal_influxdb_url: str
    - internal_influxdb_org: str
    - internal_influxdb_token: str
    - internal_influxdb_bucket: str
  - 方法
    - load() -> bool
      - 仅在启动时调用
    - save() -> None

##### 3.2.1.2 加解密

- CryptoAES: object
  - 输入
    - password: bytes
  - 方法
    - encrypt(plainbytes: bytes) -> str
    - decrypt(cipherb64: str) -> bytes

- CryptoRSA: object
  - 输入
    - size: int
  - 方法
    - public_pem() -> str
    - encrypt(plainbytes: bytes) -> str
    - decrypt(cipherb64: str) -> bytes
    - load_private_key(pem: bytes) -> None
    - verify_signature(signature: bytes, data: bytes) -> bool

##### 3.2.1.3 错误码

- ErrorCode: Enum

##### 3.2.1.4 缓存

- default_cache: aiocache.SimpleMemoryCache | aiocache.RedisCache
  - key: bytes
    - b'login_nonce\xff' + nonce
    - b'email_verify\xff' + email_hash
    - b'session_nonce\xff' + session_id
  - value: any
  - ttl: None
    - 在set方法中指定

###### 3.2.1.4.1 函数缓存

- func_caches_data_clear: list[aiocache.cached]
- func_caches_session_update: list[aiocache.cached]
- func_caches_auto_refresh: list[aiocache.cached]

#### 3.2.2 SQL

封装SQL操作。

不使用解包参数。

##### 3.2.2.1 读

- get_all_users
  - 输入
    - email_hash: list[bytes] = None
    - user_id: list[UUID] = None
    - admin: bool = None
    - status: list[int] = None
    - name: str = None
    - protect: bool = None
  - 处理

    ```pseudo
    _cols = [*tb_users_main.__table__.columns] + [*tb_users_other.__table__.columns]
    _cols.remove(tb_users_main.id)
    _cols.remove(tb_users_other.id)
    _cols.remove(tb_users_other.user_id)
    results = select(*_cols).join(tb_users_other)
    if email_hash:
      .where(tb_users_main.email.in_(email_hash))
    if user_id:
      .where(tb_users_main.user_id.in_(user_id))
    if admin is not None:
      .where(tb_users_main.admin == admin)
    if status:
      .where(tb_users_main.status.in_(status))
    if name:
      .where(tb_users_other.name.like(f'%{name}%'))
    if protect is not None:
      .where(tb_users_other.protect == protect)
    ```

  - 输出: list[dict]
    - [row._asdict() for row in results.all()]

- get_one_user
  - 输入
    - email_or_id: bytes | UUID
  - 处理

    ```pseudo
    _cols = [*tb_users_main.__table__.columns] + [*tb_users_other.__table__.columns]
    _cols.remove(tb_users_main.id)
    _cols.remove(tb_users_other.id)
    _cols.remove(tb_users_other.user_id)
    result = select(*_cols).join(tb_users_other)
    if isinstance(email_or_id, bytes):
      .where(tb_users_main.email == email_or_id)
    elif isinstance(email_or_id, UUID):
      .where(tb_users_main.user_id == email_or_id)
    else:
      raise TypeError(f'Invalid email_or_id type: {type(email_or_id)}')
    ```

  - 输出: dict | None
    - result.first()._asdict() if result.first() else None

- get_all_user_ids_in_session
  - 处理

    ```pseudo
    results = select(tb_sessions.user_id).distinct()
    ```

  - 输出: ScalarResult
    - results.scalars()

- simple_select_one
  - 输入
    - table: Table
    - filter: dict
  - 处理

    ```pseudo
    result = select([*table.__table__.columns])
    for k, v in filter.items():
      col = getattr(table, k)
      .where(col == v)
    ```

  - 输出：dict | None
    - result.first()._asdict() if result.first() else None

- select_multi
  - 输入
    - table: Table
    - column: list[str]
    - in: dict[str, list[Any]] = None
    - gt: dict[str, Any] = None
    - lt: dict[str, Any] = None
    - order: dict[str, bool] = None
    - offset: int = None
    - limit: int = None
  - 处理

    ```pseudo
    cols = []
    if len(column) == 0:
      column = table.__table__.columns.keys()
    for c in column:
      cols.append(getattr(table, c))
    results = select(*cols)
    if in:
      for k, v in in.items():
        col = getattr(table, k)
        .where(col.in_(v))
    if gt:
      for k, v in gt.items():
        col = getattr(table, k)
        .where(col > v)
    if lt:
      for k, v in lt.items():
        col = getattr(table, k)
        .where(col < v)
    if order:
      for k, desc in order.items():
        col = getattr(table, k)
        if desc:
          .order_by(col.desc())
        else:
          .order_by(col)
    if offset:
      .offset(offset)
    if limit:
      .limit(limit)
    ```

  - 输出：list[dict]
    - [row._asdict() for row in results.all()]

- get_count
  - 输入
    - table: Table
    - in: dict[str, list[Any]]
  - 处理

    ```pseudo
    result = select(func.count()).select_from(table)
    for k, v in in.items():
      col = getattr(table, k)
      .where(col.in_(v))
    ```

  - 输出：int
    - result.scalar()

##### 3.2.2.2 写

- simple_insert_one
  - 输入
    - table: Table
    - value: dict
    - returning: List[str] = None
  - 处理

    ```pseudo
    result = insert(table).values(value)
    if returning:
      col = []
      for r in returning:
        col.append(getattr(table, r))
      .returning(*col)
    ```

  - 输出：dict | None
    - result.first()._asdict()

- insert_multi
  - 输入
    - table: Table
    - value: list[dict]
    - returning: List[str] = None
  - 处理

    ```pseudo
    results = insert(table).values(value)
    if returning:
      col = []
      for r in returning:
        col.append(getattr(table, r))
      .returning(*col)
    ```

  - 输出：list[dict] | None
    - [row._asdict() for row in results]

- simple_update_one
  - 输入
    - table: Table
    - filter: dict
    - value: dict
    - returning: List[str] = None
  - 处理

    ```pseudo
    update(table).values(value)
    for k, v in filter.items():
      col = getattr(table, k)
      .where(col == v)
    if returning:
      col = []
      for r in returning:
        col.append(getattr(table, r))
      .returning(*col)
    ```

  - 输出：dict | None
    - result.first()._asdict()

- simple_upsert_one
  - 输入
    - table: Table
    - value: dict
    - index: list[str]
  - 处理

    ```pseudo
    insert(table).values(value)
    .on_conflict_do_update(index_elements=index, set_=value)
    ```

- delete_multi
  - 输入
    - table: Table
    - in: dict[str, list[Any]] = None
    - gt: dict[str, Any] = None
    - lt: dict[str, Any] = None
    - returning: list[str] = None
  - 处理

    ```pseudo
    delete(table)
    if in:
      for k, v in in.items():
        col = getattr(table, k)
        .where(col.in_(v))
    if gt:
      for k, v in gt.items():
        col = getattr(table, k)
        .where(col > v)
    if lt:
      for k, v in lt.items():
        col = getattr(table, k)
        .where(col < v)
    if returning:
      col = []
      for r in returning:
        col.append(getattr(table, r))
      .returning(*col)
    ```

  - 输出：list[dict] | None
    - [row._asdict() for row in results]

- delete_multi_with_subquery
  - 输入
    - table: Table
    - in: dict[str, list[Any]] = None
    - gt: dict[str, Any] = None
    - lt: dict[str, Any] = None
    - order: dict[str, bool] = None
    - offset: int = None
    - limit: int = None
    - returning: list[str] = None
  - 处理

    ```pseudo
    delete(table)
    if in:
      for k, v in in.items():
        col = getattr(table, k)
        .where(col.in_(v))
    if gt:
      for k, v in gt.items():
        col = getattr(table, k)
        .where(col > v)
    if lt:
      for k, v in lt.items():
        col = getattr(table, k)
        .where(col < v)
    if order:
      for k, v in order.items():
        col = getattr(table, k)
        if v:
          .order_by(col.desc())
        else:
          .order_by(col)
    if offset:
      .offset(offset)
    if limit is not None:
      .limit(limit)
    if returning:
      col = []
      for r in returning:
        col.append(getattr(table, r))
      .returning(*col)
    ```

  - 输出：list[dict] | None
    - [row._asdict() for row in results]

#### 3.2.3 批处理

不直接调用SQL操作。

可以使用解包参数，并转换为明确参数向下传递。

- check_cidr
  - 输入
    - cidr: str
  - 处理

    ```pseudo
    try ipaddress.ip_network(cidr, strict=False)
    ```

  - 输出: ipaddress.IPv4Network | ipaddress.IPv6Network | None

- match_ip
  - 缓存：SystemConfig().internal_func_cache_ttl
  - 输入
    - ip: str
    - allow_ip: list[str]
      - 不缓存
    - deny_ip: list[str]
      - 不缓存
    - acl_serial: bytes
  - 处理

    ```pseudo
    try _ip = ipaddress.ip_address(ip)
    for _cidr in deny_ip:
      if _ip in check_cidr(_cidr):
        # check_cidr不可能在这返回None
        return False
    for _cidr in allow_ip:
      if _ip in check_cidr(_cidr):
        return True
    return False
    ```

  - 输出: bool

- get_hash
  - 输入
    - data: bytes
    - salt: bytes = b''
    - algorithm: str = 'shake_256'
  - 处理

    ```pseudo
    digest = hashlib.new(algorithm)
    digest.update(data)
    if salt: digest.update(salt)
    if algorithm == 'shake_256':
      result = digest.digest(64)
    elif algorithm == 'shake_128':
      result = digest.digest(32)
    else:
      result = digest.digest()
    ```

  - 输出：bytes
    - base64.b64encode(result).rstrip(b'=')

- get_user_by_session

  *已展开到log_with_user_info_before_nonce_check*

  - 输入
    - ip: str
    - session_id: UUID
    - session_token: bytes
    - time: float = time.time()
  - 处理

    ```pseudo
    system_config = SystemConfig()
    user_session_expire = system_config.user_session_expire
    delete_expired_users_session(time)
    delete_redundant_users_session()
    session = simple_select_one(tb_users_session, {'session_id': session_id})
    user_session_number = SystemConfig().user_session_number
    results = select_multi(tb_users_session, ['session_id'], {'user_id': [session['user_id']]}, order={'id': True}, limit=user_session_number)
    if session_id not in [row['session_id'] for row in results]: return {}
    if get_hash(session_token, algorithm='md5').decode() not in session['session_token']: return {}
    if time - session['refresh_time'] > user_session_expire: return {}
    user = get_one_user(session['user_id'])
    if ip != session['ip']:
      # 为了节省性能
      # 用户在误屏蔽自己的IP之后，在logout或变更IP之前依旧有机会挽救
      match_ip(ip, user['allow_ip'], user['deny_ip'], user['acl_serial'] + b'\xff' + user['user_id'].bytes)
    ```

  - 输出: dict
    - user_id: UUID
    - session_id: UUID
    - session_tokens: list[int]
      - tb_users_session['session_token']
    - user_info: dict
      - user
    - error: str
      - 'session'
      - 'ip'

- update_user_session
  - 缓存：SystemConfig().internal_session_refresh_interval
  - 输入
    - session_id: UUID
    - session_tokens: list[int]
      - 不缓存
    - ip: str
      - 不缓存
    - refresh_time: float = time.time()
      - 不缓存
  - 处理

    ```pseudo
    user_session_token_fallback = SystemConfig().user_session_token_fallback
    new_session_token = os.urandom(64)
    session_tokens.insert(0, get_hash(new_session_token, algorithm='md5').decode())
    while len(session_tokens) > max(user_session_token_fallback + 1, 1):
      session_tokens.pop()
    simple_update_one(tb_users_session, {'session_id': session_id}, {'session_token': session_tokens, 'ip': ip, 'refresh_time': refresh_time})
    ```

  - 输出：tuple[bytes, float]
    - new_session_token
    - refresh_time

- delete_expired_users_session
  - 缓存：SystemConfig().internal_data_clear_interval
  - 输入
    - time: float
      - 不缓存
  - 处理

    ```pseudo
    user_session_expire = SystemConfig().user_session_expire
    delete_multi(tb_users_session, lt={'refresh_time': time - user_session_expire * 60})
    ```

  - 输出：bool

- delete_redundant_users_session

  删除每个用户过多的会话，以及已删除用户的所有会话
  - 缓存：SystemConfig().internal_data_clear_interval
  - 处理

    ```pseudo
    user_session_number = SystemConfig().user_session_number
    sids = []
    all_uids = await get_all_user_ids_in_session()
    results = select_multi(tb_users_main, ['user_id'], gt={'trashed_time': 0})
    deleted_uids = [row['user_id'] for row in results]
    sids.extend([row['session_id'] for row in delete_multi(tb_users_session, in_={'user_id': deleted_uids}, returning=['session_id'])])
    remain_uids = [x for x in all_uids if x not in deleted_uids]
    for user_id in remain_uids:
      results = delete_multi_with_subquery(tb_users_session, in_={'user_id': [user_id]}, order={'id': True}, offset=user_session_number, returning=['session_id'])
      if results:
        sids.extend([row['session_id'] for row in results])
    ```

  - 输出：bool

- check_session_nonce：在验证session之后
  - 输入
    - session_id: bytes
    - nonce: int
  - 处理

    ```pseudo
    _nonce = default_cache.get(b'session_nonce\xff' + session_id)
    if not _nonce:
      return 2
    if nonce in _nonce:
      return 0
    if nonce < min(_nonce):
      return 0
    if nonce >= 18446744073709551615:
      default_cache.delete(b'session_nonce\xff' + session_id)
    else:
      default_cache.set(b'session_nonce\xff' + session_id, _nonce + [nonce], ttl=system_config.user_session_expire * 60)
    asyncio.create_task(delete_old_nonce(session_id, nonce))
    # 不考虑取消正在执行的task，防止有人不停的发送请求导致旧的nonce一直删不掉
    ```

  - 输出：int
    - 0: 无效
    - 1: 有效
    - 2: 需要重新获取

- delete_old_nonce
  - 输入
    - session_id: bytes
    - nonce: int
  - 处理

    ```pseudo
    await asyncio.sleep(system_config.internal_old_nonce_timeout)
    _nonce = default_cache.get(b'session_nonce\xff' + session_id)
    default_cache.set(b'session_nonce\xff' + session_id, [x for x in _nonce if x >= nonce], ttl=system_config.user_session_expire * 60)
    ```

### 3.3 本体

#### 3.3.1 类

无

#### 3.3.2 SQL

无

#### 3.3.3 批处理

不直接调用SQL操作。

可以使用解包参数，并转换为明确参数向下传递。

- add_user
  - 输入
    - email: bytes
    - password: bytes
    - admin: bool
    - email2: bytes
    - name: str
    - allow_ip: list[str]
    - deny_ip: list[str]
    - protect: bool
    - time: float = time.time()
    - ip: str = 'system'
  - 处理

    ```pseudo
    password_salt = os.urandom(32)
    user_id, = simple_insert_one(tb_users_main, {'email': get_hash(email), 'email_mask': email.decode()[:3], 'password': get_hash(password, password_salt), 'password_salt': password_salt, 'data_key': CryptoAES(get_hash(email + password_salt[::-1])).encrypt(os.urandom(80)), 'admin': admin, 'status': 0, 'created_time': time, 'created_ip': ip}, returning=['user_id'])
    simple_insert_one(tb_users_other, {'user_id': user_id, 'email2': get_hash(email2) if email2 else '', 'email2_mask': email2.decode()[:3], 'name': name, 'allow_ip': allow_ip, 'deny_ip': deny_ip, 'protect': protect})
    insert_history_passwd(user_id, get_hash(password, password_salt), time)
    ```

  - 输出: UUID
    - user_id

- check_password_compliance
  - 输入
    - password: str
  - 处理

    ```pseudo
    SystemConfig()
    # 获取
    # user_passwd_require_digit
    # user_passwd_require_upper
    # user_passwd_require_lower
    # user_passwd_require_special
    # user_passwd_require_unicode
    # user_passwd_require_length
    ```

  - 输出: bool

- generate_random_string
  - 输入
    - length: int = 4
    - digit: bool = True
    - upper: bool = True
    - lower: bool = True
    - special: bool = False
  - 处理

    ```pseudo
    dic = ''
    if digit: dic += string.digits
    if upper: dic += string.ascii_uppercase
    if lower: dic += string.ascii_lowercase
    if special: dic += string.punctuation
    ```

  - 输出: str
    - ''.join(random.choice(dic) for i in range(length))

- insert_history_login
  - 输入
    - user_id: UUID
    - time: float
    - ip: str
    - result: int
  - 处理

    ```pseudo
    user_history_login_number = SystemConfig().user_history_login_number
    if user_history_login_number != 0:
      simple_insert_one(tb_users_history_login, {'user_id': user_id, 'time': time, 'ip': ip, 'result': result})
    delete_old_users_history_login(user_id)
    ```

- delete_old_users_history_login
  - 缓存：SystemConfig().internal_data_clear_interval
  - 输入
    - user_id: UUID
  - 处理

    ```pseudo
    user_history_login_number = SystemConfig().user_history_login_number
    if user_history_login_number < 0: return
    delete_multi_with_subquery(tb_users_history_login, {'user_id': [user_id]}, order={'id': True}, offset=user_history_login_number)
    ```

  - 输出：bool

- insert_history_passwd
  - 输入
    - user_id: UUID
    - password: int
    - time: float
  - 处理

    ```pseudo
    user_history_passwd_number = SystemConfig().user_history_passwd_number
    if user_history_passwd_number != 0:
      simple_insert_one(tb_users_history_passwd, {'user_id': user_id, 'password': password, 'time': time})
    delete_old_users_history_passwd(user_id)
    ```

- delete_old_users_history_passwd
  - 缓存：SystemConfig().internal_data_clear_interval
  - 输入
    - user_id: UUID
  - 处理

    ```pseudo
    user_history_passwd_number = SystemConfig().user_history_passwd_number
    if user_history_passwd_number < 0: return
    delete_multi_with_subquery(tb_users_history_passwd, {'user_id': [user_id]}, order={'id': True}, offset=user_history_passwd_number)
    ```

  - 输出：bool

- insert_history_config
  - 输入
    - user_id: UUID
    - time: float
    - ip: str
    - **values: HistoryConfigModel
  - 处理

    ```pseudo
    user_history_config_number = SystemConfig().user_history_config_number
    if user_history_config_number != 0:
      simple_insert_one(tb_users_history_config, {'user_id': user_id, 'time': time, 'ip': ip, **values})
    delete_old_users_history_config(user_id)
    ```

- delete_old_users_history_config
  - 缓存：SystemConfig().internal_data_clear_interval
  - 输入
    - user_id: UUID
  - 处理

    ```pseudo
    user_history_config_number = SystemConfig().user_history_config_number
    if user_history_config_number < 0: return
    delete_multi_with_subquery(tb_users_history_config, {'user_id': [user_id]}, order={'id': True}, offset=user_history_config_number)
    ```

  - 输出：bool

- delete_old_users
  - 缓存：SystemConfig().internal_data_clear_interval
  - 输入
    - time: float = time.time()
  - 处理

    ```pseudo
    user_delete_retain_period = SystemConfig().user_delete_retain_period
    results = delete_multi(tb_users_main, gt={'trashed_time': 0}, lt={'trashed_time': time - user_delete_retain_period * 24 * 60 * 60}, returning=['user_id', 'email', 'email_mask','trashed_time', 'trashed_ip'])
    insert_multi(tb_users_history_delete, [{**row, 'trashed_time': time, 'deleted_by': 'system'} for row in results])
    delete_old_users_history_delete()
    ```

  - 输出：bool

- delete_old_users_history_delete
  - 缓存：SystemConfig().internal_data_clear_interval
  - 处理

    ```pseudo
    user_history_delete_number = SystemConfig().user_history_delete_number
    if user_history_delete_number < 0: return
    delete_multi_with_subquery(tb_users_history_delete, order={'id': True}, offset=user_history_delete_number)
    ```

  - 输出：bool

- delete_expired_users_lock
  - 缓存：SystemConfig().internal_data_clear_interval
  - 输入
    - time: float
      - 不缓存
  - 处理

    ```pseudo
    user_lock_period = SystemConfig().user_lock_period
    login_fail_count_expire = SystemConfig().login_fail_count_expire
    if user_lock_period >= 0:
      delete_multi(tb_users_lock, lt={'time': time - user_lock_period * 60})
    delete_multi(tb_users_login_fail, lt={'time': time - login_fail_count_expire * 60})
    ```

  - 输出：bool

#### 3.3.4 参数模型

- NewUserModel: pydantic.BaseModel
  - email: str
  - password: str
  - admin: bool = False
  - email2: str = None
  - name: str = None
  - allow_ip: list[str] = ['0.0.0.0/0', '::/0']
  - deny_ip: list[str] = []
  - protect: bool = False

- HistoryConfigModel: pydantic.BaseModel
  - email_mask: str = None
  - password: int = None
  - email2_mask: str = None
  - name: str = None
  - allow_ip: list[str] = None
  - deny_ip: list[str] = None
  - protect: bool = None
  - locked: bool = None

- SystemCommonConfigModel: pydantic.BaseModel
  - system_allow_register: bool = None
  - user_passwd_require_digit: bool = None
  - user_passwd_require_upper: bool = None
  - user_passwd_require_lower: bool = None
  - user_passwd_require_special: bool = None
  - user_passwd_require_unicode: bool = None
  - user_passwd_require_length: int = None
  - user_passwd_expire: float = None
  - user_history_login_number: int = None
  - user_history_passwd_number: int = None
  - user_history_config_number: int = None
  - user_history_delete_number: int = None
  - user_delete_retain_period: float = None
  - user_session_expire: float = None
  - user_session_token_fallback: int = None
  - user_session_number: int = None
  - user_lock_period: float = None
  - user_lock_ip_only: bool = None
  - login_fail_count: int = None
  - login_fail_count_expire: float = None
  - email_verify_expire: int = None
  - system_allow_ip: list[str] = None
  - system_deny_ip: list[str] = None
  - 没有system_acl_serial

- SystemInternalConfigModel: pydantic.BaseModel
  - 全部为base64密文
  - internal_data_clear_interval: str = None
  - internal_session_refresh_interval: str = None
  - internal_login_nonce_ttl: str = None
  - internal_old_nonce_timeout: str = None
  - internal_func_cache_ttl: str = None
  - internal_signature_private_key: str = None
  - internal_elasticsearch_url: str = None
  - internal_elasticsearch_index: str = None
  - internal_elasticsearch_apikey: str = None
  - internal_influxdb_url: str = None
  - internal_influxdb_org: str = None
  - internal_influxdb_token: str = None
  - internal_influxdb_bucket: str = None

- UserOtherConfigModel: pydantic.BaseModel
  - name: str = None
  - allow_ip: list[str] = None
  - deny_ip: list[str] = None
  - protect: bool = None

### 3.4 应用

#### 3.4.1 类

- Totp: object
  - 输入
    - secret: bytes
    - algorithm: str = 'SHA1'
    - interval: int = 30
    - digits: int = 6
    - results: int = 10
  - 方法
    - codes(time: float = time.time()) -> list[str]

#### 3.4.2 SQL

无

#### 3.4.3 批处理

无

#### 3.4.4 参数模型

- MFAConfigModel: pydantic.BaseModel
  - protect: bool

- MFANewDataModel: pydantic.BaseModel
  - name: str
  - comment: str = None
  - secret: str
  - position: int
  - algorithm: Literal['SHA1', 'SHA256', 'SHA512'] = 'SHA1'
  - interval: int = 30
  - digits: Literal[6, 7, 8] = 6

- MFAUpdateDataModel: pydantic.BaseModel
  - name: str = None
  - comment: str = None
  - secret: str = None
  - position: int = None
  - algorithm: Literal['SHA1', 'SHA256', 'SHA512'] = None
  - interval: int = None
  - digits: Literal[6, 7, 8] = None

## 4 API

### 4.1 共通

- 使用RESTful格式，更直观
  - POST: 新建，重置
  - PUT: 更新
  - DELETE: 删除
  - GET: 通过query传参
    - get：对单数端点
    - list：对复数端点
- `x-custom-encryption-key`头 = 使用公钥加密后的*通信密钥*
  - 响应中包含敏感信息也是用*通信密钥*加密
- ~~会话信息只在返回200时更新（set-cookie）~~
- set-cookie的值使用hex编码，不包含特殊字符

#### 4.1.1 响应

- 响应体
  - isOK: bool
  - data?: any
  - error?: str
  - errorCode?: int
  - errorMessage?: str
- 正常的返回码
  - 200:
    - isOK: true
- 错误代码
  - 位数
    - 服务器错误：1
    - 客户端错误
      - 可恢复：2
      - 数据错误：3
      - 限制：4
      - 畸形请求：5
      - 其他：6
  - 开头
    - 加密相关：1
    - nonce：2
    - 会话：3
    - 用户信息：4
    - 应用数据：5
    - 访问控制：6
    - 邮件验证：7
    - 系统：8
    - 其他：9
- 异常的返回码
  - 303:
    - isOK: false
    - error: password
      - message: expired
        - code: 41
      - message: weak
        - code: 42
    - error: nonce
      - message: get a new nonce
        - code: 20
  - 400
    - isOK: false
    - error: nonce
      - message: invalid
        - code: 20000
    - error: encryption
      - message: invalid data encryption
        - code: 101
    - error: session
      - message: malformed session id
        - code: 30001
  - 401
    - isOK: false
    - error: session
      - message: not found
        - code: 301
      - message: replaced by new login
        - code: 302
      - message: session token wrong
        - code: 303
      - message: expired
        - code: 304
  - 403
    - isOK: false
    - error: ip
      - message: forbidden
        - code: 6001
  - 404
    - isOK: false
    - error: user
      - message: deleted
        - code: 43
      - message: not found
        - code: 401
  - 406
    - isOK: false
    - error: encryption
      - message: invalid encryption key
        - code: 102
  - 500
    - isOK: false
    - error: server
      - message: internal error
        - code: 9
- 返回以下错误时关闭连接（connection: close）
  - 400
  - 403

#### 4.1.2 前置处理

- 构建并返回log对象
  - 获取请求信息
  - 获取用户信息
  - 获取会话信息
  - 更新会话信息

#### 4.1.3 有“副作用”的API

使用BackgroundTasks做后续处理（未在本文记载）

- [4.3.3 POST /api/user/session](#433-post-apiusersession)
  - 更新main.status
  - 清理失败记录
  - 清理过期锁定
- 其他所有
  - 清理过期会话
  - 清理多余会话

### 4.2 /api/crypto

#### 4.2.1 GET /api/crypto/public

用于加密POST请求中的邮箱和密码，服务器启动时随机生成*私钥*

- 输出
  - isOK: bool
  - data: str
    - pem

#### 4.2.2 GET /api/crypto/nonce1

用于获取登录nonce

- 处理

  ```pseudo
  data = b'\x00' * 4 + os.urandom(4)
  default_cache.set(b'login_nonce\xff' + nonce, True, ttl=system_config.internal_login_nonce_ttl)
  ```

- 输出
  - isOK: bool
  - data: list[int]
    - list(data)

#### 4.2.3 GET /api/crypto/nonce2

用于更新会话nonce

- 处理

  ```pseudo
  # 前置处理
  data = b'\x00' * 4 + os.urandom(4)
  default_cache.set(b'session_nonce\xff' + session_id.bytes, [int.from_bytes(nonce) - 1], ttl=system_config.user_session_expire * 60)
  ```

- 输出
  - isOK: bool
  - data: list[int]
    - list(data)

### 4.3 /api/user

#### 4.3.1 POST /api/user

注册
- 输入
  - config: NewUserModel
- 处理

  ```pseudo
  # 前置处理
  # 获取now, ip, key
  system_config = SystemConfig()
  if not system_config.system_allow_register: return
  CryptoRSA.decrypt(key) # 使用 私钥 解密 通信密钥
  CryptoAES(key).decrypt(...) # 使用 通信密钥 解密config.email, config.password, config.email2
  if default_cache.get(b'email_verify\xff' + get_hash(解密email)) != 'email_verify_register': return
  simple_select_one(tb_users_main, {'email': get_hash(解密email)})
    await default_cache.delete(b'email_verify\xff' + get_hash(解密email))
    if 存在：return
  check_password_compliance(解密password) or return
  for _cidr in config.allow_ip + config.deny_ip:
    if not check_cidr(_cidr): return
  await default_cache.delete(b'email_verify\xff' + get_hash(解密email))
  add_user(解密email, 解密password, False, 解密email2, config.name or f'user_{generate_random_string()}', config.allow_ip, config.deny_ip, config.protect, now, ip)
  ```

- 输出
  - isOK: bool
  - error: str
    - 403
      - system: not open(8001)
    - 404
      - verify email: not found(700)
    - 406
      - data invalid: *cidr*(90001)
    - 409
      - email: already exists(403)

#### 4.3.2 DELETE /api/user

临时删除
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, email, email2, protect, admin
  if protect:
    _email = email if not email2 else email2
    if default_cache.get(b'email_verify\xff' + \_email) != f'email_verify_{user_id.hex}': return
    default_cache.delete(b'email_verify\xff' + _email)
  if admin:
    if get_count(tb_users_main, {'admin': True}) <= 1:
      return
  simple_update_one(tb_users_main, {'user_id': user_id}, {'trashed_time': now, 'trashed_ip': ip})
  insert_history_config(user_id, now, ip, password=3)
  ```

- 输出
  - isOK: bool
  - error: str
    - 404
      - verify email: not found(700)
    - 406
      - system: last admin user(8002)
- 头
  - set-cookie: session_id=''; path=/api; expires=Thu, 01 Jan 1970 00:00:00 GMT; sameSite=Strict

#### 4.3.3 POST /api/user/session

登录
- 输入
  - email: str
  - password: str
- 处理

  ```pseudo
  # 前置处理
  # 获取ip, key
  CryptoRSA.decrypt(key) # 使用 私钥 解密 通信密钥
  CryptoAES(key).decrypt(...) # 使用 通信密钥 解密email, password
  nonce = key[64:]
  if not default_cache.get(b'login_nonce\xff' + nonce): return
  default_cache.delete(b'login_nonce\xff' + nonce)
  get_one_user(get_hash(解密email))
  # 获取user_id, password, password_salt, status, allow_ip, deny_ip, acl_serial, trashed_time
  if 不存在：return
  SystemConfig()
    # 获取
    # user_passwd_expire
    # login_fail_count
    # login_fail_count_expire
    # user_lock_period
    # user_lock_ip_only
  delete_expired_users_lock(now)
  match_ip(ip, allow_ip, deny_ip, acl_serial + b'\xff' + user_id.bytes)
  False
    insert_history_login(user_id, now, ip, 4)
    return
  if user_lock_ip_only:
    select_multi(tb_users_lock, ['id'], {'user_id': [user_id], 'ip': [ip]}, gt={'time': now - user_lock_period * 60})
  else:
    select_multi(tb_users_lock, ['id'], {'user_id': [user_id]}, gt={'time': now - user_lock_period * 60})
  存在
    insert_history_login(user_id, now, ip, 3)
    return
  if trashed_time:
    if default_cache.get(b'email_verify\xff' + get_hash(解密email)) != 'email_verify_login':
      return
  哈希password：get_hash(password, password_salt)
  验证password
  成功
    if trashed_time:
      simple_update_one(tb_users_main, {'user_id': user_id}, {'trashed_time': -1, 'trashed_ip': None})
      insert_history_config(user_id, now, ip, password=0)
      default_cache.delete(b'email_verify\xff' + get_hash(解密email))
    new_status = 0
    select_multi(tb_users_history_passwd, ['time'], {'user_id': [user_id]}, order={'id': True}, limit=1)
      获取time
    验证user_passwd_expire
    失败
      new_status = 1
    check_password_compliance(password)
    失败
      new_status = 2 | new_status
    if new_status != status:
      simple_update_one(tb_users_main, {'user_id': user_id}, {'status': new_status})
    insert_history_login(user_id, now, ip, 0)
    delete_multi(tb_users_login_fail, {'user_id': [user_id], 'ip': [ip]})
    session_token = os.urandom(64)
    session_id, = simple_insert_one(tb_users_session, {'session_token': [get_hash(session_token, algorithm='md5').decode()], 'user_id': user_id, 'ip': ip, 'login_time': now, 'refresh_time': now}, ['session_id'])
    default_cache.set(b'session_nonce\xff' + session_id.bytes, [int.from_bytes(nonce)], ttl=system_config.user_session_expire * 60)
  失败
    select_multi(tb_users_login_fail, ['count'], {'user_id': [user_id], 'ip': [ip]}, gt={'time': now - login_fail_count_expire * 60})
      获取count
    存在
      count++
    不存在
      count = 1
    if count > login_fail_count:
      simple_upsert_one(tb_users_lock, {'user_id': user_id, 'ip': ip, 'time': now}, ['user_id', 'ip'])
      delete_multi(tb_users_login_fail, {'user_id': [user_id], 'ip': [ip]})
      insert_history_login(user_id, now, ip, 2)
      insert_history_config(user_id, now, ip, locked=True)
    else
      simple_upsert_one(tb_users_login_fail, {'user_id': user_id, 'ip': ip, 'count': count, 'time': now}, ['user_id', 'ip'])
      insert_history_login(user_id, now, ip, 1)
  ```

- 输出
  - isOK: bool
  - error
    - 401
      - password: wrong(404)
    - 403
      - locked: *time*(6002)
    - 404
      - email: not found(402)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(session_token)
  - set-cookie: session_id=session_id; path=/api; expires=Fri, 31 Dec 9999 23:59:59 GMT; sameSite=Strict

#### 4.3.4 DELETE /api/user/session

登出
- 输入
  - target_session_id?: UUID
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, session_id
  if target_session_id:
    simple_select_one(tb_users_session, {'session_id': target_session_id, 'user_id': user_id})
    不存在: return
    delete_multi(tb_users_session, {'session_id': [target_session_id]})
  else:
    delete_multi(tb_users_session, {'session_id': [session_id]})
    new_session_token = b''
  ```

- 输出
  - isOK: bool
  - error: session
    - 404
      - session: not found(305)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.3.5 GET /api/user/sessions

获取当前用户所有有效会话
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  system_config = SystemConfig()
  data = select_multi(tb_users_session, ['session_id', 'ip', 'login_time'], {'user_id': [user_id]}, gt={'refresh_time': log.start_time - system_config.user_session_expire * 60}, order={'id': True})
  for row in data[:system_config.user_session_number]:
    row['session_id'] = row['session_id'].hex
  if len(data) > system_config.user_session_number:
    delete_multi('user_id': [user_id], tb_users_session, {'session_id': [row['session_id'] for row in data[system_config.user_session_number:]]})
  ```

- 输出
  - isOK: bool
  - data: list[dict]
    - session_id: str
    - ip: str
    - login_time: number
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.3.6 GET /api/user/settings

- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  # 获取email_mask, email2_mask, name, allow_ip, deny_ip, protect
  ```

- 输出
  - isOK: bool
  - data: Object
    - user_id: str
    - email_mask: str
    - email2_mask: str
    - name: str
    - allow_ip: list[str]
    - deny_ip: list[str]
    - protect: bool
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.3.7 PUT /api/user/settings

修改其他属性（不需要验证当前设定）
- 输入
  - config: UserOtherConfigModel
    - 使用pydantic验证时，在实际请求中并不需要“config”这一层嵌套
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  # 获取email, email2, allow_ip, deny_ip, protect
  data = {}
  if config.name:
    data['name'] = config.name
  if config.allow_ip:
    for _cidr in config.allow_ip:
      if not check_cidr(_cidr): return
    data['allow_ip'] = config.allow_ip
    data['acl_serial'] = os.urandom(4)
  if config.deny_ip:
    for _cidr in config.deny_ip:
      if not check_cidr(_cidr): return
    data['deny_ip'] = config.deny_ip
    data['acl_serial'] = os.urandom(4)
  if config.protect:
    data['protect'] = config.protect
  if not data: return
  if protect:
    _email = email if not email2 else email2
    if default_cache.get(b'email_verify\xff' + \_email) != f'email_verify_{user_id.hex}': return
    default_cache.delete(b'email_verify\xff' + _email)
  insert_history_config(user_id, now, ip, **data)
  simple_update_one(tb_users_other, {'user_id': user_id}, data)
  ```

- 输出
  - isOK: bool
  - error: str
    - 404
      - verify email: not found(700)
    - 406
      - data invalid: *cidr*(90001)
      - parameter: parameter required(90002)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.3.8 PUT /api/user/settings/email

修改邮箱
- 输入
  - curEmail: str
  - newEmail: str
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  # 获取email, email2, protect
  CryptoAES(key).decrypt(...) # 使用*通信密钥*解密email, newEmail
  if get_hash(curEmail) != email: return
  if protect:
    _email = email if not email2 else email2
    if default_cache.get(b'email_verify\xff' + \_email) != f'email_verify_{user_id.hex}': return
    default_cache.delete(b'email_verify\xff' + _email)
  if simple_select_one(tb_users_main, {'email': get_hash(newEmail)}):
    return
  insert_history_config(user_id, now, ip, email_mask=newEmail[:3])
  # 使用curEmail解密data_key
  # 使用newEmail加密data_key
  simple_update_one(tb_users_main, {'user_id': user_id}, {'email': get_hash(newEmail), 'email_mask': newEmail[:3], 'data_key': 加密data_key})
  ```

- 输出
  - isOK: bool
  - error: str
    - 403
      - email: wrong(405)
    - 404
      - verify email: not found(700)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.3.9 PUT /api/user/settings/email2

修改安全邮箱，必须进行**邮箱验证**
- 输入
  - curEmail2: str
  - newEmail2: str
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  # 获取email, email2, protect
  CryptoAES(key).decrypt(...) # 使用*通信密钥*解密curEmail2, newEmail2
  _email = email if not email2 else email2
  if default_cache.get(b'email_verify\xff' + \_email) != f'email_verify_{user_id.hex}': return
  default_cache.delete(b'email_verify\xff' + _email)
  if email2:
    if get_hash(curEmail2) != email2: return
  else:
    if curEmail2: return
  insert_history_config(user_id, now, ip, email2_mask=newEmail2[:3])
  simple_update_one(tb_users_other, {'user_id': user_id}, {'email2': get_hash(newEmail2), 'email2_mask': newEmail2[:3]})
  ```

- 输出
  - isOK: bool
  - error: str
    - 403
      - email2: wrong(406)
    - 404
      - verify email: not found(700)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.3.10 PUT /api/user/settings/password

修改密码
- 输入
  - curPassword: str
  - newPassword: str
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  # 获取password, password_salt, email, email2, protect
  CryptoAES(key).decrypt(...) # 使用*通信密钥*解密curPassword, newPassword
  check_password_compliance(newPassword) or return
  if get_hash(curPassword, password_salt) != password: return
  if curPassword == newPassword: return
  simple_select_one(tb_users_history_passwd, {'user_id': user_id, 'password': get_hash(newPassword, password_salt)})
  存在: return
  if protect:
    _email = email if not email2 else email2
    if default_cache.get(b'email_verify\xff' + \_email) != f'email_verify_{user_id.hex}': return
    default_cache.delete(b'email_verify\xff' + _email)
  insert_history_passwd(user_id, password, now)
  insert_history_config(user_id, now, ip, password=1)
  simple_update_one(tb_users_main, {'user_id': user_id}, {'password': get_hash(newPassword, password_salt), 'status': 0})
  ```

- 输出
  - isOK: bool
  - error: str
    - 401
      - password: wrong(404)
    - 404
      - verify email: not found(700)
    - 406
      - new password: weak(407)|used(408)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.3.11 POST /api/user/settings/password

重置密码，邮箱验证依旧需要email2，如果有
- 输入
  - email: str
  - newPassword: str
- 处理

  ```pseudo
  # 前置处理
  # 获取ip, key
  CryptoRSA.decrypt(key) # 使用 私钥 解密 通信密钥
  CryptoAES(key).decrypt(...) # 使用 通信密钥 解密email, newPassword
  get_one_user(get_hash(email))
  # 获取user_id, password, password_salt, email2, allow_ip, deny_ip, acl_serial
  不存在：retrun
  _email = email if not email2 else email2
  if default_cache.get(b'email_verify\xff' + _email) != 'email_verify_password': return
  default_cache.delete(b'email_verify\xff' + _email)
  match_ip(ip, allow_ip, deny_ip, acl_serial + b'\xff' + user_id.bytes) or return
  check_password_compliance(newPassword) or return
  if get_hash(newPassword) == password: return
  simple_select_one(tb_users_history_passwd, {'user_id': user_id, 'password': get_hash(newPassword, password_salt)})
  存在: return
  insert_history_passwd(user_id, password, now)
  insert_history_config(user_id, now, ip, password=2)
  simple_update_one(tb_users_main, {'user_id': user_id}, {'password': get_hash(newPassword, password_salt), 'status': 0})
  ```

- 输出
  - isOK: bool
  - error: str
    - 404
      - email: not found(402)
      - verify email: not found(700)
    - 406
      - new password: weak(407)|used(408)

#### 4.3.12 GET /api/user/locks

- 输入
  - start?: int = 1
  - end?: int = 10
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  data = select_multi(tb_users_lock, ['ip', 'time'], {'user_id': [user_id]}, order={'id': True}, offset=max(start - 1, 0), limit=max(end - start + 1, 0))
  count = get_count(tb_users_lock, {'user_id': [user_id]})
  ```

- 输出
  - isOK: bool
  - data: list[dict]
    - ip: str
    - time: number
  - total: int
    - count
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.3.13 DELETE /api/user/locks

解除锁定IP
- 输入
  - ips: list[str]
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  delete_multi(tb_users_lock, {'user_id': [user_id], 'ip': ips})
  ```

- 输出
  - isOK: bool
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.3.14 GET /api/user/history/logins

- 输入
  - start?: int = 1
  - end?: int = 10
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  data = select_multi(tb_users_history_login, ['time', 'ip','result'], {'user_id': [user_id]}, order={'id': True}, offset=max(start - 1, 0), limit=max(end - start + 1, 0))
  count = get_count(tb_users_history_login, {'user_id': [user_id]})
  ```

- 输出
  - isOK: bool
  - data: list[dict]
    - time: number
    - ip: str
    - result: number
  - total: int
    - count
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.3.15 GET /api/user/history/settings

- 输入
  - start?: int = 1
  - end?: int = 10
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  results = select_multi(tb_users_history_config, [], {'user_id': [user_id]}, order={'id': True}, offset=max(start - 1, 0), limit=max(end - start + 1, 0))
  data = []
  for row in results:
    row.pop('id')
    row.pop('user_id')
    for key, value in row.items():
      if value is None:
        row.pop(key)
    data.append(row)
  count = get_count(tb_users_history_config, {'user_id': [user_id]})
  ```

- 输出
  - isOK: bool
  - data: list[dict]
    - time: number
    - ip: str
    - <非空字段>: str|number
    - <非空字段>: ...
  - total: int
    - count
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

### 4.4 /api/email

#### 4.4.1 POST /api/email/verify

从外部邮件服务发送
- 输入
  - from: str
  - to: str
  - signature: str
- 处理

  ```pseudo
  try RSAPublicKey().verify(signature.encode(), f'{from}.{to}'.encode())
  default_cache.set(b'email_verify\xff' + get_hash(from.encode()), to)
  ```

- 输出
  - isOK: bool
  - error: str
    - 403
      - signature: wrong(199)

### 4.5 /api/system

开放

#### 4.5.1 GET /api/system/settings

- 处理

  ```pseudo
  # 前置处理
  system_config = SystemConfig()
  data = {key: getattr(system_config, key) for key in system_config.\_\_slots__ if not key.startswith('internal_') and not key.endswith('_hash')}
  ```

- 输出
  - isOK: bool
  - data: dict

#### 4.5.2 WebSocket /api/system/ping

- 处理

  ```pseudo
  ws = WebSocket()
  count = 0
  await ws.accept()
  while count < 10:
    data = await asyncio.wait_for(ws.recive_bytes(), timeout=10) or break
    await ws.send_bytes(data)
    count += 1
  ```

### 4.6 /api/admin

需要管理员会话。

#### 4.6.1 GET /api/admin/users

- 输入
  - start?: int = 1
  - end?: int = 10
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  验证admin
  data = get_all_users(offset=max(start - 1, 0), limit=max(end - start + 1, 0))
  for row in data:
    row.pop('password')
    row.pop('password_salt')
    row.pop('data_key')
    row['deleted'] = row.pop('trashed_time') > 0
    row.pop('trashed_ip')
    row.pop('acl_serial')
  ```

- 输出
  - isOK: bool
  - error
    - 403
      - system: not admin(6003)
  - data: list[dict]
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.6.2 GET /api/admin/user/history/delete

- 输入
  - email?: str = None
  - start?: int = 1
  - end?: int = 10
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  验证admin
  if email:
    CryptoAES(key).decrypt(email) # 使用*通信密钥*解密email
    _in = {'email': get_hash(email)}
  else:
    _in = {}
  data = select_multi(tb_users_history_delete, ['email', 'email_mask', 'user_id', 'trashed_time', 'trashed_ip', 'deleted_time', 'deleted_by'], _in, order={'id': True}, offset=max(start - 1, 0), limit=max(end - start + 1, 0))
  count = get_count(tb_users_history_delete, _in)
  ```

- 输出
  - isOK: bool
  - data: list[dict]
    - email: str
      - base64
    - email_mask: str
    - user_id: str
      - hex
    - trashed_time: number
    - trashed_ip: str
    - deleted_time: number
    - deleted_by: str
  - total: int
    - count
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.6.3 POST /api/admin/user

- 输入
  - config: NewUserModel
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  验证admin
  CryptoAES(key).decrypt(...) # 使用*通信密钥*解密config.email, config.password, config.email2
  simple_select_one(tb_users_main, {'email': get_hash(解密email)})
    存在：return
  for _cidr in config.allow_ip + config.deny_ip:
    if not check_cidr(_cidr): return
  add_user(解密email, 解密password, config.admin, 解密email2, config.name or f'user_{generate_random_string()}', config.allow_ip, config.deny_ip, config.protect, now, 'admin')
  ```

- 输出
  - isOK: bool
  - error: str
    - 403
      - system: not admin(6003)
    - 406
      - data invalid: *cidr*(90001)
    - 409
      - email: already exists(403)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.6.4 PUT /api/admin/user/config

- 输入
  - userId: str
  - newPassword?: str = None
  - newStatus?: number = None
  - newEmail2?: str = None
  - other?: UserOtherConfigModel
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, allow_ip, deny_ip, new_session_token
  验证admin
  user = simple_select_one(tb_users_main, {'user_id': userId})
    if 不存在：return
    if user['admin']: return
    if user['trashed_time'] >= 0: return
  main_data = {}
  other_data = {}
  history_data = {}
  if newPassword:
    CryptoAES(key).decrypt(newPassword) # 使用*通信密钥*解密newPassword
    main_data['password'] = get_hash(newPassword, password_salt)
    history_data['password'] = 2
    insert_history_passwd(userId, password, now)
  if newStatus is not None:
    main_data['status'] = newStatus
  if newEmail2:
    CryptoAES(key).decrypt(newEmail2) # 使用*通信密钥*解密newEmail2
    other_data['email2'] = get_hash(newEmail2)
    other_data['email2_mask'] = newEmail2[:3]
    history_data['email2_mask'] = newEmail2[:3]
  if other.name:
    other_data['name'] = other.name
    history_data['name'] = other.name
  if other.allow_ip:
    for _cidr in other.allow_ip:
      if not check_cidr(_cidr): return
    other_data['allow_ip'] = other.allow_ip
    other_data['acl_serial'] = os.urandom(4)
    history_data['allow_ip'] = other.allow_ip
  if other.deny_ip:
    for _cidr in other.deny_ip:
      if not check_cidr(_cidr): return
    other_data['deny_ip'] = other.deny_ip
    other_data['acl_serial'] = os.urandom(4)
    history_data['deny_ip'] = other.deny_ip
  if other.protect:
    other_data['protect'] = other.protect
    history_data['protect'] = other.protect
  simple_update_one(tb_users_main, {'user_id': userId}, {**main_data})
  simple_update_one(tb_users_other, {'user_id': userId}, {**other_data})
  insert_history_config(userId, now, 'admin', **history_data)
  ```

- 输出
  - isOK: bool
  - error: str
    - 403
      - system: not admin(6003)
    - 404
      - user: not found(401)
    - 406
      - data invalid: *cidr*(90001)
      - system: delete only deleted user(8003)
      - system: target user is admin(8004)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.6.5 PUT /api/admin/user/trash

临时删除

- 输入
  - userId: str
  - undo?: bool = False
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  验证admin
  user = simple_select_one(tb_users_main, {'user_id': userId})
    if 不存在：return
    if user['admin']: return
    if user['trashed_time'] >= 0 and not undo: return
    if user['trashed_time'] < 0 and undo: return
  simple_update_one(tb_users_main, {'user_id': userId}, {'trashed_time': -1 if undo else now, 'trashed_ip': None if undo else 'admin'})
  insert_history_config(userId, now, 'admin', password=0 if undo else 3)
  ```

- 输出
  - isOK: bool
  - error: str
    - 403
      - system: not admin(6003)
    - 404
      - user: not found(401)
    - 406
      - system: delete only deleted user(8003)
      - system: target user is admin(8004)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.6.6 DELETE /api/admin/user

永久删除，需要先临时删除。

- 输入
  - userId: str
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  验证admin
  user = simple_select_one(tb_users_main, {'user_id': userId})
    if 不存在：return
    if user['admin']: return
    if user['trashed_time'] < 0: return
  result = delete_multi(tb_users_main, {'user_id': [userId]}, returning=['email', 'email_mask', 'user_id', 'trashed_time', 'trashed_ip'])
  simple_insert_one(tb_users_history_delete, {**row, 'deleted_time': now, 'deleted_by': 'admin'} for row in result)
  delete_old_users_history_delete()
  ```

- 输出
  - isOK: bool
  - error: str
    - 403
      - system: not admin(6003)
    - 404
      - user: not found(401)
    - 406
      - system: delete only deleted user(8003)
      - system: target user is admin(8004)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.6.7 PUT /api/admin/system/settings/common

- 输入
  - config: SystemCommonConfigModel
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  验证admin
  system_config = SystemConfig()
  _hash = system_config.system_acl_serial
  if config.system_allow_ip:
    for _cidr in config.system_allow_ip:
      if not check_cidr(_cidr): return
    _hash = int.from_bytes(os.urandom(4))
  if config.system_deny_ip:
    for _cidr in config.system_deny_ip:
      if not check_cidr(_cidr): return
    _hash = int.from_bytes(os.urandom(4))
  _new_config = False
  for key, value in config:
    if value is not None:
      setattr(system_config, key, value)
      if not _new_config:
        _new_config = True
  if not _new_config: return
  if system_config.system_acl_serial != \_hash:
    system_config.system_acl_serial = \_hash
  system_config.user_session_expire = max(round(system_config.internal_session_refresh_interval * 2 / 60), system_config.user_session_expire)
  try system_config.save()
  ```

- 输出
  - isOK: bool
  - error
    - 403
      - system: not admin(6003)
    - 406
      - data invalid: *cidr*(90001)
      - parameter: parameter required(90002)
    - 503
      - system: save data failed(802)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.6.8 GET /api/admin/system/settings/internals

- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  验证admin
  system_config = SystemConfig()
  data = {}
  for key in system_config.\_\_slots__:
    if key.startswith('internal_'):
      _value = getattr(system_config, key)
      if type(_value) is str:
        data[key] = CryptoAES(log.key).encrypt(_value.encode())
      else:
        data[key] = CryptoAES(log.key).encrypt(_value.to_bytes((_value.bit_length() + 1 + 7) // 8, signed=True))
  ```

- 输出
  - isOK: bool
  - data: dict
  - error
    - 403
      - system: not admin(6003)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.6.9 PUT /api/admin/system/settings/internals

- 输入
  - config: SystemInternalConfigModel
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  验证admin
  system_config = SystemConfig()
  _change_db = False
  _new_config = {}
  for key, value in config:
    if value is not None:
      CryptoAES(key).decrypt(value) # 使用*通信密钥*解密value
      _new_config[key] = 解密value
      setattr(system_config, key, 解密value)
  if not _new_config: return
  if 'internal_data_clear_interval' in _new_config:
    for cache in func_caches_data_clear:
      cache.ttl = _new_config['internal_data_clear_interval']
  if 'internal_session_refresh_interval' in _new_config:
    for cache in func_caches_session_update:
      cache.ttl = _new_config['internal_session_refresh_interval']
  if 'internal_func_cache_ttl' in _new_config:
    for cache in func_caches_auto_refresh:
      cache.ttl = _new_config['internal_func_cache_ttl']
  if 'internal_signature_private_key' in _new_config:
    try verify_rsa.load_private_key(_new_config['internal_signature_private_key'])
  if any(key.startswith('internal_elasticsearch_') for key in _new_config):
    try await Logger.set_elasticsearch_client()
  if any(key.startswith('internal_influxdb_') for key in _new_config):
    try await Logger.set_influxdb_client()
  try system_config.save()
  ```

- 输出
  - isOK: bool
  - error
    - 403
      - system: not admin(6003)
    - 406
      - parameter: parameter required(90002)
    - 503
      - system: load data failed(801)|save data failed(802)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

### 4.7 /api/app

管理员不能使用。

#### 4.7.1 GET /api/app/mfas

- 输入
  - start?: int = 1
  - limit?: int = 10
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, data_key
  验证admin
  data = select_multi(tb_apps_mfa_main, ['id', 'name', 'comment', 'secret', 'position', 'algorithm', 'interval', 'digits'], {'user_id': [user_id]}, order={'position': False}, offset=max(start - 1, 0), limit=max(end - start + 1, 0))
  count = get_count(tb_apps_mfa_main, {'user_id': [user_id]})
  for row in data:
    CryptoAES(data_key).decrypt(row['secret']) # 使用data_key解密secret
    _codes = Totp(解密secret, row['algorithm'], row['digits'], row['interval']).codes(now)
    _codes = json.dumps(_codes)
    _codes = CryptoAES(key).encrypt(_codes.encode())
    row['codes'] = _codes
    row['id'] = row['id'].hex
    row.pop('secret')
    row.pop('user_id')
    row['time'] = now
  ```

- 输出
  - isOK: bool
  - error: str
    - 403
      - app: not for admin(8005)
  - data: list[str]
  - total: count
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.7.2 POST /api/app/mfa

- 输入
  - data: MFANewDataModel
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, data_key
  验证admin
  CryptoAES(key).decrypt(data['secret']) # 使用*通信密钥*解密secret
  try Totp(解密secret, data['algorithm'], data['digits'], data['interval']).codes(now)
  CryptoAES(data_key).encrypt(解密secret) # 使用data_key加密secret
  data['secret'] = 加密secret
  data['created_time'] = now
  data['updated_time'] = now
  simple_insert_one(tb_apps_mfa_main, {'user_id': user_id, **data})
  ```

- 输出
  - isOK: bool
  - error: str
    - 403
      - app: not for admin(8005)
    - 406
      - secret: invalid(50001)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.7.3 PUT /api/app/mfa

- 输入
  - id: str
  - data: MFAUpdateDataModel
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, email, email2, data_key
  验证admin
  result = simple_select_one(tb_apps_mfa_main, {'user_id': user_id, 'id': uuid.UUID(id)})
  不存在: return
  if not result: return
  _protect = select_multi(tb_apps_mfa_other, ['protect'], {'user_id': user_id})
  if _protect and _protect[0]['protect']:
    _email = email if not email2 else email2
    if default_cache.get(b'email_verify\xff' + \_email) != f'email_verify_{user_id.hex}': return
    default_cache.delete(b'email_verify\xff' + _email)
  if 'secret' in data:
    CryptoAES(key).decrypt(data['secret']) # 使用*通信密钥*解密secret
    try Totp(解密secret, data['algorithm'], data['digits'], data['interval']).codes(now)
    CryptoAES(data_key).encrypt(解密secret) # 使用data_key加密secret
    data['secret'] = 加密secret
    data['updated_time'] = now
  simple_update_one(tb_apps_mfa_main, {'user_id': user_id, 'id': uuid.UUID(id)}, {**data})
  ```

- 输出
  - isOK: bool
  - error: str
    - 403
      - app: not for admin(8005)
    - 404
      - verify email: not found(700)
      - id: not found(501)
    - 406
      - secret: invalid(50001)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.7.4 GET /api/app/mfa

导出密钥
- 输入
  - id: str
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, email, email2, data_key
  验证admin
  _protect = select_multi(tb_apps_mfa_other, ['protect'], {'user_id': user_id})
  if _protect and _protect[0]['protect']:
    _email = email if not email2 else email2
    if default_cache.get(b'email_verify\xff' + \_email) != f'email_verify_{user_id.hex}': return
    default_cache.delete(b'email_verify\xff' + _email)
  results = select_multi(tb_apps_mfa_main, ['id', 'secret'], {'user_id': [user_id], 'id': [id]})
  CryptoAES(data_key).decrypt(results[0]['secret']) # 使用data_key解密secret
  CryptoAES(key).encrypt(解密secret) # 使用*通信密钥*加密secret
  data = {'secret': 加密secret}
  ```

- 输出
  - isOK: bool
  - error: str
    - 403
      - app: not for admin(8005)
  - data: list[dict]
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.7.5 DELETE /api/app/mfa

- 输入
  - ids?: list[str] = None
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token, email, email2
  验证admin
  _protect = select_multi(tb_apps_mfa_other, ['protect'], {'user_id': user_id})
  if _protect and _protect[0]['protect']:
    _email = email if not email2 else email2
    if default_cache.get(b'email_verify\xff' + \_email) != f'email_verify_{user_id.hex}': return
    default_cache.delete(b'email_verify\xff' + _email)
  if ids:
    delete_multi(tb_apps_mfa_main, {'user_id': [user_id], 'id': [uuid.UUID(id) for id in ids]})
  else:
    delete_multi(tb_apps_mfa_main, {'user_id': [user_id]})
  ```

- 输出
  - isOK: bool
  - error: str
    - 403
      - app: not for admin(8005)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.7.6 GET /api/app/mfa/settings

- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token
  验证admin
  data = simple_select_one(tb_apps_mfa_other, {'user_id': user_id})
  data.pop('id')
  data.pop('user_id')
  ```

- 输出
  - isOK: bool
  - error: str
    - 403
      - app: not for admin(8005)
  - data: dict
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

#### 4.7.7 PUT /api/app/mfa/settings

- 输入
  - config: MFAConfigModel
- 处理

  ```pseudo
  # 前置处理
  # 获取user_id, new_session_token, email, email2
  验证admin
  _protect = select_multi(tb_apps_mfa_other, ['protect'], {'user_id': user_id})
  if _protect and _protect[0]['protect']:
    _email = email if not email2 else email2
    if default_cache.get(b'email_verify\xff' + \_email) != f'email_verify_{user_id.hex}': return
    default_cache.delete(b'email_verify\xff' + _email)
  simple_update_one(tb_apps_mfa_other, {'user_id': user_id}, {**config})
  ```

- 输出
  - isOK: bool
  - error: str
    - 403
      - app: not for admin(8005)
    - 404
      - verify email: not found(700)
- 头
  - x-custom-session-token: CryptoAES(key).encrypt(new_session_token)

## 5 数据库

选用SQLite。

- 要件
  - 嵌入式：免去单独设置服务器
  - 文档型：支持复杂数据结构
  - 原生支持Python
  - 高性能：不使用纯Python编写
- 参数
  - synchronous: OFF
  - foreign_keys: ON
  - temp_store: MEMORY
  - cache_size: -1048576
    - 1GiB
    - 正数表示page数，负数表示KiB

## 6 表结构

### 6.1 本体

- tb_users_main
  - id: string, primary key
    - UUIDv7, 基于时间和随机数的递增ID
    - v8算法定义和v7类似，但是允许厂家自定义算法所以不选用
  - user_id: string, unique
    - UUIDv4
  - email: binary, unique
    - SHAKE256，输出512位以上时安全级别与SHA3-512相同（都是256位级别），速度略快，输出长度不限
    - 重复的可能性忽略不计，如果重复，即视为邮箱地址重复
  - email_mask: string
    - *email*的前三个字符
  - password: binary
    - SHAKE256
  - password_salt: binary
    - 不更新
  - data_key: string
    - 使用*email*进行AES-GCM加密
    - 用于应用数据加解密
    - encrypt方法输出base64
  - admin: bool, index
    - 管理员**只**可以管理系统及用户设置
    - 不可注册
  - status: number, index
    - `0`: 正常
    - `1`: 密码过期
    - `2`: 密码不符合要求
  - created_time: number
  - created_ip: string
    - IP
    - `admin`
    - `system`
  - trashed_time: number, index
    - `-1`: 未删除
  - trashed_ip: string, null
    - IP
    - `admin`

- tb_users_other
  - id: string, primary key
    - UUIDv7
  - user_id: string, index, foreign key tb_users_main(user_id) on delete cascade
  - email2: binary
    - SHAKE256
    - 仅用于**邮箱验证**操作，如果空则使用*email*
    - 空时就是空，不是空的哈希值
    - 修改时必须进行**邮箱验证**
  - email2_mask: string
  - name: string, index
    - 仅用于显示
    - 默认：`user<随机数>`
  - allow_ip: [string]
    - 默认：`['0.0.0.0/0', '::/0']`
  - deny_ip: [string]
    - 默认：`[]`
  - acl_serial: binary
    - 4字节随机数
    - 默认：`b'\0\0\0\0'`
    - 用于match_ip缓存
  - protect: bool, index
    - 修改任何用户设置需要**邮箱验证**
    - 默认：`false`

- tb_users_login_fail
  - id: string, primary key
    - UUIDv7
  - user_id: string, index, foreign key tb_users_main(user_id) on delete cascade
  - ip: string
  - count: number
  - time: number
    - *当前时间*

- tb_users_lock
  - id: string, primary key
    - UUIDv7
  - user_id: string, index, foreign key tb_users_main(user_id) on delete cascade
  - ip: string
  - time: number
    - *当前时间*

- tb_users_session
  - id: string, primary key
    - UUIDv7
  - session_id: string, index
    - UUIDv4
  - session_token: JSON(list[str])
    - MD5
    - 个数有限，MD5足够
  - session_data_key: JSON(list[str])
    - 使用会话令牌加密的数据密钥
  - user_id: string, index, foreign key tb_users_main(user_id) on delete cascade
  - ip: string
  - login_time: number
    - *当前时间*
    - 不再更新
  - refresh_time: number
    - *当前时间*

- tb_users_history_login
  - id: string, primary key
    - UUIDv7
  - user_id: string, index, foreign key tb_users_main(user_id) on delete cascade
  - time: number
    - *当前时间*
  - ip: string
  - result: number
    - `0`: 成功
    - `1`: 密码错误
    - `2`: 密码错误+锁定
    - `3`: 已锁定
    - `4`: IP阻止

- tb_users_history_passwd: 包含当前密码
  - id: string, primary key
    - UUIDv7
  - user_id: string, index, foreign key tb_users_main(user_id) on delete cascade
  - password: binary
  - time: number

- tb_users_history_config
  - id: string, primary key
    - UUIDv7
  - user_id: string, index, foreign key tb_users_main(user_id) on delete cascade
  - time: number
    - *当前时间*
  - ip: string
  - email_mask: string, null
  - password: number, null
    - `0`: 恢复用户
    - `1`: 修改密码
    - `2`: 重置密码
    - `3`: 临时删除用户
  - email2_mask: string, null
  - name: string, null
  - allow_ip: [string], null
  - deny_ip: [string], null
  - protect: bool, null
  - locked: bool, null
    - 因为是IP相关的，所以没有整合到password

- tb_users_history_delete
  - id: string, primary key
    - UUIDv7
  - email: binary, index
  - email_mask: string
  - user_id: string, index
  - trashed_time: number
  - trashed_ip: string
  - deleted_time: number, index
  - deleted_by: string
    - `system`
    - `admin`

### 6.2 应用

创建用户时不会自动创建，不存在时视为默认值。

#### 6.2.1 MFA

- tb_apps_mfa_main
  - id: string, primary key
    - UUIDv7
  - user_id: string, index, foreign key tb_users_main(user_id) on delete cascade
  - name: string
  - comment: string, null
  - secret: string
    - 使用data_key加密
  - position: number
    - 允许相同
  - algorithm: string
    - 默认：`SHA1`
    - 可选：`SHA256`, `SHA512`
  - interval: number
    - 秒
    - 默认：`30`
  - digites: number
    - 默认：`6`
    - 可选：`7`, `8`
  - created_time: number
  - updated_time: number
    - 仅密钥更新的时间

- tb_apps_mfa_other
  - id: string, primary key
    - UUIDv7
  - user_id: string, index, foreign key tb_users_main(user_id) on delete cascade
  - protect: bool
    - 更新，删除时需要**邮箱验证**
    - 默认：`false`

## 7 日志

使用Logging模块。

- 格式：使用空格分隔
  - time：ISO8601格式，精确到秒，带时区
  - level：DEBUG, INFO, WARNING, ERROR
  - ip
  - "method path"
  - user_id
  - status
  - start_time
  - proc_time
  - query
  - req_params
  - ErrorCode.name
  - error

可选用InfluxDB和Elasticsearch作为外部日志服务。

- 要件
  - 时序列数据库
  - 支持保存字符串
  - 官方支持Python
- 通用格式
  - measurement: data-midware
  - tags
    - level
    - method
    - path
  - time: unix时间戳
- 记录内容
  - INFO: API请求
    - fields
      - ip
      - user_id
      - status
      - start_time
      - proc_time
      - query
      - req_params: 请求参数
      - res_error: 响应错误码
  - 其他：错误、警告、调试等
    - fields
      - server_error: 错误信息

### 7.1 类

- Logger
  - 方法
    - async set_elasticsearch_client() -> bool
    - async set_influxdb_client() -> bool
    - async log(level: str, log: Log_Fields, server_error: str = None) -> None

### 7.2 参数模型

- Log_Fields: BaseModel
  - ip: str
  - method: str
  - path: str
  - key: bytes = b''
  - aes: CryptoAES = None
  - session_id: UUID = None
  - session_info: dict = {}
  - new_session_token: bytes = b''
  - user_id: UUID | str = '-'
  - user_info: dict = {}
  - start_time: float = 0.0
  - proc_time: float = 0.0
  - query: str = '-'
  - req_params: str = '-'
  - res_error: ErrorCode = ErrorCode.OK
  - internal_error: str = '-'
  - debug_error: str = '-'
