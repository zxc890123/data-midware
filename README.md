# data-midware

(THIS file is almost AI generated😪)

用于在应用与数据库之间以安全的API方式提供用户与应用数据的操作与管理

## 特性

- 以安全、可审计的方式管理用户、会话与访问控制
- 数据加密与防重放设计（传输与存储敏感数据）
- 支持管理员与用户级别的管理接口

## 设计细节

见[DESIGN.md](DESIGN.md)

## 可选外部依赖

### 外部缓存

- Redis
  - 用途: 作为函数级、会话与nonce等缓存后端，加速并发与重放保护逻辑
  - 配置/环境变量: `REDIS_HOST`, `REDIS_PORT`
  - 注: 未配置时使用本地内存缓存

### 日志服务器

- Elasticsearch
  - 用途: 存储与检索结构化日志，便于全文检索和审计
  - 配置项: `internal_elasticsearch_url`, `internal_elasticsearch_index`, `internal_elasticsearch_apikey`

- InfluxDB
  - 配置项: `internal_influxdb_url`, `internal_influxdb_org`, `internal_influxdb_token`, `internal_influxdb_bucket`

### 邮件接收服务

- 邮件中继 / 验证接收
  - 用途: 接收外部邮件并将邮箱验证消息转发到本服务的 `/api/email/verify` 接口
  - 实现示例: Cloudflare Worker（见[cloudflare-repeater.js](cloudflare-repeater.js)）或任意支持webhook的邮件接收服务
  - 配置项: `internal_signature_private_key`
  - 注:
    - 按设计，服务器自身不主动外发邮件，仅依赖外部邮件服务发送验证信息。
    - 未部署相关服务时账户/应用保护功能不工作。

## 安装&运行

```bash
git clone https://github.com/zxc890123/data-midware.git
cd data-midware
pip install .
python -m data_midware
```

## 更新历史

见[CHANGELOG.md](CHANGELOG.md)

## 许可

[Apache License 2.0](LICENSE)
