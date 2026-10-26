# calltrace

**报错现场抓不住，是因为日志里只留了一句 500。**

`calltrace` 把一次接口调用变成一份**可重放、可归档、已脱敏**的记录：
请求摘要、响应摘要、耗时、错误类型，以及一条能直接粘贴执行的 curl 命令。

- 零依赖，Python 3.10+ 标准库即可运行
- 单文件，`calltrace.py` 拷走就能用
- **脱敏发生在落盘前**：原始凭据不进记录文件

## 为什么需要它

线上接口出问题时，最难受的往往不是不会修，而是**复现不了**。

报错只出现在那一次，日志里只有一句 `500 Internal Server Error`，
连请求参数是什么都没留下。于是排查变成一场考古：
翻日志、猜参数、问同事「你当时传的是哪个 ID」。

更麻烦的是，抓下来的日志往往**混着密钥**——
`Authorization: Bearer ...`、`?token=...`、请求体里的 `password`。
想贴给同事看一眼都不敢。

`calltrace` 处理这两件事：

1. **留下足够复现的最小信息**：方法、路径、查询参数、请求头、请求体、状态码、耗时。
2. **在落盘前把凭据换掉**：敏感字段以 `[REDACTED]` 占位。

## 最重要的一个区分

工具会明确把一次失败归到三类，因为这三类的排查方向**完全相反**：

| 归类 | 判定依据 | 下一步查什么 |
|---|---|---|
| **请求侧问题** | 4xx | 参数、方法、鉴权、请求体格式 |
| **服务侧问题** | 5xx | 服务端日志、上游依赖、容量 |
| **传输层失败** | 没有状态码 | DNS、超时、网络、证书 |

「接口出错了」这句话在排查时几乎没有信息量。
`400` 是你传错了，`500` 是它自己坏了——这两件事不该混着说。

## 用法

```bash
# 脱敏并归类一批调用
python calltrace.py capture --input calls.json --output records.json

# 只看报告，不落盘
python calltrace.py capture --input calls.json

# 机器可读输出
python calltrace.py capture --input calls.json --json

# 由记录生成 curl 重放命令
python calltrace.py replay --record records.json --index 0
```

输入文件接受三种顶层结构：

```json
[
  {
    "method": "POST",
    "url": "https://api.example.com/v1/orders?token=abc123",
    "headers": {"Authorization": "Bearer secret", "Content-Type": "application/json"},
    "body": {"sku": "A-1", "password": "hunter2"},
    "status": 400,
    "response_body": {"error": "invalid sku"},
    "duration_ms": 143
  }
]
```

也接受 `{"calls": [...]}` / `{"entries": [...]}` 包裹的形式，以及单条调用对象。

输出：

```
调用数：4

  成功：1
  请求侧问题：1
  服务侧问题：1
  传输层失败：1

[1] POST https://api.example.com/v1/orders?token=[REDACTED]&page=2
    归类：请求侧问题
    状态码：400
    耗时：143 ms
    错误摘要：invalid sku
    下一步：查请求：参数、方法、鉴权、请求体格式
    证据：请求已脱敏，敏感字段以 [REDACTED] 占位
```

## 脱敏覆盖哪些字段

**请求头**：`Authorization`、`Proxy-Authorization`、`Cookie`、`Set-Cookie`、
`X-Api-Key`、`Api-Key`、`X-Auth-Token`、`X-CSRF-Token`、`X-Session-Id` 等。

**URL 查询串**：`token`、`access_token`、`api_key`、`key`、`secret`、
`password`、`signature`、`sig`、`auth`、`session`。

**请求体与响应体**：`password`、`secret`、`token`、`access_token`、
`refresh_token`、`id_token`、`api_key`、`client_secret`、`private_key`、
`authorization`、`session`、`credential`、`signature`、`ssn`、`card_number` 等。
字段名匹配不区分大小写，且会递归进入嵌套的字典与数组。

**字符串形式的请求体**：先尝试按 JSON 解析；解析不了则按 `key=value` 形式按键名脱敏。

## 重放

`replay` 子命令把记录还原成一条 curl 命令：

```bash
curl -X POST -H 'Content-Type: application/json' -H 'Authorization: <需自行填入>' \
  -d '{"sku": "A-1", "password": "[REDACTED]"}' \
  'https://api.example.com/v1/orders?token=[REDACTED]'
```

被脱敏的部分用 `<需自行填入>` 提示——**工具不会替你填回真凭据**，
因为它从一开始就没保存过。

注意：**重放 POST 请求可能真的再写一次数据**。
工具只负责生成命令，不执行；执行与否由你决定。

## 已知局限

- **不发起网络请求**。它处理的是已经抓到的调用记录，不做抓包代理，也不内置 HTTP 客户端。
- **不识别全部敏感字段**。字段名列表是固定的；自定义的凭据字段名（比如 `x_company_key`）
  需要你自己在 `SENSITIVE_FIELDS` 里加。
- **不判断幂等性**。工具不区分「安全重放」和「危险重放」。
- **4xx 一律归请求侧**。但 401/403 可能是**服务端换了密钥**导致的，
  这时该查的是服务端；工具不区分这种情形。
- **响应体里的业务错误不算失败**。`status=200` 但 body 里带 `error` 字段时，
  仍归为「成功」——这符合 HTTP 语义，但和某些 API 的实际约定不同。
- **不做耗时基线分析**。只报告单次耗时，不判断「是否变慢」。
- **不处理 gzip 等压缩响应**。
- **不合并多次重试**。重试产生的多条记录各自独立。

## 跑测试

```bash
python test_calltrace.py
```

测试里有一条专门检查**凭据不泄漏**：把带 `Authorization`、`password`、
`access_token`、`token` 查询参数的样例过一遍，断言这些原始值
在输出文本和落盘文件里都不存在。

## 为什么还要做这个

现有的接口日志要么把请求体整个丢掉（留不下可复现信息），
要么整个存下来（连密钥一起存）。两头都不对。

`calltrace` 的取舍很明确：**保留能复现请求的最小信息，去掉一切凭据**，
并且在报告里把「该查哪边」写出来。

## 来源与参考

- RFC 9110 HTTP Semantics（状态码语义）：<https://www.rfc-editor.org/rfc/rfc9110>
- OWASP Logging Cheat Sheet（日志脱敏建议）：<https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>
- `curl` 手册页：<https://curl.se/docs/manpage.html>

---

## 关于作者

nubevigor 做接口调用记录与脱敏。记录是为了下次能查清楚，不是为了好看。

- 个人主页：<https://nubevigor.github.io>
- 仓库：<https://github.com/nubevigor/calltrace>

## 许可

MIT，见 [LICENSE](LICENSE)。
