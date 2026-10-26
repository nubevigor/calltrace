"""calltrace —— 接口调用记录与脱敏工具。

设计原则：
1. 凭据在落盘前就换掉：记录里只留能复现请求的最小信息。
2. 「请求本身错了」和「服务返回了错误」必须分开归类。
3. 记录要能重放：方法、路径、关键头、请求体都要留全。

仅依赖 Python 标准库。

    python calltrace.py --help
    python calltrace.py capture --input calls.json --output records.json
    python calltrace.py replay --record records.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

VERSION = "0.1.0"

# 需要脱敏的请求头（大小写不敏感）
SENSITIVE_HEADERS = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "apikey",
    "api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-session-id",
    "x-amz-security-token",
)

# 需要脱敏的请求体 / 响应体字段名
SENSITIVE_FIELDS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "api-key",
    "client_secret",
    "private_key",
    "authorization",
    "session",
    "credential",
    "credentials",
    "signature",
    "ssn",
    "card_number",
)

REDACTED = "[REDACTED]"

# URL 查询串里需要脱敏的参数
SENSITIVE_QUERY_KEYS = (
    "token",
    "access_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "pwd",
    "signature",
    "sig",
    "auth",
    "session",
)

# 响应体里常见的错误标识
_ERROR_BODY_KEYS = ("error", "errors", "message", "detail", "code", "reason")


class Classification:
    """一次调用的归类结果。"""

    OK = "ok"                       # 成功
    REQUEST_SIDE = "request_side"   # 请求本身有问题（4xx）
    SERVICE_SIDE = "service_side"   # 服务端返回错误（5xx）
    TRANSPORT = "transport"         # 没拿到响应（超时、连接失败）
    UNKNOWN = "unknown"             # 信息不足，无法判断

    LABEL = {
        OK: "成功",
        REQUEST_SIDE: "请求侧问题",
        SERVICE_SIDE: "服务侧问题",
        TRANSPORT: "传输层失败",
        UNKNOWN: "无法判断",
    }

    NEXT_STEP = {
        OK: "无需排查",
        REQUEST_SIDE: "查请求：参数、方法、鉴权、请求体格式",
        SERVICE_SIDE: "查服务：服务端日志、依赖、容量",
        TRANSPORT: "查链路：DNS、超时、网络、证书",
        UNKNOWN: "补全记录：状态码或错误体缺失",
    }


def redact_headers(headers: dict) -> dict:
    """把敏感请求头替换掉。"""
    out = {}
    for key, value in (headers or {}).items():
        if str(key).strip().lower() in SENSITIVE_HEADERS:
            out[key] = REDACTED
        else:
            out[key] = value
    return out


def redact_value(value):
    """递归脱敏一个结构里的敏感字段。"""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if str(key).strip().lower() in SENSITIVE_FIELDS:
                out[key] = REDACTED
            else:
                out[key] = redact_value(item)
        return out
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    return value


def redact_body(body):
    """脱敏请求体 / 响应体。

    支持 dict / list / 字符串：
    - dict、list 走字段名匹配
    - 字符串先尝试按 JSON 解析，失败则按 key=value 形式做键名匹配
    """
    if body is None:
        return None
    if isinstance(body, (dict, list)):
        return redact_value(body)
    if isinstance(body, str):
        text = body.strip()
        if not text:
            return body
        if text.startswith("{") or text.startswith("["):
            try:
                return redact_value(json.loads(text))
            except (ValueError, TypeError):
                pass
        return _redact_kv_string(text)
    return body


def _redact_kv_string(text: str) -> str:
    """对形如 ``a=1&password=x`` 的字符串按键名脱敏。"""
    pattern = re.compile(r"([A-Za-z0-9_.\-]+)=([^&\s]*)")
    lowered = {k.lower() for k in SENSITIVE_QUERY_KEYS}

    def repl(match: "re.Match[str]") -> str:
        key = match.group(1)
        if key.lower() in lowered:
            return f"{key}={REDACTED}"
        return match.group(0)

    return pattern.sub(repl, text)


def redact_url(url: str) -> str:
    """脱敏 URL 查询串里的敏感参数。"""
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.query:
        return url
    lowered = {k.lower() for k in SENSITIVE_QUERY_KEYS}
    pairs = []
    for chunk in parts.query.split("&"):
        if not chunk:
            continue
        if "=" in chunk:
            key, value = chunk.split("=", 1)
            if key.strip().lower() in lowered:
                pairs.append(f"{key}={REDACTED}")
            else:
                pairs.append(chunk)
        else:
            pairs.append(chunk)
    rebuilt = parts._replace(query="&".join(pairs))
    return rebuilt.geturl()


def classify(status: int | None, response_body=None,
             error: str | None = None) -> str:
    """把一次调用归类。

    4xx 归「请求侧」，5xx 归「服务侧」，没有响应归「传输层」，
    其余情况看错误体里有没有明确的错误标识。
    """
    if status is None:
        return Classification.TRANSPORT
    if 200 <= status < 300:
        if error:
            return Classification.TRANSPORT
        return Classification.OK
    if 400 <= status < 500:
        return Classification.REQUEST_SIDE
    if status >= 500:
        return Classification.SERVICE_SIDE
    if error:
        return Classification.TRANSPORT
    return Classification.UNKNOWN


def extract_error_summary(response_body) -> str:
    """从响应体里抽出一句可读的错误摘要。"""
    if response_body is None:
        return ""
    if isinstance(response_body, str):
        text = response_body.strip()
        return text[:200]
    if isinstance(response_body, dict):
        for key in _ERROR_BODY_KEYS:
            if key in response_body:
                value = response_body[key]
                if isinstance(value, (dict, list)):
                    return json.dumps(value, ensure_ascii=False)[:200]
                return str(value)[:200]
        return json.dumps(response_body, ensure_ascii=False)[:200]
    if isinstance(response_body, list):
        return json.dumps(response_body, ensure_ascii=False)[:200]
    return str(response_body)[:200]


def redact_call(call: dict) -> dict:
    """把一次原始调用转成脱敏后的记录。"""
    headers = call.get("headers") or {}
    query = call.get("query") or {}
    body = call.get("body")
    if body is None:
        body = call.get("request_body")
    response_body = call.get("response_body")
    if response_body is None:
        response_body = call.get("response")

    status = call.get("status")
    if status is not None:
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = None
    error = call.get("error") or None

    redacted_query = {
        k: (REDACTED if str(k).lower() in SENSITIVE_QUERY_KEYS else v)
        for k, v in (query or {}).items()
    }

    record = {
        "method": str(call.get("method") or "GET").upper(),
        "url": redact_url(str(call.get("url") or "")),
        "headers": redact_headers(headers),
        "query": redacted_query,
        "body": redact_body(body),
        "status": status,
        "duration_ms": call.get("duration_ms"),
        "error": error,
        "response_body": redact_body(response_body),
    }

    category = classify(status, record["response_body"], error)
    record["category"] = category
    record["category_label"] = Classification.LABEL[category]
    record["next_step"] = Classification.NEXT_STEP[category]
    record["error_summary"] = extract_error_summary(record["response_body"])
    record["replayable"] = bool(record["url"]) and (
        record["method"] != "GET" or bool(record["query"]) or bool(record["body"]))
    return record


def redact_calls(calls: list) -> list:
    return [redact_call(c) for c in calls]


def curl_command(record: dict) -> str:
    """由记录生成一条 curl 重放命令（只生成，不执行）。"""
    method = record.get("method", "GET")
    url = record.get("url", "")
    parts = [f"curl -X {method}"]
    headers = record.get("headers") or {}
    for key, value in headers.items():
        if value == REDACTED:
            parts.append(f"-H '{key}: <需自行填入>'")
        else:
            parts.append(f"-H '{key}: {value}'")
    body = record.get("body")
    if body not in (None, "", [], {}):
        if isinstance(body, (dict, list)):
            text = json.dumps(body, ensure_ascii=False)
        else:
            text = str(body)
        text = text.replace("'", "'\\''")
        parts.append(f"-d '{text}'")
    parts.append(f"'{url}'")
    return " ".join(parts)


def build_report(records: list) -> dict:
    counts: dict[str, int] = {}
    for record in records:
        key = record.get("category", Classification.UNKNOWN)
        counts[key] = counts.get(key, 0) + 1
    return {
        "version": VERSION,
        "call_count": len(records),
        "counts": {Classification.LABEL.get(k, k): v for k, v in counts.items()},
        "calls": records,
    }


def render_text(report: dict) -> str:
    lines = []
    lines.append(f"调用数：{report['call_count']}")
    lines.append("")
    for label, count in report["counts"].items():
        lines.append(f"  {label}：{count}")
    lines.append("")
    for index, record in enumerate(report["calls"], 1):
        lines.append(f"[{index}] {record.get('method')} {record.get('url')}")
        lines.append(f"    归类：{record.get('category_label')}")
        if record.get("status") is not None:
            lines.append(f"    状态码：{record.get('status')}")
        if record.get("duration_ms") is not None:
            lines.append(f"    耗时：{record.get('duration_ms')} ms")
        if record.get("error"):
            lines.append(f"    传输错误：{record.get('error')}")
        if record.get("error_summary"):
            lines.append(f"    错误摘要：{record.get('error_summary')}")
        lines.append(f"    下一步：{record.get('next_step')}")
        lines.append("    证据：请求已脱敏，敏感字段以 [REDACTED] 占位")
        lines.append("")
    lines.append("说明：")
    lines.append("  「请求侧问题」与「服务侧问题」排查方向相反，不要混为一谈：")
    lines.append("    请求侧 → 参数、方法、鉴权、请求体格式；")
    lines.append("    服务侧 → 服务端日志、上游依赖、容量。")
    lines.append("  脱敏发生在落盘前，原始凭据不进入记录文件。")
    return "\n".join(lines)


def load_calls(text: str) -> list:
    """从 JSON 文本里读出一批调用。

    支持三种顶层结构：数组、``{"calls": [...]}``、``{"entries": [...]}``。
    """
    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("calls", "entries", "records", "items"):
            if isinstance(data.get(key), list):
                return data[key]
        # 单条调用
        if "url" in data or "method" in data:
            return [data]
    raise ValueError("无法识别的输入结构")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="calltrace",
        description="接口调用记录与脱敏工具：区分请求侧与服务侧错误，产出可重放记录",
        epilog=(
            "示例:\n"
            "  python calltrace.py capture --input calls.json --output records.json\n"
            "  python calltrace.py capture --input calls.json\n"
            "  python calltrace.py replay --record records.json\n"
            "\n"
            "脱敏在落盘前完成，原始凭据不会进入记录文件。\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--version", action="version", version=f"calltrace {VERSION}")
    sub = ap.add_subparsers(dest="command")

    cap = sub.add_parser("capture", help="脱敏并归类一批调用")
    cap.add_argument("--input", required=True, help="原始调用 JSON 文件")
    cap.add_argument("--output", help="记录输出路径（默认打印到标准输出）")
    cap.add_argument("--json", action="store_true", help="输出 JSON")

    rep = sub.add_parser("replay", help="由记录生成 curl 重放命令")
    rep.add_argument("--record", required=True, help="记录文件路径")
    rep.add_argument("--index", type=int, default=0, help="第几条调用（从 0 开始）")

    args = ap.parse_args(argv)
    if not args.command:
        ap.print_help()
        return 0

    if args.command == "capture":
        source = Path(args.input)
        if not source.is_file():
            print(f"找不到输入文件：{source}", file=sys.stderr)
            return 2
        try:
            calls = load_calls(source.read_text(encoding="utf-8", errors="replace"))
        except (ValueError, OSError) as e:
            print(f"读取失败：{e}", file=sys.stderr)
            return 2
        records = redact_calls(calls)
        report = build_report(records)
        if args.output:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                           encoding="utf-8")
            print(f"已写入记录：{out}（{report['call_count']} 条）")
            return 0
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print(render_text(report))
        return 0

    if args.command == "replay":
        path = Path(args.record)
        if not path.is_file():
            print(f"找不到记录文件：{path}", file=sys.stderr)
            return 2
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (ValueError, OSError) as e:
            print(f"读取失败：{e}", file=sys.stderr)
            return 2
        records = data.get("calls") if isinstance(data, dict) else data
        if not isinstance(records, list) or not records:
            print("记录文件里没有可重放的调用。", file=sys.stderr)
            return 2
        if args.index < 0 or args.index >= len(records):
            print(f"序号超出范围：0..{len(records) - 1}", file=sys.stderr)
            return 2
        record = records[args.index]
        print(f"# {record.get('method')} {record.get('url')}")
        print(f"# 归类：{record.get('category_label')}；"
              f"下一步：{record.get('next_step')}")
        print(curl_command(record))
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
