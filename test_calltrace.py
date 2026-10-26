"""calltrace 的自检测试。只用内存与临时目录里的样例数据。"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from calltrace import (Classification, classify, curl_command,  # noqa: E402
                       extract_error_summary, redact_body, redact_call,
                       redact_calls, redact_headers, redact_url)

ENTRY = os.path.join(BASE, "calltrace.py")


def _sample_calls() -> list:
    return [
        {
            "method": "post",
            "url": "https://api.example.com/v1/orders?token=abc123&page=2",
            "headers": {"Authorization": "Bearer secret-token",
                        "Content-Type": "application/json",
                        "X-Api-Key": "key-999"},
            "body": {"sku": "A-1", "password": "hunter2",
                     "nested": {"access_token": "tok-xyz", "keep": 1}},
            "status": 400,
            "response_body": {"error": "invalid sku", "code": "BAD_SKU"},
        },
        {
            "method": "GET",
            "url": "https://api.example.com/v1/orders/17",
            "headers": {"Accept": "application/json"},
            "status": 500,
            "response_body": {"message": "upstream timeout"},
        },
        {
            "method": "GET",
            "url": "https://api.example.com/v1/health",
            "headers": {"Accept": "application/json"},
            "status": 204,
            "response_body": None,
        },
        {
            "method": "POST",
            "url": "https://api.example.com/v1/pay",
            "headers": {"Authorization": "Bearer secret-token"},
            "body": {"amount": 100},
            "status": None,
            "error": "ReadTimeout('read timed out')",
        },
    ]


def test_redact_headers_masks_sensitive() -> None:
    out = redact_headers({"Authorization": "Bearer x", "Accept": "json",
                          "Cookie": "sid=1", "X-Api-Key": "k"})
    assert out["Authorization"] == "[REDACTED]"
    assert out["Cookie"] == "[REDACTED]"
    assert out["X-Api-Key"] == "[REDACTED]"
    assert out["Accept"] == "json"


def test_redact_headers_case_insensitive() -> None:
    out = redact_headers({"AUTHORIZATION": "x", "authorization": "y"})
    assert out["AUTHORIZATION"] == "[REDACTED]"
    assert out["authorization"] == "[REDACTED]"


def test_redact_url_masks_query_secrets() -> None:
    out = redact_url("https://x.test/a?token=abc&page=1&api_key=k")
    assert "abc" not in out, out
    assert "page=1" in out, out
    assert "[REDACTED]" in out, out


def test_redact_url_leaves_normal_query() -> None:
    out = redact_url("https://x.test/a?page=1&size=20")
    assert out == "https://x.test/a?page=1&size=20", out


def test_redact_body_masks_fields() -> None:
    out = redact_body({"user": "bob", "password": "p", "list": [{"token": "t"}]})
    assert out["password"] == "[REDACTED]"
    assert out["list"][0]["token"] == "[REDACTED]"
    assert out["user"] == "bob"


def test_redact_body_parses_json_string() -> None:
    out = redact_body('{"a": 1, "secret": "s"}')
    assert out["secret"] == "[REDACTED]"
    assert out["a"] == 1


def test_redact_body_handles_kv_string() -> None:
    out = redact_body("user=bob&password=p&keep=1")
    assert "password=p" not in out, out
    assert "password=[REDACTED]" in out, out
    assert "keep=1" in out, out


def test_redact_body_passes_through_none() -> None:
    assert redact_body(None) is None


def test_classify_request_side() -> None:
    assert classify(400) == Classification.REQUEST_SIDE
    assert classify(404) == Classification.REQUEST_SIDE
    assert classify(499) == Classification.REQUEST_SIDE


def test_classify_service_side() -> None:
    assert classify(500) == Classification.SERVICE_SIDE
    assert classify(503) == Classification.SERVICE_SIDE


def test_classify_transport_when_no_status() -> None:
    assert classify(None, error="timeout") == Classification.TRANSPORT


def test_classify_ok() -> None:
    assert classify(200) == Classification.OK
    assert classify(204) == Classification.OK


def test_classify_unknown_status() -> None:
    assert classify(302) == Classification.UNKNOWN


def test_extract_error_summary_prefers_error_key() -> None:
    out = extract_error_summary({"error": "boom", "message": "other"})
    assert out == "boom", out


def test_extract_error_summary_string() -> None:
    out = extract_error_summary("plain text")
    assert out == "plain text", out


def test_redact_call_produces_classification() -> None:
    record = redact_call(_sample_calls()[0])
    assert record["method"] == "POST", record
    assert record["category"] == Classification.REQUEST_SIDE, record
    assert record["status"] == 400, record
    assert record["error_summary"] == "invalid sku", record


def test_redact_call_never_leaks_secret() -> None:
    text = json.dumps(redact_calls(_sample_calls()), ensure_ascii=False)
    for secret in ("secret-token", "hunter2", "tok-xyz", "abc123", "key-999"):
        assert secret not in text, secret


def test_redact_call_service_side() -> None:
    record = redact_call(_sample_calls()[1])
    assert record["category"] == Classification.SERVICE_SIDE, record


def test_redact_call_transport() -> None:
    record = redact_call(_sample_calls()[3])
    assert record["category"] == Classification.TRANSPORT, record
    assert record["status"] is None, record


def test_next_step_differs_by_side() -> None:
    req = redact_call(_sample_calls()[0])
    srv = redact_call(_sample_calls()[1])
    assert req["next_step"] != srv["next_step"]


def test_curl_command_uses_placeholder_for_redacted() -> None:
    record = redact_call(_sample_calls()[0])
    cmd = curl_command(record)
    assert "secret-token" not in cmd, cmd
    assert "需自行填入" in cmd, cmd
    assert "-X POST" in cmd, cmd


def test_cli_help_exits_zero() -> None:
    r = subprocess.run([sys.executable, ENTRY, "--help"], capture_output=True,
                       text=True, timeout=30, encoding="utf-8", errors="replace")
    assert r.returncode == 0, r.stderr
    assert "calltrace" in r.stdout


def test_cli_capture_text_output() -> None:
    tmp = tempfile.mkdtemp(prefix="calltrace_")
    try:
        src = Path(tmp) / "calls.json"
        src.write_text(json.dumps(_sample_calls(), ensure_ascii=False),
                       encoding="utf-8")
        r = subprocess.run([sys.executable, ENTRY, "capture", "--input", str(src)],
                           capture_output=True, text=True, timeout=30,
                           encoding="utf-8", errors="replace")
        assert r.returncode == 0, r.stderr
        assert "请求侧问题" in r.stdout, r.stdout
        assert "服务侧问题" in r.stdout, r.stdout
        assert "secret-token" not in r.stdout, r.stdout
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_cli_capture_writes_output_file() -> None:
    tmp = tempfile.mkdtemp(prefix="calltrace_")
    try:
        src = Path(tmp) / "calls.json"
        src.write_text(json.dumps(_sample_calls(), ensure_ascii=False),
                       encoding="utf-8")
        out = Path(tmp) / "nested" / "records.json"
        r = subprocess.run([sys.executable, ENTRY, "capture", "--input", str(src),
                            "--output", str(out)], capture_output=True, text=True,
                           timeout=30, encoding="utf-8", errors="replace")
        assert r.returncode == 0, r.stderr
        assert out.is_file(), out
        text = out.read_text(encoding="utf-8")
        assert "secret-token" not in text, "凭据泄漏到记录文件"
        data = json.loads(text)
        assert data["call_count"] == 4, data
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_cli_replay_generates_curl() -> None:
    tmp = tempfile.mkdtemp(prefix="calltrace_")
    try:
        src = Path(tmp) / "calls.json"
        src.write_text(json.dumps(_sample_calls(), ensure_ascii=False),
                       encoding="utf-8")
        rec = Path(tmp) / "records.json"
        subprocess.run([sys.executable, ENTRY, "capture", "--input", str(src),
                        "--output", str(rec)], check=True, capture_output=True,
                       timeout=30)
        r = subprocess.run([sys.executable, ENTRY, "replay",
                            "--record", str(rec), "--index", "0"],
                           capture_output=True, text=True, timeout=30,
                           encoding="utf-8", errors="replace")
        assert r.returncode == 0, r.stderr
        assert "curl -X POST" in r.stdout, r.stdout
        assert "secret-token" not in r.stdout, r.stdout
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_cli_missing_input_exits_two() -> None:
    r = subprocess.run([sys.executable, ENTRY, "capture", "--input", "no_such.json"],
                       capture_output=True, text=True, timeout=30,
                       encoding="utf-8", errors="replace")
    assert r.returncode == 2, (r.returncode, r.stderr)


def test_cli_replay_index_out_of_range() -> None:
    tmp = tempfile.mkdtemp(prefix="calltrace_")
    try:
        rec = Path(tmp) / "records.json"
        rec.write_text(json.dumps({"calls": [{"method": "GET", "url": "https://x.test/"}]}),
                       encoding="utf-8")
        r = subprocess.run([sys.executable, ENTRY, "replay", "--record", str(rec),
                            "--index", "9"], capture_output=True, text=True,
                           timeout=30, encoding="utf-8", errors="replace")
        assert r.returncode == 2, (r.returncode, r.stderr)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  [OK  ] {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  [FAIL] {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n共 {len(tests)} 项，失败 {failed} 项")
    raise SystemExit(1 if failed else 0)
