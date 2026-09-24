#!/usr/bin/env python3

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import bisect
import csv
import duckdb
import gzip
import hashlib
import heapq
import json
import logging
import math
import os
import pyarrow as pa
import pyarrow.parquet as pq
import queue
import random
import re
import requests
import signal
import socket
import sqlite3
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError as ReqConnectionError, RequestException, Timeout as ReqTimeout
from typing import Any, Iterable
from urllib.parse import quote, urlsplit, urlunsplit, parse_qsl, urlencode

try:
  import tomllib
except ModuleNotFoundError:
  import tomli as tomllib

logger = logging.getLogger("pluto")

# ------------------- Paths -------------------

REPO_ROOT = Path(__file__).resolve().parent
INPUT_DIR = REPO_ROOT / "input"
OUTPUT_DIR = REPO_ROOT / "output"
REGISTRY_DIR = REPO_ROOT / "registry"

UPSTREAM_REGISTRY = "https://github.com/overbrowsing/web-archive.txt.git"

# ------------------- Settings -------------------

USER_AGENT = os.environ.get("PLUTO_USER_AGENT", "Pluto :: Overbrowsing")

LIVE_WEB_SETTINGS = {
  "timeout_seconds": 10,
  "requests_per_second": 100,
  "breaker_failure_threshold": 200,
}

ARCHIVE_REGISTRY_SETTINGS = {
  "default_timeout_seconds": 20,
  "default_requests_per_second": 10,
  "rate_limited_requests_per_second": 10,
  "only": [],
  "exclude": [],
  "overrides": {"ia": {"timeout_seconds": 120}},
}

RATE_LIMITER_SETTINGS = {
  "max_speedup": 4.0,
  "max_slowdown": 10.0,
  "ease_up_factor": 1.02,
  "back_off_factor": 2.0,
  "soft_back_off_factor": 1.25,
}

CIRCUIT_BREAKER_SETTINGS = {
  "failure_threshold": 5,
  "cooldown_seconds": 120,
}

UNREACHABLE_SETTINGS = {
  "grace_seconds_once_only_unreachable_left": 300,
}

CONCURRENCY_SETTINGS = {
  "max_threads_per_witness": 128,
  "assumed_latency_fraction_of_timeout": 0.5,
  "warn_total_threads": 1500,
}

OUTPUT_SETTINGS = {
  "flush_rows": 100_000,
  "flush_interval_seconds": 1800,
  "raw_enabled": True,
  "raw_segment_bytes": 256 * 1024 * 1024,
  "raw_compress_level": 1,
}

DEFAULT_CORROBORATION_THRESHOLD = 2

CONTENT_REPLACEMENT_LENGTH_RATIO = 0.5


@dataclass
class WitnessConfig:
  name: str
  adapter: str
  enabled: bool
  timeout_seconds: float
  requests_per_second: float
  extra: dict


# ------------------- Canonicalize -------------------

_DROP_PARAMS = {
  "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
  "fbclid", "gclid", "mc_cid", "mc_eid",
}


def canonicalize(raw_url: str) -> str:
  parts = urlsplit(raw_url.strip())
  scheme = (parts.scheme or "http").lower()
  netloc = parts.netloc.lower()
  if scheme == "http" and netloc.endswith(":80"):
    netloc = netloc[: -len(":80")]
  if scheme == "https" and netloc.endswith(":443"):
    netloc = netloc[: -len(":443")]

  path = parts.path or "/"
  if len(path) > 1 and path.endswith("/"):
    path = path.rstrip("/") or "/"

  query_pairs = sorted(
    (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
    if k not in _DROP_PARAMS
  )
  return urlunsplit((scheme, netloc, path, urlencode(query_pairs), ""))


def url_id(raw_url: str) -> str:
  return hashlib.sha256(canonicalize(raw_url).encode("utf-8")).hexdigest()[:24]


@dataclass(frozen=True)
class UrlParts:
  canonical_url: str
  domain: str
  tld: str


_TLD_EXTRACTOR = None


def split_url(raw_url: str, canonical: str | None = None) -> UrlParts:
  global _TLD_EXTRACTOR
  if _TLD_EXTRACTOR is None:
    import tldextract
    _TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

  canonical = canonical or canonicalize(raw_url)
  host = urlsplit(canonical).netloc
  suffix = _TLD_EXTRACTOR(host).suffix
  return UrlParts(canonical_url=canonical, domain=host, tld=f".{suffix}" if suffix else "")


def content_digest(content: bytes) -> str:
  return "sha256:" + hashlib.sha256(content).hexdigest()


# ------------------- Schema -------------------

URLS_SCHEMA = pa.schema([
  ("url_id", pa.string()),
  ("original_url", pa.string()),
  ("canonical_url", pa.string()),
  ("domain", pa.string()),
  ("tld", pa.string()),
  ("url_type", pa.string()),
  ("entry_cohort", pa.string()),
  ("first_observed", pa.string()),
])

OBSERVATIONS_SCHEMA = pa.schema([
  ("url_id", pa.string()),
  ("observer", pa.string()),
  ("observation_time", pa.timestamp("s", tz="UTC")),
  ("query_time", pa.timestamp("s", tz="UTC")),
  ("status", pa.string()),
  ("http_status", pa.int32()),
  ("error_class", pa.string()),
  ("redirect_target", pa.string()),
  ("mime_type", pa.string()),
  ("content_length", pa.int64()),
  ("content_digest", pa.string()),
  ("response_digest", pa.string()),
  ("confidence", pa.float64()),
])

CAPTURES_SCHEMA = pa.schema([
  ("url_id", pa.string()),
  ("archive", pa.string()),
  ("capture_time", pa.timestamp("s", tz="UTC")),
  ("memento_url", pa.string()),
  ("mime_type", pa.string()),
  ("status", pa.string()),
  ("digest", pa.string()),
  ("warc_file", pa.string()),
  ("record_id", pa.string()),
  ("query_status", pa.string()),
  ("content_length", pa.int64()),
])

EVENTS_SCHEMA = pa.schema([
  ("url_id", pa.string()),
  ("event_type", pa.string()),
  ("event_start", pa.timestamp("s", tz="UTC")),
  ("event_end", pa.timestamp("s", tz="UTC")),
  ("confidence", pa.float64()),
  ("evidence_count", pa.int32()),
  ("witness_count", pa.int32()),
  ("archive", pa.string()),
])

TABLES = {
  "urls": URLS_SCHEMA,
  "observations": OBSERVATIONS_SCHEMA,
  "captures": CAPTURES_SCHEMA,
  "events": EVENTS_SCHEMA,
}


def table_dir(output_dir: Path, table: str) -> Path:
  if table not in TABLES:
    raise ValueError(f"unknown table {table!r}; expected one of {sorted(TABLES)}")
  path = Path(output_dir) / "parquet" / table
  path.mkdir(parents=True, exist_ok=True)
  return path


def append_rows(output_dir: Path, table: str, rows: Iterable[dict]) -> Path | None:
  rows = list(rows)
  if not rows:
    return None
  out_dir = table_dir(output_dir, table)
  part_path = out_dir / f"part-{uuid.uuid4().hex}.parquet"
  tmp_path = part_path.with_name(part_path.name + ".tmp")
  pq.write_table(pa.Table.from_pylist(rows, schema=TABLES[table]), tmp_path)
  os.replace(tmp_path, part_path)
  return part_path


def _batches(result, size: int):
  if hasattr(result, "to_arrow_reader"):
    return result.to_arrow_reader(size)
  return result.fetch_record_batch(size)


def has_rows(output_dir: Path, table: str) -> bool:
  return any(table_dir(output_dir, table).glob("*.parquet"))


def init_tables(output_dir: Path) -> None:
  for table in TABLES:
    table_dir(output_dir, table)


# ------------------- Registry -------------------


def _endpoint(table: dict, *path: str) -> tuple[str | None, str | None]:
  node = table
  for key in path:
    if not isinstance(node, dict) or key not in node:
      return None, None
    node = node[key]
  return (node.get("endpoint"), node.get("access")) if isinstance(node, dict) else (None, None)


def _display_name(name_field) -> str:
  if isinstance(name_field, str):
    return name_field
  if isinstance(name_field, list) and name_field:
    primary = name_field[0]
    variants = [n for n in name_field[1:] if isinstance(n, dict)]
    en = next((n.get("en") for n in variants if n.get("en")), None)
    alt = next((n.get("alt") for n in variants if n.get("alt")), None)
    suffix = en or alt
    return f"{primary} ({suffix})" if suffix else str(primary)
  return "unknown"


def _established_year(value) -> int | None:
  if value is None:
    return None
  text = str(value).strip()
  return int(text) if text.isdigit() else None


def _compile_one(toml_path: Path) -> dict | None:
  data = tomllib.loads(toml_path.read_text(encoding="utf-8"))
  archive, api = data.get("archive", {}), data.get("api", {})

  cdx_endpoint, cdx_access = _endpoint(api, "cdx", "query")
  timemap_endpoint, timemap_access = _endpoint(api, "memento", "timemap")
  timegate_endpoint, _ = _endpoint(api, "memento", "timegate")
  if not any([cdx_endpoint, timemap_endpoint, timegate_endpoint]):
    return None

  entry = {
    "id": archive.get("id") or toml_path.parent.name,
    "name": _display_name(archive.get("name")),
    "rate_limited": bool(api.get("rate_limit", True)),
    "cdx_endpoint": cdx_endpoint, "cdx_access": cdx_access,
    "timemap_endpoint": timemap_endpoint, "timemap_access": timemap_access,
    "established": _established_year(archive.get("established")),
  }

  endpoints = " ".join(filter(None, [cdx_endpoint, timemap_endpoint]))
  if "{collection}" in endpoints:
    collections = archive.get("scope", {}).get("collections", [])
    ids = [c.get("id") for c in collections if isinstance(c, dict) and c.get("id")]
    if ids:
      entry["default_collection"] = ids[0]
      entry["collections"] = ids

  return entry


def import_registry(dest: Path = REGISTRY_DIR, source: Path | None = None) -> int:
  import shutil
  import subprocess
  import tempfile

  dest = Path(dest)

  def _copy_all(registry_dir: Path) -> int:
    entries = [
      (src_file.parent.name, src_file.read_bytes())
      for src_file in sorted(registry_dir.glob("*/web-archive.txt"))
    ]
    dest.mkdir(parents=True, exist_ok=True)
    for child in dest.iterdir():
      if child.is_dir():
        shutil.rmtree(child)
    for name, content in entries:
      archive_dir = dest / name
      archive_dir.mkdir(parents=True, exist_ok=True)
      (archive_dir / "web-archive.txt").write_bytes(content)
    return len(entries)

  if source:
    return _copy_all(Path(source))
  with tempfile.TemporaryDirectory() as tmp:
    clone_dir = Path(tmp) / "web-archive.txt"
    subprocess.run(["git", "clone", "--depth", "1", UPSTREAM_REGISTRY, str(clone_dir)],
            check=True, capture_output=True)
    return _copy_all(clone_dir / "registry")


def compile_archives(registry_dir: Path = REGISTRY_DIR) -> list[dict]:
  entries = [e for p in sorted(Path(registry_dir).glob("*/web-archive.txt")) if (e := _compile_one(p))]
  entries.sort(key=lambda e: e["id"])
  return entries

# ------------------- Backfill-disclosure scanning -------------------

_COMMENT_LINE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_.]*)\s*=.*?#\s*(.+?)\s*$')
_CAPTURING_BEGAN = re.compile(r'\bcaptur\w*\s+began\s+in\s+(\d{4})|\bbegan\s+captur\w*\s+in\s+(\d{4})', re.I)


def scan_backfill_notes(registry_dir: Path = REGISTRY_DIR) -> list[dict]:
  notes = []
  for path in sorted(Path(registry_dir).glob("*/web-archive.txt")):
    archive_id = path.parent.name
    text = path.read_text(encoding="utf-8")

    try:
      established = _established_year(
        tomllib.loads(text).get("archive", {}).get("established")
      )
    except tomllib.TOMLDecodeError:
      established = None

    for line in text.splitlines():
      m = _COMMENT_LINE.match(line)
      if not m:
        continue
      fieldname, comment = m.group(1), m.group(2)
      if "backfill" not in comment.lower():
        continue

      began_match = _CAPTURING_BEGAN.search(comment)
      capturing_began = None
      if began_match:
        capturing_began = int(began_match.group(1) or began_match.group(2))

      notes.append({
        "id": archive_id,
        "field": fieldname,
        "comment": comment,
        "established": established,
        "capturing_began": capturing_began,
        "mismatch": bool(
          capturing_began is not None
          and established is not None
          and capturing_began != established
        ),
      })
  return notes


def established_years(registry_dir: Path = REGISTRY_DIR) -> dict[str, int]:
  archives = compile_archives(registry_dir)
  result = {
    f"archive:{e['id']}": e["established"]
    for e in archives
    if e.get("established") is not None
  }
  for note in scan_backfill_notes(registry_dir):
    began = note.get("capturing_began")
    if began is None:
      continue
    key = f"archive:{note['id']}"
    if began > result.get(key, 0):
      result[key] = began
  return result


def live_witness() -> WitnessConfig:
  return WitnessConfig(
    name="live_web", adapter="LiveWebAdapter", enabled=True,
    timeout_seconds=LIVE_WEB_SETTINGS["timeout_seconds"],
    requests_per_second=LIVE_WEB_SETTINGS["requests_per_second"],
    extra={},
  )


def archive_witnesses(registry_dir: Path = REGISTRY_DIR) -> list[WitnessConfig]:
  settings = ARCHIVE_REGISTRY_SETTINGS
  only = set(settings.get("only") or []) or None
  exclude = set(settings.get("exclude") or [])
  default_rps = settings.get("default_requests_per_second", 0.5)
  limited_rps = settings.get("rate_limited_requests_per_second", default_rps)
  timeout = settings.get("default_timeout_seconds", 20)

  out = []
  for entry in compile_archives(registry_dir):
    archive_id = entry["id"]
    if only is not None and archive_id not in only:
      continue
    if archive_id in exclude:
      continue
    if entry.get("cdx_access") != "online" and entry.get("timemap_access") != "online":
      continue
    rps = limited_rps if entry.get("rate_limited", True) else default_rps
    override = (settings.get("overrides") or {}).get(archive_id, {})
    out.append(WitnessConfig(
      name=f"archive:{archive_id}",
      adapter="WebArchiveAdapter",
      enabled=True,
      timeout_seconds=override.get("timeout_seconds", timeout),
      requests_per_second=override.get("requests_per_second", rps),
      extra={"registry_entry": entry},
    ))
  return out

# ------------------- Adapters -------------------

ERROR_CLASSES = (
  "timeout", "rate_limited", "server_error", "connection_error",
  "dns_failure", "malformed_response", "client_error", "not_found",
)

_LIVE_WEB_FAILURE_IS_EVIDENCE = frozenset({"dns_failure", "connection_error", "timeout"})


class WitnessError(Exception):

  def __init__(self, error_class: str, message: str = ""):
    if error_class not in ERROR_CLASSES:
      raise ValueError(f"unknown error_class {error_class!r}")
    self.error_class = error_class
    super().__init__(message or error_class)


@dataclass
class AdapterResult:
  observations: list[dict] = field(default_factory=list)
  captures: list[dict] = field(default_factory=list)


class ArchiveAdapter:
  name: str = "base"
  limiter_signals: frozenset = frozenset({"timeout", "connection_error", "server_error", "rate_limited"})
  hard_signals: frozenset = frozenset({"rate_limited"})
  breaker_signals: frozenset = frozenset({"timeout", "connection_error", "server_error", "rate_limited"})

  def __init__(self, config: Any):
    self.config = config

  def query(self, url: str) -> Any:
    raise NotImplementedError

  def parse(self, url: str, raw: Any) -> AdapterResult:
    raise NotImplementedError

  def health_check(self) -> bool:
    raise NotImplementedError

  def timeout_seconds(self) -> float:
    return getattr(self.config, "timeout_seconds", 15.0)


_TERMINAL_INACCESSIBLE = {204, 400, 404, 410, 500, 501, 502, 503, 523}


def _classify_status(http_status: int) -> str:
  if 200 <= http_status < 300:
    return "S0_observed_alive"
  if http_status in (403, 429):
    return "access_restricted"
  if http_status in _TERMINAL_INACCESSIBLE:
    return "terminal_inaccessible"
  if 500 <= http_status <= 504:
    return "server_error"
  return "other_response"


def _make_session(pool_size: int = 64) -> requests.Session:
  session = requests.Session()
  adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=0)
  session.mount("http://", adapter)
  session.mount("https://", adapter)
  return session


LIVE_BODY_LIMIT = 1_000_000


@dataclass
class LiveResponse:
  status_code: int
  url: str
  content_type: str
  headers: dict
  body: bytes


def _read_prefix(response: requests.Response, limit: int) -> bytes:
  chunks: list[bytes] = []
  size = 0
  for chunk in response.iter_content(chunk_size=65536):
    if not chunk:
      continue
    chunks.append(chunk)
    size += len(chunk)
    if size >= limit:
      break
  return b"".join(chunks)[:limit]


class LiveWebAdapter(ArchiveAdapter):
  name = "live_web"
  limiter_signals = frozenset()
  hard_signals = frozenset()
  breaker_signals = frozenset({"dns_failure", "connection_error", "timeout"})

  def __init__(self, config):
    super().__init__(config)
    self._session = _make_session(pool_size=160)

  def query(self, url: str) -> LiveResponse:
    host = urlsplit(url).hostname
    if host:
      try:
        socket.getaddrinfo(host, None)
      except socket.gaierror as exc:
        raise WitnessError("dns_failure", str(exc)) from exc
    try:
      response = self._session.get(
        url, headers={"User-Agent": USER_AGENT},
        timeout=self.timeout_seconds(), allow_redirects=True, stream=True,
      )
    except ReqTimeout as exc:
      raise WitnessError("timeout", str(exc)) from exc
    except ReqConnectionError as exc:
      raise WitnessError("connection_error", str(exc)) from exc
    except RequestException as exc:
      raise WitnessError("malformed_response", str(exc)) from exc
    try:
      try:
        body = _read_prefix(response, LIVE_BODY_LIMIT)
      except Exception as exc:
        raise WitnessError("malformed_response", f"body read failed: {type(exc).__name__}: {exc}") from exc
      return LiveResponse(
        status_code=response.status_code, url=response.url,
        content_type=response.headers.get("Content-Type", ""),
        headers=dict(response.headers), body=body,
      )
    finally:
      response.close()

  def parse(self, url: str, raw: LiveResponse) -> AdapterResult:
    body = raw.body
    status = _classify_status(raw.status_code)
    error_class = {"access_restricted": "client_error", "server_error": "server_error"}.get(status, "")
    return AdapterResult(observations=[{
      "url_id": None, "observer": self.name,
      "observation_time": None, "query_time": None,
      "status": status, "http_status": raw.status_code, "error_class": error_class,
      "redirect_target": raw.url if raw.url != url else "",
      "mime_type": raw.content_type.split(";")[0],
      "content_length": len(body),
      "content_digest": content_digest(body), "response_digest": content_digest(body),
      "confidence": 1.0,
    }])

  def health_check(self) -> bool:
    try:
      self._session.head("https://www.iana.org/", timeout=5)
      return True
    except RequestException:
      return False


@dataclass(frozen=True)
class WitnessRegistryEntry:
  id: str
  name: str
  cdx_endpoint: str | None = None
  cdx_access: str | None = None
  timemap_endpoint: str | None = None
  timemap_access: str | None = None
  default_collection: str | None = None
  collections: list[str] | None = None
  rate_limited: bool = True
  established: int | None = None

  @classmethod
  def from_dict(cls, d: dict) -> "WitnessRegistryEntry":
    known = {f.name for f in cls.__dataclass_fields__.values()}
    return cls(**{k: v for k, v in d.items() if k in known})

  def usable_cdx(self) -> bool:
    return bool(self.cdx_endpoint) and self.cdx_access == "online"

  def usable_timemap(self) -> bool:
    return bool(self.timemap_endpoint) and self.timemap_access == "online"


def _fill_template(template: str, url: str, entry: WitnessRegistryEntry) -> str:
  filled = template.replace("{url}", quote(url, safe=""))
  if "{collection}" in filled:
    filled = filled.replace("{collection}", entry.default_collection or "")
  return filled


def _safe_int(value) -> int | None:
  try:
    return int(value)
  except (TypeError, ValueError):
    return None


def _parse_timestamp(ts: str) -> datetime | None:
  ts = re.sub(r"\D", "", ts)[:14].ljust(14, "0")
  try:
    return datetime.strptime(ts, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
  except ValueError:
    return None


def _parse_memento_datetime(dt: str) -> datetime | None:
  try:
    return datetime.strptime(dt, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=timezone.utc)
  except ValueError:
    pass
  return _parse_timestamp(dt) if re.match(r"^\d+$", dt.strip()) else None


class WebArchiveAdapter(ArchiveAdapter):

  def __init__(self, config):
    super().__init__(config)
    self.entry = WitnessRegistryEntry.from_dict(config.extra["registry_entry"])
    self.name = f"archive:{self.entry.id}"
    self._session = _make_session()
    self.history = config.extra.get("history", "full")
    self._latest_differs = 0
    self._latest_same = 0

  def _collection_ids(self) -> list[str | None]:
    return list(self.entry.collections) if self.entry.collections else [self.entry.default_collection]

  def query(self, url: str) -> list[tuple[str, str]]:
    if self.entry.usable_cdx():
      if self.history == "lifespan":
        return [item for collection in self._collection_ids() for item in self._get_first_and_last(url, collection)]
      return [("cdx", self._get_paginated_cdx(url, collection)) for collection in self._collection_ids()]
    if self.entry.usable_timemap():
      return [
        ("timemap", self._get(_fill_template(
          self.entry.timemap_endpoint, url, replace(self.entry, default_collection=collection))))
        for collection in self._collection_ids()
      ]
    raise WitnessError("client_error", f"{self.entry.id} has no usable online endpoint")

  _MAX_CDX_PAGES = 200

  _LATEST_UNRELIABLE_AFTER = 20

  def _get_first_and_last(self, url: str, collection: str | None) -> list[tuple[str, str]]:
    entry = replace(self.entry, default_collection=collection)
    endpoint = _fill_template(entry.cdx_endpoint, url, entry)
    sep = "&" if "?" in endpoint else "?"
    first = self._get(f"{endpoint}{sep}output=json&limit=2")
    if not first.strip() or self._cdx_is_empty(first):
      return [("cdx", first)]
    earliest = self._parse_cdx(first)
    if len(earliest) != 2:
      return [("cdx", first)]
    last = self._get(f"{endpoint}{sep}output=json&sort=reverse&limit=1")
    latest = self._parse_cdx(last) if last.strip() else []
    if len(latest) == 1:
      if latest[0]["capture_time"] != earliest[0]["capture_time"]:
        self._latest_differs += 1
      else:
        self._latest_same += 1
    return [("cdx", first), ("cdx", last)]

  def latest_unreliable(self) -> bool:
    return self._latest_differs == 0 and self._latest_same >= self._LATEST_UNRELIABLE_AFTER

  def _get_paginated_cdx(self, url: str, collection: str | None) -> str:
    entry = replace(self.entry, default_collection=collection)
    endpoint = _fill_template(entry.cdx_endpoint, url, entry)
    sep = "&" if "?" in endpoint else "?"
    base = f"{endpoint}{sep}output=json&showResumeKey=true"

    header: list | None = None
    records: list[list] = []
    resume_key: str | None = None
    first_page_text = ""
    for page_num in range(self._MAX_CDX_PAGES):
      page_url = base + (f"&resumeKey={quote(resume_key, safe='')}" if resume_key else "")
      text = self._get(page_url)
      if page_num == 0:
        first_page_text = text
      if not text.strip():
        break
      try:
        rows = json.loads(text)
      except json.JSONDecodeError:
        return text if header is None else self._reassemble(header, records)
      if not (isinstance(rows, list) and rows and isinstance(rows[0], list)):
        return text if header is None else self._reassemble(header, records)

      body = rows
      new_resume_key = None
      if len(rows) > 1 and len(rows[-1]) == 1 and rows[-1] != rows[0]:
        *body, resume_row = rows
        new_resume_key = resume_row[0]

      if header is None:
        header, body = body[0], body[1:]
      elif body and body[0] == header:
        body = body[1:]
      records.extend(row for row in body if row)

      if not new_resume_key or new_resume_key == resume_key:
        break
      resume_key = new_resume_key

    return self._reassemble(header, records) if header is not None else first_page_text

  @staticmethod
  def _reassemble(header: list, records: list[list]) -> str:
    return json.dumps([header, *records])

  def _get(self, full_url: str) -> str:
    try:
      resp = self._session.get(full_url, timeout=self.timeout_seconds(),
                   headers={"User-Agent": USER_AGENT})
    except ReqTimeout as exc:
      raise WitnessError("timeout", str(exc)) from exc
    except ReqConnectionError as exc:
      raise WitnessError("connection_error", str(exc)) from exc
    except RequestException as exc:
      raise WitnessError("malformed_response", str(exc)) from exc

    if resp.status_code == 404:
      return ""
    if resp.status_code == 429:
      raise WitnessError("rate_limited", f"{self.entry.id} rate limit")
    if 500 <= resp.status_code <= 504:
      raise WitnessError("server_error", f"{self.entry.id} HTTP {resp.status_code}")
    if resp.status_code >= 400:
      raise WitnessError("client_error", f"{self.entry.id} HTTP {resp.status_code}")
    return resp.text

  def parse(self, url: str, raw: list[tuple[str, str]]) -> AdapterResult:
    all_captures: list[dict] = []
    any_text = False
    for kind, text in raw:
      if not text.strip() or (kind == "cdx" and self._cdx_is_empty(text)):
        continue
      any_text = True
      parsed = self._parse_cdx(text) if kind == "cdx" else self._parse_timemap(text)
      if not parsed and (text.lstrip()[:1] == "<" or kind == "cdx"):
        raise WitnessError(
          "malformed_response",
          f"{self.entry.id} returned something that is not capture data: {' '.join(text.split())[:100]!r}",
        )
      all_captures.extend(parsed)
    if not any_text:
      return AdapterResult(observations=[{
        "url_id": None, "observer": self.name,
        "observation_time": None, "query_time": None,
        "status": "no_evidence_this_query", "http_status": 0,
        "error_class": "not_found", "redirect_target": "",
        "mime_type": "", "content_length": 0,
        "content_digest": "", "response_digest": "", "confidence": 1.0,
      }])
    now = datetime.now(timezone.utc)
    all_captures = [c for c in all_captures if c["capture_time"] <= now]
    if self.history == "lifespan":
      unique: dict[tuple, dict] = {}
      for cap in all_captures:
        unique.setdefault((cap["capture_time"], cap["memento_url"], cap["digest"], cap["record_id"]), cap)
      all_captures = list(unique.values())
    for cap in all_captures:
      cap["archive"] = self.name
    return AdapterResult(captures=all_captures)

  @staticmethod
  def _cdx_is_empty(text: str) -> bool:
    try:
      data = json.loads(text)
    except json.JSONDecodeError:
      return False
    return isinstance(data, list) and not any(row for row in data[1:])

  def _parse_cdx(self, text: str) -> list[dict]:
    text = text.strip()
    try:
      data = json.loads(text)
      if isinstance(data, list) and not data:
        return []
      if isinstance(data, list) and data and isinstance(data[0], list):
        header, *records = data
        idx = {name: i for i, name in enumerate(header)}
        out = []
        for rec in records:
          if not rec:
            continue
          try:
            capture_time = _parse_timestamp(rec[idx["timestamp"]]) if "timestamp" in idx else None
            if capture_time is None:
              continue
            out.append({
              "capture_time": capture_time,
              "memento_url": rec[idx["original"]] if "original" in idx else "",
              "mime_type": rec[idx.get("mimetype", -1)] if "mimetype" in idx else "",
              "status": str(rec[idx.get("statuscode", -1)]) if "statuscode" in idx else "",
              "digest": rec[idx.get("digest", -1)] if "digest" in idx else "",
              "warc_file": rec[idx.get("filename", -1)] if "filename" in idx else "",
              "record_id": rec[idx.get("timestamp", -1)] if "timestamp" in idx else "",
              "query_status": "success",
              "content_length": _safe_int(rec[idx["length"]]) if "length" in idx else None,
            })
          except (IndexError, KeyError, TypeError):
            continue
        return out
    except (json.JSONDecodeError, IndexError, KeyError, TypeError):
      pass

    out = []
    for line in text.splitlines():
      line = line.strip()
      if not line:
        continue
      try:
        rec = json.loads(line)
      except json.JSONDecodeError:
        capture = self._parse_cdx_text_line(line)
        if capture is not None:
          out.append(capture)
        continue
      if not isinstance(rec, dict):
        continue
      capture_time = _parse_timestamp(rec.get("timestamp", ""))
      if capture_time is None:
        continue
      out.append({
        "capture_time": capture_time,
        "memento_url": rec.get("url", ""),
        "mime_type": rec.get("mime", ""),
        "status": str(rec.get("status", "")),
        "digest": rec.get("digest", ""),
        "warc_file": rec.get("filename", ""),
        "record_id": f"{rec.get('offset', '')}:{rec.get('length', '')}",
        "query_status": "success",
        "content_length": _safe_int(rec.get("length")),
      })
    return out

  _CDX_TIMESTAMP_RE = re.compile(r"\d{4,14}")

  def _parse_cdx_text_line(self, line: str) -> dict | None:
    fields = line.split()
    if len(fields) < 7 or not self._CDX_TIMESTAMP_RE.fullmatch(fields[1]):
      return None
    capture_time = _parse_timestamp(fields[1])
    if capture_time is None:
      return None
    offset = length = filename = None
    if len(fields) == 7:
      length = fields[6]
    elif len(fields) >= 11:
      length, offset, filename = fields[8], fields[9], fields[10]
    return {
      "capture_time": capture_time,
      "memento_url": fields[2],
      "mime_type": fields[3],
      "status": fields[4],
      "digest": fields[5],
      "warc_file": filename or "",
      "record_id": f"{offset}:{length}" if offset is not None else fields[1],
      "query_status": "success",
      "content_length": _safe_int(length),
    }

  _LINK_RE = re.compile(r'<([^>]+)>\s*;\s*rel="memento"[^,]*?datetime="([^"]+)"')

  def _parse_timemap(self, text: str) -> list[dict]:
    text = text.strip()
    if text.startswith("{") or text.startswith("["):
      try:
        data = json.loads(text)
      except json.JSONDecodeError:
        return []
      mementos = data.get("mementos", {}).get("list", []) if isinstance(data, dict) else []
      out = []
      for m in mementos:
        capture_time = _parse_memento_datetime(m.get("datetime", ""))
        if capture_time is None:
          continue
        out.append({
          "capture_time": capture_time, "memento_url": m.get("uri", ""),
          "mime_type": "", "status": "", "digest": "",
          "warc_file": "", "record_id": m.get("datetime", ""), "query_status": "success",
          "content_length": None,
        })
      return out

    out = []
    for uri, dt in self._LINK_RE.findall(text):
      capture_time = _parse_memento_datetime(dt)
      if capture_time is None:
        continue
      out.append({
        "capture_time": capture_time, "memento_url": uri,
        "mime_type": "", "status": "", "digest": "",
        "warc_file": "", "record_id": dt, "query_status": "success",
        "content_length": None,
      })
    return out

  def health_check(self) -> bool:
    try:
      endpoint = self.entry.cdx_endpoint or self.entry.timemap_endpoint
      resp = self._session.get(_fill_template(endpoint, "example.com", self.entry), timeout=5)
      return resp.status_code < 500
    except RequestException:
      return False


ADAPTER_REGISTRY = {"LiveWebAdapter": LiveWebAdapter, "WebArchiveAdapter": WebArchiveAdapter}

# ------------------- Reliability -------------------

SUCCESS, RETRY, PERMANENT_FAILURE, SKIPPED_EARLY_STOP = (
  "SUCCESS", "RETRY", "PERMANENT_FAILURE", "SKIPPED_EARLY_STOP",
)
_DONE_STATES = (SUCCESS, PERMANENT_FAILURE, SKIPPED_EARLY_STOP)

_CHECKPOINT_SCHEMA = """
CREATE TABLE IF NOT EXISTS checkpoints (
    url_id TEXT NOT NULL,
    witness TEXT NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error_class TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (url_id, witness)
);
"""


_UPSERT_SQL = """
INSERT INTO checkpoints (url_id, witness, state, attempts, last_error_class, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(url_id, witness) DO UPDATE SET
    state=excluded.state,
    attempts=checkpoints.attempts + excluded.attempts,
    last_error_class=COALESCE(excluded.last_error_class, checkpoints.last_error_class),
    updated_at=excluded.updated_at
"""

_COUNTED_STATES = frozenset({SUCCESS, RETRY, PERMANENT_FAILURE})


class CheckpointStore:

  def __init__(self, db_path: Path):
    self.db_path = Path(db_path)
    self.db_path.parent.mkdir(parents=True, exist_ok=True)
    self._conn = sqlite3.connect(
      self.db_path, isolation_level=None, check_same_thread=False, timeout=60,
    )
    self._lock = threading.Lock()
    with self._lock, self._cursor() as cur:
      cur.execute("PRAGMA synchronous=OFF")
      cur.execute(_CHECKPOINT_SCHEMA)

  @contextmanager
  def _cursor(self):
    cur = self._conn.cursor()
    try:
      yield cur
    finally:
      cur.close()

  def done_pairs(self):
    with self._lock:
      cur = self._conn.cursor()
      try:
        cur.execute(
          "SELECT url_id, witness FROM checkpoints WHERE state IN (?, ?, ?) ORDER BY url_id",
          _DONE_STATES,
        )
        while True:
          rows = cur.fetchmany(100_000)
          if not rows:
            return
          yield from rows
      finally:
        cur.close()

  def mark_retry(self, url_id: str, witness: str, error_class: str) -> None:
    self.mark_many([(url_id, witness, RETRY, error_class)])

  def attempts(self, url_id: str, witness: str) -> int:
    with self._lock, self._cursor() as cur:
      cur.execute("SELECT attempts FROM checkpoints WHERE url_id=? AND witness=?", (url_id, witness))
      row = cur.fetchone()
      return row[0] if row else 0

  def mark_many(self, entries: list[tuple[str, str, str, str | None]]) -> None:
    if not entries:
      return
    now = datetime.now(timezone.utc).isoformat()
    params = [
      (url_id, witness, state, 1 if state in _COUNTED_STATES else 0, error_class, now)
      for url_id, witness, state, error_class in entries
    ]
    with self._lock, self._cursor() as cur:
      cur.execute("BEGIN")
      try:
        cur.executemany(_UPSERT_SQL, params)
      except BaseException:
        cur.execute("ROLLBACK")
        raise
      cur.execute("COMMIT")

  def clear_permanent_failures(self, witnesses: list[str]) -> int:
    if not witnesses:
      return 0
    placeholders = ",".join("?" for _ in witnesses)
    with self._lock, self._cursor() as cur:
      cur.execute(
        f"DELETE FROM checkpoints WHERE state=? AND witness IN ({placeholders})",
        (PERMANENT_FAILURE, *witnesses),
      )
      return cur.rowcount

  def close(self) -> None:
    self._conn.close()


@dataclass(frozen=True)
class BackoffPolicy:
  max_attempts: int
  base_seconds: float
  max_seconds: float

  def delay(self, attempt: int) -> float:
    raw = min(self.max_seconds, self.base_seconds * (2 ** max(0, attempt - 1)))
    return random.uniform(0, raw)


RETRY_POLICIES: dict[str, BackoffPolicy] = {
  "timeout": BackoffPolicy(max_attempts=4, base_seconds=2, max_seconds=30),
  "connection_error": BackoffPolicy(max_attempts=4, base_seconds=2, max_seconds=30),
  "rate_limited": BackoffPolicy(max_attempts=5, base_seconds=10, max_seconds=300),
  "server_error": BackoffPolicy(max_attempts=5, base_seconds=5, max_seconds=120),
  "dns_failure": BackoffPolicy(max_attempts=3, base_seconds=30, max_seconds=600),
  "client_error": BackoffPolicy(max_attempts=1, base_seconds=0, max_seconds=0),
  "not_found": BackoffPolicy(max_attempts=1, base_seconds=0, max_seconds=0),
  "malformed_response": BackoffPolicy(max_attempts=1, base_seconds=0, max_seconds=0),
}
DEFAULT_RETRY_POLICY = BackoffPolicy(max_attempts=2, base_seconds=5, max_seconds=60)


def policy_for(error_class: str) -> BackoffPolicy:
  return RETRY_POLICIES.get(error_class, DEFAULT_RETRY_POLICY)


def should_retry(error_class: str, attempts_so_far: int) -> bool:
  return attempts_so_far < policy_for(error_class).max_attempts


@dataclass
class CircuitBreaker:
  failure_threshold: int = 5
  cooldown_seconds: float = 120

  _consecutive_failures: int = field(default=0, init=False)
  _failed_health_checks: int = field(default=0, init=False)
  _open_since: float | None = field(default=None, init=False)
  _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False, compare=False)

  @property
  def is_open(self) -> bool:
    with self._lock:
      return self._open_since is not None

  def record_success(self) -> None:
    with self._lock:
      self._consecutive_failures = 0
      self._failed_health_checks = 0
      self._open_since = None

  def record_failed_health_check(self) -> None:
    with self._lock:
      self._failed_health_checks += 1
      self._open_since = time.monotonic()

  @property
  def failed_health_checks(self) -> int:
    with self._lock:
      return self._failed_health_checks

  @property
  def seconds_until_health_check(self) -> float:
    with self._lock:
      if self._open_since is None:
        return 0.0
      return max(0.0, self.cooldown_seconds - (time.monotonic() - self._open_since))

  def record_failure(self) -> None:
    with self._lock:
      self._consecutive_failures += 1
      if self._consecutive_failures >= self.failure_threshold and self._open_since is None:
        self._open_since = time.monotonic()

  def ready_for_health_check(self) -> bool:
    with self._lock:
      return self._open_since is not None and (time.monotonic() - self._open_since) >= self.cooldown_seconds


_SHUTDOWN = threading.Event()


class _ShuttingDown(BaseException):
  pass


class RateLimiter:

  def __init__(self, requests_per_second: float, settings: dict = RATE_LIMITER_SETTINGS):
    base_interval = 1.0 / max(requests_per_second, 0.001)
    self._floor_interval = base_interval / settings["max_speedup"]
    self._ceiling_interval = base_interval * settings["max_slowdown"]
    self._ease_up_factor = settings["ease_up_factor"]
    self._back_off_factor = settings["back_off_factor"]
    self._soft_back_off_factor = settings.get("soft_back_off_factor", settings["back_off_factor"])
    self._interval = base_interval
    self._lock = threading.Lock()
    self._next_allowed = 0.0

  def wait(self) -> None:
    with self._lock:
      interval = self._interval
      now = time.monotonic()
      sleep_for = max(0.0, self._next_allowed - now)
      self._next_allowed = max(now, self._next_allowed) + interval
    if sleep_for > 0 and _SHUTDOWN.wait(sleep_for):
      raise _ShuttingDown()

  def record_success(self) -> None:
    with self._lock:
      self._interval = max(self._floor_interval, self._interval / self._ease_up_factor)

  def record_failure(self, hard: bool = True) -> None:
    factor = self._back_off_factor if hard else self._soft_back_off_factor
    with self._lock:
      self._interval = min(self._ceiling_interval, self._interval * factor)

  @property
  def current_rps(self) -> float:
    return 1.0 / self._interval

  @property
  def min_interval(self) -> float:
    return self._floor_interval

# ------------------- Stage 1 -------------------

def _iter_csv_rows(path: Path):
  with open(path, newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
      yield {
        "url": row["url"].strip(),
        "first_observed_year": row.get("first_observed_year", "") or "",
        "url_type": (row.get("url_type") or "unknown").strip().lower() or "unknown",
      }


def _iter_cdx_gz_rows(path: Path):
  name = path.name.lower()
  if "root" in name:
    url_type = "root"
  elif "deep" in name:
    url_type = "deep"
  else:
    url_type = "unknown"
  with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
    for line in f:
      fields = line.split()
      if len(fields) < 4:
        continue
      timestamp, original_url = fields[2], fields[3]
      if len(fields) >= 6:
        status = fields[5]
        if status not in ("-", "") and status.isdigit() and not (200 <= int(status) < 300):
          continue
      yield {"url": original_url, "first_observed_year": timestamp[:4], "url_type": url_type}


def _iter_candidate_rows(path: Path):
  path = Path(path)
  if path.suffix == ".gz":
    yield from _iter_cdx_gz_rows(path)
  else:
    yield from _iter_csv_rows(path)


def _entry_cohort(year_str: str) -> str:
  try:
    year = int(str(year_str)[:4])
  except (ValueError, TypeError):
    return "unknown"
  start = (year // 5) * 5
  return f"{start}-{start + 4}"


def _first_observed_timestamp(year_str: str) -> str:
  try:
    return datetime(int(str(year_str)[:4]), 1, 1, tzinfo=timezone.utc).isoformat()
  except (ValueError, TypeError):
    return datetime.now(timezone.utc).isoformat()


def _existing_url_ids(output_dir: Path) -> set[str]:
  if not has_rows(output_dir, "urls"):
    return set()
  con = duckdb.connect()
  glob = str(table_dir(output_dir, "urls") / "*.parquet")
  ids: set[str] = set()
  reader = _batches(con.execute(f"SELECT url_id FROM read_parquet('{glob}')"), 100_000)
  for batch in reader:
    ids.update(batch.column("url_id").to_pylist())
  return ids


def write_urls_table(
  output_dir: Path,
  urls: list[dict],
  already: set[str] | None = None,
) -> tuple[Path | None, int, int]:
  if already is None:
    already = _existing_url_ids(output_dir)
  rows, skipped = [], 0
  for row in urls:
    canonical = canonicalize(row["url"])
    uid = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
    if uid in already:
      skipped += 1
      continue
    already.add(uid)
    parts = split_url(row["url"], canonical)
    year_str = row.get("first_observed_year", "")
    rows.append({
      "url_id": uid,
      "original_url": row["url"],
      "canonical_url": parts.canonical_url,
      "domain": parts.domain,
      "tld": parts.tld,
      "url_type": row.get("url_type") or "unknown",
      "entry_cohort": _entry_cohort(year_str),
      "first_observed": _first_observed_timestamp(year_str),
    })
  return append_rows(output_dir, "urls", rows), len(rows), skipped


def sample_from_files(
  output_dir: Path,
  candidates_paths: list[Path],
  n: int | None = None,
  seed: int = 1337,
  batch_size: int = 500_000,
  show_progress: bool = False,
  allowed_url_types: frozenset[str] | None = None,
) -> tuple[Path | None, int, int]:
  total_added = total_skipped = 0
  n_rows_seen = 0
  last_path: Path | None = None
  already = _existing_url_ids(output_dir)

  def write_batch(batch: list[dict]) -> None:
    nonlocal total_added, total_skipped, last_path, n_rows_seen
    if not batch:
      return
    n_rows_seen += len(batch)
    path, added, skipped = write_urls_table(output_dir, batch, already)
    total_added += added
    total_skipped += skipped
    if path is not None:
      last_path = path
    if show_progress:
      import sys
      print(f"  ...{n_rows_seen:,} rows processed "
         f"({total_added:,} added, {total_skipped:,} already tracked)",
         file=sys.stderr)

  def all_rows():
    for p in candidates_paths:
      for row in _iter_candidate_rows(p):
        if allowed_url_types is not None and _row_scope_type(row) not in allowed_url_types:
          continue
        yield row

  if n is None:
    batch: list[dict] = []
    for item in all_rows():
      batch.append(item)
      if len(batch) >= batch_size:
        write_batch(batch)
        batch = []
    write_batch(batch)
  else:
    rng = random.Random(seed)
    reservoir: list[dict] = []
    for i, item in enumerate(all_rows()):
      if i < n:
        reservoir.append(item)
      else:
        j = rng.randint(0, i)
        if j < n:
          reservoir[j] = item
    write_batch(reservoir)

  return last_path, total_added, total_skipped


def _resolve_candidate_paths(paths: list[Path]) -> list[Path]:
  resolved: list[Path] = []
  for p in paths:
    p = Path(p)
    if p.is_dir():
      resolved.extend(sorted(p.glob("*.csv")) + sorted(p.glob("*.gz")))
    else:
      resolved.append(p)
  return resolved


def _default_candidates() -> list[Path]:
  return sorted(INPUT_DIR.glob("*.csv")) + sorted(INPUT_DIR.glob("*.gz"))

# ------------------- Discover -------------------

def _discover_cdx_bases(entry: dict) -> list[str]:
  endpoint = entry.get("cdx_endpoint") or ""
  if "{collection}" not in endpoint:
    base = endpoint.split("?", 1)[0]
    return [base] if base else []
  collections = entry.get("collections") or (
    [entry["default_collection"]] if entry.get("default_collection") else [])
  return [endpoint.replace("{collection}", c).split("?", 1)[0] for c in collections if c]


def _discover_normalise_domain(domain: str) -> str:
  return domain.lower().replace("http://", "").replace("https://", "").strip("/")


def _discover_host(url: str) -> str:
  from urllib.parse import urlparse
  try:
    return (urlparse(url).hostname or "").lower()
  except ValueError:
    return ""


def _discover_in_domain(host: str, domain: str) -> bool:
  return bool(host) and (host == domain or host.endswith("." + domain))


_WWW_LABEL_RE = re.compile(r"^www\d*$")


def _discover_canonical_host(host: str) -> str:
  labels = host.split(".")
  if len(labels) > 1 and _WWW_LABEL_RE.match(labels[0]):
    return ".".join(labels[1:])
  return host


def _discover_has_coverage(domain: str, cdx_base_url: str, session: requests.Session) -> bool | str | None:
  params = {"url": f"{domain}/", "matchType": "domain", "output": "text", "limit": 1}
  for attempt in range(1, 4):
    try:
      response = session.get(cdx_base_url, params=params,
                  headers={"User-Agent": USER_AGENT}, timeout=60)
      response.raise_for_status()
      text = response.text.strip()
      if text[:1] == "<":
        raise RequestException("response looked like an HTML/error page, not CDX data")
      return bool(text)
    except RequestException as error:
      logger.info("discover: coverage check %s attempt %d/3 failed: %s", cdx_base_url, attempt, error)
      time.sleep(attempt * 3)
  return "blocked"


def _fetch_domain_captures(domain: str, cdx_base_url: str, session: requests.Session,
                page_size: int, stats: dict | None = None):
  resume_key = None
  while True:
    params = {
      "url": f"{domain}/",
      "matchType": "domain",
      "output": "text",
      "limit": page_size,
      "showResumeKey": "true",
    }
    if resume_key:
      params["resumeKey"] = resume_key

    text = None
    for attempt in range(1, 6):
      try:
        response = session.get(cdx_base_url, params=params,
                    headers={"User-Agent": USER_AGENT}, timeout=180)
        response.raise_for_status()
        candidate = response.text.rstrip("\n")
        if candidate.lstrip()[:1] == "<":
          raise RequestException("response looked like an HTML/error page, not CDX data")
        text = candidate
        break
      except RequestException as error:
        logger.info("discover: %s attempt %d/5 failed: %s", cdx_base_url, attempt, error)
        time.sleep(attempt * 5)
    if text is None:
      if stats is not None:
        stats["incomplete"] = True
      break
    if not text.strip():
      break

    parts = text.split("\n\n")
    data = parts[0]
    next_key = parts[1].strip() if len(parts) > 1 else None

    for line in data.splitlines():
      fields = line.split()
      if len(fields) < 3:
        continue
      yield fields[1], fields[2]

    if not next_key or next_key == resume_key:
      break
    resume_key = next_key


_SCOPE_ALIASES = {
  "root": frozenset({"root"}),
  "hosts": frozenset({"hosts"}),
  "deep": frozenset({"deep"}),
  "all": frozenset({"root", "hosts", "deep"}),
}


def _parse_scope(value: str) -> frozenset[str]:
  tokens = {t.strip().lower() for t in value.split(",") if t.strip()}
  unknown = tokens - set(_SCOPE_ALIASES)
  if unknown:
    raise UIError(f"--scope: unknown value(s) {', '.join(sorted(unknown))} -- "
            "use root, hosts, deep, or all (comma-separated to combine, e.g. 'root,deep').")
  resolved: set[str] = set()
  for t in tokens:
    resolved |= _SCOPE_ALIASES[t]
  return frozenset(resolved)


def _row_scope_type(row: dict) -> str:
  url_type = row.get("url_type")
  if url_type in ("root", "deep"):
    return url_type
  path = urlsplit(canonicalize(row["url"])).path
  return "root" if path == "/" else "deep"


def _scope_allowed_url_types(scope: frozenset[str]) -> frozenset[str]:
  allowed = set()
  if "root" in scope or "hosts" in scope:
    allowed.add("root")
  if "deep" in scope:
    allowed.add("deep")
  return frozenset(allowed)


def discover_candidates(
  domain: str,
  scope: frozenset[str] | set[str] = frozenset({"root", "hosts", "deep"}),
  registry_dir: Path = REGISTRY_DIR,
  only_archives: list[str] | None = None,
  page_size: int = 500_000,
) -> list[dict]:
  scope = frozenset(scope)
  if not scope <= {"root", "hosts", "deep"}:
    raise ValueError(f"scope must be drawn from root/hosts/deep, got {scope!r}")

  domain = _discover_normalise_domain(domain)
  entries = [e for e in compile_archives(registry_dir)
       if e.get("cdx_endpoint") and e.get("cdx_access") == "online"]
  if only_archives:
    wanted = {a.strip().lower() for a in only_archives}
    entries = [e for e in entries if e["id"] in wanted]
  if not entries:
    raise UIError("No archives with an online CDX endpoint found in the registry "
            "(run `python pluto.py fetch-archives` first, or check --archives).")

  earliest_host: dict[str, str] = {}
  earliest_url: dict[str, str] = {}
  session = requests.Session()

  UI.log("info", f"Searching {len(entries)} {_plural(len(entries), 'archive')} for {domain} ({'/'.join(sorted(scope))})...")
  for i, entry in enumerate(entries):
    last = i == len(entries) - 1
    bases = _discover_cdx_bases(entry)
    if not bases:
      UI.leaf(f"{entry['id']}: skipped (no collection id on file)", last=last)
      continue
    count = 0
    stats = {"incomplete": False}
    any_coverage = False
    for base in bases:
      coverage = _discover_has_coverage(domain, base, session)
      if coverage is False:
        continue
      if coverage == "blocked":
        stats["incomplete"] = True
        continue
      any_coverage = True
      for timestamp, original_url in _fetch_domain_captures(domain, base, session, page_size, stats):
        host = _discover_host(original_url)
        if not _discover_in_domain(host, domain):
          continue
        count += 1
        canonical_host = _discover_canonical_host(host)
        if canonical_host not in earliest_host or timestamp < earliest_host[canonical_host]:
          earliest_host[canonical_host] = timestamp
        if original_url not in earliest_url or timestamp < earliest_url[original_url]:
          earliest_url[original_url] = timestamp
    if not any_coverage and not stats["incomplete"]:
      UI.leaf(f"{entry['id']}: no coverage", last=last)
      continue
    flag = " (stopped early, likely incomplete: rate-limited or unresponsive)" if stats["incomplete"] else ""
    UI.leaf(f"{entry['id']}: {count:,} {_plural(count, 'capture')}{flag}", last=last)

  rows = []
  if "hosts" in scope:
    rows += [{"url": f"https://{host}/", "first_observed_year": ts[:4], "url_type": "root"}
         for host, ts in earliest_host.items()]
  if "root" in scope and "hosts" not in scope:
    ts = earliest_host.get(_discover_canonical_host(domain)) or \
      (min(earliest_host.values()) if earliest_host else None)
    if ts:
      rows.append({"url": f"https://{domain}/", "first_observed_year": ts[:4], "url_type": "root"})
  if "deep" in scope:
    existing_urls = {r["url"] for r in rows}
    rows += [{"url": url, "first_observed_year": ts[:4], "url_type": "deep"}
         for url, ts in earliest_url.items() if url not in existing_urls]
  return rows

# ------------------- Stage 2 -------------------

class _RawSegment:

  def __init__(self, directory: Path, tag: str, segment_bytes: int, compress_level: int):
    self._directory = directory
    self._tag = tag
    self._segment_bytes = segment_bytes
    self._compress_level = compress_level
    self._lock = threading.Lock()
    self._fh = None
    self._written = 0
    self._index = 0

  def _rotate(self) -> None:
    if self._fh is not None:
      self._fh.close()
    self._directory.mkdir(parents=True, exist_ok=True)
    name = f"{self._tag}-{os.getpid()}-{int(time.time())}-{self._index:05d}.jsonl.gz"
    self._index += 1
    self._fh = gzip.open(self._directory / name, "wb", compresslevel=self._compress_level)
    self._written = 0

  def write(self, line: bytes) -> None:
    with self._lock:
      if self._fh is None or self._written >= self._segment_bytes:
        self._rotate()
      self._fh.write(line)
      self._written += len(line)

  def flush(self) -> None:
    with self._lock:
      if self._fh is not None:
        self._fh.flush()

  def close(self) -> None:
    with self._lock:
      if self._fh is not None:
        self._fh.close()
        self._fh = None


def _raw_for_storage(raw: Any) -> Any:
  if isinstance(raw, LiveResponse):
    return {"status_code": raw.status_code, "url": raw.url, "headers": raw.headers,
        "body_bytes": len(raw.body)}
  return raw


def _raw_is_empty(payload: Any) -> bool:
  if isinstance(payload, list):
    return all(
      not (isinstance(item, (tuple, list)) and len(item) == 2 and str(item[1]).strip())
      for item in payload
    )
  return payload is None


class RawStore:

  def __init__(self, output_dir: Path, tag: str = "single", settings: dict = OUTPUT_SETTINGS):
    self.enabled = bool(settings["raw_enabled"])
    self._root = Path(output_dir) / "raw"
    self._tag = tag
    self._segment_bytes = settings["raw_segment_bytes"]
    self._compress_level = settings["raw_compress_level"]
    self._segments: dict[str, _RawSegment] = {}
    self._lock = threading.Lock()

  def _segment(self, witness: str) -> _RawSegment:
    segment = self._segments.get(witness)
    if segment is None:
      with self._lock:
        segment = self._segments.get(witness)
        if segment is None:
          segment = _RawSegment(self._root / witness, self._tag, self._segment_bytes, self._compress_level)
          self._segments[witness] = segment
    return segment

  def write(self, witness: str, uid: str, raw: Any) -> None:
    if not self.enabled:
      return
    payload = _raw_for_storage(raw)
    if _raw_is_empty(payload):
      return
    record = {
      "url_id": uid, "witness": witness,
      "stored_at": datetime.now(timezone.utc).isoformat(), "payload": payload,
    }
    line = (json.dumps(record, default=str, separators=(",", ":")) + "\n").encode("utf-8")
    self._segment(witness).write(line)

  def flush(self) -> None:
    for segment in list(self._segments.values()):
      segment.flush()

  def close(self) -> None:
    for segment in list(self._segments.values()):
      segment.close()


@dataclass
class WitnessRuntime:
  config: WitnessConfig
  adapter: ArchiveAdapter
  limiter: RateLimiter
  breaker: CircuitBreaker


def build_runtimes(witness_configs: list[WitnessConfig], breaker_cfg: dict) -> dict[str, WitnessRuntime]:
  runtimes = {}
  for wc in witness_configs:
    if not wc.enabled:
      continue
    cfg = dict(breaker_cfg)
    if wc.name == "live_web":
      cfg["failure_threshold"] = LIVE_WEB_SETTINGS["breaker_failure_threshold"]
    runtimes[wc.name] = WitnessRuntime(
      config=wc,
      adapter=ADAPTER_REGISTRY[wc.adapter](wc),
      limiter=RateLimiter(wc.requests_per_second),
      breaker=CircuitBreaker(**cfg),
    )
  return runtimes


_UNEXPECTED_ERRORS = [0]


def _process_unit(uid, witness, original_url, runtime, raw_store, store) -> dict:
  breaker = runtime.breaker
  if breaker.is_open:
    if not breaker.ready_for_health_check():
      return {"outcome": "skipped_circuit_open"}
    if runtime.adapter.health_check():
      breaker.record_success()
    else:
      breaker.record_failed_health_check()
      return {"outcome": "skipped_circuit_open"}

  runtime.limiter.wait()
  query_time = datetime.now(timezone.utc)

  error: WitnessError | None = None
  penalise = True
  unexpected = False
  result = None
  try:
    raw = runtime.adapter.query(original_url)
    result = runtime.adapter.parse(original_url, raw)
  except WitnessError as exc:
    error = exc
  except Exception as exc:
    _UNEXPECTED_ERRORS[0] += 1
    logger.error(
      "%s: unexpected error handling %s: %s: %s", witness, original_url, type(exc).__name__, exc,
      exc_info=_UNEXPECTED_ERRORS[0] <= 20,
    )
    error = WitnessError("malformed_response", f"{type(exc).__name__}: {exc}")
    penalise = False
    unexpected = True

  if error is None:
    raw_store.write(witness, uid, raw)
    breaker.record_success()
    runtime.limiter.record_success()
    now = datetime.now(timezone.utc)
    observations = []
    for obs in result.observations:
      obs = {**obs, "url_id": uid}
      obs["observation_time"] = obs["observation_time"] or now
      obs["query_time"] = obs["query_time"] or query_time
      observations.append(obs)
    captures = [{**cap, "url_id": uid} for cap in result.captures]
    return {"outcome": "success", "observations": observations, "captures": captures,
        "checkpoint": (SUCCESS, None)}

  if penalise:
    adapter = runtime.adapter
    if error.error_class in adapter.breaker_signals:
      breaker.record_failure()
    if error.error_class in adapter.limiter_signals:
      runtime.limiter.record_failure(hard=error.error_class in adapter.hard_signals)
  attempts = store.attempts(uid, witness) + 1
  if should_retry(error.error_class, attempts):
    store.mark_retry(uid, witness, error.error_class)
    return {"outcome": "retried", "retry_after": policy_for(error.error_class).delay(attempts)}
  status = (
    _INACCESSIBLE_STATUS
    if witness == "live_web" and error.error_class in _LIVE_WEB_FAILURE_IS_EVIDENCE
    else "unresolved"
  )
  return {"outcome": "permanent_failure", "observations": [{
    "url_id": uid, "observer": witness,
    "observation_time": query_time, "query_time": query_time,
    "status": status, "http_status": 0,
    "error_class": error.error_class, "redirect_target": "",
    "mime_type": "", "content_length": 0,
    "content_digest": "", "response_digest": "", "confidence": 0.0,
  }], "checkpoint": (PERMANENT_FAILURE, error.error_class), "unexpected": unexpected}


def _url_shard(uid: str, num_shards: int) -> int:
  return int(uid[:8], 16) % num_shards


def _hpc_shard_from_env() -> tuple[int, int | None, str] | None:
  if "SLURM_ARRAY_TASK_ID" in os.environ and "SLURM_ARRAY_TASK_COUNT" in os.environ:
    task_id = int(os.environ["SLURM_ARRAY_TASK_ID"])
    task_min = int(os.environ.get("SLURM_ARRAY_TASK_MIN", task_id))
    step = int(os.environ.get("SLURM_ARRAY_TASK_STEP", 1)) or 1
    count = int(os.environ["SLURM_ARRAY_TASK_COUNT"])
    return (task_id - task_min) // step, count, "SLURM"

  sge_task_id = os.environ.get("SGE_TASK_ID")
  if sge_task_id and sge_task_id != "undefined":
    first = int(os.environ.get("SGE_TASK_FIRST", 1))
    last = int(os.environ.get("SGE_TASK_LAST", sge_task_id))
    step = int(os.environ.get("SGE_TASK_STEPSIZE", 1)) or 1
    count = (last - first) // step + 1
    return (int(sge_task_id) - first) // step, count, "Grid Engine (SGE)"

  for var in ("PBS_ARRAY_INDEX", "PBS_ARRAYID"):
    if var in os.environ:
      return int(os.environ[var]), None, "PBS"

  if "LSB_JOBINDEX" in os.environ:
    end = os.environ.get("LSB_JOBINDEX_END")
    return int(os.environ["LSB_JOBINDEX"]) - 1, (int(end) if end else None), "LSF"

  return None


def _stop_early_resolved(evidence: dict | None, threshold: int) -> bool:
  return bool(evidence) and (evidence["alive"] or len(evidence["inaccessible"]) >= threshold)


def _witness_concurrency_cap(min_interval: float, timeout_seconds: float = 20.0) -> int:
  settings = CONCURRENCY_SETTINGS
  rate = 1.0 / min_interval
  latency = max(1.0, timeout_seconds * settings["assumed_latency_fraction_of_timeout"])
  return max(2, min(settings["max_threads_per_witness"], math.ceil(rate * latency)))


_SKIP_SLICE = 50_000


def _load_done_bits(store: CheckpointStore, url_ids: list[str], witnesses: list[str]) -> dict[str, bytearray]:
  size = (len(url_ids) + 7) // 8
  bits = {w: bytearray(size) for w in witnesses}
  for uid, w in store.done_pairs():
    flags = bits.get(w)
    if flags is None:
      continue
    i = bisect.bisect_left(url_ids, uid)
    if i < len(url_ids) and url_ids[i] == uid:
      flags[i >> 3] |= 1 << (i & 7)
  return bits


def _install_sigterm_handler():

  def _handler(signum, frame):
    raise KeyboardInterrupt

  try:
    return signal.signal(signal.SIGTERM, _handler)
  except ValueError:
    return None


def run_witnesses(
  urls: list[tuple[str, str]],
  output_dir: Path,
  only_witnesses: list[str] | None = None,
  flush_every: int | None = None,
  max_workers: int | None = None,
  shard: int = 0,
  num_shards: int = 1,
  stop_early: bool = True,
  stop_early_threshold: int | None = None,
  history: str = "full",
  retry_failed: bool = False,
) -> dict:
  flush_every = flush_every or OUTPUT_SETTINGS["flush_rows"]
  flush_interval = OUTPUT_SETTINGS["flush_interval_seconds"]
  witness_configs = [live_witness()] + archive_witnesses()
  if only_witnesses:
    witness_configs = [w for w in witness_configs if w.name in only_witnesses]
  if num_shards > 1:
    witness_configs = [
      replace(wc, requests_per_second=wc.requests_per_second / num_shards)
      for wc in witness_configs
    ]
  witness_configs = [replace(wc, extra={**wc.extra, "history": history}) for wc in witness_configs]
  runtimes = build_runtimes(witness_configs, CIRCUIT_BREAKER_SETTINGS)

  if num_shards > 1:
    urls = {uid: u for uid, u in urls.items() if _url_shard(uid, num_shards) == shard}
    ckpt_path = Path(output_dir) / "checkpoints" / f"shard-{shard:03d}-of-{num_shards:03d}.db"
    raw_tag = f"shard-{shard:03d}"
  else:
    ckpt_path = Path(output_dir) / "checkpoints.db"
    raw_tag = "single"

  store = CheckpointStore(ckpt_path)
  raw_store = RawStore(output_dir, tag=raw_tag)
  url_ids = sorted(urls)
  witness_names = list(runtimes.keys())
  if retry_failed:
    cleared = store.clear_permanent_failures(witness_names)
    if cleared:
      logging.getLogger(__name__).info(
        "run: --retry cleared %d permanently-failed checkpoint(s) for %s; "
        "retrying them this run.", cleared, ", ".join(witness_names),
      )
  done_bits = _load_done_bits(store, url_ids, witness_names)

  obs_buffer: list[dict] = []
  cap_buffer: list[dict] = []
  marks: list[tuple[str, str, str, str | None]] = []
  summary = {"queried": 0, "success": 0, "retried": 0, "permanent_failure": 0,
       "skipped_circuit_open": 0, "skipped_early_stop": 0, "unexpected_errors": 0,
       "abandoned_witnesses": 0}
  last_flush_at = time.monotonic()

  def flush():
    nonlocal last_flush_at
    raw_store.flush()
    if obs_buffer:
      append_rows(output_dir, "observations", obs_buffer)
      obs_buffer.clear()
    if cap_buffer:
      append_rows(output_dir, "captures", cap_buffer)
      cap_buffer.clear()
    store.mark_many(marks)
    marks.clear()
    last_flush_at = time.monotonic()

  def flush_due(now: float) -> bool:
    return (
      len(obs_buffer) >= flush_every or len(cap_buffer) >= flush_every
      or len(marks) >= flush_every or now - last_flush_at >= flush_interval
    )

  threshold = stop_early_threshold if stop_early_threshold is not None else DEFAULT_CORROBORATION_THRESHOLD
  evidence_lock = threading.Lock()
  url_evidence: dict[str, dict] = {}

  def _resolved(uid: str) -> bool:
    return stop_early and _stop_early_resolved(url_evidence.get(uid), threshold)

  def _record_evidence(uid: str, w: str, observations: list[dict]) -> None:
    if not stop_early or not observations:
      return
    with evidence_lock:
      ev = url_evidence.setdefault(uid, {"alive": False, "inaccessible": set()})
      for obs in observations:
        if obs["status"] == _ALIVE_STATUS:
          ev["alive"] = True
        elif obs["status"] == _INACCESSIBLE_STATUS:
          ev["inaccessible"].add(w)

  def pending_for(w: str):
    bits = done_bits[w]
    for i, uid in enumerate(url_ids):
      if i % _SKIP_SLICE == _SKIP_SLICE - 1:
        yield None
      if bits[i >> 3] >> (i & 7) & 1:
        continue
      if _resolved(uid):
        marks.append((uid, w, SKIPPED_EARLY_STOP, None))
        summary["skipped_early_stop"] += 1
        continue
      yield uid

  pending_iters = {w: pending_for(w) for w in witness_names}
  exhausted = {w: False for w in witness_names}
  retry_heaps: dict[str, list] = {w: [] for w in witness_names}
  inflight = {w: 0 for w in witness_names}
  probing = {w: False for w in witness_names}
  abandoned: set[str] = set()
  seq = iter(range(1 << 62))
  unreachable_grace = UNREACHABLE_SETTINGS["grace_seconds_once_only_unreachable_left"]
  only_unreachable_since: float | None = None

  def only_unreachable_left() -> bool:
    return not any(
      w not in abandoned and not runtimes[w].breaker.is_open
      and (inflight[w] or retry_heaps[w] or not exhausted[w])
      for w in witness_names
    )

  caps = {
    w: _witness_concurrency_cap(runtimes[w].limiter.min_interval, runtimes[w].config.timeout_seconds)
    for w in witness_names
  }
  recommended_workers = sum(caps.values())
  auto_cap = CONCURRENCY_SETTINGS["warn_total_threads"]
  if max_workers is None:
    if recommended_workers > auto_cap:
      max_workers = auto_cap
      logging.getLogger(__name__).warning(
        "run: witnesses could use up to %d threads total across %d witnesses, but "
        "auto-sizing caps this at %d threads by default to stay well inside typical "
        "per-user thread/file-descriptor limits on a shared HPC node. The busiest "
        "witnesses will fall a bit behind their configured rate as a result -- pass "
        "--workers %d explicitly if you've confirmed the node can take it (check "
        "`ulimit -u` and `ulimit -n` first).",
        recommended_workers, len(witness_names), auto_cap, recommended_workers,
      )
    else:
      max_workers = recommended_workers
      logging.getLogger(__name__).info(
        "run: auto-sizing the worker pool to %d threads across %d witnesses (pass "
        "--workers to override; each witness's own rate limit is still the real ceiling).",
        max_workers, len(witness_names),
      )
  elif max_workers < recommended_workers:
    logging.getLogger(__name__).info(
      "run: %d witnesses want up to %d worker slots total to each reach its own "
      "configured rate; --workers is %d, so the busiest witnesses will fall behind "
      "their allowance. Raise --workers to >= %d for full throughput.",
      len(witness_names), recommended_workers, max_workers, recommended_workers,
    )
  if max_workers > CONCURRENCY_SETTINGS["warn_total_threads"]:
    logging.getLogger(__name__).warning(
      "run: %d worker threads in a single process is a lot; consider --shard i/n to "
      "spread the work over several processes.", max_workers,
    )

  total_tasks = len(url_ids) * len(witness_names)
  tty = sys.stdout.isatty()
  progress_interval = 0.5 if tty else 30.0
  start_time = time.monotonic()
  last_progress_at = start_time
  completed = 0
  done_by_witness = {w: 0 for w in witness_names}
  succeeded_by_witness = {w: 0 for w in witness_names}
  stats_interval = 300.0
  last_stats_at = start_time
  UI._progress_lines = 0

  executor = ThreadPoolExecutor(max_workers=max_workers)
  done_q: queue.SimpleQueue = queue.SimpleQueue()
  in_flight: dict = {}

  def next_uid(w: str):
    heap = retry_heaps[w]
    if heap and heap[0][0] <= time.monotonic():
      return heapq.heappop(heap)[2]
    if exhausted[w]:
      return None
    try:
      uid = next(pending_iters[w])
    except StopIteration:
      exhausted[w] = True
      return None
    return uid if uid is not None else ""

  def submit(w: str, uid: str, probe: bool) -> None:
    fut = executor.submit(_process_unit, uid, w, urls[uid], runtimes[w], raw_store, store)
    in_flight[fut] = (w, uid, probe)
    inflight[w] += 1
    if probe:
      probing[w] = True
    fut.add_done_callback(done_q.put)

  def fill(w: str) -> None:
    if w in abandoned:
      return
    breaker = runtimes[w].breaker
    if (
      breaker.is_open and only_unreachable_since is not None
      and time.monotonic() - only_unreachable_since >= unreachable_grace
    ):
      abandoned.add(w)
      logger.warning(
        "%s: still unreachable after %d failed health checks and every other archive has "
        "finished; its remaining URLs are left for the next run.", w, breaker.failed_health_checks,
      )
      return
    while inflight[w] < caps[w]:
      probe = breaker.is_open
      if probe and (probing[w] or not breaker.ready_for_health_check()):
        return
      uid = next_uid(w)
      if not uid:
        return
      submit(w, uid, probe)
      if probe:
        return

  def work_remaining() -> bool:
    return any(
      w not in abandoned and (retry_heaps[w] or not exhausted[w]) for w in witness_names
    )

  def waiting_on() -> list[str]:
    out = []
    for w in witness_names:
      if w in abandoned or inflight[w] or not (retry_heaps[w] or not exhausted[w]):
        continue
      breaker = runtimes[w].breaker
      if breaker.is_open:
        note = f"unreachable; next check in {breaker.seconds_until_health_check:,.0f}s"
        if only_unreachable_since is not None:
          left = max(0.0, unreachable_grace - (time.monotonic() - only_unreachable_since))
          note += f"; left for next run in {left:,.0f}s"
        out.append(f"{w} ({note})")
      elif retry_heaps[w]:
        out.append(f"{w} (retrying after a failure)")
    return out

  def handle(fut) -> str:
    nonlocal completed
    w, uid, probe = in_flight.pop(fut)
    inflight[w] -= 1
    if probe:
      probing[w] = False
    result = fut.result()
    outcome = result["outcome"]
    if outcome != "skipped_circuit_open":
      summary["queried"] += 1
    summary[outcome] += 1
    if outcome == "skipped_circuit_open":
      heapq.heappush(retry_heaps[w], (time.monotonic(), next(seq), uid))
      return w
    if outcome == "retried":
      heapq.heappush(retry_heaps[w], (time.monotonic() + result["retry_after"], next(seq), uid))
      return w
    completed += 1
    done_by_witness[w] += 1
    if outcome == "success":
      succeeded_by_witness[w] += 1
    if result.get("unexpected"):
      summary["unexpected_errors"] += 1
    marks.append((uid, w, *result["checkpoint"]))
    obs_buffer.extend(result.get("observations", []))
    cap_buffer.extend(result.get("captures", []))
    _record_evidence(uid, w, result.get("observations", []))
    return w

  previous_sigterm = _install_sigterm_handler()
  _SHUTDOWN.clear()
  finished = False
  try:
    for w in witness_names:
      fill(w)
    last_tick = time.monotonic()
    while True:
      batch = []
      try:
        batch.append(done_q.get(timeout=1.0))
      except queue.Empty:
        pass
      while True:
        try:
          batch.append(done_q.get_nowait())
        except queue.Empty:
          break
      touched = {handle(fut) for fut in batch}
      now = time.monotonic()
      if only_unreachable_left():
        if only_unreachable_since is None:
          only_unreachable_since = now
      else:
        only_unreachable_since = None
      if now - last_tick >= 1.0:
        touched = set(witness_names)
        last_tick = now
      for w in touched:
        fill(w)

      if flush_due(now):
        flush()

      if now - last_progress_at >= progress_interval:
        UI.progress(summary, completed + summary["skipped_early_stop"], total_tasks, start_time, tty,
                    waiting=waiting_on())
        last_progress_at = now

      if now - last_stats_at >= stats_interval:
        last_stats_at = now
        for w in witness_names:
          rt = runtimes[w]
          logger.info(
            "%s: %.2f req/s now (configured %.2f), %d in flight, %d done, breaker %s",
            w, rt.limiter.current_rps, rt.config.requests_per_second, inflight[w],
            done_by_witness[w], "open" if rt.breaker.is_open else "closed",
          )

      if not in_flight and not work_remaining():
        break
    finished = True
  finally:
    if not finished:
      _SHUTDOWN.set()
    try:
      flush()
    finally:
      executor.shutdown(wait=finished, cancel_futures=True)
      if previous_sigterm is not None:
        signal.signal(signal.SIGTERM, previous_sigterm)
      raw_store.close()
      store.close()

  summary["abandoned_witnesses"] = len(abandoned)
  UI.progress(summary, completed + summary["skipped_early_stop"], total_tasks, start_time, tty, final=True)
  if abandoned:
    UI.log("issue", f"Left for the next run (still unreachable): {', '.join(sorted(abandoned))}")
  unreliable = sorted(
    w for w, rt in runtimes.items()
    if isinstance(rt.adapter, WebArchiveAdapter) and rt.adapter.latest_unreliable()
  )
  if unreliable:
    logger.warning("latest-capture dates look unreliable for: %s", ", ".join(unreliable))
    UI.log("issue", f"{', '.join(unreliable)}: the latest-capture query always returned the earliest "
                    f"capture, so this archive probably ignores sort=reverse and its latest dates can't be trusted "
                    f"(use --changes to fetch full histories instead)")
  return summary

# ------------------- Stage 3 -------------------

S0_ALIVE = "S0"
S1_CONTENT_CHANGED = "S1"
S2_URL_SURVIVES_CONTENT_GONE = "S2"
S3_STRONG_DISAPPEARANCE = "S3"
S4_UNRESOLVED = "S4"

_ALIVE_STATUS = "S0_observed_alive"
_INACCESSIBLE_STATUS = "terminal_inaccessible"

_TERMINAL_CAPTURE_STATUSES = {204, 400, 404, 410, 500, 501, 502, 503, 523}


def _latest_by(items: list[dict], key: str, time_field: str) -> dict[str, dict]:
  latest: dict[str, dict] = {}
  for item in items:
    k = item[key]
    if k not in latest or item[time_field] > latest[k][time_field]:
      latest[k] = item
  return latest


def _is_terminal_capture(capture: dict) -> bool:
  try:
    return int(capture.get("status") or "") in _TERMINAL_CAPTURE_STATUSES
  except ValueError:
    return False


def _independent_captures(captures: list[dict], established_by_archive: dict[str, int] | None) -> list[dict]:
  established_by_archive = established_by_archive or {}
  out = []
  for c in captures:
    established = established_by_archive.get(c.get("archive"))
    capture_time = c.get("capture_time")
    if established is not None and capture_time is not None and capture_time.year < established:
      continue
    out.append(c)
  return out


def _inaccessible_witnesses(
  observations: list[dict],
  captures: list[dict],
  established_by_archive: dict[str, int] | None = None,
) -> set[str]:
  latest_obs = _latest_by(observations, "observer", "observation_time")
  inaccessible = {o for o, obs in latest_obs.items() if obs["status"] == _INACCESSIBLE_STATUS}
  latest_caps = _latest_by(_independent_captures(captures, established_by_archive), "archive", "capture_time")
  inaccessible |= {a for a, cap in latest_caps.items() if _is_terminal_capture(cap)}
  return inaccessible


def _content_survival(observations: list[dict], captures: list[dict]) -> str:
  changed = False
  stable = False

  live_digests = sorted(
    (o["observation_time"], o["content_digest"]) for o in observations
    if o.get("observer") == "live_web" and o.get("content_digest")
  )
  if len(live_digests) >= 2:
    if len({d for _, d in live_digests}) > 1:
      changed = True
    else:
      stable = True

  by_archive: dict[str, list] = {}
  for c in captures:
    if c.get("digest"):
      by_archive.setdefault(c["archive"], []).append((c["capture_time"], c["digest"]))
  for series in by_archive.values():
    if len(series) < 2:
      continue
    if len({d for _, d in series}) > 1:
      changed = True
    else:
      stable = True

  if changed:
    return "changed"
  if stable:
    return "stable"
  return "unknown"


def _content_trajectory(observations: list[dict], captures: list[dict]) -> str | None:

  def _from_series(triples: list[tuple]) -> str | None:
    with_length = sorted((t, ln) for t, _, ln in triples if ln is not None and ln > 0)
    if len(with_length) < 2:
      return None
    first_len, last_len = with_length[0][1], with_length[-1][1]
    ratio = min(first_len, last_len) / max(first_len, last_len)
    return "replaced" if ratio < CONTENT_REPLACEMENT_LENGTH_RATIO else "edited"

  live = [
    (o["observation_time"], o["content_digest"], o.get("content_length"))
    for o in observations if o.get("observer") == "live_web" and o.get("content_digest")
  ]
  if len({d for _, d, _ in live}) > 1:
    result = _from_series(live)
    if result:
      return result

  by_archive: dict[str, list] = {}
  for c in captures:
    if c.get("digest"):
      by_archive.setdefault(c["archive"], []).append(
        (c["capture_time"], c["digest"], c.get("content_length"))
      )
  for series in by_archive.values():
    if len({d for _, d, _ in series}) > 1:
      result = _from_series(series)
      if result:
        return result
  return None


def _witness_digest_transitions(observations: list[dict], captures: list[dict]) -> list[dict]:
  series_by_witness: dict[str, list[tuple]] = {}

  live = sorted(
    (o["observation_time"], o["content_digest"])
    for o in observations if o.get("observer") == "live_web" and o.get("content_digest")
  )
  if live:
    series_by_witness["live_web"] = live

  by_archive: dict[str, list] = {}
  for c in captures:
    if c.get("digest"):
      by_archive.setdefault(c["archive"], []).append((c["capture_time"], c["digest"]))
  for archive, series in by_archive.items():
    series_by_witness[archive] = sorted(series)

  transitions = []
  for witness, series in series_by_witness.items():
    for (t0, d0), (t1, d1) in zip(series, series[1:]):
      if d1 != d0:
        transitions.append({"witness": witness, "last_old_time": t0, "first_new_time": t1})
  return transitions


def classify_resource_state(
  observations: list[dict],
  captures: list[dict],
  corroboration_threshold: int = DEFAULT_CORROBORATION_THRESHOLD,
  established_by_archive: dict[str, int] | None = None,
  with_changes: bool = True,
) -> dict:
  latest_obs = _latest_by(observations, "observer", "observation_time")
  alive = any(o["status"] == _ALIVE_STATUS for o in latest_obs.values())
  inaccessible = _inaccessible_witnesses(observations, captures, established_by_archive)
  content_survival = _content_survival(observations, captures) if with_changes else "unknown"

  if alive:
    trajectory = _content_trajectory(observations, captures) if content_survival == "changed" else None
    if trajectory == "edited":
      state = S1_CONTENT_CHANGED
    elif trajectory == "replaced":
      state = S2_URL_SURVIVES_CONTENT_GONE
    else:
      state = S0_ALIVE
  elif len(inaccessible) >= corroboration_threshold:
    state = S3_STRONG_DISAPPEARANCE
  else:
    state = S4_UNRESOLVED

  witness_count = len(set(latest_obs) | {c["archive"] for c in captures})
  return {
    "state": state,
    "preserved": len(captures) > 0,
    "witness_count": witness_count,
    "corroborating_inaccessible_count": len(inaccessible),
    "evidence_count": len(observations) + len(captures),
    "content_survival": content_survival,
  }


def archival_risk(
  observations: list[dict],
  captures: list[dict],
  resource_state: dict,
  established_by_archive: dict[str, int] | None = None,
) -> dict:
  ever_existed = resource_state["state"] in ("S0", "S1", "S2", "S3")
  preserved = resource_state["preserved"]
  latest_obs = _latest_by(observations, "observer", "observation_time")
  alive = any(o["status"] == _ALIVE_STATUS for o in latest_obs.values())
  inaccessible = _inaccessible_witnesses(observations, captures, established_by_archive)

  return {
    "capture_gap": ever_existed and not preserved,
    "preservation_gap": resource_state["state"] == "S3" and not preserved,
    "witness_disagreement": alive and bool(inaccessible),
    "evidential_uncertainty": resource_state["state"] == "S4",
  }


_OBS_COLUMNS = ("url_id", "observer", "observation_time", "status", "content_digest", "content_length")
_OBS_ORDER = "url_id, observer, observation_time, status, content_digest"
_CAP_COLUMNS = ("url_id", "archive", "capture_time", "status", "digest", "content_length")
_CAP_ORDER = "url_id, archive, capture_time, status, digest"
_STREAM_BATCH_ROWS = 100_000
_EVENT_CHUNK_ROWS = 500_000


def _stream_by_url(cur: duckdb.DuckDBPyConnection, glob: str, columns: tuple[str, ...], order: str):
  query = f"SELECT {', '.join(columns)} FROM read_parquet('{glob}') ORDER BY {order}"
  try:
    reader = _batches(cur.execute(query), _STREAM_BATCH_ROWS)
  except duckdb.IOException:
    return
  current: str | None = None
  rows: list[dict] = []
  for batch in reader:
    for row in batch.to_pylist():
      uid = row["url_id"]
      if uid != current:
        if current is not None:
          yield current, rows
        current, rows = uid, []
      rows.append(row)
  if current is not None:
    yield current, rows


def _merge_by_url(obs_stream, cap_stream):
  obs = next(obs_stream, None)
  cap = next(cap_stream, None)
  while obs is not None or cap is not None:
    uid = min(item[0] for item in (obs, cap) if item is not None)
    observations: list[dict] = []
    captures: list[dict] = []
    if obs is not None and obs[0] == uid:
      observations = obs[1]
      obs = next(obs_stream, None)
    if cap is not None and cap[0] == uid:
      captures = cap[1]
      cap = next(cap_stream, None)
    yield uid, observations, captures


def _events_for_url(
  uid: str,
  observations: list[dict],
  captures: list[dict],
  corroboration_threshold: int,
  established_by_archive: dict[str, int] | None,
  with_changes: bool = True,
) -> list[dict]:
  state = classify_resource_state(observations, captures, corroboration_threshold, established_by_archive, with_changes)
  risk = archival_risk(observations, captures, state, established_by_archive)

  times = [t for t in (
    [o["observation_time"] for o in observations] + [c["capture_time"] for c in captures]
  ) if t is not None]
  event_start, event_end = (min(times), max(times)) if times else (None, None)
  base = {
    "url_id": uid, "event_start": event_start, "event_end": event_end,
    "evidence_count": state["evidence_count"], "witness_count": state["witness_count"],
    "archive": None,
  }
  events = [{**base, "event_type": f"state_{state['state']}",
        "confidence": 1.0 if state["state"] != "S4" else 0.5}]
  events.extend(
    {**base, "event_type": f"risk_{name}", "confidence": 1.0}
    for name, flagged in risk.items() if flagged
  )

  transitions = _witness_digest_transitions(observations, captures) if with_changes else []
  if transitions:
    by_witness: dict[str, list[dict]] = {}
    for tr in transitions:
      by_witness.setdefault(tr["witness"], []).append(tr)
    events.extend(
      {
        "url_id": uid, "event_type": "content_changed",
        "event_start": min(t["last_old_time"] for t in tr_list),
        "event_end": max(t["first_new_time"] for t in tr_list),
        "confidence": 1.0, "evidence_count": len(tr_list), "witness_count": 1,
        "archive": witness,
      }
      for witness, tr_list in by_witness.items()
    )
  elif state["content_survival"] == "stable":
    events.append({**base, "event_type": "content_stable", "confidence": 1.0})
  return events


def classify_all(
  output_dir: Path,
  corroboration_threshold: int = DEFAULT_CORROBORATION_THRESHOLD,
  established_by_archive: dict[str, int] | None = None,
  with_changes: bool = True,
) -> int:
  events_dir = table_dir(output_dir, "events")
  for stale in events_dir.glob("*.staged"):
    stale.unlink()

  tmp_dir = Path(output_dir) / ".duckdb_tmp"
  tmp_dir.mkdir(parents=True, exist_ok=True)
  con = duckdb.connect()
  con.execute(f"SET temp_directory='{tmp_dir}'")
  con.execute("SET preserve_insertion_order=false")

  obs_stream = _stream_by_url(
    con.cursor(), str(table_dir(output_dir, "observations") / "*.parquet"), _OBS_COLUMNS, _OBS_ORDER)
  cap_stream = _stream_by_url(
    con.cursor(), str(table_dir(output_dir, "captures") / "*.parquet"), _CAP_COLUMNS, _CAP_ORDER)

  staged: list[Path] = []
  events: list[dict] = []
  classified = 0

  def stage_chunk() -> None:
    path = events_dir / f"part-{uuid.uuid4().hex}.parquet.staged"
    pq.write_table(pa.Table.from_pylist(events, schema=TABLES["events"]), path)
    staged.append(path)
    events.clear()

  for uid, observations, captures in _merge_by_url(obs_stream, cap_stream):
    classified += 1
    events.extend(_events_for_url(
      uid, observations, captures, corroboration_threshold, established_by_archive, with_changes,
    ))
    if len(events) >= _EVENT_CHUNK_ROWS:
      stage_chunk()
  if events:
    stage_chunk()

  if classified == 0:
    return 0

  for old_part in events_dir.glob("*.parquet"):
    old_part.unlink()
  for path in staged:
    os.replace(path, path.with_suffix(""))
  return classified

# ------------------- Stage 4 -------------------

_SUMMARY_QUERY = """
WITH established(archive, established_year) AS ({established_values}),
captures_flagged AS (
    SELECT c.*,
           (e.established_year IS NULL OR date_part('year', c.capture_time) >= e.established_year)
               AS is_independent
    FROM {captures} c
    LEFT JOIN established e USING (archive)
),
cap_agg AS (
    SELECT
        url_id,
        min(capture_time) AS first_appearance,
        max(capture_time) AS last_appearance,
        arg_min(archive, capture_time) AS first_archive,
        arg_max(archive, capture_time) AS last_archive,
        array_agg(DISTINCT archive) AS archives,
        count(DISTINCT archive) AS n_archives,
        count(*) AS n_captures,
        min(capture_time) FILTER (WHERE is_independent) AS first_independent_appearance,
        arg_min(archive, capture_time) FILTER (WHERE is_independent) AS first_independent_archive,
        array_agg(DISTINCT archive) FILTER (WHERE is_independent) AS independent_archives,
        count(DISTINCT archive) FILTER (WHERE is_independent) AS n_independent_archives
    FROM captures_flagged
    GROUP BY url_id
),
obs_agg AS (
    SELECT
        url_id,
        count(*) AS n_observations,
        count(DISTINCT observer) AS n_observers
    FROM {observations}
    GROUP BY url_id
),
ev_agg AS (
    SELECT
        url_id,
        arg_max(event_type, event_end) FILTER (WHERE event_type LIKE 'state_%') AS current_state,
        bool_or(event_type = 'risk_capture_gap') AS capture_gap,
        bool_or(event_type = 'risk_preservation_gap') AS preservation_gap,
        bool_or(event_type = 'risk_witness_disagreement') AS witness_disagreement,
        bool_or(event_type = 'risk_evidential_uncertainty') AS evidential_uncertainty,
        bool_or(event_type = 'content_changed') AS content_changed,
        bool_or(event_type = 'content_stable') AS content_stable,
        sum(evidence_count) FILTER (WHERE event_type = 'content_changed') AS n_content_changes,
        min(event_start) FILTER (WHERE event_type = 'content_changed') AS first_content_change_at,
        arg_min(archive, event_start) FILTER (WHERE event_type = 'content_changed') AS first_content_change_archive,
        max(event_end) FILTER (WHERE event_type = 'content_changed') AS last_content_change_at,
        arg_max(archive, event_end) FILTER (WHERE event_type = 'content_changed') AS last_content_change_archive
    FROM {events}
    GROUP BY url_id
)
SELECT
    u.url_id, u.original_url, u.domain, u.tld, u.url_type, u.entry_cohort, u.first_observed,
    cap_agg.first_appearance, cap_agg.last_appearance,
    date_diff('day', cap_agg.first_appearance, cap_agg.last_appearance) AS temporal_span_days,
    cap_agg.first_archive, cap_agg.last_archive, cap_agg.archives, cap_agg.n_archives, cap_agg.n_captures,
    cap_agg.first_independent_appearance, cap_agg.first_independent_archive,
    cap_agg.independent_archives, cap_agg.n_independent_archives,
    coalesce(obs_agg.n_observations, 0) AS n_observations,
    coalesce(obs_agg.n_observers, 0) AS n_observers,
    replace(ev_agg.current_state, 'state_', '') AS current_state,
    coalesce(ev_agg.capture_gap, false) AS capture_gap,
    coalesce(ev_agg.preservation_gap, false) AS preservation_gap,
    coalesce(ev_agg.witness_disagreement, false) AS witness_disagreement,
    coalesce(ev_agg.evidential_uncertainty, false) AS evidential_uncertainty,
    CASE WHEN ev_agg.content_changed THEN 'changed'
         WHEN ev_agg.content_stable THEN 'stable'
         ELSE 'unknown' END AS content_survival,
    coalesce(ev_agg.n_content_changes, 0) AS n_content_changes,
    ev_agg.first_content_change_at,
    ev_agg.first_content_change_archive,
    ev_agg.last_content_change_at,
    ev_agg.last_content_change_archive
FROM {urls} u
LEFT JOIN cap_agg USING (url_id)
LEFT JOIN obs_agg USING (url_id)
LEFT JOIN ev_agg USING (url_id)
"""

_PA_TO_DUCKDB = {pa.string(): "VARCHAR", pa.int32(): "INTEGER", pa.int64(): "BIGINT", pa.float64(): "DOUBLE"}


def _duckdb_type(field_: pa.Field) -> str:
  if pa.types.is_timestamp(field_.type):
    return "TIMESTAMPTZ" if field_.type.tz else "TIMESTAMP"
  return _PA_TO_DUCKDB[field_.type]


def _table_source(output_dir: Path, table: str) -> str:
  if has_rows(output_dir, table):
    glob = str(table_dir(output_dir, table) / "*.parquet")
    return f"read_parquet('{glob}')"
  cols = ", ".join(f"NULL::{_duckdb_type(f)} AS {f.name}" for f in TABLES[table])
  return f"(SELECT {cols} WHERE FALSE)"


def _established_values(established_by_archive: dict[str, int] | None) -> str:
  if not established_by_archive:
    return "SELECT NULL, NULL WHERE FALSE"
  rows = ", ".join(f"('{archive}', {year})" for archive, year in established_by_archive.items())
  return f"VALUES {rows}"


def summarize_urls(
  output_dir: Path,
  out_path: Path | None = None,
  established_by_archive: dict[str, int] | None = None,
) -> tuple[Path, int]:
  if not has_rows(output_dir, "urls"):
    raise UIError("No data to summarize -- run `python pluto.py run` first.")

  out_path = Path(out_path) if out_path else Path(output_dir) / "summary.parquet"
  query = _SUMMARY_QUERY.format(
    established_values=_established_values(established_by_archive),
    urls=_table_source(output_dir, "urls"),
    captures=_table_source(output_dir, "captures"),
    observations=_table_source(output_dir, "observations"),
    events=_table_source(output_dir, "events"),
  )
  con = duckdb.connect()
  con.execute(f"COPY ({query}) TO '{out_path}' (FORMAT PARQUET)")
  n = con.execute(f"SELECT count(*) FROM read_parquet('{out_path}')").fetchone()[0]
  return out_path, n

# ------------------- CLI -------------------

def _plural(n: int, word: str, plural: str | None = None) -> str:
  return word if n == 1 else (plural or f"{word}s")


class UI:
  SYMBOLS = {
    "info":  "[▪]",
    "ok":    "[✓]",
    "error": "[✕]",
    "issue": "[-]",
  }

  COLORS = {
    "cyan":   "\033[36m",
    "green":  "\033[32m",
    "red":    "\033[31m",
    "yellow": "\033[33m",
    "reset":  "\033[0m",
  }

  @classmethod
  def paint(cls, text, colour):
    return f"{cls.COLORS[colour]}{text}{cls.COLORS['reset']}"

  @classmethod
  def log(cls, kind, message):
    mapping = {
      "info":  ("info", "cyan"),
      "ok":    ("ok", "green"),
      "error": ("error", "red"),
      "issue": ("issue", "yellow"),
    }

    sym, col = mapping[kind]
    print(f"{cls.paint(cls.SYMBOLS[sym], col)} {message}")

  @staticmethod
  def tree(lines, indent=" "):
    for i, line in enumerate(lines):
      connector = "└─" if i == len(lines) - 1 else "├─"
      print(f"{indent}{connector} {line}")

  @staticmethod
  def leaf(text, last=False, indent=" "):
    connector = "└─" if last else "├─"
    print(f"{indent}{connector} {text}")

  @staticmethod
  def line():
    print()

  _progress_lines = 0

  @classmethod
  def progress(cls, summary, done, total, start, tty, final=False, waiting=None):
    elapsed = max(time.monotonic() - start, 1e-9)
    rate = done / elapsed
    pct = (done / total * 100) if total else 100.0
    eta = (total - done) / rate if rate > 0 and total > done else 0.0
    skipped = summary["skipped_circuit_open"] + summary["skipped_early_stop"]

    progress_line = f"Progress: {done:,}/{total:,} ({pct:.0f}%)"
    counts_line = (f"Success: {summary['success']:,} · Retried: {summary['retried']:,} · "
           f"Failed: {summary['permanent_failure']:,} · Skipped: {skipped:,}")
    rates_line = f"Elapsed: {elapsed:,.0f}s · Pace: {rate:.1f}/s"
    if not final and eta and not waiting:
      rates_line += f" · Eta: {eta:,.0f}s"

    block = [f" ├─ {progress_line}", f" ├─ {counts_line}"]
    if waiting and not final:
      shown = ", ".join(waiting[:3]) + (f" and {len(waiting) - 3} more" if len(waiting) > 3 else "")
      block.append(f" ├─ Waiting on: {shown}")
    block.append(f" └─ {rates_line}")

    if tty:
      if cls._progress_lines:
        print(f"\033[{cls._progress_lines}A", end="")
      for line in block:
        print(f"\033[2K{line}")
      extra = max(0, cls._progress_lines - len(block))
      if extra:
        for _ in range(extra):
          print("\033[2K")
        print(f"\033[{extra}A", end="")
      cls._progress_lines = 0 if final else len(block)
    else:
      for line in block:
        print(line)


class UIError(Exception):
  pass


def _load_urls(
  output_dir: Path, limit: int | None, shard: int, num_shards: int,
) -> tuple[dict[str, str], int]:
  glob = str(table_dir(output_dir, "urls") / "*.parquet")
  con = duckdb.connect()
  try:
    reader = _batches(con.execute(f"SELECT url_id, original_url FROM read_parquet('{glob}')"), 100_000)
  except duckdb.IOException:
    return {}, 0
  urls: dict[str, str] = {}
  total = 0
  for batch in reader:
    ids = batch.column("url_id").to_pylist()
    originals = batch.column("original_url").to_pylist()
    for uid, original in zip(ids, originals):
      total += 1
      if num_shards <= 1 or _url_shard(uid, num_shards) == shard:
        urls[uid] = original
      if limit and total >= limit:
        return urls, total
  return urls, total


def _prepare_urls(output_dir: Path, input_values, scope_spec: str | None, only_witnesses: str | None) -> None:
  input_values = list(input_values)
  domain_values = [v for v in input_values if not Path(v).exists()]
  path_values = [Path(v) for v in input_values if Path(v).exists()]

  scope = _parse_scope(scope_spec) if scope_spec else None
  file_scope_types = _scope_allowed_url_types(scope) if scope else None

  discover_archives = None
  if only_witnesses:
    discover_archives = [w[len("archive:"):] if w.startswith("archive:") else w
                for w in only_witnesses.split(",") if w.strip() and w.strip() != "live_web"]

  if not has_rows(output_dir, "urls"):
    if not input_values:
      paths = _default_candidates()
      if not paths:
        raise UIError(
          f"No URLs picked yet, and no input found. Put a URL list (.csv or .gz) "
          f"in {INPUT_DIR} -- or point --input at a file/folder, or domain."
        )
      _pick_from_files(output_dir, paths, allowed_url_types=file_scope_types)
    else:
      if path_values:
        _pick_from_files(output_dir, _resolve_candidate_paths(path_values), allowed_url_types=file_scope_types)
      for d in domain_values:
        rows = discover_candidates(d, scope=scope or frozenset({"root", "hosts", "deep"}), only_archives=discover_archives)
        if not rows:
          raise UIError(f"No captures found for {d} across the queried archives.")
        _, added, skipped = write_urls_table(output_dir, rows)
        UI.log("ok", f"{added:,} {_plural(added, 'URL')} picked from {d}"
               f"{f' ({skipped:,} already tracked)' if skipped else ''}")


def _pick_from_files(output_dir: Path, paths: list[Path], allowed_url_types: frozenset[str] | None = None) -> None:
  names = ", ".join(Path(p).name for p in paths[:3]) + (f" and {len(paths) - 3} more" if len(paths) > 3 else "")
  UI.log("info", f"Picking URLs from {names}...")
  _, added, skipped = sample_from_files(output_dir, paths, show_progress=False, allowed_url_types=allowed_url_types)
  UI.log("ok", f"{added:,} {_plural(added, 'URL')} picked"
         f"{f' ({skipped:,} duplicates skipped)' if skipped else ''}")


_URLS_LOCK_STALE_SECONDS = 3600


def _urls_last_activity(output_dir: Path, lock: Path) -> float:
  newest = 0.0
  for path in [lock, *table_dir(output_dir, "urls").glob("*")]:
    try:
      newest = max(newest, path.stat().st_mtime)
    except OSError:
      pass
  return newest


def _ensure_urls(output_dir: Path, input_values, scope_spec: str | None, only_witnesses: str | None) -> bool:
  output_dir = Path(output_dir)
  ready = output_dir / "urls.ready"
  lock = output_dir / "urls.building"
  waited = False
  built = False
  while not ready.exists():
    try:
      fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
      if not waited:
        UI.log("info", "Another job is picking the URLs; waiting for it to finish...")
        waited = True
      if time.time() - _urls_last_activity(output_dir, lock) > _URLS_LOCK_STALE_SECONDS:
        try:
          os.replace(lock, output_dir / f"urls.building.stale-{os.getpid()}")
        except OSError:
          pass
      time.sleep(2)
      continue
    os.close(fd)
    try:
      if not ready.exists():
        was_empty = not has_rows(output_dir, "urls")
        _prepare_urls(output_dir, input_values, scope_spec, only_witnesses)
        built = built or was_empty
        if not has_rows(output_dir, "urls"):
          raise UIError("No URLs found. Point --input at a file/folder, or domain.")
        ready.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
    finally:
      try:
        os.remove(lock)
      except OSError:
        pass
  return built or waited


def _read_history(output_dir: Path) -> str | None:
  path = Path(output_dir) / "history.json"
  try:
    return json.loads(path.read_text(encoding="utf-8")).get("history")
  except (OSError, ValueError):
    return "full" if has_rows(output_dir, "captures") or has_rows(output_dir, "observations") else None


def _claim_history(output_dir: Path, wanted: str) -> None:
  existing = _read_history(output_dir)
  if existing is not None and existing != wanted:
    have = "full histories (--changes)" if existing == "full" else "first and last captures only"
    fix = "add --changes to continue it" if existing == "full" else "drop --changes to continue it"
    raise UIError(f"This output folder already holds {have}; {fix}, or use a new --output.")
  path = Path(output_dir) / "history.json"
  tmp = path.with_name(f"history.json.{os.getpid()}.tmp")
  tmp.write_text(json.dumps({"history": wanted}), encoding="utf-8")
  os.replace(tmp, path)


def _parse_shard(spec: str | None) -> tuple[int, int]:
  shard = num_shards = None
  if spec:
    parts = spec.split("/")
    if len(parts) not in (1, 2):
      raise UIError(f"--shard must be 'i' or 'i/n' -- got {spec!r}.")
    shard = _safe_int(parts[0])
    num_shards = _safe_int(parts[1]) if len(parts) == 2 else None
    if shard is None or (len(parts) == 2 and num_shards is None):
      raise UIError(f"--shard must be 'i' or 'i/n' with integers -- got {spec!r}.")
  if shard is None or num_shards is None:
    detected = _hpc_shard_from_env()
    if detected:
      det_shard, det_count, scheduler = detected
      if shard is None:
        shard = det_shard
      if num_shards is None:
        if det_count is None:
          raise UIError(
            f"Detected a {scheduler} job array (task index {det_shard}) but "
            f"{scheduler} doesn't expose the array's total size as an "
            f"environment variable -- pass --shard {det_shard}/<n> explicitly."
          )
        num_shards = det_count
  shard = 0 if shard is None else shard
  num_shards = 1 if num_shards is None else num_shards
  if not (0 <= shard < num_shards):
    raise UIError(
      f"--shard index must be in [0, {num_shards}) -- got {shard}. If this came from "
      f"a job array, check its index range starts at 0, or pass --shard i/n explicitly."
    )
  return shard, num_shards


def _witness_names(spec: str | None) -> list[str] | None:
  if not spec:
    return None
  return [n if n == "live_web" or n.startswith("archive:") else f"archive:{n}" for n in spec.split(",")]


def cmd_run(args) -> None:
  shard, num_shards = _parse_shard(args.shard)

  output_dir = args.output_dir
  history = "full" if args.changes else "lifespan"
  _claim_history(output_dir, history)
  UI.line()
  if _ensure_urls(output_dir, args.input, args.scope, args.witnesses):
    UI.line()

  urls, total_urls = _load_urls(output_dir, args.limit, shard, num_shards)
  if total_urls == 0:
    raise UIError("No URLs found. Point --input at a file/folder, or domain.")

  only = _witness_names(args.witnesses)
  all_witnesses = [live_witness()] + archive_witnesses()
  if only:
    all_witnesses = [w for w in all_witnesses if w.name in only]
  archive_count = sum(1 for w in all_witnesses if w.name != "live_web")

  threshold_given = args.stop_early_threshold is not None
  stop_early = threshold_given or not args.changes
  stop_early_threshold = args.stop_early_threshold if threshold_given else DEFAULT_CORROBORATION_THRESHOLD

  details = [f"live_web + {archive_count} {_plural(archive_count, 'archive')}"]
  if num_shards > 1:
    details.append(f"shard {shard}/{num_shards}")
  if stop_early:
    details.append(f"stop-early at {stop_early_threshold} inaccessible")
  if args.retry:
    details.append("retrying past failures")
  details.append("full histories" if args.changes else "first and last captures")
  if args.workers:
    details.append(f"{args.workers} workers")
  UI.log("info", f"Running {len(urls):,} {_plural(len(urls), 'URL')} across {len(all_witnesses)} "
                 f"{_plural(len(all_witnesses), 'witness', 'witnesses')} ({', '.join(details)})")
  UI.leaf(f"Logs: {Path(output_dir) / 'pluto.log'} (add -v to stream them here)")
  summary = run_witnesses(
    urls,
    output_dir=output_dir, only_witnesses=only,
    max_workers=args.workers, shard=shard, num_shards=num_shards,
    stop_early=stop_early, stop_early_threshold=stop_early_threshold,
    history=history, retry_failed=args.retry,
  )
  UI.line()
  problems = []
  if summary["permanent_failure"]:
    problems.append(f"{summary['permanent_failure']:,} {_plural(summary['permanent_failure'], 'query', 'queries')} failed for good")
  if summary["unexpected_errors"]:
    problems.append(f"{summary['unexpected_errors']:,} unexpected {_plural(summary['unexpected_errors'], 'error')} (details in pluto.log)")
  if summary["abandoned_witnesses"]:
    problems.append(f"{summary['abandoned_witnesses']} {_plural(summary['abandoned_witnesses'], 'archive')} left for the next run")
  if problems:
    UI.log("issue", "Run finished with issues: " + "; ".join(problems))
  else:
    UI.log("ok", "Run complete. Next: python pluto.py classify")
  UI.line()


def cmd_classify(args) -> None:
  output_dir = args.output_dir
  UI.line()
  UI.log("info", "Classifying URLs...")
  established_by_archive = established_years()
  with_changes = _read_history(output_dir) != "lifespan"
  n = classify_all(output_dir, corroboration_threshold=args.corroboration_threshold,
           established_by_archive=established_by_archive, with_changes=with_changes)
  details = []
  if not args.no_summarize:
    path, _ = summarize_urls(output_dir, out_path=None, established_by_archive=established_by_archive)
    details.append(f"Summary: {path}")
  details.append(f"Events: {table_dir(output_dir, 'events')}")
  UI.log("ok", f"Classified {n:,} {_plural(n, 'URL')}"
         f"{'' if with_changes else ' (lifespan only: S1/S2 need a run with --changes)'}")
  UI.tree(details)
  UI.line()


def cmd_list_archives(args) -> None:
  witnesses = archive_witnesses()
  UI.line()
  UI.log("info", f"{len(witnesses)} {_plural(len(witnesses), 'archive')} loaded from registry/")
  width = max((len(wc.extra["registry_entry"]["id"]) for wc in witnesses), default=0)
  UI.tree([
    f"{wc.extra['registry_entry']['id']:<{width}}  {wc.extra['registry_entry']['name']}"
    for wc in witnesses
  ])
  UI.line()


def cmd_export(args) -> None:
  import shutil

  output_dir = args.output_dir
  out_dir = args.out or (Path(output_dir) / "export")
  out_dir.mkdir(parents=True, exist_ok=True)
  con = duckdb.connect()

  UI.line()
  UI.log("info", "Exporting tables...")
  rows = []
  for table in TABLES:
    glob = str(table_dir(output_dir, table) / "*.parquet")
    out_path = out_dir / f"{table}.parquet"
    try:
      con.execute(f"COPY (SELECT * FROM read_parquet('{glob}')) TO '{out_path}' (FORMAT PARQUET)")
      n = con.execute(f"SELECT count(*) FROM read_parquet('{glob}')").fetchone()[0]
    except duckdb.IOException:
      n = 0
    rows.append(f"{table}.parquet: {n:,} {_plural(n, 'row')}")

  summary_src = Path(output_dir) / "summary.parquet"
  if summary_src.exists():
    shutil.copy2(summary_src, out_dir / "summary.parquet")
    rows.append("summary.parquet: copied")

  UI.log("ok", f"Exported to {out_dir}")
  UI.tree(rows)
  UI.line()


def cmd_fetch_archives(args) -> None:
  if args.source is not None and not args.source.exists():
    raise UIError(f"--source {args.source} does not exist.")
  UI.line()
  UI.log("info", "Fetching web archive registry from web-archive.txt...")
  n = import_registry(source=args.source)
  UI.log("ok", f"Imported {n:,} web-archive.txt {_plural(n, 'descriptor')} into {REGISTRY_DIR}")

  notes = scan_backfill_notes()
  mismatches = [note for note in notes if note["mismatch"]]
  if notes:
    UI.log("info", f"{len(notes)} {_plural(len(notes), 'archive')} disclose a backfill in their archive scope coverage")
  if mismatches:
    UI.log("issue", f"{len(mismatches)} disagree with the registry's own `established` field "
            f"(overridden in established_years() -- see README):")
    UI.tree([
      f"{note['id']}: established={note['established']} but comment says "
      f"capturing began in {note['capturing_began']} ({note['comment']!r})"
      for note in mismatches
    ])
  UI.line()


def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="pluto.py", description="Reconstruct web URL histories across the live web and web archives.",
  )
  parser.add_argument("--output", dest="output_dir", type=Path, default=OUTPUT_DIR, metavar="PATH",
    help="Root directory for parquet tables, raw responses and checkpoints (default: output/).")
  parser.add_argument("-v", "--verbose", action="store_true", help="Also stream INFO-level logs to the terminal.")
  sub = parser.add_subparsers(dest="command", metavar="<command>")

  p = sub.add_parser("fetch-archives", help="Download the latest archive registry from web-archive.txt.")
  p.add_argument("--source", type=Path, default=None, metavar="PATH",
    help="Existing local checkout of web-archive.txt's registry/ dir, instead of cloning.")
  p.set_defaults(func=cmd_fetch_archives)

  p = sub.add_parser("list-archives", help="List the archives loaded from the registry.")
  p.set_defaults(func=cmd_list_archives)

  p = sub.add_parser("run", help="Query the live web and every archive for each URL in the study.")
  p.add_argument("--input", action="append", default=[], metavar="PATH|DOMAIN",
    help="A URL list (file or folder), or a bare domain to discover URLs for; repeat to mix, "
         "e.g. --input urls.csv --input example.com. Anything that exists on disk is read as a "
         f"URL list, anything else is treated as a domain. Default: auto-detect a list in {INPUT_DIR}. "
         "Ignored once URLs already exist for this study.")
  p.add_argument("--scope", default=None, metavar="SCOPE",
    help="What to discover for a domain given via --input: root (its own homepage), hosts (one "
         "homepage per subdomain), deep (every archived URL with a path), or a comma-separated "
         "mix. Default: all.")
  p.add_argument("--witnesses", default=None, metavar="IDS",
    help="Comma-separated witnesses to query, e.g. live_web,ia,arq. Default: all. Also limits "
         "which archives --scope searches.")
  p.add_argument("--limit", type=int, default=None, metavar="N", help="Only query the first N URLs.")
  p.add_argument("--workers", type=int, default=None, metavar="N",
    help="Worker threads. Default: sized automatically from each witness's rate.")
  p.add_argument("--shard", default=None, metavar="I/N",
    help="This process's shard, e.g. 2/8. Detected automatically from SLURM/SGE job arrays.")
  p.add_argument("--min-witnesses", dest="stop_early_threshold", type=int,
    default=None, metavar="N",
    help="Skip a URL's remaining witnesses once its state is certain -- alive in one, or "
         "inaccessible in at least N (pairs with --witnesses). On by default at "
    f"N={DEFAULT_CORROBORATION_THRESHOLD}, except with --changes, where every witness's "
         "full history is wanted instead; pass --min-witnesses explicitly to switch it back "
         "on even with --changes.")
  p.add_argument("--changes", action="store_true",
    help="Fetch each archive's full capture history so content changes (S1/S2) can be detected. "
         "Default: only the first and last capture per archive.")
  p.add_argument("--retry", action="store_true",
    help="Also re-attempt URLs a witness gave up on for good last run (e.g. a live-web check "
         "that never came back cleanly), not just ones it hasn't reached yet. Combine with "
         "--witnesses to retry just one, e.g. --witnesses live_web --retry.")
  p.set_defaults(func=cmd_run)

  p = sub.add_parser("classify", help="Classify every URL's state (S0-S4) from its collected evidence.")
  p.add_argument("--corroboration-threshold", type=int, default=DEFAULT_CORROBORATION_THRESHOLD, metavar="N",
    help="Independent witnesses required to score a URL S3.")
  p.add_argument("--no-summarize", action="store_true", help="Skip writing summary.parquet.")
  p.set_defaults(func=cmd_classify)

  p = sub.add_parser("export", help="Copy every table to a single clean Parquet file per table.")
  p.add_argument("--out", type=Path, default=None, metavar="PATH", help="Output directory (default: <output>/export).")
  p.set_defaults(func=cmd_export)
  return parser


def main(argv: list[str] | None = None) -> int:
  parser = build_parser()
  args = parser.parse_args(argv)
  if not args.command:
    parser.print_help()
    return 0
  output_dir = Path(args.output_dir)
  output_dir.mkdir(parents=True, exist_ok=True)
  handlers: list[logging.Handler] = [logging.FileHandler(output_dir / "pluto.log")]
  if args.verbose:
    handlers.append(logging.StreamHandler())
  logging.basicConfig(level=logging.INFO, handlers=handlers, force=True,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s")
  args.output_dir = output_dir
  init_tables(output_dir)
  try:
    args.func(args)
  except UIError as exc:
    UI.log("error", str(exc))
    return 1
  except KeyboardInterrupt:
    print("\nInterrupted. Progress is saved; run the same command again to resume.")
    return 130
  return 0


if __name__ == "__main__":
  sys.exit(main())