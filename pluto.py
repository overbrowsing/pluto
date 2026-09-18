#!/usr/bin/env python3

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import csv
import gzip
import hashlib
import json
import logging
import math
import os
import random
import re
import socket
import sqlite3
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, urlsplit, urlunsplit, parse_qsl, urlencode

try:
  import tomllib
except ModuleNotFoundError:
  import tomli as tomllib

import click
import duckdb
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import requests
from requests.exceptions import ConnectionError as ReqConnectionError, RequestException, Timeout as ReqTimeout

logger = logging.getLogger("pluto")

# ------------------- Paths -------------------

REPO_ROOT = Path(__file__).resolve().parent
INPUT_DIR = REPO_ROOT / "input"
GARG_DIR = INPUT_DIR / "garg"
OUTPUT_DIR = REPO_ROOT / "output"
REGISTRY_DIR = REPO_ROOT / "registry"
DEFAULT_CANDIDATES_PATH = INPUT_DIR / "candidates.csv"

UPSTREAM_REGISTRY = "https://github.com/overbrowsing/web-archive.txt.git"

# ------------------- Settings -------------------

LIVE_WEB_SETTINGS = {
  "timeout_seconds": 10,
  "requests_per_second": 50,
}

ARCHIVE_REGISTRY_SETTINGS = {
  "default_timeout_seconds": 20,
  "default_requests_per_second": 10,
  "rate_limited_requests_per_second": 5,
  "only": [],
  "exclude": [],
}

CIRCUIT_BREAKER_SETTINGS = {
  "failure_threshold": 5,
  "cooldown_seconds": 120,
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


def split_url(raw_url: str) -> UrlParts:
  global _TLD_EXTRACTOR
  if _TLD_EXTRACTOR is None:
    import tldextract
    _TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

  canonical = canonicalize(raw_url)
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
  pq.write_table(pa.Table.from_pylist(rows, schema=TABLES[table]), part_path)
  return part_path


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
    alt = next((n.get("alt") for n in name_field[1:] if isinstance(n, dict) and n.get("alt")), None)
    return f"{primary} ({alt})" if alt else str(primary)
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
    if collections and isinstance(collections[0], dict):
      entry["default_collection"] = collections[0].get("id")

  return entry


def import_registry(dest: Path = REGISTRY_DIR, source: Path | None = None) -> int:
  import shutil
  import subprocess
  import tempfile

  dest = Path(dest)

  def _copy_all(registry_dir: Path) -> int:
    # Read every source descriptor into memory before touching dest, so this
    # is safe even if source and dest are the same directory (e.g. --source
    # pointed at REGISTRY_DIR itself).
    entries = [
      (src_file.parent.name, src_file.read_bytes())
      for src_file in sorted(registry_dir.glob("*/web-archive.txt"))
    ]
    dest.mkdir(parents=True, exist_ok=True)
    # Only clear the per-archive subdirectories -- leave any top-level files
    # (e.g. .gitkeep) in dest alone.
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
    out.append(WitnessConfig(
      name=f"archive:{archive_id}",
      adapter="WebArchiveAdapter",
      enabled=True,
      timeout_seconds=timeout,
      requests_per_second=rps,
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


class LiveWebAdapter(ArchiveAdapter):
  name = "live_web"

  def __init__(self, config):
    super().__init__(config)
    self._session = requests.Session()

  def query(self, url: str) -> requests.Response:
    host = urlsplit(url).hostname
    if host:
      try:
        socket.getaddrinfo(host, None)
      except socket.gaierror as exc:
        raise WitnessError("dns_failure", str(exc)) from exc
    try:
      return self._session.get(
        url, headers={"User-Agent": "Pluto :: Overbrowsing"},
        timeout=self.timeout_seconds(), allow_redirects=True, stream=True,
      )
    except ReqTimeout as exc:
      raise WitnessError("timeout", str(exc)) from exc
    except ReqConnectionError as exc:
      raise WitnessError("connection_error", str(exc)) from exc
    except RequestException as exc:
      raise WitnessError("malformed_response", str(exc)) from exc

  def parse(self, url: str, raw: requests.Response) -> AdapterResult:
    body = raw.content[:1_000_000]
    status = _classify_status(raw.status_code)
    error_class = {"access_restricted": "client_error", "server_error": "server_error"}.get(status, "")
    return AdapterResult(observations=[{
      "url_id": None, "observer": self.name,
      "observation_time": None, "query_time": None,
      "status": status, "http_status": raw.status_code, "error_class": error_class,
      "redirect_target": raw.url if raw.url != url else "",
      "mime_type": raw.headers.get("Content-Type", "").split(";")[0],
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
    self._session = requests.Session()

  def query(self, url: str) -> tuple[str, str]:
    if self.entry.usable_cdx():
      return "cdx", self._get_paginated_cdx(url)
    if self.entry.usable_timemap():
      return "timemap", self._get(_fill_template(self.entry.timemap_endpoint, url, self.entry))
    raise WitnessError("client_error", f"{self.entry.id} has no usable online endpoint")

  _MAX_CDX_PAGES = 200

  def _get_paginated_cdx(self, url: str) -> str:
    endpoint = _fill_template(self.entry.cdx_endpoint, url, self.entry)
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
      records.extend(body)

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
                   headers={"User-Agent": "pluto-research-bot/0.1"})
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

  def parse(self, url: str, raw: tuple[str, str]) -> AdapterResult:
    kind, text = raw
    if not text.strip():
      return AdapterResult(observations=[{
        "url_id": None, "observer": self.name,
        "observation_time": None, "query_time": None,
        "status": "no_evidence_this_query", "http_status": 0,
        "error_class": "not_found", "redirect_target": "",
        "mime_type": "", "content_length": 0,
        "content_digest": "", "response_digest": "", "confidence": 1.0,
      }])
    captures = self._parse_cdx(text) if kind == "cdx" else self._parse_timemap(text)
    now = datetime.now(timezone.utc)
    captures = [c for c in captures if c["capture_time"] <= now]
    for cap in captures:
      cap["archive"] = self.name
    return AdapterResult(captures=captures)

  def _parse_cdx(self, text: str) -> list[dict]:
    text = text.strip()
    try:
      data = json.loads(text)
      if isinstance(data, list) and data and isinstance(data[0], list):
        header, *records = data
        idx = {name: i for i, name in enumerate(header)}
        out = []
        for rec in records:
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

PENDING, RUNNING, SUCCESS, RETRY, FAILED, PERMANENT_FAILURE, SKIPPED_EARLY_STOP = (
  "PENDING", "RUNNING", "SUCCESS", "RETRY", "FAILED", "PERMANENT_FAILURE", "SKIPPED_EARLY_STOP",
)

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


class CheckpointStore:

  def __init__(self, db_path: Path):
    self.db_path = Path(db_path)
    self.db_path.parent.mkdir(parents=True, exist_ok=True)
    self._conn = sqlite3.connect(self.db_path, isolation_level=None, check_same_thread=False)
    self._lock = threading.Lock()
    with self._lock, self._cursor() as cur:
      cur.execute(_CHECKPOINT_SCHEMA)

  @contextmanager
  def _cursor(self):
    cur = self._conn.cursor()
    try:
      yield cur
    finally:
      cur.close()

  def get_state(self, url_id: str, witness: str) -> str:
    with self._lock, self._cursor() as cur:
      cur.execute("SELECT state FROM checkpoints WHERE url_id=? AND witness=?", (url_id, witness))
      row = cur.fetchone()
      return row[0] if row else PENDING

  def is_done(self, url_id: str, witness: str) -> bool:
    return self.get_state(url_id, witness) in (SUCCESS, PERMANENT_FAILURE, SKIPPED_EARLY_STOP)

  def mark_running(self, url_id: str, witness: str) -> None:
    self._upsert(url_id, witness, RUNNING, increment_attempts=True)

  def mark_success(self, url_id: str, witness: str) -> None:
    self._upsert(url_id, witness, SUCCESS)

  def mark_retry(self, url_id: str, witness: str, error_class: str) -> None:
    self._upsert(url_id, witness, RETRY, last_error_class=error_class)

  def mark_permanent_failure(self, url_id: str, witness: str, error_class: str) -> None:
    self._upsert(url_id, witness, PERMANENT_FAILURE, last_error_class=error_class)

  def mark_skipped_early_stop(self, url_id: str, witness: str) -> None:
    self._upsert(url_id, witness, SKIPPED_EARLY_STOP)

  def attempts(self, url_id: str, witness: str) -> int:
    with self._lock, self._cursor() as cur:
      cur.execute("SELECT attempts FROM checkpoints WHERE url_id=? AND witness=?", (url_id, witness))
      row = cur.fetchone()
      return row[0] if row else 0

  def _upsert(self, url_id, witness, state, increment_attempts=False, last_error_class=None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with self._lock, self._cursor() as cur:
      cur.execute("SELECT attempts FROM checkpoints WHERE url_id=? AND witness=?", (url_id, witness))
      row = cur.fetchone()
      attempts = (row[0] if row else 0) + (1 if increment_attempts else 0)
      cur.execute(
        """
                INSERT INTO checkpoints (url_id, witness, state, attempts, last_error_class, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(url_id, witness) DO UPDATE SET
                    state=excluded.state, attempts=excluded.attempts,
                    last_error_class=COALESCE(excluded.last_error_class, checkpoints.last_error_class),
                    updated_at=excluded.updated_at
                """,
        (url_id, witness, state, attempts, last_error_class, now),
      )

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
  _open_since: float | None = field(default=None, init=False)
  _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False, compare=False)

  @property
  def is_open(self) -> bool:
    with self._lock:
      return self._open_since is not None

  def record_success(self) -> None:
    with self._lock:
      self._consecutive_failures = 0
      self._open_since = None

  def record_failure(self) -> None:
    with self._lock:
      self._consecutive_failures += 1
      if self._consecutive_failures >= self.failure_threshold and self._open_since is None:
        self._open_since = time.monotonic()

  def ready_for_health_check(self) -> bool:
    with self._lock:
      return self._open_since is not None and (time.monotonic() - self._open_since) >= self.cooldown_seconds

  def allow_request(self) -> bool:
    return not self.is_open


class RateLimiter:

  def __init__(self, requests_per_second: float):
    self.min_interval = 1.0 / max(requests_per_second, 0.001)
    self._lock = threading.Lock()
    self._next_allowed = 0.0

  def wait(self) -> None:
    with self._lock:
      now = time.monotonic()
      sleep_for = max(0.0, self._next_allowed - now)
      self._next_allowed = max(now, self._next_allowed) + self.min_interval
    if sleep_for > 0:
      time.sleep(sleep_for)


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
  return set(con.execute(f"SELECT DISTINCT url_id FROM read_parquet('{glob}')").fetchdf()["url_id"])


def write_urls_table(output_dir: Path, urls: list[dict]) -> tuple[Path | None, int, int]:
  already = _existing_url_ids(output_dir)
  rows, skipped = [], 0
  for row in urls:
    uid = url_id(row["url"])
    if uid in already:
      skipped += 1
      continue
    already.add(uid)
    parts = split_url(row["url"])
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
) -> tuple[Path | None, int, int]:
  total_added = total_skipped = 0
  n_rows_seen = 0
  last_path: Path | None = None

  def write_batch(batch: list[dict]) -> None:
    nonlocal total_added, total_skipped, last_path, n_rows_seen
    if not batch:
      return
    n_rows_seen += len(batch)
    path, added, skipped = write_urls_table(output_dir, batch)
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
      yield from _iter_candidate_rows(p)

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


GARG_FILENAMES = ("nypw_downsampled_root_firstcdx.gz", "nypw_downsampled_deep_firstcdx.gz")


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
  garg = [GARG_DIR / name for name in GARG_FILENAMES if (GARG_DIR / name).exists()]
  if not garg:
    garg = [INPUT_DIR / name for name in GARG_FILENAMES if (INPUT_DIR / name).exists()]
  if garg:
    return garg
  if DEFAULT_CANDIDATES_PATH.exists():
    return [DEFAULT_CANDIDATES_PATH]
  return sorted(INPUT_DIR.glob("*.csv")) + sorted(INPUT_DIR.glob("*.gz"))


# ------------------- Stage 2 -------------------


def store_raw(output_dir: Path, witness: str, uid: str, payload: Any) -> str:
  if isinstance(payload, bytes):
    raw_bytes, suffix = payload, ".bin"
  else:
    raw_bytes, suffix = json.dumps(payload, default=str, sort_keys=True).encode("utf-8"), ".json"

  digest = hashlib.sha256(raw_bytes).hexdigest()
  out_dir = Path(output_dir) / "raw" / witness / digest[:2]
  out_dir.mkdir(parents=True, exist_ok=True)
  out_path = out_dir / f"{digest}{suffix}"
  if not out_path.exists():
    out_path.write_bytes(raw_bytes)
  return digest


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
    runtimes[wc.name] = WitnessRuntime(
      config=wc,
      adapter=ADAPTER_REGISTRY[wc.adapter](wc),
      limiter=RateLimiter(wc.requests_per_second),
      breaker=CircuitBreaker(**breaker_cfg),
    )
  return runtimes


def _raw_for_storage(raw):
  if isinstance(raw, requests.Response):
    return {"status_code": raw.status_code, "headers": dict(raw.headers),
        "url": raw.url, "text": raw.text[:200_000]}
  return raw


def _process_unit(uid, witness, original_url, runtime, output_dir, store) -> dict:
  if runtime.breaker.is_open:
    if not runtime.breaker.ready_for_health_check():
      return {"outcome": "skipped_circuit_open"}
    if runtime.adapter.health_check():
      runtime.breaker.record_success()
    else:
      return {"outcome": "skipped_circuit_open"}

  runtime.limiter.wait()
  store.mark_running(uid, witness)
  query_time = datetime.now(timezone.utc)

  try:
    raw = runtime.adapter.query(original_url)
    store_raw(output_dir, witness, uid, _raw_for_storage(raw))
    result = runtime.adapter.parse(original_url, raw)
    runtime.breaker.record_success()
  except WitnessError as exc:
    runtime.breaker.record_failure()
    attempts = store.attempts(uid, witness)
    if should_retry(exc.error_class, attempts):
      store.mark_retry(uid, witness, exc.error_class)
      time.sleep(min(policy_for(exc.error_class).delay(attempts), 2))
      return {"outcome": "retried"}
    store.mark_permanent_failure(uid, witness, exc.error_class)
    status = (
      _INACCESSIBLE_STATUS
      if witness == "live_web" and exc.error_class in _LIVE_WEB_FAILURE_IS_EVIDENCE
      else "unresolved"
    )
    return {"outcome": "permanent_failure", "observations": [{
      "url_id": uid, "observer": witness,
      "observation_time": query_time, "query_time": query_time,
      "status": status, "http_status": 0,
      "error_class": exc.error_class, "redirect_target": "",
      "mime_type": "", "content_length": 0,
      "content_digest": "", "response_digest": "", "confidence": 0.0,
    }]}

  now = datetime.now(timezone.utc)
  observations = []
  for obs in result.observations:
    obs = {**obs, "url_id": uid}
    obs["observation_time"] = obs["observation_time"] or now
    obs["query_time"] = obs["query_time"] or query_time
    observations.append(obs)
  captures = [{**cap, "url_id": uid} for cap in result.captures]

  store.mark_success(uid, witness)
  return {"outcome": "success", "observations": observations, "captures": captures}


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


def _witness_concurrency_cap(min_interval: float) -> int:
  rate = 1.0 / min_interval
  return max(1, math.ceil(rate * 2))


def run_witnesses(
  urls: list[tuple[str, str]],
  output_dir: Path,
  only_witnesses: list[str] | None = None,
  flush_every: int = 200,
  max_workers: int | None = None,
  shard: int = 0,
  num_shards: int = 1,
  stop_early: bool = False,
  stop_early_threshold: int | None = None,
  report_changes: bool = False,
) -> dict:
  witness_configs = [live_witness()] + archive_witnesses()
  if only_witnesses:
    witness_configs = [w for w in witness_configs if w.name in only_witnesses]
  if num_shards > 1:
    witness_configs = [
      replace(wc, requests_per_second=wc.requests_per_second / num_shards)
      for wc in witness_configs
    ]
  runtimes = build_runtimes(witness_configs, CIRCUIT_BREAKER_SETTINGS)

  if num_shards > 1:
    urls = [(uid, u) for uid, u in urls if _url_shard(uid, num_shards) == shard]
    ckpt_path = Path(output_dir) / "checkpoints" / f"shard-{shard:03d}-of-{num_shards:03d}.db"
  else:
    ckpt_path = Path(output_dir) / "checkpoints.db"

  store = CheckpointStore(ckpt_path)
  url_lookup = dict(urls)
  url_ids = list(url_lookup.keys())
  witness_names = list(runtimes.keys())

  obs_buffer: list[dict] = []
  cap_buffer: list[dict] = []
  summary = {"queried": 0, "success": 0, "retried": 0, "permanent_failure": 0,
       "skipped_circuit_open": 0, "skipped_early_stop": 0}

  def flush():
    if obs_buffer:
      append_rows(output_dir, "observations", obs_buffer)
      obs_buffer.clear()
    if cap_buffer:
      append_rows(output_dir, "captures", cap_buffer)
      cap_buffer.clear()

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
    for uid in url_ids:
      if store.is_done(uid, w):
        continue
      if _resolved(uid):
        store.mark_skipped_early_stop(uid, w)
        summary["skipped_early_stop"] += 1
        continue
      yield uid

  pending_iters = {w: pending_for(w) for w in witness_names}
  caps = {w: _witness_concurrency_cap(runtimes[w].limiter.min_interval) for w in witness_names}
  recommended_workers = sum(caps.values())
  if max_workers is None:
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

  total_tasks = len(url_ids) * len(witness_names)
  tty = sys.stdout.isatty()
  progress_interval = 0.5 if tty else 30.0
  start_time = time.monotonic()
  last_progress_at = start_time
  completed = 0
  UI._progress_lines = 0

  with ThreadPoolExecutor(max_workers=max_workers) as executor:
    in_flight: dict = {}

    def submit_for(w: str) -> bool:
      for uid in pending_iters[w]:
        fut = executor.submit(
          _process_unit, uid, w, url_lookup[uid], runtimes[w], output_dir, store,
        )
        in_flight[fut] = (w, uid)
        return True
      return False

    for w in witness_names:
      for _ in range(caps[w]):
        if not submit_for(w):
          break

    while in_flight:
      done, _ = wait(set(in_flight), return_when=FIRST_COMPLETED)
      for fut in done:
        w, uid = in_flight.pop(fut)
        result = fut.result()
        outcome = result["outcome"]
        if outcome != "skipped_circuit_open":
          summary["queried"] += 1
        summary[outcome] += 1
        completed += 1
        obs_buffer.extend(result.get("observations", []))
        cap_buffer.extend(result.get("captures", []))
        _record_evidence(uid, w, result.get("observations", []))
        if len(obs_buffer) >= flush_every or len(cap_buffer) >= flush_every:
          flush()

        if report_changes:
          transitions = _witness_digest_transitions(
            result.get("observations", []), result.get("captures", []),
          )
          if transitions:
            latest = max(transitions, key=lambda t: t["first_new_time"])
            UI._progress_lines = 0
            UI.log("info", f"{url_lookup[uid]} -- {len(transitions)} content "
                    f"change(s) seen by {latest['witness']}, most recent "
                    f"{latest['first_new_time']:%Y-%m-%d %H:%M} UTC")

        submit_for(w)

      now = time.monotonic()
      if now - last_progress_at >= progress_interval:
        UI.progress(summary, completed, total_tasks, start_time, tty)
        last_progress_at = now

  UI.progress(summary, completed, total_tasks, start_time, tty, final=True)
  flush()
  store.close()
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
) -> dict:
  latest_obs = _latest_by(observations, "observer", "observation_time")
  alive = any(o["status"] == _ALIVE_STATUS for o in latest_obs.values())
  inaccessible = _inaccessible_witnesses(observations, captures, established_by_archive)
  content_survival = _content_survival(observations, captures)

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


def _read_table(con: duckdb.DuckDBPyConnection, glob: str) -> pd.DataFrame:
  try:
    return con.execute(f"SELECT * FROM read_parquet('{glob}')").fetchdf()
  except duckdb.IOException:
    return pd.DataFrame()


def _group_by_url(df: pd.DataFrame) -> dict[str, list[dict]]:
  return {} if df.empty else {uid: g.to_dict("records") for uid, g in df.groupby("url_id")}


def classify_all(
  output_dir: Path,
  corroboration_threshold: int = DEFAULT_CORROBORATION_THRESHOLD,
  established_by_archive: dict[str, int] | None = None,
) -> int:
  con = duckdb.connect()
  obs_by_url = _group_by_url(_read_table(con, str(table_dir(output_dir, "observations") / "*.parquet")))
  cap_by_url = _group_by_url(_read_table(con, str(table_dir(output_dir, "captures") / "*.parquet")))
  url_ids = set(obs_by_url) | set(cap_by_url)
  if not url_ids:
    return 0

  for old_part in table_dir(output_dir, "events").glob("*.parquet"):
    old_part.unlink()

  events = []
  for uid in url_ids:
    observations = obs_by_url.get(uid, [])
    captures = cap_by_url.get(uid, [])
    state = classify_resource_state(observations, captures, corroboration_threshold, established_by_archive)
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
    events.append({**base, "event_type": f"state_{state['state']}",
            "confidence": 1.0 if state["state"] != "S4" else 0.5})
    events.extend(
      {**base, "event_type": f"risk_{name}", "confidence": 1.0}
      for name, flagged in risk.items() if flagged
    )

    transitions = _witness_digest_transitions(observations, captures)
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

  append_rows(output_dir, "events", events)
  return len(url_ids)


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
    raise RuntimeError("No data to summarize -- run `pluto.py sample` first.")

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


def _plural(n: int, word: str) -> str:
  return word if n == 1 else f"{word}s"


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
  def line():
    print()

  _progress_lines = 0

  @classmethod
  def progress(cls, summary, done, total, start, tty, final=False):
    elapsed = max(time.monotonic() - start, 1e-9)
    rate = done / elapsed
    pct = (done / total * 100) if total else 100.0
    eta = (total - done) / rate if rate > 0 and total > done else 0.0
    skipped = summary["skipped_circuit_open"] + summary["skipped_early_stop"]

    progress_line = f"Progress: {done:,}/{total:,} ({pct:.0f}%)"
    counts_line = (f"Success: {summary['success']:,} · Retried: {summary['retried']:,} · "
           f"Failed: {summary['permanent_failure']:,} · Skipped: {skipped:,}")
    rates_line = f"Elapsed: {elapsed:,.0f}s · Pace: {rate:.1f}/s"
    if not final and eta:
      rates_line += f" · Eta: {eta:,.0f}s"

    block = [f" ├─ {progress_line}", f" ├─ {counts_line}", f" └─ {rates_line}"]

    if tty:
      if cls._progress_lines:
        print(f"\033[{cls._progress_lines}A", end="")
      for line in block:
        print(f"\033[2K{line}")
      cls._progress_lines = 0 if final else len(block)
    else:
      for line in block:
        print(line)


class UIError(click.ClickException):

  def show(self, file=None) -> None:
    UI.log("error", self.format_message())


class OrderedGroup(click.Group):
  ORDER = ["fetch-archives", "list-archives", "sample", "run", "classify", "summarize", "export", "status"]

  def list_commands(self, ctx):
    order = {name: i for i, name in enumerate(self.ORDER)}
    return sorted(self.commands, key=lambda name: order.get(name, len(order)))


@click.group(cls=OrderedGroup)
@click.option("--output-dir", type=click.Path(path_type=Path), default=OUTPUT_DIR,
       help="Root directory for parquet tables, raw responses and checkpoints.")
@click.option("-v", "--verbose", is_flag=True, help="Enable INFO-level logging.")
@click.pass_context
def cli(ctx, output_dir: Path, verbose: bool):
  output_dir = Path(output_dir)
  output_dir.mkdir(parents=True, exist_ok=True)
  handlers: list[logging.Handler] = [logging.FileHandler(output_dir / "pluto.log")]
  if verbose:
    handlers.append(logging.StreamHandler())
  logging.basicConfig(level=logging.INFO, handlers=handlers,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s")
  ctx.ensure_object(dict)
  ctx.obj["output_dir"] = output_dir
  init_tables(output_dir)


@cli.command(short_help="Pick a random sample of URLs from your input files into the study.")
@click.option("--candidates", "candidates_paths", type=click.Path(exists=True, path_type=Path), multiple=True,
       help="Input files or a folder to pick from: Garg et al.'s *_firstcdx.gz files, "
         "or a .csv with columns url[, first_observed_year]. Default: auto-detect "
         f"from {INPUT_DIR} (looks for {GARG_DIR}/, then {DEFAULT_CANDIDATES_PATH}, "
         f"then any .csv/.gz directly in {INPUT_DIR}).")
@click.option("--n", "n", type=int, default=None,
       help="Only check N URLs (random sample across all input files). Omit for every candidate.")
@click.pass_context
def sample(ctx, candidates_paths: tuple[Path, ...], n: int | None):
  paths = _resolve_candidate_paths(list(candidates_paths)) if candidates_paths else _default_candidates()
  if not paths:
    raise UIError(
      f"No input found. Put Garg et al.'s *_firstcdx.gz files (in {GARG_DIR}/), or a "
      f"candidates.csv, in {INPUT_DIR} -- or point --candidates at a file or folder."
    )
  UI.line()
  UI.log("info", f"Sampling from input {_plural(len(paths), 'file')}...")
  path, added, skipped = sample_from_files(ctx.obj["output_dir"], paths, n=n, show_progress=False)
  if added == 0 and skipped == 0:
    raise UIError(f"No candidate rows found in {', '.join(str(p) for p in paths)}")
  if skipped:
    UI.log("ok", f"Added {added} new {_plural(added, 'URL')} ({skipped} already in the study, skipped)")
  else:
    UI.log("ok", f"Added {added} {_plural(added, 'URL')} to {path}")
  UI.line()


@cli.command(short_help="Query the live web and every archive for each URL in the study.")
@click.option("--candidates", "candidates_paths", type=click.Path(exists=True, path_type=Path), multiple=True,
       help="Input files or a folder to pick target URLs from, if none have been "
         "picked yet -- same as `sample --candidates`. Default: auto-detect from "
         f"{INPUT_DIR}. Ignored once URLs already exist; use `pluto.py sample` "
         "directly to add more later.")
@click.option("--witnesses", "only_witnesses", default=None,
       help="Comma-separated witnesses, e.g. 'live_web,ia,cc' (archive ids auto-expand "
         "to 'archive:<id>'). Default: every enabled witness.")
@click.option("--limit", type=int, default=None, help="Only query the first N URLs.")
@click.option("--workers", type=int, default=None,
       help="Concurrent worker threads; each witness gets its own share so a fast "
         "one (live_web) isn't held to a slow archive's pace. Default: auto-sized "
         "to exactly cover every enabled witness's own configured rate (startup "
         "logs the number chosen).")
@click.option("--shard", type=int, default=None,
       help="This process's shard index (HPC job arrays); auto-detected from "
         "SLURM_ARRAY_TASK_ID or SGE_TASK_ID (Eddie, most UK clusters) unless "
         "given explicitly. Default: 0 (no sharding).")
@click.option("--num-shards", type=int, default=None,
       help="Total shard count; auto-detected alongside --shard for SLURM and Grid "
         "Engine. PBS and LSF need this explicit, since neither exposes array "
         "size. Default: 1 (no sharding). Splits URLs across shards, but each "
         "witness's own configured rate is shared across all shards, not "
         "multiplied by shard count -- more shards means faster iteration over "
         "URLs, not a higher hit rate against any one witness.")
@click.option("--stop-early", is_flag=True, default=False,
       help="Once a URL's evidence already makes its state certain (any witness "
         "alive, or --stop-early-threshold independent witnesses inaccessible), "
         "skip its remaining witnesses. Trades evidence completeness for speed -- "
         "see run_witnesses()'s docstring for the caveat around Section 4.3's "
         "independence filter. Off by default.")
@click.option("--stop-early-threshold", type=int, default=None,
       help=f"Independent inaccessible witnesses needed to stop early (default: "
         f"{DEFAULT_CORROBORATION_THRESHOLD}, matching `classify`'s own default -- "
         f"set it higher than your intended --corroboration-threshold as a margin "
         f"against captures later excluded by the independence filter).")
@click.option("--report-changes", is_flag=True, default=False,
       help="Print a line to the terminal whenever a witness's own capture history "
         "shows the content changed, with the archive ID and the datetimes bounding "
         "the change. Handy on a small exploratory run; noisy at HPC scale -- classify "
         "always records every change to the events table regardless of this flag.")
@click.pass_context
def run(ctx, candidates_paths, only_witnesses, limit, workers, shard, num_shards,
    stop_early, stop_early_threshold, report_changes):
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
            f"environment variable -- pass --num-shards explicitly."
          )
        num_shards = det_count
  shard = 0 if shard is None else shard
  num_shards = 1 if num_shards is None else num_shards
  if not (0 <= shard < num_shards):
    raise UIError(
      f"--shard must be in [0, {num_shards}) -- got {shard}. If this came from a job "
      f"array, check its index range starts at 0, or pass --shard/--num-shards explicitly."
    )

  output_dir = ctx.obj["output_dir"]

  if not has_rows(output_dir, "urls"):
    paths = _resolve_candidate_paths(list(candidates_paths)) if candidates_paths else _default_candidates()
    if not paths:
      raise UIError(
        f"No URLs picked yet, and no input found. Put Garg et al.'s *_firstcdx.gz "
        f"files (in {GARG_DIR}/), or a candidates.csv, in {INPUT_DIR} -- or point "
        f"--candidates at a file or folder."
      )
    sample_from_files(output_dir, paths, show_progress=False)

  urls_glob = str(table_dir(output_dir, "urls") / "*.parquet")
  con = duckdb.connect()
  try:
    df = con.execute(f"SELECT DISTINCT url_id, original_url FROM read_parquet('{urls_glob}')").fetchdf()
  except duckdb.IOException:
    raise UIError("No URLs found — run `pluto.py sample` first.")
  if limit:
    df = df.head(limit)
  if df.empty:
    raise UIError("No URLs found — run `pluto.py sample` first.")

  only = None
  if only_witnesses:
    only = [n if n == "live_web" or n.startswith("archive:") else f"archive:{n}"
        for n in only_witnesses.split(",")]

  all_witnesses = [live_witness()] + archive_witnesses()
  if only:
    all_witnesses = [w for w in all_witnesses if w.name in only]
  archive_count = sum(1 for w in all_witnesses if w.name != "live_web")

  UI.line()
  UI.log("info", "Initialising Pluto...")
  UI.tree([
    f"URLs: {len(df):,}",
    f"Witnesses: {len(all_witnesses)} (live_web + {archive_count} {_plural(archive_count, 'archive')})"
    f"{f' -- shard {shard}/{num_shards}' if num_shards > 1 else ''}"
    f"{', stop-early' if stop_early else ''}, workers={workers or 'auto'}",
    f"Logs: {Path(output_dir) / 'pluto.log'} (pass -v to also stream them here)",
  ])
  UI.line()
  UI.log("info", "Running Pluto...")
  summary = run_witnesses(
    list(zip(df["url_id"], df["original_url"])),
    output_dir=output_dir, only_witnesses=only,
    max_workers=workers, shard=shard, num_shards=num_shards,
    stop_early=stop_early, stop_early_threshold=stop_early_threshold,
    report_changes=report_changes,
  )
  UI.line()
  UI.log("ok", "Run complete!")
  UI.tree([f"{k.replace('_', ' ').title()}: {v:,}" for k, v in summary.items()])
  UI.line()


@cli.command(short_help="Classify every URL's state (S0-S4) from its collected evidence.")
@click.option("--corroboration-threshold", type=int, default=DEFAULT_CORROBORATION_THRESHOLD,
       help="Independent witnesses required to score a URL S3.")
@click.option("--no-summarize", is_flag=True, default=False,
       help="Skip the automatic summarize step (stage 4) that normally runs after classifying.")
@click.pass_context
def classify(ctx, corroboration_threshold: int, no_summarize: bool):
  output_dir = ctx.obj["output_dir"]
  UI.line()
  UI.log("info", "Classifying observed URLs...")
  established_by_archive = established_years()
  n = classify_all(output_dir, corroboration_threshold=corroboration_threshold,
           established_by_archive=established_by_archive)
  UI.log("ok", "Classify complete!")
  details = [
    f"Classified: {n:,} {_plural(n, 'URL')} ({len(established_by_archive):,} "
    f"{_plural(len(established_by_archive), 'archive')} with a known establishment date)",
    f"Events: {table_dir(output_dir, 'events')}",
  ]
  if not no_summarize:
    path, n_rows = summarize_urls(output_dir, out_path=None, established_by_archive=established_by_archive)
    details.append(f"Summary: {n_rows:,} {_plural(n_rows, 'row')} -> {path}")
  UI.tree(details)
  UI.line()


@cli.command(short_help="Rebuild summary.parquet from existing events, without reclassifying.")
@click.option("--out", type=click.Path(path_type=Path), default=None,
       help="Output path (default: <output-dir>/summary.parquet).")
@click.pass_context
def summarize(ctx, out: Path | None):
  UI.line()
  UI.log("info", "Summarizing...")
  path, n = summarize_urls(ctx.obj["output_dir"], out_path=out, established_by_archive=established_years())
  UI.log("ok", "Summarize complete!")
  UI.tree([f"Wrote {n:,} {_plural(n, 'row')} -> {path}"])
  UI.line()


@cli.command("list-archives", short_help="List the archives loaded from the registry.")
@click.pass_context
def archives(ctx):
  witnesses = archive_witnesses()
  UI.line()
  UI.log("info", f"{len(witnesses)} {_plural(len(witnesses), 'archive')} loaded from registry/")
  width = max((len(wc.extra["registry_entry"]["id"]) for wc in witnesses), default=0)
  UI.tree([
    f"{wc.extra['registry_entry']['id']:<{width}}  {wc.extra['registry_entry']['name']}"
    for wc in witnesses
  ])
  UI.line()


@cli.command(short_help="Copy every table to a single clean Parquet file per table.")
@click.option("--out", type=click.Path(path_type=Path), default=None,
       help="Output directory (default: <output-dir>/export).")
@click.pass_context
def export(ctx, out: Path | None):
  output_dir = ctx.obj["output_dir"]
  out_dir = out or (Path(output_dir) / "export")
  out_dir.mkdir(parents=True, exist_ok=True)
  con = duckdb.connect()

  UI.line()
  UI.log("info", f"Exporting tables to {out_dir}...")
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
    import shutil

    shutil.copy2(summary_src, out_dir / "summary.parquet")
    rows.append("summary.parquet: copied")

  UI.log("ok", "Export complete!")
  UI.tree(rows)
  UI.line()


@cli.command("fetch-archives", short_help="Download the latest archive registry from web-archive.txt.")
@click.option("--source", type=click.Path(exists=True, path_type=Path), default=None,
       help="Existing local checkout of web-archive.txt's registry/ dir, instead of cloning.")
def fetch_registry(source: Path | None):
  UI.line()
  UI.log("info", "Fetching web archive registry from web-archive.txt...")
  n = import_registry(source=source)
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


@cli.command(short_help="Show row counts per table, e.g. to check progress on a long run.")
@click.pass_context
def status(ctx):
  output_dir = ctx.obj["output_dir"]
  con = duckdb.connect()

  def count(table: str) -> int:
    try:
      glob = str(table_dir(output_dir, table) / "*.parquet")
      return con.execute(f"SELECT count(*) FROM read_parquet('{glob}')").fetchone()[0]
    except duckdb.IOException:
      return 0

  UI.line()
  UI.log("info", f"Status ({output_dir})")
  rows = [f"{table}: {count(table):,} {_plural(count(table), 'row')}" for table in ["urls", "observations", "captures"]]

  events_glob = str(table_dir(output_dir, "events") / "*.parquet")
  try:
    breakdown = con.execute(
      f"SELECT event_type, count(*) AS n FROM read_parquet('{events_glob}') "
      "GROUP BY event_type ORDER BY n DESC"
    ).fetchall()
  except duckdb.IOException:
    breakdown = []
  n_events = sum(n for _, n in breakdown)
  events_row = f"events: {n_events:,} {_plural(n_events, 'row')}"
  if breakdown:
    events_row += " (" + ", ".join(f"{event_type}: {n:,}" for event_type, n in breakdown) + ")"
  rows.append(events_row)

  from collections import Counter

  ckpt_dbs = [Path(output_dir) / "checkpoints.db"] if (Path(output_dir) / "checkpoints.db").exists() \
    else sorted((Path(output_dir) / "checkpoints").glob("shard-*.db"))
  totals = Counter()
  for db in ckpt_dbs:
    conn = sqlite3.connect(db)
    for state, n in conn.execute("SELECT state, count(*) FROM checkpoints GROUP BY state"):
      totals[state] += n
    conn.close()
  if totals:
    ckpt_row = f"checkpoints ({len(ckpt_dbs)} {_plural(len(ckpt_dbs), 'shard')}): " + \
      ", ".join(f"{state}: {n:,}" for state, n in totals.items())
    rows.append(ckpt_row)

  UI.tree(rows)
  UI.line()


if __name__ == "__main__":
  cli()