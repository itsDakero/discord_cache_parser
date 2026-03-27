#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import html
import importlib.util
import io
import json
import mimetypes
import os
import pathlib
import re
import struct
import sys
import types
import typing
import urllib.parse
import zlib
from collections import defaultdict
from dataclasses import asdict, dataclass, field

try:
    import brotli
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    brotli = None

__version__ = "0.1.0"


MSG_TYPES = {
    0: "DEFAULT",
    1: "RECIPIENT_ADD",
    2: "RECIPIENT_REMOVE",
    3: "CALL",
    4: "CHANNEL_NAME_CHANGE",
    5: "CHANNEL_ICON_CHANGE",
    6: "CHANNEL_PINNED_MESSAGE",
    7: "USER_JOIN",
    8: "GUILD_BOOST",
    9: "GUILD_BOOST_TIER_1",
    10: "GUILD_BOOST_TIER_2",
    11: "GUILD_BOOST_TIER_3",
    12: "CHANNEL_FOLLOW_ADD",
    14: "GUILD_DISCOVERY_DISQUALIFIED",
    15: "GUILD_DISCOVERY_REQUALIFIED",
    16: "GUILD_DISCOVERY_GRACE_PERIOD_INITIAL_WARNING",
    17: "GUILD_DISCOVERY_GRACE_PERIOD_FINAL_WARNING",
    18: "THREAD_CREATED",
    19: "REPLY",
    20: "CHAT_INPUT_COMMAND",
    21: "THREAD_STARTER_MESSAGE",
    22: "GUILD_INVITE_REMINDER",
    23: "CONTEXT_MENU_COMMAND",
    24: "AUTO_MODERATION_ACTION",
    25: "ROLE_SUBSCRIPTION_PURCHASE",
    26: "INTERACTION_PREMIUM_UPSELL",
    27: "STAGE_START",
    28: "STAGE_END",
    29: "STAGE_SPEAKER",
    31: "STAGE_TOPIC",
    32: "GUILD_APPLICATION_PREMIUM_SUBSCRIPTION",
    36: "GUILD_INCIDENT_ALERT_MODE_ENABLED",
    37: "GUILD_INCIDENT_ALERT_MODE_DISABLED",
    38: "GUILD_INCIDENT_REPORT_RAID",
    39: "GUILD_INCIDENT_REPORT_FALSE_ALARM",
    44: "PURCHASE_NOTIFICATION",
    46: "POLL_RESULT",
}


_CHROME_EPOCH = dt.datetime(1601, 1, 1)
_SIMPLE_EOF_SIZE = 24
_SIMPLE_FILE_PATTERN = re.compile(r"^[0-9a-f]{16}_0$")
_OKHTTP_FILE_PATTERN = re.compile(r"^[0-9a-f]{16}\.[01]$")


def load_chromium_cache_class_guesser():
    try:
        from ccl_chromium_reader.ccl_chromium_cache import guess_cache_class

        return guess_cache_class
    except ModuleNotFoundError:
        module_path_candidates = []
        current_dir = pathlib.Path(__file__).resolve().parent
        module_path_candidates.append(
            current_dir / "vendor" / "ccl_chromium_reader" / "ccl_chromium_reader" / "ccl_chromium_cache.py"
        )
        for path_entry in map(pathlib.Path, sys.path):
            module_path_candidates.append(path_entry / "ccl_chromium_reader" / "ccl_chromium_cache.py")

        for module_path in module_path_candidates:
            if not module_path.exists():
                continue
            spec = importlib.util.spec_from_file_location("embedded_chromium_cache", module_path)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return getattr(module, "guess_cache_class", None)
        return None


chromium_cache_class_guesser = load_chromium_cache_class_guesser()


class BinaryReader:
    def __init__(self, stream: typing.BinaryIO):
        self._stream = stream

    @classmethod
    def from_bytes(cls, buffer: bytes) -> "BinaryReader":
        return cls(io.BytesIO(buffer))

    def close(self) -> None:
        self._stream.close()

    def tell(self) -> int:
        return self._stream.tell()

    def seek(self, offset: int, whence: int) -> int:
        return self._stream.seek(offset, whence)

    def read_raw(self, count: int) -> bytes:
        data = self._stream.read(count)
        if len(data) != count:
            raise ValueError(f"Unable to read {count} byte(s)")
        return data

    def read_uint16(self) -> int:
        return struct.unpack("<H", self.read_raw(2))[0]

    def read_uint32(self) -> int:
        return struct.unpack("<I", self.read_raw(4))[0]

    def read_uint64(self) -> int:
        return struct.unpack("<Q", self.read_raw(8))[0]

    def read_int32(self) -> int:
        return struct.unpack("<i", self.read_raw(4))[0]

    def read_datetime(self) -> dt.datetime:
        return _CHROME_EPOCH + dt.timedelta(microseconds=self.read_uint64())

    @property
    def is_eof(self) -> bool:
        marker = self._stream.read(1)
        if not marker:
            return True
        self._stream.seek(-1, os.SEEK_CUR)
        return False

    def __enter__(self) -> "BinaryReader":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class CachedMetadata:
    def __init__(
        self,
        header_declarations: set[str],
        header_attributes: dict[str, list[str]],
        request_time: dt.datetime,
        response_time: dt.datetime,
    ):
        self._declarations = header_declarations.copy()
        self._attributes = types.MappingProxyType(header_attributes.copy())
        self._request_time = request_time
        self._response_time = response_time

    @property
    def request_time(self) -> dt.datetime:
        return self._request_time

    @property
    def response_time(self) -> dt.datetime:
        return self._response_time

    def get_attribute(self, attribute: str) -> list[str]:
        return self._attributes.get(attribute.lower()) or []

    @classmethod
    def from_buffer(cls, buffer: bytes) -> "CachedMetadata":
        reader = BinaryReader.from_bytes(buffer)
        total_length = reader.read_uint32()
        if total_length != len(buffer) - 4:
            raise ValueError("Metadata buffer size mismatch")

        def align() -> None:
            alignment = reader.tell() % 4
            if alignment:
                reader.read_raw(4 - alignment)

        flags = reader.read_uint32()
        has_extra_flags = bool(flags & (1 << 31))
        extra_flags = reader.read_uint32() if has_extra_flags else 0

        request_time = reader.read_datetime()
        response_time = reader.read_datetime()

        if extra_flags & (1 << 2):
            _ = reader.read_datetime()

        http_header_length = reader.read_uint32()
        http_header_raw = reader.read_raw(http_header_length)

        header_attributes: dict[str, list[str]] = {}
        header_declarations = set()
        for header_entry in http_header_raw.split(b"\x00"):
            if not header_entry:
                continue
            parsed_entry = header_entry.decode("latin-1").split(":", 1)
            if len(parsed_entry) == 1:
                header_declarations.add(parsed_entry[0])
            else:
                key = parsed_entry[0].lower()
                header_attributes.setdefault(key, []).append(parsed_entry[1].strip())

        if flags & (1 << 8):
            align()
            cert_count = reader.read_uint32()
            for _ in range(cert_count):
                align()
                cert_length = reader.read_uint32()
                reader.read_raw(cert_length)

        if flags & (1 << 10):
            align()
            reader.read_uint32()

        if flags & (1 << 9):
            align()
            reader.read_int32()

        if flags & (1 << 16):
            align()
            reader.read_int32()

        return cls(header_declarations, header_attributes, request_time, response_time)


class SimpleCacheEOF:
    MAGIC = 0xF4FA6F45970D41D8

    def __init__(self, flags: int, data_crc: int, stream_size: int):
        self.flags = flags
        self.data_crc = data_crc
        self.stream_size = stream_size

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "SimpleCacheEOF":
        magic = reader.read_uint64()
        if magic != cls.MAGIC:
            raise ValueError("Invalid simple cache EOF marker")
        flags = reader.read_uint32()
        data_crc = reader.read_uint32()
        stream_size = reader.read_uint32()
        return cls(flags, data_crc, stream_size)

    @property
    def has_key_sha256(self) -> bool:
        return bool(self.flags & 2)


class SimpleCacheHeader:
    MAGIC = 0xFCFB6D1BA7725C30

    def __init__(self, version: int, key_length: int, key_hash: int):
        self.version = version
        self.key_length = key_length
        self.key_hash = key_hash

    @classmethod
    def from_reader(cls, reader: BinaryReader) -> "SimpleCacheHeader":
        magic = reader.read_uint64()
        if magic != cls.MAGIC:
            raise ValueError("Invalid simple cache header")
        version = reader.read_uint32()
        key_length = reader.read_uint32()
        key_hash = reader.read_uint32()
        reader.read_uint32()
        return cls(version, key_length, key_hash)


class SimpleCacheFile:
    def __init__(self, cache_file: pathlib.Path):
        self.path = cache_file
        self._reader = BinaryReader(cache_file.open("rb"))
        self._header = SimpleCacheHeader.from_reader(self._reader)
        self.key = self._reader.read_raw(self._header.key_length).decode("latin-1")

        if self._reader.is_eof:
            self._has_data = False
            self._stream_0_eof = None
            self._stream_1_start_offset = 0
            self._stream_1_length = 0
            self._stream_0_start_offset_negative = 0
            return

        self._has_data = True
        self._reader.seek(-_SIMPLE_EOF_SIZE, os.SEEK_END)
        self._stream_0_eof = SimpleCacheEOF.from_reader(self._reader)
        self._stream_0_start_offset_negative = -_SIMPLE_EOF_SIZE - self._stream_0_eof.stream_size
        if self._stream_0_eof.has_key_sha256:
            self._stream_0_start_offset_negative -= 32

        self._reader.seek(-(_SIMPLE_EOF_SIZE * 2) - self._stream_0_eof.stream_size, os.SEEK_END)
        if self._stream_0_eof.has_key_sha256:
            self._reader.seek(-32, os.SEEK_CUR)
        stream_1_end_offset = self._reader.tell()
        _ = SimpleCacheEOF.from_reader(self._reader)
        self._stream_1_start_offset = _SIMPLE_EOF_SIZE + self._header.key_length
        self._stream_1_length = stream_1_end_offset - self._stream_1_start_offset

    def get_stream_0(self) -> bytes:
        if not self._has_data:
            return b""
        self._reader.seek(self._stream_0_start_offset_negative, os.SEEK_END)
        return self._reader.read_raw(self._stream_0_eof.stream_size)

    def get_stream_1(self) -> bytes:
        if not self._has_data:
            return b""
        self._reader.seek(self._stream_1_start_offset, os.SEEK_SET)
        return self._reader.read_raw(self._stream_1_length)

    def close(self) -> None:
        self._reader.close()

    def __enter__(self) -> "SimpleCacheFile":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class ChromiumSimpleFileCache:
    def __init__(self, cache_dir: pathlib.Path):
        self.cache_dir = cache_dir
        self._file_lookup = self._build_keys()

    def _build_keys(self) -> dict[str, list[pathlib.Path]]:
        lookup: dict[str, list[pathlib.Path]] = {}
        for cache_file in self.cache_dir.iterdir():
            if cache_file.is_file() and _SIMPLE_FILE_PATTERN.match(cache_file.name):
                with SimpleCacheFile(cache_file) as cache_entry:
                    lookup.setdefault(cache_entry.key, []).append(cache_file)
        return lookup

    def cache_keys(self) -> typing.Iterable[str]:
        yield from self._file_lookup.keys()

    def get_metadata(self, key: str) -> list[CachedMetadata | None]:
        results = []
        for file in self._file_lookup[key]:
            with SimpleCacheFile(file) as cache_entry:
                buffer = cache_entry.get_stream_0()
                results.append(CachedMetadata.from_buffer(buffer) if buffer else None)
        return results

    def get_cachefile(self, key: str) -> list[bytes]:
        results = []
        for file in self._file_lookup[key]:
            with SimpleCacheFile(file) as cache_entry:
                results.append(cache_entry.get_stream_1())
        return results

    def __enter__(self) -> "ChromiumSimpleFileCache":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        return None


@dataclass(frozen=True)
class AttachmentFile:
    sha256: str
    relative_path: str
    size: int


@dataclass(frozen=True)
class CachedAttachment:
    attachment_id: str
    channel_id: str
    original_name: str
    files: list[AttachmentFile]


@dataclass(frozen=True)
class CachedAvatar:
    avatar_key: str
    avatar_id: str
    original_name: str
    files: list[AttachmentFile]


@dataclass(frozen=True)
class Attachment:
    attachment_id: str
    filename: str
    url: str
    proxy_url: str | None
    content_type: str | None
    cached_files: list[AttachmentFile] = field(default_factory=list)


@dataclass(frozen=True, eq=True)
class Author:
    author_id: str
    username: str
    global_name: str | None
    avatar: str | None


@dataclass
class Message:
    msg_id: str
    channel_id: str
    msg_type: int
    content: str
    timestamp: str
    edited_timestamp: str | None
    author: Author
    attachments: list[Attachment]


@dataclass
class Channel:
    channel_id: str
    messages: list[Message] = field(default_factory=list)
    authors: set[Author] = field(default_factory=set)


def get_msg_type(value: int) -> str:
    return f"{MSG_TYPES.get(value, 'UNKNOWN')} ({value})"


def inflate_bytes(payload: bytes, encoding: str | None) -> bytes:
    if not encoding:
        return payload
    encoding = encoding.strip().lower()
    if encoding == "gzip":
        return gzip.decompress(payload)
    if encoding == "br":
        if brotli is None:
            raise RuntimeError("Brotli-compressed cache entry found but 'Brotli' is not installed.")
        return brotli.decompress(payload)
    if encoding == "deflate":
        return zlib.decompress(payload, -zlib.MAX_WBITS)
    return payload


def parse_okhttp_meta_file(meta_file_path: pathlib.Path) -> tuple[str, dict[str, str | None]]:
    result: dict[str, str | None] = {}
    with meta_file_path.open("rt", encoding="utf-8") as handle:
        url = handle.readline().strip()
        for line in handle:
            line = line.strip()
            key, sep, value = line.partition(": ")
            result[key] = value if sep else None
    return url, result


def yield_okhttp_objects(cache_dir: pathlib.Path) -> typing.Iterable[tuple[str, dict[str, str | None], pathlib.Path]]:
    seen = set()
    for child in cache_dir.iterdir():
        if child.name == "journal" or child.stat().st_size == 0:
            continue
        stem = child.stem
        if stem in seen:
            continue
        meta_file = cache_dir / f"{stem}.0"
        content_file = cache_dir / f"{stem}.1"
        if not meta_file.exists() or not content_file.exists():
            continue
        seen.add(stem)
        url, meta = parse_okhttp_meta_file(meta_file)
        yield url, meta, content_file


def detect_cache_type(cache_dir: pathlib.Path) -> str:
    names = {child.name for child in cache_dir.iterdir()}
    if "journal" in names or any(_OKHTTP_FILE_PATTERN.match(name) for name in names):
        return "okhttp"
    if "index-dir" in names or any(_SIMPLE_FILE_PATTERN.match(name) for name in names):
        return "chromium-simple"
    if "data_0" in names or any(name.startswith("f_") for name in names):
        return "chromium-block"
    return "unknown"


def ensure_empty_output_dir(output_dir: pathlib.Path) -> None:
    if output_dir.exists():
        raise ValueError(f"Output directory already exists: {output_dir}")
    output_dir.mkdir(parents=True)
    (output_dir / "attachments").mkdir()
    (output_dir / "avatars").mkdir()


def write_blob(base_dir: pathlib.Path, subdir: str, digest: str, preferred_name: str, payload: bytes) -> AttachmentFile:
    suffix = pathlib.Path(preferred_name).suffix
    filename = f"{digest}{suffix}" if suffix else digest
    relative_path = pathlib.Path(subdir) / filename
    destination = base_dir / relative_path
    if not destination.exists():
        destination.write_bytes(payload)
    return AttachmentFile(sha256=digest, relative_path=relative_path.as_posix(), size=len(payload))


def dedupe_files(files: list[AttachmentFile]) -> list[AttachmentFile]:
    unique: dict[str, AttachmentFile] = {}
    for file_ref in files:
        unique[file_ref.sha256] = file_ref
    return list(unique.values())


def process_chromium_simple_cache(
    cache_dir: pathlib.Path,
    output_dir: pathlib.Path,
) -> tuple[set[str], dict[str, list[CachedAvatar]], dict[str, list[CachedAttachment]]]:
    deduplicated_messages: set[str] = set()
    avatars: dict[str, list[CachedAvatar]] = defaultdict(list)
    attachments: dict[str, list[CachedAttachment]] = defaultdict(list)

    with ChromiumSimpleFileCache(cache_dir) as cache:
        for key in cache.cache_keys():
            parsed_url = urllib.parse.urlparse(key)
            metas = cache.get_metadata(key)
            datas = cache.get_cachefile(key)

            if parsed_url.path.endswith("/messages"):
                for meta, data in zip(metas, datas):
                    if not data:
                        continue
                    encoding = meta.get_attribute("content-encoding")[0] if meta and meta.get_attribute("content-encoding") else ""
                    inflated = inflate_bytes(data, encoding)
                    payload = json.loads(inflated)
                    if isinstance(payload, list):
                        for message in payload:
                            deduplicated_messages.add(json.dumps(message, sort_keys=True))
                continue

            if parsed_url.path.startswith("/avatars/") and "discord" in parsed_url.netloc:
                parts = parsed_url.path.split("/")
                if len(parts) < 4:
                    continue
                avatar_id = parts[2]
                avatar_name = parts[3]
                files: list[AttachmentFile] = []
                for meta, data in zip(metas, datas):
                    if not data:
                        continue
                    encoding = meta.get_attribute("content-encoding")[0] if meta and meta.get_attribute("content-encoding") else ""
                    inflated = inflate_bytes(data, encoding)
                    digest = hashlib.sha256(inflated).hexdigest()
                    files.append(write_blob(output_dir, "avatars", digest, avatar_name, inflated))
                if files:
                    avatar_key = pathlib.Path(avatar_name).stem
                    avatars[avatar_key].append(CachedAvatar(avatar_key, avatar_id, avatar_name, dedupe_files(files)))
                continue

            if parsed_url.path.startswith("/attachments/") and "discord" in parsed_url.netloc:
                parts = parsed_url.path.split("/")
                if len(parts) < 5:
                    continue
                channel_id = parts[2]
                attachment_id = parts[3]
                original_name = parts[4]
                files = []
                for meta, data in zip(metas, datas):
                    if not data:
                        continue
                    encoding = meta.get_attribute("content-encoding")[0] if meta and meta.get_attribute("content-encoding") else ""
                    inflated = inflate_bytes(data, encoding)
                    digest = hashlib.sha256(inflated).hexdigest()
                    files.append(write_blob(output_dir, "attachments", digest, original_name, inflated))
                if files:
                    attachments[attachment_id].append(
                        CachedAttachment(attachment_id, channel_id, original_name, dedupe_files(files))
                    )

    return deduplicated_messages, avatars, attachments


def process_okhttp_cache(
    cache_dir: pathlib.Path,
    output_dir: pathlib.Path,
) -> tuple[set[str], dict[str, list[CachedAvatar]], dict[str, list[CachedAttachment]]]:
    deduplicated_messages: set[str] = set()
    avatars: dict[str, list[CachedAvatar]] = defaultdict(list)
    attachments: dict[str, list[CachedAttachment]] = defaultdict(list)

    for url, meta, content_file in yield_okhttp_objects(cache_dir):
        parsed_url = urllib.parse.urlparse(url)
        if "discord" not in parsed_url.netloc:
            continue
        payload = content_file.read_bytes()
        encoding = meta.get("Content-Encoding") or meta.get("content-encoding") or ""
        payload = inflate_bytes(payload, typing.cast(str, encoding))

        if parsed_url.path.endswith("/messages"):
            parsed_payload = json.loads(payload)
            if isinstance(parsed_payload, list):
                for message in parsed_payload:
                    deduplicated_messages.add(json.dumps(message, sort_keys=True))
            continue

        if parsed_url.path.startswith("/avatars/"):
            parts = parsed_url.path.split("/")
            if len(parts) < 4:
                continue
            avatar_id = parts[2]
            avatar_name = parts[3]
            digest = hashlib.sha256(payload).hexdigest()
            file_ref = write_blob(output_dir, "avatars", digest, avatar_name, payload)
            avatar_key = pathlib.Path(avatar_name).stem
            avatars[avatar_key].append(CachedAvatar(avatar_key, avatar_id, avatar_name, [file_ref]))
            continue

        if parsed_url.path.startswith("/attachments/"):
            parts = parsed_url.path.split("/")
            if len(parts) < 5:
                continue
            channel_id = parts[2]
            attachment_id = parts[3]
            original_name = parts[4]
            digest = hashlib.sha256(payload).hexdigest()
            file_ref = write_blob(output_dir, "attachments", digest, original_name, payload)
            attachments[attachment_id].append(CachedAttachment(attachment_id, channel_id, original_name, [file_ref]))

    return deduplicated_messages, avatars, attachments


def process_blockfile_cache(
    cache_dir: pathlib.Path,
    output_dir: pathlib.Path,
) -> tuple[set[str], dict[str, list[CachedAvatar]], dict[str, list[CachedAttachment]]]:
    deduplicated_messages: set[str] = set()
    avatars: dict[str, list[CachedAvatar]] = defaultdict(list)
    attachments: dict[str, list[CachedAttachment]] = defaultdict(list)
    cache_type = chromium_cache_class_guesser(cache_dir)
    if cache_type is None:
        raise ValueError(f"Could not detect Chromium cache type in {cache_dir}")

    with cache_type(cache_dir) as cache:
        for cache_key in cache.cache_keys():
            parsed_url = urllib.parse.urlparse(cache_key.url)
            metas = cache.get_metadata(cache_key)
            datas = cache.get_cachefile(cache_key)

            if parsed_url.path.endswith("/messages"):
                for meta, data in zip(metas, datas):
                    if not data:
                        continue
                    encoding = (meta.get_attribute("content-encoding") or [""])[0] if meta else ""
                    inflated = inflate_bytes(data, encoding)
                    payload = json.loads(inflated)
                    if isinstance(payload, list):
                        for message in payload:
                            deduplicated_messages.add(json.dumps(message, sort_keys=True))
                continue

            if parsed_url.path.startswith("/avatars/") and "discord" in parsed_url.netloc:
                parts = parsed_url.path.split("/")
                if len(parts) < 4:
                    continue
                avatar_id = parts[2]
                avatar_name = parts[3]
                files = []
                for meta, data in zip(metas, datas):
                    if not data:
                        continue
                    encoding = (meta.get_attribute("content-encoding") or [""])[0] if meta else ""
                    inflated = inflate_bytes(data, encoding)
                    digest = hashlib.sha256(inflated).hexdigest()
                    files.append(write_blob(output_dir, "avatars", digest, avatar_name, inflated))
                if files:
                    avatar_key = pathlib.Path(avatar_name).stem
                    avatars[avatar_key].append(CachedAvatar(avatar_key, avatar_id, avatar_name, dedupe_files(files)))
                continue

            if parsed_url.path.startswith("/attachments/") and "discord" in parsed_url.netloc:
                parts = parsed_url.path.split("/")
                if len(parts) < 5:
                    continue
                channel_id = parts[2]
                attachment_id = parts[3]
                original_name = parts[4]
                files = []
                for meta, data in zip(metas, datas):
                    if not data:
                        continue
                    encoding = (meta.get_attribute("content-encoding") or [""])[0] if meta else ""
                    inflated = inflate_bytes(data, encoding)
                    digest = hashlib.sha256(inflated).hexdigest()
                    files.append(write_blob(output_dir, "attachments", digest, original_name, inflated))
                if files:
                    attachments[attachment_id].append(
                        CachedAttachment(attachment_id, channel_id, original_name, dedupe_files(files))
                    )

    return deduplicated_messages, avatars, attachments


def build_channels(messages_json: set[str], attachments_by_id: dict[str, list[CachedAttachment]]) -> dict[str, Channel]:
    channels: dict[str, Channel] = {}
    seen_messages = set()

    for raw_message in messages_json:
        msg = json.loads(raw_message)
        channel_id = msg["channel_id"]
        author_json = msg["author"]
        author = Author(
            author_id=author_json["id"],
            username=author_json["username"],
            global_name=author_json.get("global_name"),
            avatar=author_json.get("avatar"),
        )

        attachments = []
        for attachment_json in msg.get("attachments") or []:
            attachment_id = attachment_json["id"]
            cached_files: list[AttachmentFile] = []
            for cached_attachment in attachments_by_id.get(attachment_id, []):
                cached_files.extend(cached_attachment.files)
            attachments.append(
                Attachment(
                    attachment_id=attachment_id,
                    filename=attachment_json["filename"],
                    url=attachment_json["url"],
                    proxy_url=attachment_json.get("proxy_url"),
                    content_type=attachment_json.get("content_type"),
                    cached_files=dedupe_files(cached_files),
                )
            )

        message = Message(
            msg_id=msg["id"],
            channel_id=channel_id,
            msg_type=msg["type"],
            content=msg.get("content", ""),
            timestamp=msg["timestamp"],
            edited_timestamp=msg.get("edited_timestamp"),
            author=author,
            attachments=attachments,
        )

        unique_key = (
            message.msg_id,
            message.msg_type,
            message.timestamp,
            message.content,
            tuple(att.attachment_id for att in message.attachments),
        )
        if unique_key in seen_messages:
            continue
        seen_messages.add(unique_key)

        channels.setdefault(channel_id, Channel(channel_id))
        channels[channel_id].messages.append(message)
        channels[channel_id].authors.add(author)

    for channel in channels.values():
        channel.messages.sort(key=lambda item: item.timestamp)

    return channels


def collect_used_ids(channels: dict[str, Channel]) -> tuple[set[str], set[str]]:
    used_attachments = set()
    used_avatars = set()
    for channel in channels.values():
        for message in channel.messages:
            for attachment in message.attachments:
                used_attachments.add(attachment.attachment_id)
            if message.author.avatar:
                used_avatars.add(message.author.avatar)
    return used_attachments, used_avatars


def message_to_dict(message: Message) -> dict[str, typing.Any]:
    return {
        "msg_id": message.msg_id,
        "channel_id": message.channel_id,
        "msg_type": get_msg_type(message.msg_type),
        "content": message.content,
        "timestamp": message.timestamp,
        "edited_timestamp": message.edited_timestamp,
        "author": asdict(message.author),
        "attachments": [asdict(attachment) for attachment in message.attachments],
    }


def serialise_channels(channels: dict[str, Channel], avatars_by_key: dict[str, list[CachedAvatar]]) -> list[dict[str, typing.Any]]:
    payload = []
    for channel in sorted(channels.values(), key=lambda item: item.channel_id):
        authors = []
        for author in sorted(channel.authors, key=lambda item: (item.username.lower(), item.author_id)):
            avatar_files = []
            if author.avatar:
                for cached_avatar in avatars_by_key.get(author.avatar, []):
                    avatar_files.extend(cached_avatar.files)
            authors.append(
                {
                    "author_id": author.author_id,
                    "username": author.username,
                    "global_name": author.global_name,
                    "avatar_key": author.avatar,
                    "avatar_files": [asdict(item) for item in dedupe_files(avatar_files)],
                }
            )
        payload.append(
            {
                "channel_id": channel.channel_id,
                "message_count": len(channel.messages),
                "authors": authors,
                "messages": [message_to_dict(message) for message in channel.messages],
            }
        )
    return payload


def render_links(file_refs: list[AttachmentFile]) -> str:
    if not file_refs:
        return "<em>None</em>"
    links = []
    for file_ref in file_refs:
        rel = html.escape(file_ref.relative_path)
        links.append(f'<a href="{rel}">{rel}</a> ({file_ref.size} bytes)')
    return "<br>".join(links)


def render_html_report(
    output_dir: pathlib.Path,
    channels: dict[str, Channel],
    avatars_by_key: dict[str, list[CachedAvatar]],
    attachments_by_id: dict[str, list[CachedAttachment]],
) -> None:
    used_attachments, used_avatars = collect_used_ids(channels)
    orphan_attachments = [
        item
        for attachment_id, items in sorted(attachments_by_id.items())
        if attachment_id not in used_attachments
        for item in items
    ]
    orphan_avatars = [
        item
        for avatar_key, items in sorted(avatars_by_key.items())
        if avatar_key not in used_avatars
        for item in items
    ]

    sections = []
    channel_nav = []
    for channel in sorted(channels.values(), key=lambda item: len(item.messages), reverse=True):
        channel_nav.append(
            f'<li><a href="#channel-{html.escape(channel.channel_id)}">{html.escape(channel.channel_id)}</a> '
            f'({len(channel.messages)} messages)</li>'
        )

        author_rows = []
        for author in sorted(channel.authors, key=lambda item: (item.username.lower(), item.author_id)):
            avatar_files = []
            if author.avatar:
                for cached_avatar in avatars_by_key.get(author.avatar, []):
                    avatar_files.extend(cached_avatar.files)
            author_rows.append(
                "<tr>"
                f"<td>{html.escape(author.author_id)}</td>"
                f"<td>{html.escape(author.username)}</td>"
                f"<td>{html.escape(author.global_name or '')}</td>"
                f"<td>{render_links(dedupe_files(avatar_files))}</td>"
                "</tr>"
            )

        message_rows = []
        for message in channel.messages:
            attachment_html = []
            for attachment in message.attachments:
                attachment_html.append(
                    "<div class='attachment'>"
                    f"<strong>{html.escape(attachment.filename)}</strong><br>"
                    f"ID: {html.escape(attachment.attachment_id)}<br>"
                    f"Type: {html.escape(attachment.content_type or '')}<br>"
                    f"URL: {html.escape(attachment.url)}<br>"
                    f"Proxy: {html.escape(attachment.proxy_url or '')}<br>"
                    f"Cached files:<br>{render_links(attachment.cached_files)}"
                    "</div>"
                )
            message_rows.append(
                "<tr>"
                f"<td>{html.escape(message.msg_id)}</td>"
                f"<td>{html.escape(get_msg_type(message.msg_type))}</td>"
                f"<td>{html.escape(message.timestamp)}</td>"
                f"<td>{html.escape(message.edited_timestamp or '')}</td>"
                f"<td><pre>{html.escape(message.content)}</pre></td>"
                f"<td>{html.escape(message.author.username)} ({html.escape(message.author.author_id)})</td>"
                f"<td>{''.join(attachment_html) or '<em>None</em>'}</td>"
                "</tr>"
            )

        sections.append(
            f"<section id='channel-{html.escape(channel.channel_id)}'>"
            f"<h2>Channel {html.escape(channel.channel_id)}</h2>"
            "<h3>Participants</h3>"
            "<table><thead><tr><th>ID</th><th>Username</th><th>Global name</th><th>Avatars</th></tr></thead>"
            f"<tbody>{''.join(author_rows)}</tbody></table>"
            "<h3>Messages</h3>"
            "<table><thead><tr><th>ID</th><th>Type</th><th>Time</th><th>Edited</th><th>Content</th><th>Author</th><th>Attachments</th></tr></thead>"
            f"<tbody>{''.join(message_rows)}</tbody></table>"
            "</section>"
        )

    orphan_attachment_rows = []
    for attachment in orphan_attachments:
        orphan_attachment_rows.append(
            "<tr>"
            f"<td>{html.escape(attachment.channel_id)}</td>"
            f"<td>{html.escape(attachment.attachment_id)}</td>"
            f"<td>{html.escape(attachment.original_name)}</td>"
            f"<td>{render_links(attachment.files)}</td>"
            "</tr>"
        )

    orphan_avatar_rows = []
    for avatar in orphan_avatars:
        orphan_avatar_rows.append(
            "<tr>"
            f"<td>{html.escape(avatar.avatar_id)}</td>"
            f"<td>{html.escape(avatar.original_name)}</td>"
            f"<td>{render_links(avatar.files)}</td>"
            "</tr>"
        )

    report = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Discord Cache Parser Report</title>
  <style>
    :root {{
      --bg: #f4f1ea;
      --panel: #fffdf8;
      --line: #d8ccbc;
      --ink: #221c15;
      --accent: #0f766e;
    }}
    body {{
      margin: 0;
      padding: 2rem;
      background: linear-gradient(180deg, #ece5d8, var(--bg));
      color: var(--ink);
      font: 16px/1.45 Georgia, "Times New Roman", serif;
    }}
    h1, h2, h3 {{ font-family: "Trebuchet MS", Verdana, sans-serif; }}
    section, nav {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 1rem 1.25rem;
      margin-bottom: 1.5rem;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.06);
    }}
    a {{ color: var(--accent); }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 1rem;
      table-layout: fixed;
    }}
    th, td {{
      border: 1px solid var(--line);
      padding: 0.5rem;
      vertical-align: top;
      word-wrap: break-word;
    }}
    th {{ background: #efe7da; }}
    pre {{
      white-space: pre-wrap;
      margin: 0;
      font: inherit;
    }}
    .attachment {{
      margin-bottom: 0.75rem;
      padding-bottom: 0.75rem;
      border-bottom: 1px dashed var(--line);
    }}
  </style>
</head>
<body>
  <h1>Discord Cache Parser Report</h1>
  <nav>
    <h2>Channels</h2>
    <ul>{''.join(channel_nav)}</ul>
  </nav>
  {''.join(sections)}
  <section>
    <h2>Additional Cached Attachments</h2>
    <table><thead><tr><th>Channel ID</th><th>Attachment ID</th><th>Original name</th><th>Files</th></tr></thead>
    <tbody>{''.join(orphan_attachment_rows)}</tbody></table>
  </section>
  <section>
    <h2>Additional Cached Avatars</h2>
    <table><thead><tr><th>Avatar ID</th><th>Name</th><th>Files</th></tr></thead>
    <tbody>{''.join(orphan_avatar_rows)}</tbody></table>
  </section>
</body>
</html>
"""
    (output_dir / "index.html").write_text(report, encoding="utf-8")


def write_json_report(
    output_dir: pathlib.Path,
    cache_type: str,
    channels: dict[str, Channel],
    avatars_by_key: dict[str, list[CachedAvatar]],
    attachments_by_id: dict[str, list[CachedAttachment]],
) -> None:
    used_attachments, used_avatars = collect_used_ids(channels)
    payload = {
        "generated_at": dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z"),
        "cache_type": cache_type,
        "channel_count": len(channels),
        "channels": serialise_channels(channels, avatars_by_key),
        "orphan_attachments": [
            asdict(item)
            for attachment_id, items in sorted(attachments_by_id.items())
            if attachment_id not in used_attachments
            for item in items
        ],
        "orphan_avatars": [
            asdict(item)
            for avatar_key, items in sorted(avatars_by_key.items())
            if avatar_key not in used_avatars
            for item in items
        ],
    }
    (output_dir / "report.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def parse_cache(cache_dir: pathlib.Path, output_dir: pathlib.Path) -> str:
    cache_type = detect_cache_type(cache_dir)
    if cache_type == "okhttp":
        messages_json, avatars_by_key, attachments_by_id = process_okhttp_cache(cache_dir, output_dir)
    elif cache_type == "chromium-simple":
        messages_json, avatars_by_key, attachments_by_id = process_chromium_simple_cache(cache_dir, output_dir)
    elif cache_type == "chromium-block":
        if chromium_cache_class_guesser is None:
            raise RuntimeError(
                "Chromium blockfile cache detected. Install 'ccl_chromium_reader' to enable this format."
            )
        messages_json, avatars_by_key, attachments_by_id = process_blockfile_cache(cache_dir, output_dir)
    else:
        raise RuntimeError(f"Unsupported or unknown cache format in: {cache_dir}")

    channels = build_channels(messages_json, attachments_by_id)
    write_json_report(output_dir, cache_type, channels, avatars_by_key, attachments_by_id)
    render_html_report(output_dir, channels, avatars_by_key, attachments_by_id)
    return cache_type


def existing_dir(path_value: str) -> pathlib.Path:
    path = pathlib.Path(path_value)
    if not path.exists() or not path.is_dir():
        raise argparse.ArgumentTypeError(f"Directory does not exist: {path_value}")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Standalone Discord cache parser with JSON and HTML outputs."
    )
    parser.add_argument("-i", "--input", required=True, type=existing_dir, help="Discord cache directory")
    parser.add_argument("-o", "--output", required=True, help="Output directory (must not already exist)")
    parser.add_argument("-V", "--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    output_dir = pathlib.Path(args.output)
    ensure_empty_output_dir(output_dir)

    cache_type = parse_cache(args.input, output_dir)
    print(f"Parsed Discord cache as {cache_type}.")
    print(f"JSON report: {output_dir / 'report.json'}")
    print(f"HTML report: {output_dir / 'index.html'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
