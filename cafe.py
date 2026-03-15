"""cafe.py - reversed by kx0x"""

import io
import os
import re
import pak

from .. import types


USERNAME_RE = re.compile(r"^.+#\d{4}$")
DEBUG_ENABLED = bool(os.getenv("CASEUS_CAFE_DEBUG"))
USERNAME_OVERRIDE = os.getenv("CASEUS_CAFE_USERNAME_OVERRIDE")
USERNAME_OVERRIDE_TARGET = os.getenv("CASEUS_CAFE_USERNAME_TARGET")

# Use same override variables when we rewrite raw payloads.
USERNAME_REWRITE = USERNAME_OVERRIDE
USERNAME_REWRITE_TARGET = USERNAME_OVERRIDE_TARGET


def _debug(msg: str) -> None:
    if DEBUG_ENABLED:
        print(f"[Cafe Debug] {msg}")


def _slice_hex(payload: bytes, start: int, length: int = 48) -> str:
    end = min(len(payload), start + length)
    return payload[start:end].hex(" ")


def _is_username(s: str) -> bool:
    # Trim NULs and whitespace
    s = s.strip("\x00 ")
    return bool(USERNAME_RE.match(s))


def extract_messages_from_topic_payload(payload: bytes):
    """Heuristic parser for Cafe topic payload -> list of (username, message).

    Strategy: scan for consecutive String, String pairs where the first looks
    like a username (e.g., 'Name#1234') and the second is non-empty. This is
    robust against intervening integers because we only advance when a pair is found.
    """

    ctx = pak.Type.Context()
    out = []

    i = 0
    n = len(payload)
    while i + 2 <= n:
        # Try to unpack first string at position i
        buf = io.BytesIO(payload)
        buf.seek(i)
        try:
            s1 = types.String.unpack(buf, ctx=ctx)
            pos2 = buf.tell()
            s2 = types.String.unpack(buf, ctx=ctx)
        except Exception:
            i += 1
            continue

        if _is_username(s1) and s2.strip("\x00 "):
            out.append((s1, s2))
            i = buf.tell()  # jump past the pair
        else:
            i += 1

    # Deduplicate preserving order
    seen = set()
    uniq = []
    for u, m in out:
        key = (u, m)
        if key in seen:
            continue
        seen.add(key)
        uniq.append((u, m))

    return uniq


def extract_posts_from_topic_payload(payload: bytes):
    """Extract cafe posts with IDs, usernames, and messages from topic payload.

    Returns a list of dictionaries with 'topic_id', 'post_id', 'username', 'message', and 'liked' keys.
    Adds verbose debugging when the environment variable CASEUS_CAFE_DEBUG is set.
    """
    ctx = pak.Type.Context()
    buf = io.BytesIO(payload)
    posts = []

    if len(payload) < 5:
        _debug(f"Payload too small ({len(payload)} bytes)")
        return posts

    # Header: [post_count (1 byte? likely unreliable)][topic_id (4 bytes, big endian)]
    post_count = payload[0]
    topic_id = int.from_bytes(payload[1:5], "big")
    buf.seek(5)

    _debug(f"Header post_count={post_count} topic_id={topic_id} payload_len={len(payload)}")

    # The advertised count is often wrong; parse until exhaustion with safety cap.
    max_posts = 256
    resyncs = 0

    def _parse_single(index: int):
        start = buf.tell()
        remaining = len(payload) - start
        # Minimal bytes needed for flags + ids + two empty strings + liked byte.
        min_size = 2 + 4 + 4 + 4 + 2 + 2 + 1
        if remaining < min_size:
            raise pak.util.BufferOutOfDataError(
                f"Not enough bytes for post {index}: remaining={remaining}, needed>={min_size}"
            )

        flags = buf.read(2)
        post_id = int.from_bytes(buf.read(4), "big")
        timestamp = int.from_bytes(buf.read(4), "big")
        meta = int.from_bytes(buf.read(4), "big")

        author = types.String.unpack(buf, ctx=ctx)
        content = types.String.unpack(buf, ctx=ctx)

        liked = False
        if buf.tell() < len(payload):
            liked = bool(buf.read(1)[0])

        _debug(
            f"post[{index}] offset={start} flags={flags.hex()} post_id={post_id} "
            f"timestamp={timestamp} meta={meta} liked={liked} "
            f"author_len={len(author)} content_len={len(content)} next={buf.tell()}"
        )

        return {
            "topic_id": topic_id,
            "post_id": post_id,
            "username": author,
            "message": content,
            "liked": liked,
        }, buf.tell() - start

    idx = 0
    while buf.tell() < len(payload) and idx < max_posts:
        start_pos = buf.tell()
        try:
            post, consumed = _parse_single(idx)
        except Exception as exc:
            resyncs += 1
            _debug(
                f"Failed to parse post[{idx}] at offset={start_pos}: {exc} "
                f"slice={_slice_hex(payload, start_pos)}"
            )
            # Heuristic resync: slide by one byte and try again.
            buf.seek(start_pos + 1)
            if resyncs > len(payload):
                _debug("Too many resync attempts, aborting parse")
                break
            continue

        # Sanity checks to avoid swallowing multiple posts in one string.
        author = post["username"]
        content = post["message"]
        sane = (
            _is_username(author)
            and bool(content.strip("\x00 ").strip())
            and post["post_id"] > 0
            and len(author) < 64
            and len(content) < 4096
        )

        if not sane:
            resyncs += 1
            _debug(
                f"Discard suspicious post[{idx}] at offset={start_pos}: "
                f"post_id={post['post_id']} author={author!r} content_len={len(content)} "
                f"slice={_slice_hex(payload, start_pos)}"
            )
            buf.seek(start_pos + 1)
            continue

        # Optional username spoof for display.
        if USERNAME_OVERRIDE and (not USERNAME_OVERRIDE_TARGET or author == USERNAME_OVERRIDE_TARGET):
            post["username"] = USERNAME_OVERRIDE

        posts.append(post)
        if consumed <= 0:
            # Should never happen, but guard against infinite loops.
            _debug("Zero-byte consumption detected, aborting parse")
            break

        idx += 1

        # Stop if we're at the end of the buffer.
        if buf.tell() >= len(payload):
            break

    return posts



def _decode_all_strings(payload: bytes):
    """Scan the payload and extract all valid length-prefixed strings in order.

    We assume the engine's types.String (short-length-prefixed UTF-8) and
    advance one byte when decoding fails to resynchronize.
    """
    ctx = pak.Type.Context()
    buf = io.BytesIO(payload)
    out = []

    while True:
        if buf.tell() >= len(payload):
            break
        save = buf.tell()
        try:
            s = types.String.unpack(buf, ctx=ctx)
            out.append(s)
        except Exception:
            # Not aligned to a string; advance by one byte and retry
            buf.seek(save + 1)
            continue

    return out


def extract_topic_titles_from_list_payload(payload: bytes):
    """Best-effort extraction of cafe topic titles from a list payload.

    Strategy: scan forward trying to match a common pattern observed in captures:
    [u32][String title][u32][u32][String author]. If matched, collect the title.
    Falls back to string-scan filtered by not-a-username.
    """
    ctx = pak.Type.Context()
    titles = []

    i = 0
    n = len(payload)
    while i + 2 <= n:
        buf = io.BytesIO(payload)
        buf.seek(i)
        try:
            # Try structured read
            _ = buf.read(4)
            title = types.String.unpack(buf, ctx=ctx)
            _ = buf.read(4)
            _ = buf.read(4)
            author = types.String.unpack(buf, ctx=ctx)
        except Exception:
            i += 1
            continue

        if title.strip() and not _is_username(title) and _is_username(author):
            titles.append(title.strip())
            i = buf.tell()
        else:
            i += 1

    if titles:
        # Deduplicate preserving order
        seen = set()
        uniq = []
        for t in titles:
            if t in seen:
                continue
            seen.add(t)
            uniq.append(t)
        return uniq

    # Fallback: decode all strings and filter
    strings = _decode_all_strings(payload)
    filtered = []
    seen = set()
    for s in strings:
        t = s.strip()
        if not t or _is_username(t):
            continue
        if t in seen:
            continue
        seen.add(t)
        filtered.append(t)
    return filtered


def extract_topics_from_list_payload(payload: bytes):
    """Extract cafe topics with IDs and titles from a list payload.

    Returns a list of dictionaries with 'id' and 'title' keys.

    Strategy: scan forward trying to match the pattern:
    [u32 topic_id][String title][timestamp][u32][String author].
    """
    ctx = pak.Type.Context()
    topics = []

    i = 0
    n = len(payload)
    while i + 2 <= n:
        buf = io.BytesIO(payload)
        buf.seek(i)
        try:
            # Try structured read
            topic_id_bytes = buf.read(4)
            if len(topic_id_bytes) < 4:
                i += 1
                continue
            
            topic_id = int.from_bytes(topic_id_bytes, byteorder='big', signed=False)
            title = types.String.unpack(buf, ctx=ctx)
            _ = buf.read(4)  # timestamp or other data
            _ = buf.read(4)  # more data
            author = types.String.unpack(buf, ctx=ctx)
        except Exception:
            i += 1
            continue

        title_clean = title.strip()
        author_clean = author.strip()
        # Some cafe topics can have an empty/whitespace title.
        # Keep them instead of dropping the whole topic entry.
        title_ok = (not title_clean) or (not _is_username(title_clean))
        if title_ok and _is_username(author_clean):
            topics.append({
                'id': topic_id,
                'title': title_clean,
                'last message author': author_clean
            })
            i = buf.tell()
        else:
            i += 1

    # Deduplicate preserving order by topic_id
    seen = set()
    uniq = []
    for topic in topics:
        if topic['id'] in seen:
            continue
        seen.add(topic['id'])
        uniq.append(topic)
    
    return uniq
