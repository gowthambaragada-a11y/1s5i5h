"""Helpers shared by vendor adapters.

These are deliberately *syntactic* only (tokenizing a line, converting an
address, expanding a port spec). Security judgement belongs in the rule pack,
not here.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from typing import Any

from app.normalize.models import Endpoint, PortRange, Protocol

_CIDR = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})\s*$")
_ADDR = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$")
_ANY_TOKENS = {"any", "all", "*", "0.0.0.0/0", "any-ipv4", "any6", "::/0"}


#: Cisco wildcard mask -> prefix length (host bits set). Inverse-mask arithmetic.
def wildcard_to_prefix(wildcard: str) -> int | None:
    try:
        wc = int(ipaddress.IPv4Address(wildcard.strip()))
    except (ipaddress.AddressValueError, ValueError):
        return None
    mask = (~wc) & 0xFFFFFFFF
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


def make_endpoint(address: str | None, prefix_len: int | None = None, **kw) -> Endpoint:
    """Build an :class:`Endpoint`, inferring ``is_any`` safely."""
    addr = (address or "any").strip()
    if addr.lower() in _ANY_TOKENS:
        return Endpoint(address="any", prefix_len=None, is_any=True, **kw)
    m = _CIDR.match(addr)
    if m:
        return Endpoint(address=m.group(1), prefix_len=prefix_len or int(m.group(2)), is_any=False, **kw)
    m = _ADDR.match(addr)
    if m:
        return Endpoint(address=m.group(1), prefix_len=prefix_len, is_any=False, **kw)
    # FQDN or a named address-group: keep the token, mark it non-IP.
    return Endpoint(address=addr, prefix_len=prefix_len, is_any=False, fqdn=None, **kw)


def parse_port_spec(spec: str | None, *, protocol: str | Protocol = Protocol.TCP) -> PortRange:
    """Parse ``22``, ``1-1024``, ``1-65535``, ``eq 443``, ``any`` into a PortRange.

    Also understands PAN-OS ``service`` names (``application-default``) and
    Juniper application names by falling back to an unconstrained range with
    the name retained via tags by the caller.
    """
    proto = Protocol(protocol) if not isinstance(protocol, Protocol) else protocol
    if spec is None:
        return PortRange(protocol=proto, low=None, high=None)
    s = spec.strip().lower().removeprefix("eq ").strip()
    if s in {"any", "all", "*", ""}:
        return PortRange(protocol=proto, low=None, high=None)
    if s.isdigit():
        p = int(s)
        return PortRange(protocol=proto, low=p, high=p)
    m = re.match(r"^(\d+)\s*-\s*(\d+)$", s)
    if m:
        return PortRange(protocol=proto, low=int(m.group(1)), high=int(m.group(2)))
    m = re.match(r"^(\d+)\s+(\d+)$", s)  # "port proto" pair, e.g. "443 tcp"
    if m:
        return PortRange(protocol=Protocol(m.group(2)), low=int(m.group(1)), high=int(m.group(1)))
    # Unrecognised service name (application-default, juniper-http, ANY, ...).
    return PortRange(protocol=Protocol.ANY, low=None, high=None)


def strip_bang(line: str) -> str:
    """Remove trailing IOS/Junos comment marker and surrounding whitespace."""
    return line.rstrip().removesuffix("!").rstrip()


def kv_from(line: str, separators: Iterable[str] = (" ", "=")) -> tuple[str, str] | None:
    """Split ``key<sep>value`` on the earliest separator present."""
    best: tuple[int, str] | None = None
    for sep in separators:
        idx = line.find(sep)
        if idx > 0 and (best is None or idx < best[0]):
            best = (idx, sep)
    if best is None:
        return None
    idx, sep = best
    return line[:idx].strip().lower(), line[idx + len(sep) :].strip()


_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_HASH_COMMENT = re.compile(r"^\s*#.*$", re.M)


def strip_junos_comments(text: str) -> str:
    """Remove ``## ...`` comments and ``/* ... */`` blocks.

    ``## SECRET-DATA`` markers are how Junos annotates hashes; we drop them so
    the tokenizer never ingests redaction markers as configuration values.
    """
    text = _COMMENT.sub(" ", text)
    return _HASH_COMMENT.sub("", text)


def split_hier_braces(text: str) -> dict:
    """Parse Junos brace-delimited configuration into nested dicts.

        Junos is Lisp-like::

            system { host-name SRX-1; services { ssh { port 22; } } }

        Resulting shape::

            {"system": {"host-name": "SRX-1",
                        "services": {"ssh": {"port": "22"}}}}

    Leaves are ``keyword value`` pairs, which is what Junos overwhelmingly
        emits. Three accessors are exposed for consumers:

        * direct keys -- ``node["port"]``
        * ``_pairs`` -- name/value maps built from *repeated* keywords, e.g. two
          ``address NAME VALUE;`` lines under ``address { }`` become
          ``_pairs == {"NAME": "VALUE"}``
        * ``_tokens`` -- the lossless ordered list of every raw leaf, used when
          keyword repetition carries meaning (``any notice; any info;``)

        A bare keyword (``disable;``) lands in ``_flags``. Multi-word block headers
        (``policy allow-web {``) are keyed by the full header string; use
        :func:`find`/:func:`pairs_of` plus a regex when the header has structure.

        A purpose-built tokenizer like this is cheaper and far more predictable
        than shipping a full Junos grammar. To swap in ``junos-eznc``/pyATS later,
        only :meth:`~app.normalize.adapters.juniper.JuniperJunosNormalizer.parse`
        changes.
    """
    root: dict = {}
    stack: list[dict] = [root]
    buf: list[str] = []
    anon = 0

    def take() -> str:
        s = " ".join("".join(buf).split())
        buf.clear()
        return s

    def put(node: dict, token: str) -> None:
        if not token:
            return
        node.setdefault("_tokens", []).append(token)
        m = re.match(r"^([A-Za-z_][\w./-]*)\s+(.+)$", token)
        if not m:
            node.setdefault("_flags", []).append(token)
            return
        key, value = m.group(1), m.group(2).strip().strip('"')
        if key in node and not isinstance(node[key], dict):
            # Keyword repeated under one block: keep it addressable by name.
            node.setdefault("_pairs", {})[key] = value
        else:
            node[key] = value

    for ch in text:
        if ch == "{":
            header = take()
            parent = stack[-1]
            if not header:
                anon += 1
                header = f"__anon_{anon}"
            child = parent.get(header)
            if not isinstance(child, dict):
                # Repeated block headers merge, matching Junos semantics.
                child = {}
                parent[header] = child
            stack.append(child)
        elif ch == "}":
            put(stack[-1], take())
            if len(stack) > 1:
                stack.pop()
        elif ch in ";,":
            put(stack[-1], take())
        else:
            buf.append(ch)

    put(stack[-1], take())
    return root


def pairs_of(node: dict | None) -> dict[str, Any]:
    """Merge a parsed block's scalar keys and its ``_pairs`` repeat map."""
    if not isinstance(node, dict):
        return {}
    merged = {k: v for k, v in node.items() if not k.startswith("_") and not isinstance(v, dict)}
    merged.update(node.get("_pairs", {}) or {})
    return merged


def tokens_of(node: dict) -> list[str]:
    """Every raw leaf under ``node``, in file order."""
    return list(node.get("_tokens", []))


def find(node: dict | None, *path: str) -> Any:
    """Safely walk a parsed Junos tree; returns ``None`` instead of raising."""
    cur: Any = node
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if not isinstance(v, dict)]
    if isinstance(value, dict):
        return []
    return [value]


def xml_snippets(raw_text: str) -> list[tuple[int, str]]:
    """Return ``(line_no, line)`` for every line, XML or not.

    PAN-OS configs are XML-ish; we hand them to ``ElementTree`` after escaping
    stray ampersands, but we still need line numbers for evidence.
    """
    return [(i, ln) for i, ln in enumerate(raw_text.splitlines(), start=1)]
