"""Writes tasks.tsv: what Python's own XML parser (xml.etree) reads from the
task XML files in tests/fixtures/ (atomic/ and written/), one line per
value: the file, a name and the value. Independent of this crate: no code
shared, only the Task Scheduler schema's names.

Run: python3 -I tests/oracle/gen.py tests/fixtures > tests/oracle/tasks.tsv
"""

import gzip
import pathlib
import sys
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


def local(tag):
    return tag.split("}", 1)[-1]


def text(element, path):
    if element is None:
        return ""
    found = element.find("/".join(NS + step for step in path.split("/")))
    return (found.text or "").strip() if found is not None else ""


def children(element):
    return list(element) if element is not None else []


def decode(data):
    """Text by byte order mark, as Windows writes it; the declaration's
    encoding is not trusted (one Atomic Red Team file says UTF-16 and is
    UTF-8)."""
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16")
    return data.decode("utf-8-sig")


def rows(name, data):
    root = ET.fromstring(decode(data))
    out = []
    add = lambda key, value: out.append((name, key, value)) if value else None
    info = root.find(NS + "RegistrationInfo")
    for key in ("URI", "Author", "Description", "Date"):
        add(key, text(info, key))
    for index, trigger in enumerate(children(root.find(NS + "Triggers"))):
        prefix = f"trigger{index}."
        add(prefix + "kind", local(trigger.tag).removesuffix("Trigger"))
        add(prefix + "enabled", "false" if text(trigger, "Enabled") == "false" else "true")
        for key in ("StartBoundary", "EndBoundary", "UserId", "Subscription"):
            add(prefix + key, text(trigger, key))
        add(prefix + "Repetition", text(trigger, "Repetition/Interval"))
    for index, principal in enumerate(children(root.find(NS + "Principals"))):
        prefix = f"principal{index}."
        add(prefix + "id", principal.get("id", ""))
        for key in ("UserId", "GroupId", "LogonType", "RunLevel"):
            add(prefix + key, text(principal, key))
    settings = root.find(NS + "Settings")
    add("enabled", "false" if text(settings, "Enabled") == "false" else "true")
    add("hidden", "true" if text(settings, "Hidden") == "true" else "false")
    actions = root.find(NS + "Actions")
    add("context", actions.get("Context", "") if actions is not None else "")
    for index, action in enumerate(children(actions)):
        kind = local(action.tag)
        if kind == "Exec":
            line = text(action, "Command")
            arguments = text(action, "Arguments")
            add(f"action{index}", f"{line} {arguments}" if arguments else line)
            add(f"action{index}.WorkingDirectory", text(action, "WorkingDirectory"))
        elif kind == "ComHandler":
            data = text(action, "Data")
            line = "COM " + text(action, "ClassId")
            add(f"action{index}", f"{line} ({data})" if data else line)
    return out


def main(folder):
    lines = []
    for path in sorted(pathlib.Path(folder).glob("*/*")):
        if path.name in ("LICENSE", "NOTICE") or path.parent.name == "plaso":
            continue
        data = path.read_bytes()
        if path.suffix == ".gz":
            data = gzip.decompress(data)
        name = path.name.removesuffix(".gz")
        lines += ["\t".join((n, k, v.replace("\t", " ").replace("\r", "").replace("\n", " "))) for n, k, v in rows(name, data)]
    print("\n".join(sorted(lines)))


main(sys.argv[1])
