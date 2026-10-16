import copy
import hashlib
import json

import pytest

from xvm_control import profile


def _base(os_name="windows"):
    root = "C:\\" if os_name == "windows" else "/"
    sep = "\\" if os_name == "windows" else "/"
    return {
        "schema": 1,
        "kind": "base-image",
        "name": "b",
        "os": os_name,
        "files": [
            {"path": f"{root}Data", "type": "dir"},
            {"path": f"{root}Data{sep}a.txt", "content": {"text": "a"}},
            {"path": f"{root}Data{sep}Sub{sep}b.txt", "content": {"text": "b"}},
        ],
        "processes": [
            {"id": "init", "image": "init", "pid": 1},
            {"id": "worker", "image": "worker", "parent": "init"},
        ],
    }


def _host(**extra):
    return {
        "schema": 1,
        "kind": "host-profile",
        "name": "h",
        "base": "b",
        "os": "windows",
        "identity": {"hostname": "H"},
        **extra,
    }


def test_file_remove_takes_the_subtree():
    r = profile.resolve(_host(files=[{"path": "c:\\data\\sub", "remove": True}]), _base())
    assert [f["path"] for f in r["files"]] == ["C:\\Data", "C:\\Data\\a.txt"]


def test_file_merge_keeps_base_spelling():
    r = profile.resolve(_host(files=[{"path": "C:/DATA/A.TXT", "owner": "x"}]), _base())
    assert r["files"][1] == {"path": "C:\\Data\\a.txt", "content": {"text": "a"}, "owner": "x"}


def test_linux_paths_are_case_sensitive():
    base = _base("linux")
    host = _host(os="linux", files=[{"path": "/data/a.txt", "content": {"text": "new"}}])
    r = profile.resolve(host, base)
    # Byte order of the normal form: "S" sorts before "a".
    assert [f["path"] for f in r["files"]] == [
        "/Data",
        "/Data/Sub/b.txt",
        "/Data/a.txt",
        "/data/a.txt",
    ]
    with pytest.raises(profile.ProfileError, match="cannot remove"):
        profile.resolve(_host(os="linux", files=[{"path": "/data", "remove": True}]), base)


@pytest.mark.parametrize(
    "path", ["Windows\\x", "C:", "C:/x", "\\\\server\\share\\x", "C:\\a\\\\b", "C:\\bad|name"]
)
def test_bad_windows_paths(path):
    b = _base()
    b["files"].append({"path": path})
    with pytest.raises(profile.ProfileError):
        profile.validate(b)


def test_bad_file_entries():
    for entry, msg in [
        ({"path": "C:\\Data\\a.txt\\child"}, "below the file"),
        ({"path": "c:\\DATA"}, "duplicate path"),
        ({"path": "C:\\d", "type": "dir", "size": 1}, "should not be valid"),
        ({"path": "C:\\x", "content": {"base64": "!!"}}, "is not valid"),
        ({"path": "C:\\x", "content": {"text": "a", "base64": "YQ=="}}, "is not valid"),
        ({"path": "C:\\x", "attributes": ["sparkly"]}, "sparkly"),
        ({"path": "C:\\x", "modified": "2026-01-01T00:00:00+01:00"}, "does not match"),
    ]:
        b = _base()
        b["files"].append(entry)
        with pytest.raises(profile.ProfileError, match=msg):
            profile.validate(b)


def test_process_merge_and_checks():
    r = profile.resolve(
        _host(
            processes=[
                {"id": "worker", "user": "svc"},
                {"id": "extra", "image": "x", "parent": "worker"},
            ]
        ),
        _base(),
    )
    assert r["processes"][1] == {"id": "worker", "image": "worker", "parent": "init", "user": "svc"}
    with pytest.raises(profile.ProfileError, match="unknown parent"):
        profile.resolve(_host(processes=[{"id": "init", "remove": True}]), _base())
    with pytest.raises(profile.ProfileError, match="has no image"):
        profile.resolve(_host(processes=[{"id": "ghost"}]), _base())
    with pytest.raises(profile.ProfileError, match="same pid"):
        profile.resolve(_host(processes=[{"id": "worker", "pid": 1}]), _base())
    b = _base()
    b["processes"].append({"id": "init", "image": "again"})
    with pytest.raises(profile.ProfileError, match="duplicate id"):
        profile.validate(b)


def test_base_cannot_remove_files_or_processes():
    for field, entry in (
        ("files", {"path": "C:\\Data", "remove": True}),
        ("processes", {"id": "init", "remove": True}),
    ):
        b = _base()
        b[field] = [entry]
        with pytest.raises(profile.ProfileError, match="cannot remove"):
            profile.validate(b)


def test_compile_moves_content_to_blobs(tmp_path):
    bases, hosts = tmp_path / "bases", tmp_path / "hosts"
    bases.mkdir()
    hosts.mkdir()
    b = _base()
    b["files"].append({"path": "C:\\Data\\same.txt", "content": {"base64": "YQ=="}})  # "a" again
    (bases / "b.yaml").write_text(json.dumps(b))
    (hosts / "h.yaml").write_text(
        json.dumps(_host(files=[{"path": "C:\\Data\\h.txt", "content": {"text": "hello"}}]))
    )
    profile.compile_tree([bases], [hosts], tmp_path / "out")
    blobs = sorted(p.name for p in (tmp_path / "out/blobs").iterdir())
    digest = {t: hashlib.sha256(t).hexdigest() for t in (b"a", b"b", b"hello")}
    assert blobs == sorted(digest.values())  # "a" stored once for two files
    compiled = json.loads((tmp_path / "out/bases/b.json").read_text())
    a = compiled["files"][1]
    assert a == {
        "path": "C:\\Data\\a.txt",
        "content": {"blob": digest[b"a"]},
        "size": 1,
        "sha256": digest[b"a"],
    }
    assert (tmp_path / "out/blobs" / digest[b"hello"]).read_bytes() == b"hello"


def test_compile_rejects_wrong_declared_hash(tmp_path):
    (tmp_path / "bases").mkdir()
    (tmp_path / "hosts").mkdir()
    b = _base()
    b["files"][1]["size"] = 99
    (tmp_path / "bases/b.yaml").write_text(json.dumps(b))
    (tmp_path / "hosts/h.yaml").write_text(json.dumps(_host()))
    with pytest.raises(profile.ProfileError, match="size does not match"):
        profile.compile_tree([tmp_path / "bases"], [tmp_path / "hosts"], tmp_path / "out")


def test_compile_does_not_change_the_loaded_documents(tmp_path):
    # resolve() runs before blobs are stored; the vectors rely on inline content staying inline.
    b = _base()
    before = copy.deepcopy(b)
    profile.resolve(_host(), b)
    assert b == before
