import gzip
import shutil
import subprocess

import pytest

from xvm_census import scan, unpack

from .conftest import require

WXS = """<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="Fake Agent" Version="1.0.0" Manufacturer="xvm tests"
           UpgradeCode="6f1d2b8e-8f2a-4e0c-9a51-3c1c2d9f0a11" Language="1033">
    <Package InstallerVersion="200" Compressed="yes" />
    <Media Id="1" Cabinet="agent.cab" EmbedCab="yes" />
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="INSTALLDIR" Name="fake-agent">
          <Component Id="Main" Guid="0e0b6f6a-4a4c-4d55-9a0e-6c3e8a5d2b11">
            <File Id="agent" Source="agent.exe" />
            <File Id="helper" Source="helper.dll" />
          </Component>
        </Directory>
      </Directory>
    </Directory>
    <Feature Id="All" Level="1"><ComponentRef Id="Main" /></Feature>
  </Product>
</Wix>
"""


def _names(root):
    return sorted(p.name for p in root.rglob("*") if p.is_file())


def test_msi(pe_fixtures, tmp_path):
    require("wixl", "msiextract")
    work = tmp_path / "w"
    shutil.copytree(pe_fixtures, work)
    (work / "agent.wxs").write_text(WXS)
    subprocess.run(["wixl", "-o", "agent.msi", "agent.wxs"], cwd=work, check=True)
    msi = work / "agent.msi"
    assert unpack.detect(msi) == "msi"
    dest = tmp_path / "out"
    unpack.unpack(msi, dest)
    assert {"agent.exe", "helper.dll"} <= set(_names(dest))
    c = scan.build_census(dest, agent="fake", source="agent.msi")
    assert c["dlls"]["helper.dll"]["kind"] == "bundled"


def test_deb(pe_fixtures, tmp_path):
    require("dpkg-deb", "bsdtar")
    pkg = tmp_path / "pkg"
    (pkg / "DEBIAN").mkdir(parents=True)
    (pkg / "DEBIAN" / "control").write_text(
        "Package: fake-agent\nVersion: 1.0\nArchitecture: all\n"
        "Maintainer: xvm <x@example.invalid>\nDescription: test\n"
    )
    (pkg / "opt").mkdir()
    shutil.copy(pe_fixtures / "helper.dll", pkg / "opt" / "helper.dll")
    deb = tmp_path / "fake.deb"
    subprocess.run(
        ["dpkg-deb", "--build", "-Zgzip", str(pkg), str(deb)], check=True, capture_output=True
    )
    assert unpack.detect(deb) == "deb"
    dest = tmp_path / "out"
    unpack.unpack(deb, dest)
    assert "helper.dll" in _names(dest)


def test_pkg_with_gzip_cpio_payload(pe_fixtures, tmp_path):
    require("bsdtar", "cpio")
    payload_root = tmp_path / "payload"
    payload_root.mkdir()
    shutil.copy(pe_fixtures / "helper.dll", payload_root / "helper.dll")
    cpio = subprocess.run(
        ["cpio", "-o", "-H", "odc", "--quiet"],
        cwd=payload_root,
        input=b"helper.dll\n",
        capture_output=True,
        check=True,
    ).stdout
    flat = tmp_path / "flat" / "agent.pkg"
    flat.mkdir(parents=True)
    (flat / "Payload").write_bytes(gzip.compress(cpio))
    (flat / "PackageInfo").write_text("<pkg-info/>")
    pkg = tmp_path / "fake.pkg"
    subprocess.run(
        ["bsdtar", "--format", "xar", "-cf", str(pkg), "-C", str(tmp_path / "flat"), "agent.pkg"],
        check=True,
    )
    assert unpack.detect(pkg) == "pkg"
    dest = tmp_path / "out"
    unpack.unpack(pkg, dest)
    assert "helper.dll" in _names(dest)


def test_unknown_format(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"hello")
    assert unpack.detect(f) is None
    with pytest.raises(unpack.UnpackError):
        unpack.unpack(f, tmp_path / "out")


def test_rpm_is_detected(tmp_path):
    f = tmp_path / "x.rpm"
    f.write_bytes(b"\xed\xab\xee\xdb" + b"\0" * 100)
    assert unpack.detect(f) == "rpm"
