#!/usr/bin/env python3
"""Build installable Debian and RPM packages without touching the host system."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
VERSION = "0.2.0"
NAME = "wazuh-security-reports"
DIST = ROOT / "dist"
PAYLOAD = [
    "wazuh_report.py",
    "wazuh_security_app.py",
    "assets/timbrado_confidencial.pdf",
    "assets/br.com.hostdime.WazuhSecurityReports.svg",
    "assets/br.com.hostdime.WazuhSecurityReports.png",
    "packaging/wazuh-security-reports",
    "packaging/br.com.hostdime.WazuhSecurityReports.desktop",
    "README.md",
]


def copy_payload(stage: Path) -> None:
    files = {
        "wazuh_report.py": "usr/share/wazuh-security-reports/wazuh_report.py",
        "wazuh_security_app.py": "usr/share/wazuh-security-reports/wazuh_security_app.py",
        "assets/timbrado_confidencial.pdf": "usr/share/wazuh-security-reports/assets/timbrado_confidencial.pdf",
        "assets/br.com.hostdime.WazuhSecurityReports.svg":
            "usr/share/icons/hicolor/scalable/apps/br.com.hostdime.WazuhSecurityReports.svg",
        "assets/br.com.hostdime.WazuhSecurityReports.png":
            "usr/share/icons/hicolor/512x512/apps/br.com.hostdime.WazuhSecurityReports.png",
        "packaging/wazuh-security-reports": "usr/bin/wazuh-security-reports",
        "packaging/br.com.hostdime.WazuhSecurityReports.desktop":
            "usr/share/applications/br.com.hostdime.WazuhSecurityReports.desktop",
        "README.md": "usr/share/doc/wazuh-security-reports/README.md",
    }
    for source, target in files.items():
        destination = stage / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / source, destination)
        if target == "usr/bin/wazuh-security-reports":
            destination.chmod(0o755)


def build_deb(work: Path) -> Path:
    stage = work / "deb-root"
    copy_payload(stage)
    control_dir = stage / "DEBIAN"
    control_dir.mkdir()
    (control_dir / "control").write_text(
        f"Package: {NAME}\n"
        f"Version: {VERSION}-1\n"
        "Section: utils\n"
        "Priority: optional\n"
        "Architecture: all\n"
        "Maintainer: HostDime Brasil\n"
        "Depends: python3 (>= 3.10), python3-gi, gir1.2-gtk-4.0 (>= 4.10), "
        "gir1.2-adw-1 (>= 1.4), python3-reportlab, python3-pypdf, fonts-dejavu-core\n"
        "Description: Interface para relatórios de segurança Wazuh por cliente\n"
        " Gera PDFs com gráficos e papel timbrado a partir de alertas filtrados\n"
        " pelo valor exato de agent.labels.customer em 24 horas, 7 ou 30 dias.\n",
        encoding="utf-8",
    )
    output = DIST / f"{NAME}_{VERSION}-1_all.deb"
    subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(stage), str(output)], check=True)
    return output


def build_rpm(work: Path) -> Path:
    executable = os.environ.get("RPMBUILD") or shutil.which("rpmbuild")
    if not executable:
        raise RuntimeError("rpmbuild não encontrado. Instale o pacote rpm ou defina RPMBUILD.")
    topdir = work / "rpmbuild"
    for child in ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"):
        (topdir / child).mkdir(parents=True)
    (topdir / "tmp").mkdir()
    (topdir / "db").mkdir()
    source_archive = topdir / "SOURCES" / f"{NAME}-{VERSION}.tar.gz"
    with tarfile.open(source_archive, "w:gz") as archive:
        for relative in PAYLOAD:
            archive.add(ROOT / relative, arcname=f"{NAME}-{VERSION}/{relative}")
    spec = topdir / "SPECS" / f"{NAME}.spec"
    shutil.copy2(ROOT / "packaging" / f"{NAME}.spec", spec)
    subprocess.run([
        executable, "-bb", "--define", f"_topdir {topdir}",
        "--define", f"_dbpath {topdir / 'db'}",
        "--define", f"_tmppath {topdir / 'tmp'}",
        str(spec),
    ], check=True)
    matches = list((topdir / "RPMS").glob("**/*.rpm"))
    if len(matches) != 1:
        raise RuntimeError(f"Era esperado um RPM; encontrados {len(matches)}.")
    output = DIST / matches[0].name
    shutil.copy2(matches[0], output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=("deb", "rpm"), help="Constrói apenas um formato")
    args = parser.parse_args()
    DIST.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="wazuh-package-") as temporary:
        work = Path(temporary)
        outputs = []
        if args.only != "rpm":
            outputs.append(build_deb(work))
        if args.only != "deb":
            outputs.append(build_rpm(work))
    for output in outputs:
        print(output)
    checksums = DIST / "SHA256SUMS"
    package_files = sorted(outputs)
    checksums.write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in package_files
    ))
    print(checksums)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
