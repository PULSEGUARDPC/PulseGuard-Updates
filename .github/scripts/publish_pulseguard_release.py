#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import re
import tempfile
import zipfile
from pathlib import Path

TAG_RE = re.compile(r'^v(\d+)\.(\d+)\.(\d+)$')
RELEASE_NOTES_PATH = 'PulseGuard_PC/Rules/release_notes.json'
RUNTIME_RELEASE_NOTES_PATH = 'PulseGuard_PC/Runtime/Rules/release_notes.json'
UPDATER_PATH = 'PulseGuard_PC/Runtime/PulseGuard_Updater.ps1'
PRODUCT = 'PulseGuard PC'
SIGNING_KEY_ENV = 'PULSEGUARD_SIGNING_KEY'
PINNED_KEY_RE = re.compile(r"^\s*\$script:PGReleasePublicKeyXml\s*=\s*'([^']*)'", re.MULTILINE)


def parse_tag(tag: str) -> tuple[int, int, int]:
    match = TAG_RE.fullmatch(tag)
    if not match:
        raise ValueError('tag must match vMAJOR.MINOR.PATCH exactly')
    return tuple(int(part) for part in match.groups())


def version_text(version: tuple[int, int, int]) -> str:
    return '.'.join(str(part) for part in version)


def validate_not_downgrade(current_latest_path: Path, new_version: tuple[int, int, int]) -> None:
    try:
        current = json.loads(current_latest_path.read_text(encoding='utf-8-sig'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f'current latest.json is not valid readable JSON: {exc}') from exc

    if not isinstance(current, dict):
        raise ValueError('current latest.json must contain a JSON object')
    if current.get('schemaVersion') != 3:
        raise ValueError('current latest.json schemaVersion must be 3')
    if current.get('product') != PRODUCT:
        raise ValueError(f'current latest.json product must be {PRODUCT}')
    if current.get('channel') != 'stable':
        raise ValueError('current latest.json channel must be stable')

    current_version_text = current.get('version')
    if not isinstance(current_version_text, str):
        raise ValueError('current latest.json version must be a string')
    current_version = parse_tag(f'v{current_version_text}')
    if new_version < current_version:
        raise ValueError(
            f'new version {version_text(new_version)} is older than currently advertised '
            f'{version_text(current_version)}'
        )


def load_embedded_release_notes(asset_path: Path, expected_version: str) -> dict:
    try:
        with zipfile.ZipFile(asset_path, 'r') as archive:
            bad_member = archive.testzip()
            if bad_member is not None:
                raise ValueError(f'release asset is not a valid ZIP: corrupt member {bad_member}')
            try:
                raw = archive.read(RELEASE_NOTES_PATH)
            except KeyError as exc:
                raise ValueError(f'ZIP is missing required {RELEASE_NOTES_PATH}') from exc
            try:
                runtime_raw = archive.read(RUNTIME_RELEASE_NOTES_PATH)
            except KeyError:
                runtime_raw = None
            if runtime_raw is not None and runtime_raw != raw:
                raise ValueError(
                    f'{RUNTIME_RELEASE_NOTES_PATH} must be identical to {RELEASE_NOTES_PATH}'
                )
    except ValueError:
        raise
    except (zipfile.BadZipFile, OSError) as exc:
        raise ValueError(f'release asset is not a valid ZIP: {exc}') from exc

    try:
        notes = json.loads(raw.decode('utf-8-sig'))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f'embedded release_notes.json is not valid JSON: {exc}') from exc

    if not isinstance(notes, dict):
        raise ValueError('embedded release_notes.json must contain a JSON object')
    if notes.get('product') != PRODUCT:
        raise ValueError(f'embedded release_notes.json product must be {PRODUCT}')
    if notes.get('version') != expected_version:
        raise ValueError(
            f'embedded release_notes.json version {notes.get("version")!r} '
            f'does not match release version {expected_version!r}'
        )
    return notes


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def build_latest_manifest(tag: str, published_at: str, repository: str, asset_path: Path) -> dict:
    version = version_text(parse_tag(tag))
    expected_name = f'PulseGuard_PC_{tag}.zip'
    if asset_path.name != expected_name:
        raise ValueError(
            f'release asset filename must be exactly {expected_name}; got {asset_path.name}'
        )
    if '/' not in repository or repository.startswith('/') or repository.endswith('/'):
        raise ValueError('repository must be in OWNER/NAME form')
    try:
        size = asset_path.stat().st_size
    except OSError as exc:
        raise ValueError(f'release asset cannot be read: {exc}') from exc
    return {
        'schemaVersion': 3,
        'product': PRODUCT,
        'channel': 'stable',
        'version': version,
        'publishedAt': published_at,
        'packageUrl': (
            f'https://github.com/{repository}/releases/download/{tag}/{expected_name}'
        ),
        'packageSizeBytes': size,
        'packageSha256': sha256_file(asset_path),
        'releaseNotesUrl': (
            f'https://raw.githubusercontent.com/{repository}/main/release_notes.json'
        ),
    }


# ---------------------------------------------------------------------------
# Release signing (must match Get-PGReleaseSignedText / Test-PGReleaseSignature in
# Runtime/PulseGuard_Updater.ps1): RSA PKCS#1 v1.5 + SHA-256 over
# "PulseGuard PC|<version>|<sha256 lowercase>|<size bytes>", base64 encoded.
# Keys use the .NET <RSAKeyValue> XML format produced by Sign-PulseGuardRelease.ps1.
# ---------------------------------------------------------------------------
def signed_text(version: str, sha256: str, size: int) -> bytes:
    return f'{PRODUCT}|{version}|{sha256.lower()}|{size}'.encode('utf-8')


def _xml_int(root, name: str, required: bool = True):
    node = root.find(name)
    if node is None or not (node.text or '').strip():
        if required:
            raise ValueError(f'RSA key XML is missing <{name}>')
        return None
    try:
        return int.from_bytes(base64.b64decode(node.text.strip(), validate=True), 'big')
    except (ValueError, TypeError) as exc:
        raise ValueError(f'RSA key XML <{name}> is not valid base64') from exc


def load_rsa_xml(xml_text: str, *, private: bool):
    import xml.etree.ElementTree as ET
    from cryptography.hazmat.primitives.asymmetric import rsa
    try:
        root = ET.fromstring(xml_text.strip())
    except ET.ParseError as exc:
        raise ValueError(f'RSA key XML could not be parsed: {exc}') from exc
    if root.tag != 'RSAKeyValue':
        raise ValueError('RSA key XML must be an <RSAKeyValue> document')
    public_numbers = rsa.RSAPublicNumbers(_xml_int(root, 'Exponent'), _xml_int(root, 'Modulus'))
    if not private:
        return public_numbers.public_key()
    d = _xml_int(root, 'D', required=False)
    if d is None:
        raise ValueError(
            f'{SIGNING_KEY_ENV} holds a PUBLIC key; paste the PRIVATE key file '
            '(PulseGuard_Release_Private.xml, it contains <D>) into the secret'
        )
    private_numbers = rsa.RSAPrivateNumbers(
        p=_xml_int(root, 'P'), q=_xml_int(root, 'Q'), d=d,
        dmp1=_xml_int(root, 'DP'), dmq1=_xml_int(root, 'DQ'), iqmp=_xml_int(root, 'InverseQ'),
        public_numbers=public_numbers,
    )
    return private_numbers.private_key()


def sign_manifest(latest: dict, private_xml: str) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    key = load_rsa_xml(private_xml, private=True)
    data = signed_text(latest['version'], latest['packageSha256'], latest['packageSizeBytes'])
    return base64.b64encode(key.sign(data, padding.PKCS1v15(), hashes.SHA256())).decode('ascii')


def verify_manifest_signature(latest: dict, public_xml: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    key = load_rsa_xml(public_xml, private=False)
    data = signed_text(latest['version'], latest['packageSha256'], latest['packageSizeBytes'])
    try:
        key.verify(base64.b64decode(latest['packageSignature']), data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


def read_pinned_public_key(asset_path: Path) -> str:
    """Public key pinned in the release's own updater ('' when signing is not enforced)."""
    try:
        with zipfile.ZipFile(asset_path, 'r') as archive:
            text = archive.read(UPDATER_PATH).decode('utf-8-sig')
    except KeyError:
        return ''
    except (zipfile.BadZipFile, OSError, UnicodeError) as exc:
        raise ValueError(f'release updater could not be read: {exc}') from exc
    match = PINNED_KEY_RE.search(text)
    return match.group(1).strip() if match else ''


def apply_release_signature(latest: dict, asset_path: Path, private_xml: str) -> dict:
    pinned = read_pinned_public_key(asset_path)
    private_xml = (private_xml or '').strip()
    if not private_xml:
        if pinned:
            raise ValueError(
                f'the release updater pins a signing key but the {SIGNING_KEY_ENV} secret is not set; '
                'publishing unsigned would break updates for every user'
            )
        return latest
    signed = dict(latest)
    signed['packageSignature'] = sign_manifest(latest, private_xml)
    if pinned and not verify_manifest_signature(signed, pinned):
        raise ValueError(
            f'the {SIGNING_KEY_ENV} secret does not match the public key pinned in '
            'Runtime/PulseGuard_Updater.ps1; installs would reject this release'
        )
    return signed


def serialize_json(value: dict) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode('utf-8')


def _write_temp(repo_root: Path, basename: str, content: bytes) -> Path:
    fd, name = tempfile.mkstemp(prefix=f'.{basename}.', suffix='.tmp', dir=repo_root)
    temp_path = Path(name)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        return temp_path
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def generate_manifests(
    *, tag: str, published_at: str, repository: str, asset_path: Path, repo_root: Path
) -> tuple[dict, dict]:
    new_version = parse_tag(tag)
    expected_version = version_text(new_version)
    expected_name = f'PulseGuard_PC_{tag}.zip'
    if asset_path.name != expected_name:
        raise ValueError(
            f'release asset filename must be exactly {expected_name}; got {asset_path.name}'
        )
    if not asset_path.is_file():
        raise ValueError(f'expected release asset does not exist: {asset_path}')
    if not repo_root.is_dir():
        raise ValueError(f'repository root does not exist: {repo_root}')

    validate_not_downgrade(repo_root / 'latest.json', new_version)
    notes = load_embedded_release_notes(asset_path, expected_version)
    latest = build_latest_manifest(tag, published_at, repository, asset_path)
    latest = apply_release_signature(latest, asset_path, os.environ.get(SIGNING_KEY_ENV, ''))

    latest_bytes = serialize_json(latest)
    notes_bytes = serialize_json(notes)
    # Final sanity check before touching repository files.
    json.loads(latest_bytes.decode('utf-8'))
    json.loads(notes_bytes.decode('utf-8'))

    latest_tmp = _write_temp(repo_root, 'latest.json', latest_bytes)
    notes_tmp = _write_temp(repo_root, 'release_notes.json', notes_bytes)
    try:
        os.replace(latest_tmp, repo_root / 'latest.json')
        os.replace(notes_tmp, repo_root / 'release_notes.json')
    finally:
        latest_tmp.unlink(missing_ok=True)
        notes_tmp.unlink(missing_ok=True)
    return latest, notes


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='Publish validated PulseGuard updater manifests.')
    parser.add_argument('--tag', required=True)
    parser.add_argument('--published-at', required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--asset', required=True, type=Path)
    parser.add_argument('--repo-root', required=True, type=Path)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        latest, _ = generate_manifests(
            tag=args.tag,
            published_at=args.published_at,
            repository=args.repository,
            asset_path=args.asset.resolve(),
            repo_root=args.repo_root.resolve(),
        )
    except ValueError as exc:
        print(f'ERROR: {exc}')
        return 2
    print(
        f'Generated stable updater manifests for v{latest["version"]}: '
        f'{latest["packageSizeBytes"]} bytes, SHA-256 {latest["packageSha256"]}, '
        f'signed={"packageSignature" in latest}'
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
