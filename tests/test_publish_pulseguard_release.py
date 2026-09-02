import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / '.github' / 'scripts' / 'publish_pulseguard_release.py'


def load_module():
    spec = importlib.util.spec_from_file_location('publish_pulseguard_release', SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'Unable to import {SCRIPT}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def test_parse_tag_accepts_exact_semver_tag(self):
        self.assertEqual(self.mod.parse_tag('v0.5.9'), (0, 5, 9))

    def test_parse_tag_rejects_missing_v_prefix(self):
        with self.assertRaisesRegex(ValueError, 'tag must match'):
            self.mod.parse_tag('0.5.9')

    def test_validate_not_downgrade_rejects_older_and_allows_equal_or_newer(self):
        with tempfile.TemporaryDirectory() as tmp:
            current_latest = Path(tmp) / 'latest.json'
            current_latest.write_text(json.dumps({
                'schemaVersion': 3,
                'product': 'PulseGuard PC',
                'channel': 'stable',
                'version': '0.5.8',
            }), encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'older than currently advertised'):
                self.mod.validate_not_downgrade(current_latest, (0, 5, 7))

            self.mod.validate_not_downgrade(current_latest, (0, 5, 8))
            self.mod.validate_not_downgrade(current_latest, (0, 5, 9))


class ReleaseZipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def _write_zip(self, path: Path, *, notes=None, raw_notes=None, include_notes=True):
        import zipfile
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('PulseGuard_PC/Our_PC_Optimizer.ps1', '# fixture')
            if include_notes:
                if raw_notes is not None:
                    payload = raw_notes
                else:
                    payload = json.dumps(notes or {
                        'schemaVersion': 1,
                        'product': 'PulseGuard PC',
                        'version': '0.5.9',
                        'title': "What's New",
                        'summary': 'test',
                        'items': [],
                    })
                z.writestr('PulseGuard_PC/Rules/release_notes.json', payload)

    def test_load_embedded_release_notes_accepts_valid_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            asset = Path(tmp) / 'PulseGuard_PC_v0.5.9.zip'
            notes = {
                'schemaVersion': 1,
                'product': 'PulseGuard PC',
                'version': '0.5.9',
                'title': "What's New",
                'summary': 'test',
                'items': [],
            }
            self._write_zip(asset, notes=notes)
            self.assertEqual(self.mod.load_embedded_release_notes(asset, '0.5.9'), notes)

    def test_load_embedded_release_notes_rejects_missing_notes(self):
        with tempfile.TemporaryDirectory() as tmp:
            asset = Path(tmp) / 'PulseGuard_PC_v0.5.9.zip'
            self._write_zip(asset, include_notes=False)
            with self.assertRaisesRegex(ValueError, 'release_notes.json'):
                self.mod.load_embedded_release_notes(asset, '0.5.9')

    def test_load_embedded_release_notes_rejects_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            asset = Path(tmp) / 'PulseGuard_PC_v0.5.9.zip'
            self._write_zip(asset, raw_notes='{ definitely-not-json')
            with self.assertRaisesRegex(ValueError, 'valid JSON'):
                self.mod.load_embedded_release_notes(asset, '0.5.9')

    def test_load_embedded_release_notes_rejects_product_or_version_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            asset = Path(tmp) / 'PulseGuard_PC_v0.5.9.zip'
            wrong_product = {
                'schemaVersion': 1, 'product': 'Other Product', 'version': '0.5.9',
                'title': "What's New", 'summary': 'test', 'items': []
            }
            self._write_zip(asset, notes=wrong_product)
            with self.assertRaisesRegex(ValueError, 'product'):
                self.mod.load_embedded_release_notes(asset, '0.5.9')

            wrong_version = dict(wrong_product, product='PulseGuard PC', version='0.5.8')
            self._write_zip(asset, notes=wrong_version)
            with self.assertRaisesRegex(ValueError, 'version'):
                self.mod.load_embedded_release_notes(asset, '0.5.9')

    def test_load_embedded_release_notes_rejects_corrupt_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            asset = Path(tmp) / 'PulseGuard_PC_v0.5.9.zip'
            asset.write_bytes(b'not a zip')
            with self.assertRaisesRegex(ValueError, 'valid ZIP'):
                self.mod.load_embedded_release_notes(asset, '0.5.9')


class ManifestGenerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def test_build_latest_manifest_uses_real_asset_bytes_and_exact_urls(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            asset = Path(tmp) / 'PulseGuard_PC_v0.5.9.zip'
            asset.write_bytes(b'known release bytes\x00\x01')
            manifest = self.mod.build_latest_manifest(
                'v0.5.9',
                '2026-09-02T09:00:00Z',
                'PULSEGUARDPC/PulseGuard-Updates',
                asset,
            )
            self.assertEqual(manifest['schemaVersion'], 3)
            self.assertEqual(manifest['product'], 'PulseGuard PC')
            self.assertEqual(manifest['channel'], 'stable')
            self.assertEqual(manifest['version'], '0.5.9')
            self.assertEqual(manifest['publishedAt'], '2026-09-02T09:00:00Z')
            self.assertEqual(manifest['packageSizeBytes'], len(asset.read_bytes()))
            self.assertEqual(manifest['packageSha256'], hashlib.sha256(asset.read_bytes()).hexdigest())
            self.assertEqual(
                manifest['packageUrl'],
                'https://github.com/PULSEGUARDPC/PulseGuard-Updates/releases/download/v0.5.9/PulseGuard_PC_v0.5.9.zip',
            )
            self.assertEqual(
                manifest['releaseNotesUrl'],
                'https://raw.githubusercontent.com/PULSEGUARDPC/PulseGuard-Updates/main/release_notes.json',
            )

    def test_json_serialization_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            asset = Path(tmp) / 'PulseGuard_PC_v0.5.9.zip'
            asset.write_bytes(b'same bytes')
            manifest1 = self.mod.build_latest_manifest('v0.5.9', '2026-09-02T09:00:00Z', 'PULSEGUARDPC/PulseGuard-Updates', asset)
            manifest2 = self.mod.build_latest_manifest('v0.5.9', '2026-09-02T09:00:00Z', 'PULSEGUARDPC/PulseGuard-Updates', asset)
            self.assertEqual(self.mod.serialize_json(manifest1), self.mod.serialize_json(manifest2))


class WorkflowContractTests(unittest.TestCase):
    def test_workflow_contains_required_release_contract(self):
        workflow = ROOT / '.github' / 'workflows' / 'publish-pulseguard-release.yml'
        text = workflow.read_text(encoding='utf-8')
        required = [
            'types: [published]',
            'contents: write',
            'github.event.release.prerelease == false',
            'cancel-in-progress: false',
            'gh release download',
            'python -m unittest discover -s tests -v',
            '.github/scripts/publish_pulseguard_release.py',
            'git add -- latest.json release_notes.json',
            'git diff --cached --quiet',
        ]
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)


class EndToEndTests(unittest.TestCase):
    def test_cli_updates_manifests_from_valid_release_asset(self):
        import hashlib
        import zipfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'repo'
            root.mkdir()
            asset = Path(tmp) / 'PulseGuard_PC_v0.5.8.zip'
            notes = {
                'schemaVersion': 1,
                'product': 'PulseGuard PC',
                'version': '0.5.8',
                'title': "What's New — Auto Research",
                'summary': 'PulseGuard now researches unresolved items before deciding what to keep or safely fix.',
                'items': [
                    {
                        'heading': 'Auto Research Engine',
                        'detail': 'UNKNOWN and REVIEW items are researched before action.',
                    }
                ],
            }
            with zipfile.ZipFile(asset, 'w', compression=zipfile.ZIP_DEFLATED) as z:
                z.writestr('PulseGuard_PC/Rules/release_notes.json', json.dumps(notes))
                z.writestr('PulseGuard_PC/Our_PC_Optimizer.ps1', '# fixture')
            (root / 'latest.json').write_text(json.dumps({
                'schemaVersion': 3,
                'product': 'PulseGuard PC',
                'channel': 'stable',
                'version': '0.5.7',
            }), encoding='utf-8')
            (root / 'release_notes.json').write_text('{}\n', encoding='utf-8')

            result = subprocess.run([
                'python', str(SCRIPT),
                '--tag', 'v0.5.8',
                '--published-at', '2026-09-02T09:00:00Z',
                '--repository', 'PULSEGUARDPC/PulseGuard-Updates',
                '--asset', str(asset),
                '--repo-root', str(root),
            ], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            latest = json.loads((root / 'latest.json').read_text(encoding='utf-8'))
            published_notes = json.loads((root / 'release_notes.json').read_text(encoding='utf-8'))
            self.assertEqual(latest['version'], '0.5.8')
            self.assertEqual(latest['packageSizeBytes'], asset.stat().st_size)
            self.assertEqual(latest['packageSha256'], hashlib.sha256(asset.read_bytes()).hexdigest())
            self.assertEqual(
                latest['packageUrl'],
                'https://github.com/PULSEGUARDPC/PulseGuard-Updates/releases/download/v0.5.8/PulseGuard_PC_v0.5.8.zip',
            )
            self.assertEqual(published_notes, notes)

    def test_cli_validation_failure_leaves_existing_manifests_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'repo'
            root.mkdir()
            original_latest = json.dumps({
                'schemaVersion': 3, 'product': 'PulseGuard PC', 'channel': 'stable', 'version': '0.5.8'
            }, indent=2) + '\n'
            original_notes = '{"old": true}\n'
            (root / 'latest.json').write_text(original_latest, encoding='utf-8')
            (root / 'release_notes.json').write_text(original_notes, encoding='utf-8')
            missing_asset = Path(tmp) / 'PulseGuard_PC_v0.5.9.zip'

            result = subprocess.run([
                'python', str(SCRIPT),
                '--tag', 'v0.5.9',
                '--published-at', '2026-09-02T09:00:00Z',
                '--repository', 'PULSEGUARDPC/PulseGuard-Updates',
                '--asset', str(missing_asset),
                '--repo-root', str(root),
            ], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((root / 'latest.json').read_text(encoding='utf-8'), original_latest)
            self.assertEqual((root / 'release_notes.json').read_text(encoding='utf-8'), original_notes)


if __name__ == '__main__':
    unittest.main()
