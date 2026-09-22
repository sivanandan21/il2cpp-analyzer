from django.test import TestCase
from pathlib import Path
import tempfile
import zipfile
import struct
from analyzer.services.apk_inspector import ApkInspector


class ApkInspectorTests(TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_inspect_non_apk(self):
        fake_file = self.temp_dir / "fake.apk"
        fake_file.write_text("not a zip")
        report = ApkInspector.inspect_and_extract(fake_file, self.temp_dir / "out")
        self.assertFalse(report.is_valid_apk)

    def test_inspect_synthetic_il2cpp_apk(self):
        apk_path = self.temp_dir / "game_sample.apk"
        with zipfile.ZipFile(apk_path, 'w') as zf:
            # Add synthetic Unity version file
            zf.writestr("assets/bin/Data/globalgamemanagers", b"UnityVersion 2021.3.18f1 build signature")
            # Add synthetic global-metadata.dat
            zf.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat", struct.pack('<I', 0xFAB11BAF) + b"\x00" * 256)
            # Add synthetic ARM64 libil2cpp.so
            zf.writestr("lib/arm64-v8a/libil2cpp.so", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 128)

        out_dir = self.temp_dir / "extracted_apk"
        report = ApkInspector.inspect_and_extract(apk_path, out_dir)

        self.assertTrue(report.is_valid_apk)
        self.assertEqual(report.engine_type, "Unity (IL2CPP)")
        self.assertEqual(report.architecture, "ARM64")
        self.assertEqual(report.unity_version, "2021.3.18f1")
        self.assertIsNotNone(report.metadata_path)
        self.assertTrue(report.metadata_path.exists())
        self.assertIsNotNone(report.binary_path)
        self.assertTrue(report.binary_path.exists())

    def test_parse_android_manifest_axml(self):
        # Construct minimal AXML with string pool
        strings = ["manifest", "package", "versionName", "com.test.game", "1.2.3"]
        str_bytes = b"".join(s.encode('utf-16le') + b"\x00\x00" for s in strings)
        str_pool_header = struct.pack('<IIIIIII', 0x001D0001, len(str_bytes) + 28, len(strings), 0, 0, 28, 0)
        axml_header = struct.pack('<II', 0x00080003, len(str_bytes) + 36)
        raw_manifest = axml_header + str_pool_header + str_bytes
        info = ApkInspector.parse_android_manifest(raw_manifest)
        self.assertIn("package_name", info)

    def test_smali_parser(self):
        from analyzer.services.smali_parser import SmaliParser
        smali_sample = """
        .class public Lcom/test/game/BattleManager;
        .super Ljava/lang/Object;
        .source "BattleManager.java"

        .field public static currentDamage:I
        .field public coins:I

        .method public calculateDamage(II)I
            .locals 1
            return p1
        .end method
        """
        cls_def = SmaliParser.parse_smali_text(smali_sample)
        self.assertIsNotNone(cls_def)
        self.assertEqual(cls_def.name, "BattleManager")
        self.assertEqual(cls_def.namespace, "com.test.game")
        self.assertEqual(len(cls_def.fields), 2)
        self.assertEqual(len(cls_def.methods), 1)
        self.assertEqual(cls_def.fields[0].name, "currentDamage")
        self.assertEqual(cls_def.fields[1].name, "coins")


