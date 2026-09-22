from django.test import TestCase
from pathlib import Path
import tempfile
import zipfile
import io

from analyzer.services.project_manager import ProjectManager, SecurityError

class ZipSafetyTests(TestCase):
    def test_zip_slip_path_traversal_blocked(self):
        """Ensure malicious zip files attempting ../ path traversal are safely rejected."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            # Add malicious entry with path traversal
            zf.writestr("../../malicious_payload.txt", b"exploit")

        zip_buffer.seek(0)
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
            tf.write(zip_buffer.getvalue())
            zip_path = Path(tf.name)

        target_dir = Path(tempfile.mkdtemp())
        try:
            with self.assertRaises(SecurityError):
                ProjectManager._safe_extract_zip(zip_path, target_dir)
        finally:
            zip_path.unlink()
            import shutil
            shutil.rmtree(target_dir, ignore_errors=True)

    def test_zip_size_limit_protection(self):
        """Ensure decompression bombs exceeding safe limits are aborted."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            # 2 MB of zeros compressed to a few bytes
            zf.writestr("huge_file.dat", b"0" * (2 * 1024 * 1024))

        zip_buffer.seek(0)
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
            tf.write(zip_buffer.getvalue())
            zip_path = Path(tf.name)

        target_dir = Path(tempfile.mkdtemp())
        try:
            # Set max uncompressed limit to 1 MB so 2 MB triggers error
            with self.assertRaises(ValueError):
                ProjectManager._safe_extract_zip(zip_path, target_dir, max_uncompressed_size=1024 * 1024)
        finally:
            zip_path.unlink()
            import shutil
            shutil.rmtree(target_dir, ignore_errors=True)
