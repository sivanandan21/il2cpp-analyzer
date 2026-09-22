from django.test import TestCase
from analyzer.services.metadata_parser import MetadataParser, IL2CPP_METADATA_MAGIC
import struct

class MetadataParserTests(TestCase):
    def test_truncated_metadata_binary(self):
        """Ensure truncated metadata files do not crash the parser."""
        data = b"\x00" * 30
        res = MetadataParser.parse_binary_dat(data)
        self.assertFalse(res.is_valid)
        self.assertTrue(len(res.warnings) > 0)

    def test_invalid_magic(self):
        """Ensure invalid magic bytes are rejected."""
        data = struct.pack("<II", 0x12345678, 29) + b"\x00" * 200
        res = MetadataParser.parse_binary_dat(data)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("magic" in w.lower() for w in res.warnings))

    def test_parse_dump_cs(self):
        """Test parsing of synthetic dump.cs text."""
        sample_cs = """
// Image 0: Assembly-CSharp.dll
// Namespace: Game.Logic
public class CharacterStats : MonoBehaviour
{
    // Fields
    public float currentHealth; // 0x18
    public float maxHealth; // 0x1C
    public int attackPower; // 0x20
    public static bool IsAlive; // 0x0

    // Methods
    // RVA: 0x004A81F0 Offset: 0x002A81F0 VA: 0x70004A81F0
    public void ApplyDamage(float amount) { }
    // RVA: 0x004A8300 Offset: 0x002A8300 VA: 0x70004A8300
    public float GetHealthPercent() { }
}
"""
        res = MetadataParser.parse_dump_cs(sample_cs)
        self.assertTrue(res.is_valid)
        self.assertEqual(len(res.classes), 1)

        cls_obj = res.classes[0]
        self.assertEqual(cls_obj.name, "CharacterStats")
        self.assertEqual(cls_obj.namespace, "Game.Logic")
        self.assertEqual(cls_obj.assembly_name, "Assembly-CSharp.dll")
        self.assertEqual(len(cls_obj.fields), 4)
        self.assertEqual(len(cls_obj.methods), 2)

        # Field offset verification
        f_hp = cls_obj.fields[0]
        self.assertEqual(f_hp.name, "currentHealth")
        self.assertEqual(f_hp.offset, 0x18)
        self.assertEqual(f_hp.offset_hex, "0x18")

        # Method RVA verification
        m_dmg = cls_obj.methods[0]
        self.assertEqual(m_dmg.name, "ApplyDamage")
        self.assertEqual(m_dmg.rva, 0x004A81F0)
        self.assertEqual(m_dmg.file_offset, 0x002A81F0)
        self.assertEqual(m_dmg.va, 0x70004A81F0)
