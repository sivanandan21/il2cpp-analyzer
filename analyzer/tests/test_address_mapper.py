from django.test import TestCase
from analyzer.services.address_mapper import AddressMapper, AddressType

class AddressMapperTests(TestCase):
    def test_strict_field_offset_separation(self):
        """Ensure Field Offset is distinctly typed and not confused with RVA."""
        addr = AddressMapper.create_field_offset(
            class_name="PlayerStats",
            field_name="currentHealth",
            offset_value=0x120,
            architecture="ARM64",
            is_static=False
        )
        self.assertEqual(addr.address_type, AddressType.FIELD_OFFSET)
        self.assertEqual(addr.value_hex, "0x120")
        self.assertEqual(addr.value_int, 288)
        self.assertIn("displacement", addr.derivation.lower())
        self.assertNotEqual(addr.address_type, AddressType.METHOD_RVA)

    def test_strict_method_rva_separation(self):
        """Ensure Method RVA is distinctly typed."""
        addr = AddressMapper.create_method_rva(
            class_name="BattleManager",
            method_name="CalculateDamage",
            rva_value=0x00123456,
            architecture="ARM64"
        )
        self.assertEqual(addr.address_type, AddressType.METHOD_RVA)
        self.assertEqual(addr.value_hex, "0x00123456")
        self.assertEqual(addr.value_int, 0x123456)
        self.assertIn("relative virtual address", addr.derivation.lower())

    def test_static_address_separation(self):
        """Ensure Static Address is distinctly typed."""
        addr = AddressMapper.create_static_address(
            class_name="GlobalConfig",
            field_name="ServerTime",
            address=0x00789000
        )
        self.assertEqual(addr.address_type, AddressType.STATIC_ADDRESS)
        self.assertEqual(addr.value_hex, "0x00789000")
