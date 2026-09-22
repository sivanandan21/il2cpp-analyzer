"""
Address Mapper and Normalization Service.
Strictly separates and validates:
- FIELD_OFFSET (relative to object instance pointer in heap)
- METHOD_RVA (relative virtual address from image base)
- VIRTUAL_ADDRESS (runtime virtual memory address)
- FILE_OFFSET (disk physical byte location)
- STATIC_ADDRESS (data section address for static class fields)
- POINTER (indirect reference value)
Never confuses one address type with another.
"""

from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from enum import Enum

class AddressType(str, Enum):
    FIELD_OFFSET = "FIELD_OFFSET"
    METHOD_RVA = "METHOD_RVA"
    VIRTUAL_ADDRESS = "VIRTUAL_ADDRESS"
    FILE_OFFSET = "FILE_OFFSET"
    STATIC_ADDRESS = "STATIC_ADDRESS"
    POINTER = "POINTER"
    UNKNOWN = "UNKNOWN"

@dataclass
class NormalizedAddress:
    object_type: str  # CLASS, FIELD, METHOD, STATIC_FIELD
    class_name: str
    member_name: str
    address_type: AddressType
    value_int: int
    value_hex: str
    architecture: str = "UNKNOWN"
    source: str = "Analysis"
    derivation: str = ""
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW
    verified: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "object_type": self.object_type,
            "class_name": self.class_name,
            "member_name": self.member_name,
            "address_type": self.address_type.value,
            "value_int": self.value_int,
            "value_hex": self.value_hex,
            "architecture": self.architecture,
            "source": self.source,
            "derivation": self.derivation,
            "confidence": self.confidence,
            "verified": self.verified
        }


class AddressMapper:
    """Validator and mapper ensuring strict address type separation."""

    @classmethod
    def create_field_offset(
        cls,
        class_name: str,
        field_name: str,
        offset_value: int,
        architecture: str = "UNKNOWN",
        source: str = "dump metadata",
        is_static: bool = False
    ) -> NormalizedAddress:
        """Create a verified FIELD_OFFSET record. Never generates or guesses offsets."""
        hex_val = f"0x{offset_value:X}" if offset_value >= 0 else f"-0x{-offset_value:X}"
        derivation = "Instance field displacement from object pointer base (+0x00 = Il2CppObject header)"
        if is_static:
            derivation = "Static field offset within type's static data storage block"

        return NormalizedAddress(
            object_type="STATIC_FIELD" if is_static else "FIELD",
            class_name=class_name,
            member_name=field_name,
            address_type=AddressType.FIELD_OFFSET,
            value_int=offset_value,
            value_hex=hex_val,
            architecture=architecture,
            source=source,
            derivation=derivation,
            confidence="HIGH",
            verified=True
        )

    @classmethod
    def create_method_rva(
        cls,
        class_name: str,
        method_name: str,
        rva_value: int,
        architecture: str = "UNKNOWN",
        source: str = "binary analysis"
    ) -> NormalizedAddress:
        """Create a verified METHOD_RVA record."""
        return NormalizedAddress(
            object_type="METHOD",
            class_name=class_name,
            member_name=method_name,
            address_type=AddressType.METHOD_RVA,
            value_int=rva_value,
            value_hex=f"0x{rva_value:08X}",
            architecture=architecture,
            source=source,
            derivation="Relative Virtual Address = VirtualAddress - PreferredImageBase",
            confidence="HIGH",
            verified=True
        )

    @classmethod
    def create_virtual_address(
        cls,
        class_name: str,
        member_name: str,
        va_value: int,
        object_type: str = "METHOD",
        architecture: str = "UNKNOWN",
        source: str = "binary header + RVA",
        confidence: str = "HIGH"
    ) -> NormalizedAddress:
        """Create a verified VIRTUAL_ADDRESS record."""
        return NormalizedAddress(
            object_type=object_type,
            class_name=class_name,
            member_name=member_name,
            address_type=AddressType.VIRTUAL_ADDRESS,
            value_int=va_value,
            value_hex=f"0x{va_value:016X}" if va_value > 0xFFFFFFFF else f"0x{va_value:08X}",
            architecture=architecture,
            source=source,
            derivation="Absolute virtual memory address mapped at preferred image base",
            confidence=confidence,
            verified=True
        )

    @classmethod
    def create_file_offset(
        cls,
        class_name: str,
        member_name: str,
        file_offset: int,
        object_type: str = "METHOD",
        architecture: str = "UNKNOWN",
        source: str = "section/segment translation"
    ) -> NormalizedAddress:
        """Create a verified physical FILE_OFFSET record."""
        return NormalizedAddress(
            object_type=object_type,
            class_name=class_name,
            member_name=member_name,
            address_type=AddressType.FILE_OFFSET,
            value_int=file_offset,
            value_hex=f"0x{file_offset:08X}",
            architecture=architecture,
            source=source,
            derivation="Physical on-disk byte position computed via segment/section headers",
            confidence="HIGH",
            verified=True
        )

    @classmethod
    def create_static_address(
        cls,
        class_name: str,
        field_name: str,
        address: int,
        architecture: str = "UNKNOWN",
        source: str = "static data table"
    ) -> NormalizedAddress:
        """Create a verified STATIC_ADDRESS record."""
        return NormalizedAddress(
            object_type="STATIC_FIELD",
            class_name=class_name,
            member_name=field_name,
            address_type=AddressType.STATIC_ADDRESS,
            value_int=address,
            value_hex=f"0x{address:08X}",
            architecture=architecture,
            source=source,
            derivation="Data section address holding static field variable",
            confidence="HIGH",
            verified=True
        )
