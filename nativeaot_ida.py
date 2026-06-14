"""
nativeaot_ida.py - .NET Native AOT metadata reconstruction for IDA Pro 9.2+

A single-file IDAPython port of the Ghidra "ghidra-nativeaot" plugin by Washi
(https://github.com/washi1337/ghidra-nativeaot ;
 https://blog.washi.dev/posts/recovering-nativeaot-metadata/).

It assists reverse engineering of binaries compiled with .NET Native AOT
(.NET 7/8/9/10), whose symbols are stripped and for which no FunctionID
databases exist. Ported features:

  * ReadyToRun (RTR) directory location (symbol-based + signature scan).
  * RTR header / section-table parsing and structure markup.
  * Metadata rehydration (.NET 8.0+ "dehydrated data" decompression) writing
    the reconstructed bytes into the `hydrated` segment, with optional opcode
    markup. Manual pointer-scan fallback for .NET 7 / 10+.
  * Full MethodTable (EEType) type-hierarchy reconstruction: per-type IDA
    structs for the MethodTable, its vtable chunks and its instance layout,
    plus the inheritance + interface graph.
  * Virtual-method naming, function creation at vtable slots, __thiscall.
  * Frozen-object annotation (string literals, SZ arrays, boxed values).

Target: IDA Pro 9.2+ (IDAPython; developed and tested on 9.3). Also runs under
idalib (headless). Only x86-64 little-endian binaries are supported (as in the
original plugin).

Run inside IDA:   File > Script file... > nativeaot_ida.py
Run headless:     idat64 -A -S"nativeaot_ida.py" target.i64

Behaviour can be tuned with NAOT_* environment variables (see Config).
"""

from __future__ import annotations

import os
import json
import zlib
import struct
import traceback

import ida_netnode
import ida_bytes
import ida_segment
import ida_name
import ida_funcs
import ida_auto
import ida_typeinf
import ida_nalt
import ida_ida
import ida_idaapi
import ida_lines
import idautils
import idc

BADADDR = ida_idaapi.BADADDR


# ===========================================================================
# Configuration
# ===========================================================================

def _env_flag(name, default):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


class Config:
    VERBOSE = _env_flag("NAOT_VERBOSE", True)
    # Add an EOL comment for every dehydration opcode (slow, grows the DB a lot).
    MARKUP_REHYDRATION_CODE = _env_flag("NAOT_MARKUP_REHYDRATION", False)
    # Create IDA struct types and apply them (False => discovery-only run).
    CREATE_TYPES = _env_flag("NAOT_CREATE_TYPES", True)
    # Create functions at vtable slots and rename/annotate virtual methods.
    ASSIGN_METHODS = _env_flag("NAOT_ASSIGN_METHODS", True)
    # Apply the __thiscall calling convention to virtual methods.
    SET_THISCALL = _env_flag("NAOT_SET_THISCALL", True)
    # Annotate frozen objects (strings / arrays / boxed values).
    ANNOTATE_FROZEN = _env_flag("NAOT_ANNOTATE_FROZEN", True)
    # Write a text metadata report (type hierarchy + method tables) next to the DB.
    WRITE_REPORT = _env_flag("NAOT_REPORT", True)


# ===========================================================================
# Logging
# ===========================================================================

TAG = "NativeAOT"


class Log:
    @staticmethod
    def info(msg):
        print("[%s] %s" % (TAG, msg))

    @staticmethod
    def warn(msg):
        print("[%s][WARN] %s" % (TAG, msg))

    @staticmethod
    def error(msg, exc=None):
        print("[%s][ERROR] %s" % (TAG, msg))
        if exc is not None:
            print(traceback.format_exc())

    @staticmethod
    def debug(msg):
        if Config.VERBOSE:
            print("[%s][dbg] %s" % (TAG, msg))


# ===========================================================================
# Constants (ported from nativeaot.Constants / ReadyToRunSection)
# ===========================================================================

READY_TO_RUN_SIGNATURE = 0x00525452  # "RTR\0"
RTR_MODULES_START_SYMBOL = "__modules_a"
RTR_MODULES_END_SYMBOL = "__modules_z"
RTR_HEADER_SYMBOL = "__ReadyToRunHeader"
DEHYDRATED_DATA_SYMBOL = "__dehydrated_data"
HYDRATED_DATA_SYMBOL = "__hydrated_data"
FROZEN_SEGMENT_START_SYMBOL = "__FrozenSegmentStart"

SYSTEM_OBJECT_NAME = "System_Object"
SYSTEM_STRING_NAME = "System_String"

SECTION_FROZEN_OBJECT_REGION = 206
SECTION_DEHYDRATED_DATA = 207

EXPECTED_ENTRY_SIZE = 0x18
EXPECTED_ENTRY_TYPE = 0x01
EXPECTED_NUMBER_OF_SECTIONS_UPPER_BOUND = 0x50


class ElementType:
    UNKNOWN = 0x00
    VOID = 0x01
    BOOLEAN = 0x02
    CHAR = 0x03
    SBYTE = 0x04
    BYTE = 0x05
    INT16 = 0x06
    UINT16 = 0x07
    INT32 = 0x08
    UINT32 = 0x09
    INT64 = 0x0A
    UINT64 = 0x0B
    INTPTR = 0x0C
    UINTPTR = 0x0D
    SINGLE = 0x0E
    DOUBLE = 0x0F
    VALUETYPE = 0x10
    NULLABLE = 0x12
    CLASS = 0x14
    INTERFACE = 0x15
    SYSTEM_ARRAY = 0x16
    ARRAY = 0x17
    SZARRAY = 0x18
    BYREF = 0x19
    POINTER = 0x1A
    FUNCTION_POINTER = 0x1B

    @staticmethod
    def is_value_type(et):
        return ElementType.VOID <= et <= ElementType.VALUETYPE

    @staticmethod
    def is_primitive(et):
        return ElementType.VOID <= et <= ElementType.DOUBLE

    @staticmethod
    def is_array_instance(et):
        return et == ElementType.ARRAY or et == ElementType.SZARRAY


# ===========================================================================
# Memory helpers
# ===========================================================================

class Mem:
    @staticmethod
    def u8(ea):
        return ida_bytes.get_byte(ea)

    @staticmethod
    def u16(ea):
        return ida_bytes.get_word(ea)

    @staticmethod
    def u32(ea):
        return ida_bytes.get_dword(ea)

    @staticmethod
    def s16(ea):
        v = ida_bytes.get_word(ea)
        return v - 0x10000 if v & 0x8000 else v

    @staticmethod
    def s32(ea):
        v = ida_bytes.get_dword(ea)
        return v - 0x100000000 if v & 0x80000000 else v

    @staticmethod
    def u64(ea):
        return ida_bytes.get_qword(ea)

    @staticmethod
    def bytes(ea, n):
        b = ida_bytes.get_bytes(ea, n)
        if b is None or len(b) != n:
            raise MemError("Cannot read %d bytes at %#x" % (n, ea))
        return b

    @staticmethod
    def is_loaded(ea):
        return ida_bytes.is_loaded(ea)

    @staticmethod
    def write(ea, data):
        ida_bytes.put_bytes(ea, data)


class MemError(Exception):
    pass


def seg_of(ea):
    return ida_segment.getseg(ea)


def is_exec_addr(ea):
    s = ida_segment.getseg(ea)
    return s is not None and bool(s.perm & ida_segment.SEGPERM_EXEC)


def iter_segments():
    for i in range(ida_segment.get_segm_qty()):
        yield ida_segment.getnseg(i)


def loaded_min_max():
    """Return (min,max) over all loaded+initialized addresses (inclusive max)."""
    lo = None
    hi = None
    for s in iter_segments():
        if not Mem.is_loaded(s.start_ea):
            # segment may be partially loaded; still consider its range bounds
            pass
        if lo is None or s.start_ea < lo:
            lo = s.start_ea
        if hi is None or s.end_ea - 1 > hi:
            hi = s.end_ea - 1
    return lo, hi


# ===========================================================================
# Type factory (IDA local types)
# ===========================================================================

class TypeFactory:
    """Creates / applies struct types in the local type library."""

    def __init__(self):
        self.til = ida_typeinf.get_idati()

    def exists(self, name):
        t = ida_typeinf.tinfo_t()
        return t.get_named_type(self.til, name)

    def get(self, name):
        t = ida_typeinf.tinfo_t()
        if t.get_named_type(self.til, name):
            return t
        return None

    def create_struct(self, name, members, force=False, pack=None):
        """members: list of (c_type_str, field_name). Returns tinfo or None.

        pack: optional struct packing alignment (e.g. 4) to suppress trailing
        padding so the struct size matches the real in-memory layout.
        """
        if self.exists(name) and not force:
            return self.get(name)
        body = " ".join("%s %s;" % (ctype, fname) for (ctype, fname) in members)
        decl = "struct %s { %s };" % (name, body)
        if pack is not None:
            decl = "#pragma pack(push,%d)\n%s\n#pragma pack(pop)" % (pack, decl)
        errs = ida_typeinf.parse_decls(self.til, decl, None, ida_typeinf.HTI_DCL)
        if errs != 0:
            Log.warn("parse_decls returned %d errors for type %s" % (errs, name))
        t = self.get(name)
        if t is None:
            Log.warn("Failed to create type %s" % name)
        return t

    def rename_type(self, old_name, new_name):
        t = self.get(old_name)
        if t is None:
            return False
        try:
            return t.rename_type(new_name) == 0
        except Exception:
            # Fallback: set_named_type under new name
            try:
                t.set_named_type(self.til, new_name, ida_typeinf.NTF_REPLACE)
                return True
            except Exception:
                return False

    def apply_at(self, ea, name, clear_len=None):
        t = self.get(name)
        if t is None:
            return False
        size = t.get_size()
        if size == 0 or size == BADADDR:
            return False
        if clear_len is None:
            clear_len = size
        # ensure the bytes are present (hydrated segment is sparse by default)
        if not Mem.is_loaded(ea):
            Mem.write(ea, b"\x00" * clear_len)
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, clear_len)
        tid = t.get_tid()
        if tid != BADADDR and ida_bytes.create_struct(ea, size, tid):
            return True
        return ida_typeinf.apply_tinfo(ea, t, ida_typeinf.TINFO_DEFINITE)


TF = None  # initialised in main()


# C type strings used in struct definitions
C_PTR = "void *"
C_U8 = "unsigned __int8"
C_U16 = "unsigned __int16"
C_U32 = "unsigned __int32"
C_U64 = "unsigned __int64"
C_I16 = "__int16"
C_I32 = "__int32"
C_I64 = "__int64"
C_CHAR16 = "char16_t"


# ===========================================================================
# Name sanitising
# ===========================================================================

def sanitize_ident(s, maxlen=64):
    out = []
    for ch in s:
        if ch.isalnum() or ch == "_":
            out.append(ch)
        else:
            out.append("_")
    r = "".join(out)
    if r and r[0].isdigit():
        r = "_" + r
    if len(r) > maxlen:
        r = r[:maxlen]
    return r or "_"


def make_string_label_text(s, maxlen=56):
    """Produce a clean, readable identifier fragment from string content.

    Collapses runs of non-identifier characters to a single underscore and
    trims leading/trailing underscores, so e.g. "Declaring type: " becomes
    "Declaring_type" rather than "Declaring_type__".
    """
    out = []
    prev_us = False
    for ch in s:
        if ch.isalnum():
            out.append(ch)
            prev_us = False
        else:
            if not prev_us:
                out.append("_")
            prev_us = True
    r = "".join(out).strip("_")
    if len(r) > maxlen:
        r = r[:maxlen].rstrip("_")
    if r and r[0].isdigit():
        r = "_" + r
    return r


# ===========================================================================
# ReadyToRun directory
# ===========================================================================

class ReadyToRunSection:
    def __init__(self, type_, flags, start, end):
        self.type = type_
        self.flags = flags
        self.start = start
        self.end = end

    def pointers_in_section(self, addresses):
        return [a for a in addresses if self.start <= a < self.end]


class ReadyToRunDirectory:
    def __init__(self, address):
        self.address = address
        sig = Mem.u32(address)
        if sig != READY_TO_RUN_SIGNATURE:
            raise MemError("No RTR signature at %#x" % address)
        self.major_version = Mem.u16(address + 4)
        self.minor_version = Mem.u16(address + 6)
        self.attributes = Mem.u32(address + 8)
        section_count = Mem.u16(address + 0x0C)
        self.entry_size = Mem.u8(address + 0x0E)
        self.entry_type = Mem.u8(address + 0x0F)
        if section_count > EXPECTED_NUMBER_OF_SECTIONS_UPPER_BOUND:
            raise MemError("Unexpected number of sections %d" % section_count)
        self.sections = []
        off = address + 0x10
        for _ in range(section_count):
            t = Mem.u32(off)
            fl = Mem.u32(off + 4)
            st = Mem.u64(off + 8)
            en = Mem.u64(off + 0x10)
            self.sections.append(ReadyToRunSection(t, fl, st, en))
            off += 0x18

    def get_section_by_type(self, t):
        for s in self.sections:
            if s.type == t:
                return s
        return None

    def markup(self):
        """Create ModuleInfoRow + ReadyToRunHeader structs and label the header."""
        if TF is None or not Config.CREATE_TYPES:
            return
        TF.create_struct("ModuleInfoRow", [
            (C_U32, "Type"), (C_U32, "Flags"), (C_PTR, "Start"), (C_PTR, "End"),
        ])
        n = len(self.sections)
        TF.create_struct("ReadyToRunHeader", [
            (C_U32, "Signature"), (C_U16, "MajorVersion"), (C_U16, "MinorVersion"),
            (C_U32, "Flags"), (C_U16, "NumberOfSections"),
            (C_U8, "EntrySize"), (C_U8, "EntryType"),
            ("ModuleInfoRow", "Sections[%d]" % n),
        ], force=True)
        try:
            TF.apply_at(self.address, "ReadyToRunHeader")
        except Exception as ex:
            Log.warn("Failed to apply RTR header struct: %s" % ex)
        set_name_safe(self.address, RTR_HEADER_SYMBOL)


# ===========================================================================
# RTR locators
# ===========================================================================

def locate_modules():
    """Return a list of candidate RTR directory addresses."""
    found = locate_modules_by_symbol()
    if found:
        Log.info("Located RTR directory via symbols: %s" % [hex(x) for x in found])
        return found
    found = locate_modules_by_signature()
    if found:
        Log.info("Located RTR directory via signature scan: %s" % [hex(x) for x in found])
    return found


def locate_modules_by_symbol():
    candidates = []
    ea = ida_name.get_name_ea(BADADDR, RTR_HEADER_SYMBOL)
    if ea != BADADDR:
        candidates.append(ea)

    start = ida_name.get_name_ea(BADADDR, RTR_MODULES_START_SYMBOL)
    end = ida_name.get_name_ea(BADADDR, RTR_MODULES_END_SYMBOL)
    if start != BADADDR and end != BADADDR and end > start:
        count = (end - start) // 8
        for i in range(count):
            raw = Mem.u64(start + i * 8)
            if raw == 0:
                continue
            if raw not in candidates:
                candidates.append(raw)

    # validate signature
    valid = []
    for c in candidates:
        try:
            if Mem.u32(c) == READY_TO_RUN_SIGNATURE:
                valid.append(c)
        except Exception:
            pass
    return valid


def locate_modules_by_signature():
    result = []
    for s in iter_segments():
        if s.perm & ida_segment.SEGPERM_EXEC:
            continue
        if not (s.perm & ida_segment.SEGPERM_READ):
            continue
        ea = s.start_ea
        if ea % 8 != 0:
            ea += 8 - (ea % 8)
        end = s.end_ea
        while ea < end:
            try:
                if is_likely_rtr_header(ea):
                    result.append(ea)
            except Exception:
                break
            ea += 8
    return result


def is_likely_rtr_header(ea):
    if not Mem.is_loaded(ea):
        return False
    if Mem.u32(ea) != READY_TO_RUN_SIGNATURE:
        return False
    if Mem.u8(ea + 0x0C) >= EXPECTED_NUMBER_OF_SECTIONS_UPPER_BOUND:
        return False
    if Mem.u8(ea + 0x0E) != EXPECTED_ENTRY_SIZE:
        return False
    if Mem.u8(ea + 0x0F) != EXPECTED_ENTRY_TYPE:
        return False
    return True


# ===========================================================================
# Pointer scan result
# ===========================================================================

class PointerScanResult:
    def __init__(self, range_min, range_max, pointer_locations):
        self.range_min = range_min
        self.range_max = range_max
        self.pointer_locations = pointer_locations

    def in_range(self, value):
        return self.range_min <= value <= self.range_max


# ===========================================================================
# Metadata rehydrator (.NET 8.0+)
# ===========================================================================

class DehydratedDataCommand:
    COPY = 0x00
    ZERO_FILL = 0x01
    REL_PTR32_RELOC = 0x02
    PTR_RELOC = 0x03
    INLINE_REL_PTR32_RELOC = 0x04
    INLINE_PTR_RELOC = 0x05

    MASK = 0x07
    PAYLOAD_SHIFT = 3
    MAX_RAW_SHORT_PAYLOAD = (1 << (8 - PAYLOAD_SHIFT)) - 1   # 31
    MAX_EXTRA_PAYLOAD_BYTES = 3
    MAX_SHORT_PAYLOAD = MAX_RAW_SHORT_PAYLOAD - MAX_EXTRA_PAYLOAD_BYTES  # 28

    NAMES = {
        0: "COPY", 1: "ZERO_FILL", 2: "REL_PTR32_RELOC",
        3: "PTR_RELOC", 4: "INLINE_REL_PTR32_RELOC", 5: "INLINE_PTR_RELOC",
    }


class _Reader:
    """Sequential little-endian reader over IDA memory by absolute address."""
    def __init__(self, index):
        self.index = index

    def next_u8(self):
        v = Mem.u8(self.index)
        self.index += 1
        return v

    def next_s32(self):
        v = Mem.s32(self.index)
        self.index += 4
        return v

    def next_bytes(self, n):
        b = Mem.bytes(self.index, n)
        self.index += n
        return b

    @staticmethod
    def s32_at(index):
        return Mem.s32(index)


class MetadataRehydratorNet80:
    """Port of nativeaot.rehydration.MetadataRehydratorNet80."""

    def __init__(self, markup=False):
        self.markup = markup

    def rehydrate(self, dehy_start, dehy_end):
        reader = _Reader(dehy_start)
        hydration_base = self._read_rel_ptr32(reader)
        Log.info("Hydration base = %#x (dehydrated %#x-%#x)" %
                 (hydration_base, dehy_start, dehy_end))

        # The fixups table follows the dehydrated command stream.
        fixups_start = dehy_end

        hydrated = bytearray()
        pointer_locations = []
        cmd_count = 0

        while reader.index < dehy_end:
            offset = reader.index
            command, payload = self._read_command(reader)
            cmd_count += 1

            if self.markup:
                try:
                    ida_bytes.set_cmt(
                        offset, "%s %x" % (DehydratedDataCommand.NAMES.get(command, "?"), payload), False)
                except Exception:
                    pass

            if command == DehydratedDataCommand.COPY:
                hydrated += reader.next_bytes(payload)
            elif command == DehydratedDataCommand.ZERO_FILL:
                hydrated += b"\x00" * payload
            elif command == DehydratedDataCommand.REL_PTR32_RELOC:
                ptr = self._read_rel_ptr32_at(fixups_start + payload * 4)
                self._write_rel_ptr32(hydrated, ptr)
            elif command == DehydratedDataCommand.PTR_RELOC:
                ptr = self._read_rel_ptr32_at(fixups_start + payload * 4)
                pointer_locations.append(hydration_base + len(hydrated))
                self._write_u64(hydrated, ptr)
            elif command == DehydratedDataCommand.INLINE_REL_PTR32_RELOC:
                for _ in range(payload):
                    self._write_rel_ptr32(hydrated, self._read_rel_ptr32(reader))
            elif command == DehydratedDataCommand.INLINE_PTR_RELOC:
                for _ in range(payload):
                    pointer_locations.append(hydration_base + len(hydrated))
                    self._write_u64(hydrated, self._read_rel_ptr32(reader))
            else:
                raise MemError("Unknown dehydration command %d at %#x" % (command, reader.index))

        # Commit the rehydrated bytes into the (sparse) hydrated segment.
        self._commit(hydration_base, bytes(hydrated))

        Log.info("Rehydration done: %d commands, %d bytes hydrated, %d pointer relocs" %
                 (cmd_count, len(hydrated), len(pointer_locations)))

        set_name_safe(hydration_base, HYDRATED_DATA_SYMBOL)

        return PointerScanResult(
            hydration_base,
            hydration_base + len(hydrated),
            pointer_locations,
        )

    # --- helpers (mirroring the Java arithmetic exactly) ---

    @staticmethod
    def _read_rel_ptr32(reader):
        base = reader.index
        offset = reader.next_s32()
        return base + offset

    @staticmethod
    def _read_rel_ptr32_at(index):
        return index + _Reader.s32_at(index)

    @staticmethod
    def _write_rel_ptr32(out, ptr):
        delta = (ptr - len(out)) & 0xFFFFFFFF
        out += struct.pack("<I", delta)

    @staticmethod
    def _write_u64(out, value):
        out += struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)

    @staticmethod
    def _read_command(reader):
        b = reader.next_u8() & 0xFF
        command = b & DehydratedDataCommand.MASK
        payload = b >> DehydratedDataCommand.PAYLOAD_SHIFT
        extra = payload - DehydratedDataCommand.MAX_SHORT_PAYLOAD
        if extra > 0:
            payload = reader.next_u8() & 0xFF
            if extra > 1:
                payload += (reader.next_u8() & 0xFF) << 8
                if extra > 2:
                    payload += (reader.next_u8() & 0xFF) << 16
            payload += DehydratedDataCommand.MAX_SHORT_PAYLOAD
        return command, payload

    @staticmethod
    def _commit(base, data):
        # Make sure the destination segment can hold initialised bytes.
        seg = ida_segment.getseg(base)
        if seg is not None and not Mem.is_loaded(base):
            Log.debug("Initialising sparse segment at %#x" % base)
        CHUNK = 0x10000
        for i in range(0, len(data), CHUNK):
            Mem.write(base + i, data[i:i + CHUNK])


# ===========================================================================
# Manual pointer scan fallback (.NET 7 / 10+ with dehydration disabled)
# ===========================================================================

def scan_for_pointers():
    lo, hi = loaded_min_max()
    pointers = []
    for s in iter_segments():
        if (s.perm & ida_segment.SEGPERM_EXEC) or not Mem.is_loaded(s.start_ea):
            continue
        ea = s.start_ea
        if ea % 8 != 0:
            ea += 8 - (ea % 8)
        end = s.end_ea
        while ea + 8 <= end:
            try:
                value = Mem.u64(ea)
                if lo <= value <= hi and Mem.is_loaded(value):
                    pointers.append(ea)
            except Exception:
                pass
            ea += 8
    Log.info("Manual scan found %d candidate pointers" % len(pointers))
    return PointerScanResult(lo, hi, pointers)


# ===========================================================================
# MethodTable / VTableChunk / Method
# ===========================================================================

class Method:
    def __init__(self, chunk, slot_index):
        self.chunk = chunk
        self.slot_index = slot_index
        self.name = "Method_%d" % slot_index

    def set_name(self, name):
        self.name = name


class VTableChunk:
    def __init__(self, direct_parent, base_index, count):
        self.direct_parent = direct_parent
        self.base_index = base_index
        self.methods = [Method(self, base_index + i) for i in range(count)]

    def size(self):
        return len(self.methods)

    def get_method(self, index):
        return self.methods[index]

    def type_name(self):
        return "%s_vtbl" % self.direct_parent.name()

    def create_type(self):
        if TF is None or not Config.CREATE_TYPES:
            return None
        name = self.type_name()
        # field names encode any assigned method names (object/string specials)
        members = [(C_PTR, sanitize_ident(m.name)) for m in self.methods]
        return TF.create_struct(name, members, force=True)


class MethodTable:
    """Unified net70/net80 MethodTable."""

    def __init__(self, manager, address):
        self.manager = manager
        self.address = address
        self._class_name = None
        self.related_type = None
        self.interfaces = []
        self.derived_types = set()
        self._vtable_chunks = None
        self._own_chunk = None
        self._instance_overridden = False

        # raw fields
        self.component_size = 0
        self.flags = 0
        self.base_size = 0
        self.related_type_address = 0
        self.hash_code = 0
        self.vtable = []
        self.interface_slots = []

    # --- naming ---

    def name(self):
        if self._class_name:
            return self._class_name
        return "Class_%x" % self.address

    def default_name(self):
        et = self.element_type()
        addr = "%x" % self.address
        table = {
            ElementType.CLASS: "Class_%s",
            ElementType.VALUETYPE: "Struct_%s",
            ElementType.NULLABLE: "Nullable_%s",
            ElementType.INTERFACE: "IInterface_%s",
            ElementType.ARRAY: "Array_%s",
            ElementType.SZARRAY: "SzArray_%s",
            ElementType.BOOLEAN: "Enum_Boolean_%s",
            ElementType.CHAR: "Enum_Char_%s",
            ElementType.SBYTE: "Enum_Sbyte_%s",
            ElementType.BYTE: "Enum_Byte_%s",
            ElementType.INT16: "Enum_Int16_%s",
            ElementType.UINT16: "Enum_Uint16_%s",
            ElementType.INT32: "Enum_Int32_%s",
            ElementType.UINT32: "Enum_Uint32_%s",
            ElementType.INT64: "Enum_Int64_%s",
            ElementType.UINT64: "Enum_Uint64_%s",
            ElementType.INTPTR: "Enum_IntPtr_%s",
            ElementType.UINTPTR: "Enum_UIntPtr_%s",
            ElementType.SINGLE: "Enum_Single_%s",
            ElementType.DOUBLE: "Enum_Double_%s",
        }
        return (table.get(et, "Type_%s")) % addr

    def set_class_name(self, name):
        self._class_name = name

    # --- element type / flags (version specific) ---

    def element_type(self):
        if self.manager.is_net70:
            return (self.flags & 0xF800) >> 11
        return (self.flags & 0x7C000000) >> 26

    def is_class(self):
        return self.element_type() == ElementType.CLASS

    def is_struct(self):
        return self.element_type() == ElementType.VALUETYPE

    def is_interface(self):
        return self.element_type() == ElementType.INTERFACE

    def is_szarray(self):
        return self.element_type() == ElementType.SZARRAY

    def is_value_type(self):
        return ElementType.is_value_type(self.element_type())

    def is_array_instance(self):
        return ElementType.is_array_instance(self.element_type())

    def kind_str(self):
        return ELEMENT_TYPE_NAMES.get(self.element_type(), "et%#x" % self.element_type())

    def data_size(self):
        return self.base_size - 0x8 - 0x8

    # --- inheritance graph ---

    def set_related_type(self, rt):
        if self.related_type is not None:
            self.related_type.derived_types.discard(self)
        self.related_type = rt
        if rt is not None:
            rt.derived_types.add(self)

    # --- memory parse ---

    def init_from_memory(self):
        ea = self.address
        if self.manager.is_net70:
            self.component_size = Mem.u16(ea)
            self.flags = Mem.u16(ea + 2)
            self.base_size = Mem.u32(ea + 4)
            self.related_type_address = Mem.u64(ea + 8)
            vt_count = Mem.u16(ea + 0x10)
            if_count = Mem.u16(ea + 0x12)
            self.hash_code = Mem.u32(ea + 0x14)
            slots_off = ea + 0x18
        else:
            self.flags = Mem.u32(ea)
            self.base_size = Mem.u32(ea + 4)
            self.related_type_address = Mem.u64(ea + 8)
            vt_count = Mem.u16(ea + 0x10)
            if_count = Mem.u16(ea + 0x12)
            self.hash_code = Mem.u32(ea + 0x14)
            slots_off = ea + 0x18

        if vt_count < 0 or vt_count >= 1000:
            raise MemError("Invalid VTable slot count %d" % vt_count)
        if if_count < 0 or if_count >= 1000:
            raise MemError("Invalid interface count %d" % if_count)

        self.vtable = [Mem.u64(slots_off + i * 8) for i in range(vt_count)]
        if_off = slots_off + vt_count * 8
        self.interface_slots = [Mem.u64(if_off + i * 8) for i in range(if_count)]

        et = self.element_type()
        if et == ElementType.INTERFACE:
            if self.base_size != 0:
                raise MemError("Unexpected non-zero interface base size")
            if self.related_type_address != 0:
                raise MemError("Unexpected non-zero interface related type")
        elif self.base_size < 0x10:
            raise MemError("Unexpected base size %#x" % self.base_size)

    # --- vtable chunks (inheritance aware) ---

    def get_vtable_chunks(self):
        if self._vtable_chunks is not None:
            return self._vtable_chunks
        result = []
        if len(self.vtable) == 0:
            self._vtable_chunks = result
            return result

        if self.is_array_instance():
            base_type = self.manager.object_mt
        else:
            base_type = self.related_type

        inherited = 0
        if base_type is not None and base_type is not self:
            for chunk in base_type.get_vtable_chunks():
                result.append(chunk)
                inherited += chunk.size()
                if inherited >= len(self.vtable):
                    break

        if inherited < len(self.vtable):
            remainder = len(self.vtable) - inherited
            self._own_chunk = VTableChunk(self, inherited, remainder)
            result.append(self._own_chunk)

        self._vtable_chunks = result
        return result

    def own_vtable_chunk(self):
        self.get_vtable_chunks()
        return self._own_chunk

    def get_method(self, slot_index):
        for chunk in self.get_vtable_chunks():
            if chunk.base_index <= slot_index < chunk.base_index + chunk.size():
                return chunk.get_method(slot_index - chunk.base_index)
        return None

    # --- IDA type construction ---

    def mt_type_name(self):
        return "%s_MT" % self.name()

    def construct_mt_type(self):
        if TF is None or not Config.CREATE_TYPES:
            return None
        members = []
        if self.manager.is_net70:
            members.append((C_U16, "m_usComponentSize"))
            members.append((C_U16, "uFlags"))
        else:
            members.append((C_U32, "uFlags"))
        members.append((C_U32, "uBaseSize"))
        members.append((C_PTR, "relatedType"))
        members.append((C_U16, "usNumVtableSlots"))
        members.append((C_U16, "usNumInterfaces"))
        members.append((C_U32, "uHashCode"))

        idx = 0
        for chunk in self.get_vtable_chunks():
            chunk.create_type()
            members.append((chunk.type_name(), "vtbl_%d" % idx))
            idx += 1

        if len(self.interface_slots) > 0:
            members.append((C_PTR, "Interfaces[%d]" % len(self.interface_slots)))

        return TF.create_struct(self.mt_type_name(), members, force=True)

    def construct_instance_type(self):
        if TF is None or not Config.CREATE_TYPES:
            return None
        if self._instance_overridden:
            return TF.get(self.name())
        # The instance struct references the MT type; make sure it exists first.
        self.construct_mt_type()
        mtname = self.mt_type_name()
        members = [("%s *" % mtname, "mt")]
        ds = self.data_size()
        if ds > 0:
            members.append((C_U8, "data[%d]" % ds))
        return TF.create_struct(self.name(), members)

    def instance_size(self):
        ds = self.data_size()
        return 8 + (ds if ds > 0 else 0)

    def commit_to_db(self):
        if TF is None or not Config.CREATE_TYPES:
            return
        self.construct_mt_type()
        try:
            TF.apply_at(self.address, self.mt_type_name())
        except Exception as ex:
            Log.debug("apply MT type failed @ %#x: %s" % (self.address, ex))
        # Ensure an instance-layout struct exists (used by frozen annotation).
        try:
            self.construct_instance_type()
        except Exception as ex:
            Log.debug("instance type failed @ %#x: %s" % (self.address, ex))
        # primary label at the method table (acts like the Ghidra `vftable').
        set_name_safe(self.address, "%s_MT" % self.name())

    def rename(self, new_name, propagate_methods=True):
        """Rename the MT type, instance type, own vtbl chunk and label.

        When propagate_methods is True, the class's own virtual-method functions
        named "<OldClass>::<method>" are renamed to "<NewClass>::<method>" too.
        Functions that were renamed elsewhere (FLIRT, Lumina, by the user) do
        not match the old prefix and are left untouched.
        """
        old = self.name()
        if old == new_name:
            return
        if TF is not None and Config.CREATE_TYPES:
            TF.rename_type(self.mt_type_name(), "%s_MT" % new_name)
            TF.rename_type(old, new_name)
            if self._own_chunk is not None:
                TF.rename_type(self._own_chunk.type_name(), "%s_vtbl" % new_name)
        self.set_class_name(new_name)
        set_name_safe(self.address, "%s_MT" % new_name)
        if propagate_methods:
            self.propagate_method_names(old, new_name)

    def propagate_method_names(self, old_name, new_name):
        """Rename this class's own method functions OldClass::X -> NewClass::X."""
        try:
            chunk = self.own_vtable_chunk()
        except Exception:
            chunk = None
        if chunk is None:
            return
        prefix = old_name + "::"
        renamed = 0
        for method in chunk.methods:
            slot = method.slot_index
            if slot < 0 or slot >= len(self.vtable):
                continue
            target = self.vtable[slot]
            if not target:
                continue
            try:
                fname = ida_funcs.get_func_name(target)
            except Exception:
                continue
            if fname and fname.startswith(prefix):
                if set_name_safe(target, "%s::%s" % (new_name, fname[len(prefix):])):
                    renamed += 1
        return renamed

    def __repr__(self):
        return "%#x (%s)" % (self.address, self.name())


class MethodTableManager:
    def __init__(self, major_version):
        self.major_version = major_version
        self.is_net70 = major_version <= 0x08
        self.method_tables = {}
        self.object_mt = None
        self.string_mt = None
        # GUI/report data (populated during analysis)
        self.directory = None
        self.rtr_address = None
        self.report_strings = []   # {ea, label, text, length}
        self.report_arrays = []    # {ea, mt, mt_addr, length, elem}
        self.report_objects = []   # {ea, mt, mt_addr}
        self.stats = {}

    def count(self):
        return len(self.method_tables)

    def get(self, address):
        return self.method_tables.get(address)

    def create_mt(self, address):
        return MethodTable(self, address)

    def register(self, mt):
        self.method_tables[mt.address] = mt

    def is_likely_code_pointer(self, value):
        if value == 0:
            return True
        return is_exec_addr(value)


# ===========================================================================
# Crawler
# ===========================================================================

OBJECT_METHOD_NAMES = ["ToString", "Equals", "GetHashCode"]
RELATED_TYPE_OFFSET = 0x08
MAX_PASSES = 100


class MethodTableCrawler:
    def __init__(self, manager, pscan):
        self.manager = manager
        self.pscan = pscan

    def analyze(self):
        m = self.manager
        if m.object_mt is None:
            obj = self.find_system_object_mt()
            if obj is None:
                Log.warn("Could not identify System.Object MethodTable; aborting crawl.")
                return
            m.object_mt = obj
        Log.info("Assuming %#x is System.Object" % m.object_mt.address)

        self.find_all_mts()
        Log.info("Found %d method tables" % m.count())

        self.assign_system_object_names(m.object_mt)

        if m.string_mt is None:
            string_mt = self.find_system_string_mt()
            if string_mt is not None:
                Log.info("Assuming %#x is System.String" % string_mt.address)
                m.string_mt = string_mt
                self.assign_system_string_names(string_mt)

        for mt in list(m.method_tables.values()):
            if mt.is_szarray():
                self.assign_szarray_names(mt)

        if Config.CREATE_TYPES:
            self.create_mt_structures()
        if Config.ASSIGN_METHODS:
            self.assign_methods()

    # --- seed: System.Object ---

    def find_system_object_mt(self):
        candidates = self.find_candidate_object_mts()
        if not candidates:
            Log.warn("No System.Object candidate found.")
            return None
        if len(candidates) > 1:
            Log.warn("Multiple System.Object candidates: %s" % [hex(c) for c in candidates])
            return None
        return self.get_or_create_mt(candidates[0])

    def find_candidate_object_mts(self):
        m = self.manager
        locations = self.pscan.pointer_locations
        result = []
        expected_flags = 0xA1000000 if m.is_net70 else 0x50000000
        n = len(locations)
        for i in range(n - 3):
            loc = locations[i]
            try:
                if loc < 0x18 + 0:
                    continue
                v0 = Mem.u64(loc)
                v1 = Mem.u64(loc + 8)
                v2 = Mem.u64(loc + 16)
                v3 = Mem.u64(loc + 24)
                if not (m.is_likely_code_pointer(v0)
                        and m.is_likely_code_pointer(v1)
                        and m.is_likely_code_pointer(v2)
                        and not m.is_likely_code_pointer(v3)):
                    continue
                if Mem.u16(loc - 0x08) != 3:
                    continue
                if Mem.u16(loc - 0x06) != 0:
                    continue
                if Mem.u64(loc - 0x10) != 0:
                    continue
                if Mem.u32(loc - 0x14) != 0x18:
                    continue
                if Mem.u32(loc - 0x18) != expected_flags:
                    continue
            except Exception:
                continue
            result.append(loc - 0x18)
        return result

    def get_or_create_mt(self, address):
        mt = self.manager.get(address)
        if mt is None:
            mt = self.manager.create_mt(address)
            mt.init_from_memory()   # may raise -> invalid MT
            mt.set_class_name(mt.default_name())
            self.manager.register(mt)
        return mt

    # --- discover all MTs by following relatedType back-references ---

    def find_all_mts(self):
        m = self.manager
        ps = self.pscan
        unmatched = list(ps.pointer_locations)

        for pass_no in range(1, MAX_PASSES):
            agenda = unmatched
            unmatched = []
            Log.debug("MT crawl pass %d: %d pointers" % (pass_no, len(agenda)))
            for loc in agenda:
                try:
                    dereferenced = Mem.u64(loc)
                except Exception:
                    continue
                if not ps.in_range(dereferenced):
                    continue
                related = m.get(dereferenced)
                if related is None:
                    unmatched.append(loc)
                    continue
                try:
                    mt = self.get_or_create_mt(loc - RELATED_TYPE_OFFSET)
                    mt.set_related_type(related)
                except Exception:
                    continue
                for iface in mt.interface_slots:
                    if iface == 0:
                        continue
                    try:
                        x = self.get_or_create_mt(iface)
                        mt.interfaces.append(x)
                    except Exception:
                        continue
            if len(unmatched) >= len(agenda):
                break

    # --- seed: System.String ---

    def find_system_string_mt(self):
        m = self.manager
        candidates = []
        for mt in m.method_tables.values():
            if (mt.related_type is m.object_mt
                    and mt.element_type() == ElementType.CLASS
                    and mt.base_size == 0x16):
                candidates.append(mt)
        if not candidates:
            Log.warn("No System.String candidate found.")
            return None
        if len(candidates) > 1:
            Log.warn("Multiple System.String candidates: %s" % [hex(c.address) for c in candidates])
            return None
        return candidates[0]

    # --- special-type naming ---

    def assign_system_object_names(self, object_mt):
        object_mt.rename(SYSTEM_OBJECT_NAME)
        chunks = object_mt.get_vtable_chunks()
        if chunks:
            chunk = chunks[0]
            for i, nm in enumerate(OBJECT_METHOD_NAMES):
                if i < chunk.size():
                    chunk.get_method(i).set_name(nm)

    def assign_system_string_names(self, string_mt):
        string_mt.rename(SYSTEM_STRING_NAME)
        if TF is not None and Config.CREATE_TYPES:
            string_mt.construct_mt_type()  # ensure System_String_MT exists first
            # pack=4 so size stays 12 (mt+_length); chars begin at offset 12.
            TF.create_struct(SYSTEM_STRING_NAME, [
                ("%s *" % string_mt.mt_type_name(), "mt"),
                (C_U32, "_length"),
            ], force=True, pack=4)
            string_mt._instance_overridden = True

    def assign_szarray_names(self, mt):
        if TF is not None and Config.CREATE_TYPES:
            mt.construct_mt_type()  # ensure <name>_MT exists first
            TF.create_struct(mt.name(), [
                ("%s *" % mt.mt_type_name(), "mt"),
                (C_U32, "Length"),
                (C_U32, "Padding"),
            ], force=True)
            mt._instance_overridden = True

    # --- type commit ---

    def create_mt_structures(self):
        n = self.manager.count()
        Log.info("Creating %d method table structures..." % n)
        done = 0
        for mt in list(self.manager.method_tables.values()):
            try:
                mt.commit_to_db()
            except Exception as ex:
                Log.debug("commit failed for %r: %s" % (mt, ex))
            done += 1
            if done % 500 == 0:
                Log.debug("  committed %d/%d" % (done, n))

    # --- method assignment (BFS from object down the hierarchy) ---

    def assign_methods(self):
        m = self.manager
        Log.info("Assigning methods to vtable slots...")
        visited = set()
        agenda = [m.object_mt]
        renamed = 0
        while agenda:
            cur = agenda.pop(0)
            if cur is None or cur.address in visited:
                continue
            visited.add(cur.address)
            for d in cur.derived_types:
                agenda.append(d)

            for i, target in enumerate(cur.vtable):
                if target == 0 or not is_exec_addr(target):
                    continue
                func = ida_funcs.get_func(target)
                if func is None:
                    if not ida_funcs.add_func(target):
                        continue
                    func = ida_funcs.get_func(target)
                    if func is None:
                        continue
                cur_name = ida_funcs.get_func_name(target) or ""
                if cur_name.startswith("FUN_") or cur_name.startswith("sub_") or cur_name == "":
                    if i < len(OBJECT_METHOD_NAMES):
                        method_name = OBJECT_METHOD_NAMES[i]
                    else:
                        method_name = "Method_%d" % i
                    full = "%s::%s" % (cur.name(), method_name)
                    if set_name_safe(target, full):
                        renamed += 1
                        # Type 'this' + __thiscall once, by the declaring class,
                        # so the name and the this-pointer type stay consistent.
                        if Config.SET_THISCALL:
                            set_thiscall(target, cur.name())
        Log.info("Renamed %d virtual method functions" % renamed)
        m.stats["methods_renamed"] = renamed


# ===========================================================================
# Frozen object annotator
# ===========================================================================

STRING_LENGTH_FIELD_OFFSET = 8
ARRAY_LENGTH_FIELD_OFFSET = 8
MAX_STRING_LENGTH = 0x10000
MAX_ARRAY_LENGTH = 0x10000

ELEMENT_C_TYPE = {
    ElementType.BOOLEAN: (C_U8, 1),
    ElementType.CHAR: (C_CHAR16, 2),
    ElementType.SBYTE: ("__int8", 1),
    ElementType.BYTE: (C_U8, 1),
    ElementType.INT16: (C_I16, 2),
    ElementType.UINT16: (C_U16, 2),
    ElementType.INT32: (C_I32, 4),
    ElementType.UINT32: (C_U32, 4),
    ElementType.INT64: (C_I64, 8),
    ElementType.UINT64: (C_U64, 8),
    ElementType.INTPTR: (C_PTR, 8),
    ElementType.UINTPTR: (C_PTR, 8),
    ElementType.SINGLE: ("float", 4),
    ElementType.DOUBLE: ("double", 8),
}


class FrozenObjectAnnotator:
    def __init__(self, manager):
        self.manager = manager

    def analyze(self, directory, pointer_locations):
        section = directory.get_section_by_type(SECTION_FROZEN_OBJECT_REGION)
        if section is None:
            Log.info("No frozen object section present in ReadyToRun directory.")
            return
        set_name_safe(section.start, FROZEN_SEGMENT_START_SYMBOL)
        count = self.annotate_objects(section, pointer_locations)
        Log.info("Annotated %d frozen objects" % count)

    def annotate_objects(self, section, pointer_locations):
        m = self.manager
        in_section = section.pointers_in_section(pointer_locations)
        Log.debug("%d pointer locations inside frozen region" % len(in_section))
        count = 0
        n_str = n_arr = n_obj = 0
        for loc in in_section:
            try:
                dereferenced = Mem.u64(loc)
            except Exception:
                continue
            mt = m.get(dereferenced)
            if mt is None:
                continue
            ok = False
            if m.string_mt is not None and mt.address == m.string_mt.address:
                ok = self.annotate_string(loc)
                n_str += ok
            elif mt.is_szarray():
                ok = self.annotate_szarray(loc, mt)
                n_arr += ok
            elif mt.is_class() or mt.is_value_type():
                ok = self.annotate_object(loc, mt)
                n_obj += ok
            if ok:
                count += 1
        Log.info("Frozen objects: %d strings, %d arrays, %d boxed/objects" %
                 (n_str, n_arr, n_obj))
        return count

    def annotate_string(self, loc):
        try:
            m = self.manager
            inst_len = 12  # mt(8) + _length(4)
            length = Mem.u32(loc + STRING_LENGTH_FIELD_OFFSET)
            if length < 0 or length >= MAX_STRING_LENGTH:
                raise MemError("string length %d out of range" % length)
            string_start = loc + inst_len
            string_end = string_start + length * 2
            if Mem.u8(string_end) != 0:
                raise MemError("no zero terminator at %#x" % string_end)

            if Config.CREATE_TYPES and TF is not None and TF.exists(SYSTEM_STRING_NAME):
                TF.apply_at(loc, SYSTEM_STRING_NAME, clear_len=inst_len)
            literal = ""
            if length > 0:
                ida_bytes.del_items(string_start, ida_bytes.DELIT_SIMPLE, length * 2 + 2)
                ida_bytes.create_strlit(string_start, length * 2, ida_nalt.STRTYPE_C_16)
                literal = read_utf16(string_start, length)
                text = make_string_label_text(literal, 56)
                label = ("dn_%s_%x" % (text, loc)) if text else ("dn_str_%x" % loc)
                # Full exact string as a repeatable comment (listing view / hover).
                try:
                    ida_bytes.set_cmt(loc, '"%s"' % literal.replace("\r", "\\r").replace("\n", "\\n"), True)
                except Exception:
                    pass
            else:
                label = "dn_String_Empty_%x" % loc
            set_name_safe(loc, label)
            self.manager.report_strings.append(
                {"ea": loc, "label": label, "text": literal, "length": length})
            return True
        except Exception as ex:
            Log.debug("string annotation failed @ %#x: %s" % (loc, ex))
            return False

    def annotate_szarray(self, loc, mt):
        element_type = mt.related_type
        if element_type is None:
            return False
        try:
            inst_len = 16  # mt(8) + Length(4) + Padding(4)
            length = Mem.u32(loc + ARRAY_LENGTH_FIELD_OFFSET)
            if length < 0 or length >= MAX_ARRAY_LENGTH:
                raise MemError("array length %d out of range" % length)
            data_start = loc + inst_len
            if Config.CREATE_TYPES and TF is not None and TF.exists(mt.name()):
                TF.apply_at(loc, mt.name(), clear_len=inst_len)
            if length > 0:
                self._apply_array(data_start, element_type, length)
            self.manager.report_arrays.append({
                "ea": loc, "mt": mt.name(), "mt_addr": mt.address,
                "length": length, "elem": element_type.name()})
            return True
        except Exception as ex:
            Log.debug("szarray annotation failed @ %#x: %s" % (loc, ex))
            return False

    def _apply_array(self, data_start, element_type, length):
        et = element_type.element_type()
        spec = ELEMENT_C_TYPE.get(et)
        if spec is not None:
            ctype, esz = spec
            total = esz * length
            if not Mem.is_loaded(data_start):
                Mem.write(data_start, b"\x00" * total)
            ida_bytes.del_items(data_start, ida_bytes.DELIT_SIMPLE, total)
            arr_name = "naot_arr_%s_%d" % (sanitize_ident(ctype), length)
            decl = "typedef %s %s[%d];" % (ctype, arr_name, length)
            try:
                ida_typeinf.parse_decls(TF.til, decl, None, ida_typeinf.HTI_DCL)
                t = TF.get(arr_name)
                if t is not None:
                    ida_typeinf.apply_tinfo(data_start, t, ida_typeinf.TINFO_DEFINITE)
            except Exception:
                pass
        else:
            # struct element array (value types / object refs) - best effort
            if Config.CREATE_TYPES and TF is not None and TF.exists(element_type.name()):
                t = TF.get(element_type.name())
                arrt = ida_typeinf.tinfo_t()
                arrt.create_array(t, length)
                total = arrt.get_size()
                if total and total != BADADDR:
                    if not Mem.is_loaded(data_start):
                        Mem.write(data_start, b"\x00" * total)
                    ida_bytes.del_items(data_start, ida_bytes.DELIT_SIMPLE, total)
                    ida_typeinf.apply_tinfo(data_start, arrt, ida_typeinf.TINFO_DEFINITE)

    def annotate_object(self, loc, mt):
        try:
            if Config.CREATE_TYPES and TF is not None and TF.exists(mt.name()):
                if TF.apply_at(loc, mt.name()):
                    self.manager.report_objects.append(
                        {"ea": loc, "mt": mt.name(), "mt_addr": mt.address})
                    return True
            return False
        except Exception:
            return False


# ===========================================================================
# Misc IDA helpers
# ===========================================================================

def set_name_safe(ea, name):
    try:
        return ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE)
    except Exception:
        return False


def read_utf16(ea, nchars):
    try:
        raw = Mem.bytes(ea, nchars * 2)
        return raw.decode("utf-16-le", "replace")
    except Exception:
        return ""


def set_thiscall(ea, owner_type_name=None):
    """Tag a virtual method as __thiscall and type arg0 ('this').

    Uses the stored prototype if present, otherwise IDA's guessed prototype, so
    the existing argument inference is preserved. When the owning class instance
    type is known, arg0 is typed as a pointer to it.
    """
    try:
        tif = ida_typeinf.tinfo_t()
        if not ida_nalt.get_tinfo(tif, ea):
            ida_typeinf.guess_tinfo(tif, ea)
        if not tif.is_func():
            return False
        ftd = ida_typeinf.func_type_data_t()
        if not tif.get_func_details(ftd):
            return False
        ftd.set_cc(ida_typeinf.CM_CC_THISCALL)

        this_t = None
        if owner_type_name and TF is not None and TF.exists(owner_type_name):
            ot = TF.get(owner_type_name)
            if ot is not None:
                this_t = ida_typeinf.tinfo_t()
                this_t.create_ptr(ot)
        if this_t is None:
            this_t = ida_typeinf.tinfo_t()
            this_t.create_ptr(ida_typeinf.tinfo_t(ida_typeinf.BT_VOID))

        if ftd.empty():
            fa = ida_typeinf.funcarg_t()
            fa.name = "this"
            fa.type = this_t
            ftd.push_back(fa)
        else:
            ftd[0].name = "this"
            ftd[0].type = this_t

        newt = ida_typeinf.tinfo_t()
        if newt.create_func(ftd):
            return ida_typeinf.apply_tinfo(ea, newt, ida_typeinf.TINFO_DEFINITE)
        return False
    except Exception:
        return False


# ===========================================================================
# Metadata report (text equivalent of the Ghidra Metadata Browser)
# ===========================================================================

ELEMENT_TYPE_NAMES = {
    ElementType.VOID: "void", ElementType.BOOLEAN: "bool", ElementType.CHAR: "char",
    ElementType.SBYTE: "sbyte", ElementType.BYTE: "byte", ElementType.INT16: "int16",
    ElementType.UINT16: "uint16", ElementType.INT32: "int32", ElementType.UINT32: "uint32",
    ElementType.INT64: "int64", ElementType.UINT64: "uint64", ElementType.INTPTR: "nint",
    ElementType.UINTPTR: "nuint", ElementType.SINGLE: "float", ElementType.DOUBLE: "double",
    ElementType.VALUETYPE: "struct", ElementType.NULLABLE: "nullable",
    ElementType.CLASS: "class", ElementType.INTERFACE: "interface",
    ElementType.SYSTEM_ARRAY: "System.Array", ElementType.ARRAY: "array",
    ElementType.SZARRAY: "szarray", ElementType.BYREF: "byref",
    ElementType.POINTER: "pointer", ElementType.FUNCTION_POINTER: "fnptr",
}


def write_report(manager, path):
    """Write a text type-hierarchy / method-table report (Browser equivalent)."""
    try:
        lines = []
        mts = sorted(manager.method_tables.values(), key=lambda x: x.address)
        lines.append("# .NET Native AOT metadata report")
        lines.append("# %d method tables" % manager.count())
        if manager.object_mt:
            lines.append("# System.Object @ %#x" % manager.object_mt.address)
        if manager.string_mt:
            lines.append("# System.String @ %#x" % manager.string_mt.address)
        lines.append("")
        for mt in mts:
            et = ELEMENT_TYPE_NAMES.get(mt.element_type(), "et%#x" % mt.element_type())
            base = ("%#x" % mt.related_type.address) if mt.related_type else "-"
            lines.append("%#x  %-9s base=%-12s vt=%-3d if=%-2d size=%#x  %s" % (
                mt.address, et, base, len(mt.vtable),
                len(mt.interface_slots), mt.base_size, mt.name()))
            if mt.interfaces:
                lines.append("        interfaces: %s" % ", ".join(
                    i.name() for i in mt.interfaces))
            for i, slot in enumerate(mt.vtable):
                method = mt.get_method(i)
                mname = method.name if method else "Method_%d" % i
                lines.append("        [%2d] %-16s -> %#x" % (i, mname, slot))
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        Log.info("Wrote metadata report to %s (%d lines)" % (path, len(lines)))
    except Exception as ex:
        Log.warn("Could not write report: %s" % ex)


# ===========================================================================
# Persistence (cache reconstructed metadata in the IDB via a netnode)
# ===========================================================================

_CACHE_NODE_NAME = "$ nativeaot.metadata"
_CACHE_TAG = ord("M")
_CACHE_VERSION = 2


class _LiteSection:
    def __init__(self, t, flags, start, end):
        self.type = t
        self.flags = flags
        self.start = start
        self.end = end

    def pointers_in_section(self, addresses):
        return [a for a in addresses if self.start <= a < self.end]


class _LiteDirectory:
    def __init__(self, major, minor, sections):
        self.major_version = major
        self.minor_version = minor
        self.sections = [_LiteSection(*s) for s in sections]

    def get_section_by_type(self, t):
        for s in self.sections:
            if s.type == t:
                return s
        return None


def save_to_idb(manager):
    """Serialize the reconstructed metadata into the IDB (compressed netnode)."""
    try:
        types = []
        for mt in manager.method_tables.values():
            types.append({
                "a": mt.address, "n": mt.name(), "f": mt.flags, "bs": mt.base_size,
                "rt": mt.related_type_address, "h": mt.hash_code & 0xFFFFFFFF,
                "cs": mt.component_size, "vt": mt.vtable, "if": mt.interface_slots,
            })
        data = {
            "ver": _CACHE_VERSION,
            "major": manager.major_version,
            "minor": manager.directory.minor_version if manager.directory else 0,
            "rtr": manager.rtr_address or 0,
            "obj": manager.object_mt.address if manager.object_mt else 0,
            "str": manager.string_mt.address if manager.string_mt else 0,
            "sections": [[s.type, s.flags, s.start, s.end]
                         for s in (manager.directory.sections if manager.directory else [])],
            "stats": manager.stats,
            "types": types,
            "strings": manager.report_strings,
            "arrays": manager.report_arrays,
            "objects": manager.report_objects,
        }
        raw = zlib.compress(json.dumps(data).encode("utf-8"), 6)
        nn = ida_netnode.netnode(_CACHE_NODE_NAME, 0, True)
        nn.delblob(0, _CACHE_TAG)
        nn.setblob(raw, 0, _CACHE_TAG)
        Log.info("Saved metadata cache to IDB (%d types, %d KB compressed)" %
                 (len(types), len(raw) // 1024))
        return True
    except Exception as ex:
        Log.warn("Failed to save metadata cache: %s" % ex)
        return False


def load_from_idb():
    """Reconstruct a MethodTableManager from the IDB cache (no re-analysis)."""
    try:
        nn = ida_netnode.netnode(_CACHE_NODE_NAME, 0, False)
        raw = nn.getblob(0, _CACHE_TAG)
        if not raw:
            return None
        data = json.loads(zlib.decompress(raw).decode("utf-8"))
        if data.get("ver") != _CACHE_VERSION:
            return None

        m = MethodTableManager(data["major"])
        m.rtr_address = data["rtr"]
        m.directory = _LiteDirectory(data["major"], data["minor"], data["sections"])
        m.stats = data.get("stats", {})

        for t in data["types"]:
            mt = m.create_mt(t["a"])
            mt.flags = t["f"]
            mt.base_size = t["bs"]
            mt.related_type_address = t["rt"]
            mt.hash_code = t["h"]
            mt.component_size = t.get("cs", 0)
            mt.vtable = t["vt"]
            mt.interface_slots = t["if"]
            mt.set_class_name(t["n"])
            m.register(mt)

        for mt in m.method_tables.values():
            mt.set_related_type(m.get(mt.related_type_address))
            mt.interfaces = [m.get(a) for a in mt.interface_slots if m.get(a) is not None]

        m.object_mt = m.get(data["obj"])
        m.string_mt = m.get(data["str"])
        m.report_strings = data["strings"]
        m.report_arrays = data["arrays"]
        m.report_objects = data["objects"]
        Log.info("Loaded metadata cache from IDB (%d types)" % m.count())
        return m
    except Exception as ex:
        Log.warn("Failed to load metadata cache: %s" % ex)
        return None


def clear_idb_cache():
    try:
        nn = ida_netnode.netnode(_CACHE_NODE_NAME, 0, False)
        nn.delblob(0, _CACHE_TAG)
    except Exception:
        pass


# ===========================================================================
# Orchestration
# ===========================================================================

def process_module(module_header):
    Log.info("Processing module header at %#x" % module_header)
    directory = ReadyToRunDirectory(module_header)
    Log.info("RTR directory: version %d.%d, %d sections" %
             (directory.major_version, directory.minor_version, len(directory.sections)))
    directory.markup()

    manager = MethodTableManager(directory.major_version)
    manager.directory = directory
    manager.rtr_address = module_header
    Log.info("Using %s method table manager" %
             ("net70" if manager.is_net70 else "net80"))

    section = directory.get_section_by_type(SECTION_DEHYDRATED_DATA)
    if section is None:
        Log.info("No dehydrated data section; attempting manual pointer scan.")
        pscan = scan_for_pointers()
    else:
        set_name_safe(section.start, DEHYDRATED_DATA_SYMBOL)
        rehydrator = MetadataRehydratorNet80(markup=Config.MARKUP_REHYDRATION_CODE)
        pscan = rehydrator.rehydrate(section.start, section.end)

    crawler = MethodTableCrawler(manager, pscan)
    crawler.analyze()

    if Config.ANNOTATE_FROZEN:
        annotator = FrozenObjectAnnotator(manager)
        try:
            annotator.analyze(directory, pscan.pointer_locations)
        except Exception as ex:
            Log.error("Frozen object annotation failed", ex)

    return manager


def can_analyze():
    if not ida_ida.inf_is_64bit():
        Log.error("Only 64-bit binaries are supported.")
        return False
    procname = ida_ida.inf_get_procname()
    if procname and "metapc" not in procname.lower():
        Log.warn("Processor '%s' is not x86; results may be unreliable." % procname)
    return True


def run():
    global TF
    Log.info("=== .NET Native AOT analyzer (IDA port) ===")
    if not can_analyze():
        return None

    Log.info("Waiting for auto-analysis to finish...")
    ida_auto.auto_wait()

    TF = TypeFactory()

    headers = locate_modules()
    if not headers:
        Log.error("ReadyToRun directory not found.")
        Log.error("Locate it manually and label it '%s' (it is the 2nd argument of the "
                  "call to StartupCodeHelpers__InitializeModules in the entry point), "
                  "then re-run." % RTR_HEADER_SYMBOL)
        return None

    managers = []
    for h in headers:
        if h == 0:
            continue
        try:
            managers.append(process_module(h))
        except Exception as ex:
            Log.error("Failed to process module header %#x" % h, ex)

    ida_auto.auto_wait()
    Log.info("=== Done. Processed %d module(s). ===" % len(managers))
    if managers:
        m = managers[0]
        Log.info("Summary: %d method tables, object=%s, string=%s" % (
            m.count(),
            ("%#x" % m.object_mt.address) if m.object_mt else "?",
            ("%#x" % m.string_mt.address) if m.string_mt else "?",
        ))
        if Config.WRITE_REPORT:
            try:
                base = ida_nalt.get_input_file_path() or idc.get_idb_path()
                report_path = (base or "nativeaot") + ".naot_report.txt"
                write_report(m, report_path)
            except Exception as ex:
                Log.warn("Report generation failed: %s" % ex)
    return managers


if __name__ == "__main__":
    run()
