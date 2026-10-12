"""Tests for the collector's Ghidra-side extractors, using stand-in Ghidra objects."""

import unittest
from unittest.mock import patch

from ghidra_syscall_analyzer.pyghidra_collector import PyGhidraCollector, UsedTypeCollector


class _JavaIterator:

    def __init__(self, items):
        self._items = list(items)

    def hasNext(self):
        return bool(self._items)

    def next(self):
        return self._items.pop(0)


class _JavaList:

    def __init__(self, items):
        self._items = list(items)

    def iterator(self):
        return _JavaIterator(self._items)


class _Named:

    def __init__(self, name):
        self._name = name

    def getName(self, qualified=False):
        return self._name

    def getSimpleName(self):
        return self._name


class _Ref:

    def __init__(self, source, ref_type="DATA"):
        self._source = source
        self._ref_type = ref_type

    def getFromAddress(self):
        return self._source

    def getReferenceType(self):
        return self._ref_type


class _ReferenceManager:

    def __init__(self, refs_to):
        self._refs_to = refs_to

    def getReferencesTo(self, address):
        return _JavaIterator(_Ref(src, kind) for src, kind in self._refs_to.get(address, []))


class _FunctionManager:
    """Functions as {name: (start, end)} over hex string addresses."""

    def __init__(self, ranges):
        self._ranges = ranges

    def getFunctionContaining(self, address):
        for name, (start, end) in self._ranges.items():
            if int(start, 16) <= int(address, 16) <= int(end, 16):
                return _Named(name)
        return None


class _Block:

    def __init__(self, name, start, size, perms="r--", initialized=True, kind="DEFAULT"):
        self._name, self._start, self._size, self._perms = name, start, size, perms
        self._initialized, self._kind = initialized, kind

    def getName(self):
        return self._name

    def getStart(self):
        return self._start

    def getEnd(self):
        return format(int(self._start, 16) + self._size - 1, "x")

    def getSize(self):
        return self._size

    def isRead(self):
        return "r" in self._perms

    def isWrite(self):
        return "w" in self._perms

    def isExecute(self):
        return "x" in self._perms

    def isInitialized(self):
        return self._initialized

    def getType(self):
        return self._kind

    def contains(self, address):
        return int(self._start, 16) <= int(address, 16) < int(self._start, 16) + self._size


class _Memory:

    def __init__(self, blocks):
        self._blocks = blocks

    def getBlocks(self):
        return list(self._blocks)

    def getBlock(self, address):
        return next((b for b in self._blocks if b.contains(address)), None)


class _FakeType:

    def __init__(self, ghidra_class, name, size=0, components=(), base=None, target=None, values=None, archive=None):
        self._class, self._name, self._size = ghidra_class, name, size
        self._components, self._base, self._target = list(components), base, target
        self._values, self._archive = values or {}, archive

    def getClass(self):
        return _Named(self._class)

    def getName(self):
        return self._name

    def getPathName(self):
        return "/" + self._name

    def getLength(self):
        return self._size

    def getSourceArchive(self):
        return _Named(self._archive) if self._archive else None

    def getComponents(self):
        return list(self._components)

    def getDefinedComponents(self):
        return list(self._components)

    def getBaseDataType(self):
        return self._base

    def getDataType(self):
        return self._target

    def getNames(self):
        return list(self._values)

    def getValue(self, name):
        return self._values[name]


class _Component:

    def __init__(self, offset, name, data_type):
        self._offset, self._name, self._type = offset, name, data_type

    def getOffset(self):
        return self._offset

    def getFieldName(self):
        return self._name

    def getDataType(self):
        return self._type

    def getLength(self):
        return self._type.getLength()


UCHAR = _FakeType("ByteDataType", "uchar", 1)
CHAR = _FakeType("CharDataType", "char", 1)
SA_FAMILY_T = _FakeType("TypedefDB", "sa_family_t", 1, base=UCHAR, archive="mac_osx")
SOCKADDR = _FakeType(
    "StructureDB", "sockaddr", 16, archive="mac_osx",
    components=[
        _Component(0, "sa_len", UCHAR),
        _Component(1, "sa_family", SA_FAMILY_T),
        _Component(2, "sa_data", _FakeType("ArrayDB", "char[14]", 14, target=CHAR)),
    ],
)
PROT = _FakeType("EnumDB", "prot_t", 4, values={"PROT_READ": 1, "PROT_WRITE": 2, "PROT_EXEC": 4})
POINTER = _FakeType("PointerDB", "pointer", 8)


class _Data:

    def __init__(self, address, label, data_type, size, preview="", pointer_to=None, string_value=None):
        self._address, self._label, self._type, self._size = address, label, data_type, size
        self._preview, self._pointer_to, self._string_value = preview, pointer_to, string_value

    def getAddress(self):
        return self._address

    def getLabel(self):
        return self._label

    def getDataType(self):
        return self._type

    def getLength(self):
        return self._size

    def getDefaultValueRepresentation(self):
        return self._preview

    def hasStringValue(self):
        return self._string_value is not None

    def isPointer(self):
        return self._pointer_to is not None

    def getValue(self):
        return self._string_value if self._string_value is not None else self._pointer_to


class _Listing:

    def __init__(self, data_items):
        self._data = data_items

    def getDefinedData(self, forward):
        return _JavaIterator(self._data)

    def getDataContaining(self, address):
        return next((d for d in self._data if d.getAddress() == address), None)


class _SymbolTable:

    def __init__(self, symbols):
        self._symbols = symbols

    def getPrimarySymbol(self, address):
        name = self._symbols.get(address)
        return _Named(name) if name else None


class _Options:

    def __init__(self, values):
        self._values = values

    def getOptionNames(self):
        return _JavaList(self._values)

    def getObject(self, name, default):
        return self._values.get(name, default)


class _Program:
    """A tiny program: `/bin/ls` at 2000 is reached via the pointer at 3000 from _process_execution."""

    def __init__(self):
        self.data = [
            _Data("2000", "s_/bin/ls", _FakeType("StringDataType", "string", 8), 8, '"/bin/ls"', string_value="/bin/ls"),
            _Data("3000", "PTR_s__bin_ls_3000", POINTER, 8, "s_/bin/ls", pointer_to="2000"),
            _Data("3008", "g_addr", SOCKADDR, 16),
        ]
        self._listing = _Listing(self.data)
        self._refs = _ReferenceManager({
            "2000": [("3000", "DATA")],
            "3000": [("1010", "READ")],
            "3008": [("1020", "WRITE"), ("1030", "READ")],
        })
        self._functions = _FunctionManager({"_process_execution": ("1000", "10ff")})
        self._memory = _Memory([
            _Block("__TEXT", "1000", 0x1000, "r-x"),
            _Block("__cstring", "2000", 0x100, "r--"),
            _Block("__DATA", "3000", 0x100, "rw-"),
            _Block("__bss", "4000", 0x100, "rw-", initialized=False),
        ])

    def getListing(self):
        return self._listing

    def getReferenceManager(self):
        return self._refs

    def getFunctionManager(self):
        return self._functions

    def getMemory(self):
        return self._memory

    def getSymbolTable(self):
        return _SymbolTable({"2000": "s_/bin/ls"})

    def getOptions(self, name):
        assert name == "Program Information"
        return _Options({"Compiler ID": "clang", "Executable Format": "Mac OS X Mach-O"})

    def getExecutablePath(self):
        return "/samples/sample_binary"

    def getExecutableMD5(self):
        return "e0cbdec65ec18790e069f12205c82e93"

    def getExecutableSHA256(self):
        return None


class TestCrossReferences(unittest.TestCase):

    def setUp(self) -> None:
        self.collector = PyGhidraCollector(target_path=__file__)
        self.program = _Program()

    def test_follows_one_pointer_hop_to_the_using_function(self) -> None:
        refs = self.collector._referencing_functions(self.program, "2000")
        self.assertEqual(refs, [{"function": "_process_execution", "at": "1010", "ref_type": "READ"}])

    def test_no_pointer_hops_when_disabled(self) -> None:
        self.assertEqual(self.collector._referencing_functions(self.program, "2000", pointer_hops=0), [])

    def test_failure_returns_empty(self) -> None:
        self.assertEqual(self.collector._referencing_functions(object(), "2000"), [])


class TestUsedTypes(unittest.TestCase):

    def test_records_composites_through_pointers_and_components(self) -> None:
        types = UsedTypeCollector()
        types.add(_FakeType("PointerDB", "sockaddr *", 8, target=SOCKADDR), "_network_operations")
        types.add(PROT, "_memory_manipulation")
        types.add(UCHAR, "_network_operations")
        by_name = {t["name"]: t for t in types.serialize()}

        self.assertEqual(set(by_name), {"sockaddr", "sa_family_t", "prot_t"})
        sockaddr = by_name["sockaddr"]
        self.assertEqual((sockaddr["kind"], sockaddr["size"], sockaddr["source_archive"]), ("struct", 16, "mac_osx"))
        self.assertEqual(
            sockaddr["fields"],
            [
                {"offset": 0, "name": "sa_len", "type": "uchar", "size": 1},
                {"offset": 1, "name": "sa_family", "type": "sa_family_t", "size": 1},
                {"offset": 2, "name": "sa_data", "type": "char[14]", "size": 14},
            ],
        )
        self.assertEqual(sockaddr["used_by"], ["_network_operations"])
        self.assertEqual(by_name["sa_family_t"]["base_type"], "uchar")
        self.assertEqual(by_name["sa_family_t"]["used_by"], [])
        self.assertEqual(by_name["prot_t"]["values"], {"PROT_READ": 1, "PROT_WRITE": 2, "PROT_EXEC": 4})

    def test_type_cap(self) -> None:
        types = UsedTypeCollector(max_types=1)
        types.add(PROT, "a")
        types.add(SOCKADDR, "b")
        self.assertEqual([t["name"] for t in types.serialize()], ["prot_t"])
        self.assertTrue(types.truncated)


class TestGlobalsMemoryAndMetadata(unittest.TestCase):

    def setUp(self) -> None:
        self.collector = PyGhidraCollector(target_path=__file__)
        self.program = _Program()

    def test_globals_skip_strings_and_carry_types_and_xrefs(self) -> None:
        types = UsedTypeCollector()
        global_data = self.collector._extract_globals(self.program, types)

        self.assertEqual([g["label"] for g in global_data], ["PTR_s__bin_ls_3000", "g_addr"])
        pointer, sockaddr = global_data
        self.assertEqual(pointer["points_to"], "s_/bin/ls")
        self.assertEqual(pointer["section"], "__DATA")
        self.assertEqual(pointer["referenced_by"], [{"function": "_process_execution", "at": "1010", "ref_type": "READ"}])
        self.assertEqual([r["ref_type"] for r in sockaddr["referenced_by"]], ["WRITE", "READ"])
        self.assertEqual([t["used_by"] for t in types.serialize() if t["name"] == "sockaddr"], [["data:g_addr"]])

    def test_strings_carry_section_and_xrefs(self) -> None:
        with patch.object(PyGhidraCollector, "_iter_defined_strings", return_value=iter([self.program.data[0]])):
            [string] = self.collector._extract_strings(self.program)
        self.assertEqual(string["section"], "__cstring")
        self.assertEqual(string["encoding"], "string")
        self.assertTrue(string["referenced"])
        self.assertEqual(string["referenced_by"][0]["function"], "_process_execution")

    def test_memory_map_permissions_and_entropy(self) -> None:
        with patch.object(PyGhidraCollector, "_read_block_bytes", return_value=bytes(range(256))):
            blocks = {b["name"]: b for b in self.collector._extract_memory_map(self.program)}
        self.assertEqual(blocks["__TEXT"]["permissions"], "r-x")
        self.assertEqual(blocks["__DATA"]["permissions"], "rw-")
        self.assertEqual(blocks["__TEXT"]["entropy"], 8.0)
        self.assertNotIn("entropy", blocks["__bss"])

    def test_memory_map_without_jpype_omits_entropy(self) -> None:
        blocks = self.collector._extract_memory_map(self.program)
        self.assertEqual(len(blocks), 4)
        self.assertTrue(all("entropy" not in b for b in blocks))

    def test_program_metadata(self) -> None:
        metadata = self.collector._extract_program_metadata(self.program)
        self.assertEqual(metadata["Compiler ID"], "clang")
        self.assertEqual(metadata["executable_md5"], "e0cbdec65ec18790e069f12205c82e93")
        self.assertIsNone(metadata["executable_sha256"])


if __name__ == "__main__":
    unittest.main()
