r"""
ida-nativeaot_browser.py - IDA Pro plugin: .NET Native AOT Metadata Browser

A PySide6 GUI front-end for the Native AOT analyzer (ida-nativeaot.py). It runs
the analysis (RTR location, rehydration, MethodTable reconstruction, frozen
object annotation) and presents the recovered metadata in a rich, navigable
dockable window with multiple tabs:

  * Overview      - sample/RTR info, section table, statistics
  * Type Hierarchy- inheritance tree + per-type detail (methods, interfaces)
  * Methods       - searchable table of all recovered virtual methods
  * Strings       - searchable table of recovered frozen string literals
  * Frozen Data   - recovered frozen arrays and boxed objects

Double-click any row/node to jump to it in IDA. A toolbar lets you (re)run the
analysis and refresh the views.

Install: copy BOTH ida-nativeaot_browser.py and ida-nativeaot.py into your IDA
plugins directory (e.g. %APPDATA%\Hex-Rays\IDA Pro\plugins or <IDADIR>/plugins).
Invoke via Edit > Plugins > "NativeAOT Metadata Browser" or the hotkey
Ctrl-Shift-N.

Requires IDA Pro 9.2+ (the IDA version that ships PySide6) and an x86-64 .NET
Native AOT binary. Developed and tested on IDA Pro 9.3.
"""

import os
import sys
import importlib.util
import traceback

import ida_idaapi
import ida_kernwin
import ida_funcs
import ida_name
import ida_idp

PLUGIN_NAME = "NativeAOT Metadata Browser"
PLUGIN_HOTKEY = "Ctrl-Shift-N"
ACTION_ID = "nativeaot:open_browser"


# ===========================================================================
# Engine loading (robust whether or not the plugins dir is on sys.path)
# ===========================================================================

_ENGINE = None


def load_engine():
    global _ENGINE
    if _ENGINE is not None:
        return _ENGINE
    here = os.path.dirname(os.path.abspath(__file__))
    # 1) reuse the engine if it was already loaded this session
    eng = sys.modules.get("nativeaot_engine")
    if eng is not None:
        _ENGINE = eng
        return eng
    # 2) explicit path load from the plugin's own directory. The engine file
    #    name contains a hyphen (ida-nativeaot.py), which is not a valid Python
    #    module identifier, so it must be loaded by path rather than `import`.
    path = os.path.join(here, "ida-nativeaot.py")
    if not os.path.isfile(path):
        raise RuntimeError(
            "ida-nativeaot.py not found next to the plugin (%s). "
            "Copy it into the same directory." % here)
    spec = importlib.util.spec_from_file_location("nativeaot_engine", path)
    eng = importlib.util.module_from_spec(spec)
    sys.modules["nativeaot_engine"] = eng
    spec.loader.exec_module(eng)
    _ENGINE = eng
    return eng


# ===========================================================================
# Qt-free data extraction (testable without a GUI)
# ===========================================================================

RTR_SECTION_NAMES = {
    200: "StringTable", 201: "GCStaticRegion", 202: "ThreadStaticRegion",
    203: "TypeManagerIndirection", 204: "EagerCctor", 205: "FrozenObjectRegion?",
    206: "FrozenObjectRegion", 207: "DehydratedData", 208: "ImportAddressTables",
    213: "ModuleInitializerList",
    301: "TypeMap", 302: "InvokeMap", 305: "DelegateMap", 306: "TypeMetadataMap",
    307: "StackTraceMetadataMap", 308: "ArrayMap", 309: "FieldAccessMap",
    310: "CCWTemplateData", 313: "BlobIdResources", 314: "BlobIdResourceIndex",
    316: "DefaultConstructorMap", 317: "StructMarshallingStubMap",
    318: "DelegateMarshallingStubMap", 319: "GenericVirtualMethodTable",
    321: "InterfaceGenericVirtualMethodTable", 322: "GenericMethodsHashtable",
    324: "GenericMethodsTemplateMap", 325: "GenericTypesTemplateMap",
    327: "NativeLayoutInfo", 330: "ExactMethodInstantiationsHashtable",
    331: "GenericTypesHashtable", 332: "TypeGenericInfoMap",
    333: "StaticsInfoHashtable", 334: "ReflectionInvokeMap",
    335: "ClassConstructorContextMap", 336: "EmbeddedMetadata",
}


def best_symbol_name(ea):
    """Best human-readable name IDA has for `ea`.

    A function's name when `ea` is a function, otherwise any label IDA already
    has at the address (user-given, PDB/DWARF, or auto-generated), falling back
    to a synthesized `sub_<ea>` only when the address is truly unnamed.

    This matters because NativeAOT vtable slots are not all method-code
    pointers: for generic types a slot can point at runtime *data* such as a
    generic dictionary (`__GenericDict_*`). Those have a real name but no
    function, so reading only `ida_funcs.get_func_name` would miss it and we
    must consult `ida_name.get_name` before giving up.
    """
    if ida_funcs.get_func(ea):
        nm = ida_funcs.get_func_name(ea)
        if nm:
            return nm
    nm = ida_name.get_name(ea)
    return nm if nm else ("sub_%X" % ea)


def ida_display_name(ea, raw):
    """IDA's full, decorated (demangled) display name for `ea`.

    Returns the name exactly as IDA would show it - demangled and untrimmed - so
    a PDB vftable symbol like ``??_7X@@6B@`` is shown as ``const X::`vftable'``
    rather than a sanitized, 64-char-truncated ``___7X_...``. Falls back to the
    raw stored name if demangling is unavailable.
    """
    gn = (getattr(ida_name, "GN_VISIBLE", 0) | getattr(ida_name, "GN_DEMANGLED", 0)
          | getattr(ida_name, "GN_LONG", 0))
    try:
        vis = ida_name.get_ea_name(ea, gn)
        if vis:
            return vis
    except Exception:
        pass
    try:
        dem = ida_name.demangle_name(raw, 0)
        if dem:
            return dem
    except Exception:
        pass
    return raw


def best_type_name(engine, mt):
    """Name to display for a type.

    Prefers the full, decorated name IDA currently has at the MethodTable address
    (PDB/DWARF or user-given), so the browser mirrors symbols applied to the
    database - including a PDB loaded *after* the analyzer ran - in full and
    decorated form. Falls back to the engine's class name (itself PDB-derived
    when the symbol was present at analysis time).

    `engine` may be None or a stub lacking these helpers (e.g. in tests); in that
    case we simply return the engine name.
    """
    try:
        live = engine.existing_symbol_name(mt.address)
        if live:
            return ida_display_name(mt.address, live)
    except Exception:
        pass
    return mt.name()


def rtr_layout_label(runtime):
    """Human label for the metadata layout the analyzer used. The "net70" path
    handles .NET 7 (RTR major <= 8); "net80" handles .NET 8/9/10 (major >= 9)."""
    return ".NET 7 layout" if runtime == "net70" else ".NET 8+ layout"


def rtr_dotnet_hint(major):
    """Best-effort .NET product version for an RTR header major version.

    The RTR/NativeAOT header major version is the metadata *format* version, not
    the .NET product version, and the two do not track linearly (e.g. .NET 10
    jumped to 16). Values verified against dotnet/runtime
    (.../Internal/Runtime/ModuleHeaders.cs CurrentMajorVersion per release branch).
    Display only; returns None for unknown majors (e.g. unreleased .NET 11 = 22).
    """
    return {8: ".NET 7", 9: ".NET 8", 10: ".NET 9", 16: ".NET 10"}.get(major)


class BrowserData:
    """Pure-data view over a MethodTableManager (no Qt dependency)."""

    def __init__(self, engine, manager):
        self.engine = engine
        self.m = manager

    # --- overview ---

    def overview(self):
        m = self.m
        from collections import Counter
        dist = Counter()
        for mt in m.method_tables.values():
            dist[mt.kind_str()] += 1
        return {
            "rtr_address": m.rtr_address,
            "version": (m.directory.major_version, m.directory.minor_version) if m.directory else (0, 0),
            "runtime": "net70" if m.is_net70 else "net80",
            "sections": len(m.directory.sections) if m.directory else 0,
            "total_types": m.count(),
            "object_mt": m.object_mt.address if m.object_mt else None,
            "string_mt": m.string_mt.address if m.string_mt else None,
            "kind_dist": dict(dist),
            "n_strings": len(m.report_strings),
            "n_arrays": len(m.report_arrays),
            "n_objects": len(m.report_objects),
            "methods_renamed": m.stats.get("methods_renamed", 0),
        }

    def section_rows(self):
        m = self.m
        rows = []
        if not m.directory:
            return rows
        for i, s in enumerate(m.directory.sections):
            rows.append((i, s.type, RTR_SECTION_NAMES.get(s.type, ""),
                         s.flags, s.start, s.end))
        return rows

    # --- types ---

    def roots(self):
        """Top-level types for the hierarchy tree."""
        m = self.m
        rset = []
        for mt in m.method_tables.values():
            rt = mt.related_type
            if rt is None or (rt is not m.object_mt and rt.address not in m.method_tables):
                rset.append(mt)
        # object itself is a root
        if m.object_mt is not None and m.object_mt not in rset:
            rset.insert(0, m.object_mt)
        return sorted(rset, key=lambda x: x.name().lower())

    @staticmethod
    def children(mt):
        return sorted(mt.derived_types, key=lambda x: x.name().lower())

    def display_name(self, mt):
        """Type name to show: IDA's live PDB/user name when present, else the
        engine's class name. Keeps every type view in sync with the database."""
        return best_type_name(self.engine, mt)

    def type_detail(self, mt):
        """Return dict with header info + methods + interfaces for a type."""
        methods = []
        for i, target in enumerate(mt.vtable):
            method = mt.get_method(i)
            decl = self.display_name(method.chunk.direct_parent) if method else self.display_name(mt)
            if target:
                fname = best_symbol_name(target)
            else:
                fname = "(abstract)"
            methods.append({
                "slot": i, "name": fname, "ea": target,
                "decl": decl, "inherited": decl != self.display_name(mt),
            })
        interfaces = [{"name": self.display_name(i), "ea": i.address} for i in mt.interfaces]
        return {
            "name": self.display_name(mt), "kind": mt.kind_str(), "address": mt.address,
            "base": (self.display_name(mt.related_type) if mt.related_type else None),
            "base_ea": (mt.related_type.address if mt.related_type else None),
            "base_size": mt.base_size, "hash": mt.hash_code,
            "vtable_count": len(mt.vtable), "iface_count": len(mt.interface_slots),
            "methods": methods, "interfaces": interfaces,
        }

    def type_rows(self):
        """Flat list of all types."""
        rows = []
        for mt in self.m.method_tables.values():
            rows.append({
                "ea": mt.address, "name": self.display_name(mt), "kind": mt.kind_str(),
                "base": self.display_name(mt.related_type) if mt.related_type else "",
                "vt": len(mt.vtable), "if": len(mt.interface_slots),
                "size": mt.base_size,
            })
        return rows

    # --- methods (deduplicated by entry point) ---

    def method_rows(self):
        seen = {}
        for mt in self.m.method_tables.values():
            for i, target in enumerate(mt.vtable):
                if not target:
                    continue
                if target in seen:
                    continue
                method = mt.get_method(i)
                decl = self.display_name(method.chunk.direct_parent) if method else self.display_name(mt)
                fname = best_symbol_name(target)
                seen[target] = {"ea": target, "name": fname, "owner": decl, "slot": i}
        return list(seen.values())

    # --- strings / frozen data ---

    def string_rows(self):
        return list(self.m.report_strings)

    def _type_name_at(self, addr, fallback):
        """Resolve a type's current display name from its MT address (so frozen
        rows reflect PDB/user names too), falling back to the cached string."""
        mt = self.m.get(addr) if addr else None
        return self.display_name(mt) if mt is not None else fallback

    def array_rows(self):
        rows = []
        for a in self.m.report_arrays:
            rows.append({
                "ea": a["ea"],
                "mt": self._type_name_at(a.get("mt_addr"), a["mt"]),
                "length": a["length"],
                "elem": self._type_name_at(a.get("elem_addr"), a["elem"]),
                "mt_addr": a["mt_addr"],
            })
        return rows

    def object_rows(self):
        rows = []
        for o in self.m.report_objects:
            rows.append({
                "ea": o["ea"],
                "mt": self._type_name_at(o.get("mt_addr"), o["mt"]),
                "mt_addr": o["mt_addr"],
            })
        return rows


# ===========================================================================
# GUI (PySide6) - only imported when actually shown
# ===========================================================================

def _import_qt():
    try:
        from PySide6 import QtWidgets, QtCore, QtGui
        return QtWidgets, QtCore, QtGui
    except Exception as ex:
        raise RuntimeError(
            "PySide6 is required and is only available in the GUI version of "
            "IDA (not idalib). Error: %s" % ex)


class _RenameHook(ida_idp.IDB_Hooks):
    """Fires our callback whenever ANY address is renamed in IDA.

    This catches manual renames, FLIRT/IDS signature application, Lumina pulls,
    type/struct changes, etc. — so the browser can stay in sync with the IDB.
    """
    def __init__(self, on_renamed):
        ida_idp.IDB_Hooks.__init__(self)
        self._on_renamed = on_renamed

    def renamed(self, *args):
        try:
            self._on_renamed(args[0])  # args[0] == ea
        except Exception:
            pass
        return 0


def _form_to_widget(form_obj, form):
    """Return the parent QWidget for a PluginForm, robust across IDA builds.

    IDA 9.2+ ships PySide6, but PluginForm.FormToPySideWidget() routes through
    `ctx.QtGui.QWidget.FromCapsule()`, which is broken for PySide6 (QWidget
    lives in QtWidgets and the call depends on a context module that a plugin
    does not provide). FormToPyQtWidget() / TWidgetToQtPythonWidget() uses
    shiboken6 + PySide6.QtWidgets directly and returns a real PySide6 widget,
    so we prefer it and only fall back to the PySide variant.
    """
    for meth in ("FormToPyQtWidget", "TWidgetToQtPythonWidget", "FormToPySideWidget"):
        fn = getattr(form_obj, meth, None) or getattr(ida_kernwin.PluginForm, meth, None)
        if fn is None:
            continue
        try:
            w = fn(form)
            if w is not None:
                return w
        except Exception:
            continue
    raise RuntimeError("Could not obtain a Qt widget from the IDA form")


def jump(ea):
    if ea and ea != ida_idaapi.BADADDR:
        ida_kernwin.jumpto(ea)


def apply_rename(data, ea, new, as_type):
    """Apply a rename and return the resulting display name (or None).

    For a type (as_type=True) this propagates through the engine so the
    MethodTable type, instance type, vtable-chunk type and the address label
    are all renamed together (lazily initialising the engine's TypeFactory if
    the metadata was loaded from the IDB cache). Otherwise it renames the
    symbol at the address.
    """
    new = (new or "").strip()
    if not new:
        return None
    if as_type:
        mt = data.m.get(ea)
        if mt is not None:
            eng = load_engine()
            if getattr(eng, "TF", None) is None:
                eng.TF = eng.TypeFactory()
            mt.rename(new)
            return mt.name()
    ida_name.set_name(ea, new, ida_name.SN_NOCHECK | ida_name.SN_FORCE)
    return ida_name.get_name(ea)


def build_browser_widget(parent, data):
    """Construct the full browser UI inside `parent` (a QWidget)."""
    QtWidgets, QtCore, QtGui = _import_qt()
    Qt = QtCore.Qt

    HEX = lambda v: ("%#x" % v) if isinstance(v, int) else str(v)

    # Engine handle for live type-name resolution (PDB/user names). Tolerates a
    # missing/stub engine (tests) by falling back to mt.name() inside disp().
    try:
        _eng = load_engine()
    except Exception:
        _eng = None

    def disp(mt):
        return best_type_name(_eng, mt)

    # ---- Theme-agnostic polish ----------------------------------------
    # We deliberately do NOT hardcode background/foreground colors, so the
    # plugin inherits the user's IDA theme (e.g. dp701). The only fix needed is
    # the alternating-row + selection colors: by default Qt paints alternate
    # rows with the palette's light "AlternateBase", which becomes white-on-
    # white text under a dark theme. We override them with *translucent* greys/
    # blues that blend over whatever base color the theme provides, so rows and
    # selections stay readable on both dark and light themes.
    parent.setStyleSheet(
        "QAbstractItemView {"
        "  alternate-background-color: rgba(127,127,127,34);"
        "}"
        "QAbstractItemView::item { padding: 1px 3px; }"
        "QAbstractItemView::item:selected {"
        "  background: rgba(53,132,228,180); color: #ffffff;"
        "}"
        "QTreeView::item:selected, QTableView::item:selected {"
        "  background: rgba(53,132,228,180); color: #ffffff;"
        "}"
        "QHeaderView::section { padding: 3px; }"
    )
    # HTML documents (Overview + type detail): only override link colour, which
    # otherwise defaults to a near-black blue that is unreadable on dark themes.
    DOC_CSS = ("a { color: #3b9dff; text-decoration: none; } "
               "th { text-align: left; } td { padding: 2px 6px; }")

    # ---- type-kind icons (drawn programmatically; no image files needed) ----
    def kind_glyph(kind):
        if kind == "class":
            return ("C", "#4CAF50")
        if kind == "struct":
            return ("S", "#2196F3")
        if kind == "interface":
            return ("I", "#9C27B0")
        if kind in ("szarray", "array", "System.Array"):
            return ("A", "#607D8B")
        if kind == "nullable":
            return ("N", "#00BCD4")
        if kind == "void":
            return ("T", "#9E9E9E")
        return ("E", "#FF9800")  # primitives / enums

    _icon_cache = {}

    def kind_icon(kind):
        if kind in _icon_cache:
            return _icon_cache[kind]
        letter, color = kind_glyph(kind)
        pm = QtGui.QPixmap(16, 16)
        pm.fill(Qt.transparent)
        p = QtGui.QPainter(pm)
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        p.setBrush(QtGui.QColor(color))
        p.setPen(Qt.NoPen)
        p.drawRoundedRect(1, 1, 14, 14, 3, 3)
        p.setPen(QtGui.QColor("white"))
        f = p.font()
        f.setBold(True)
        f.setPixelSize(10)
        p.setFont(f)
        p.drawText(pm.rect(), Qt.AlignCenter, letter)
        p.end()
        icon = QtGui.QIcon(pm)
        _icon_cache[kind] = icon
        return icon

    def clip(text):
        QtWidgets.QApplication.clipboard().setText(str(text))

    def ask_rename(cur, as_type, ea, on_done):
        new, ok = QtWidgets.QInputDialog.getText(
            parent, "Rename", "New name:", text=cur or "")
        if not ok:
            return
        try:
            result = apply_rename(data, ea, new, as_type)
            if result and on_done:
                on_done(result)
        except Exception as ex:
            QtWidgets.QMessageBox.warning(parent, "Rename failed", str(ex))

    # ---- helper: a filtered table widget ----
    def make_table(headers, rows, ea_col=0, hex_cols=(), numeric_cols=()):
        table = QtWidgets.QTableWidget(len(rows), len(headers), parent)
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        table.setAlternatingRowColors(True)
        table.verticalHeader().setVisible(False)
        table.setSortingEnabled(False)
        for r, row in enumerate(rows):
            for c, val in enumerate(row):
                if c in hex_cols and isinstance(val, int):
                    text = "%#x" % val
                else:
                    text = "" if val is None else str(val)
                item = QtWidgets.QTableWidgetItem()
                if c in numeric_cols and isinstance(val, int):
                    item.setData(Qt.DisplayRole, val)
                else:
                    item.setText(text)
                if c == 0 and isinstance(row[ea_col], int):
                    item.setData(Qt.UserRole, row[ea_col])
                table.setItem(r, c, item)
        table.setSortingEnabled(True)
        table.resizeColumnsToContents()
        table.horizontalHeader().setStretchLastSection(True)
        return table

    def wire_table_jump(table, ea_col=0):
        def on_double(item):
            row = item.row()
            it0 = table.item(row, 0)
            ea = it0.data(Qt.UserRole) if it0 else None
            if ea is not None:
                jump(ea)
        table.itemDoubleClicked.connect(on_double)

    def wire_table_context(table, name_col=1, as_type=False):
        table.setContextMenuPolicy(Qt.CustomContextMenu)

        def on_menu(pos):
            it = table.itemAt(pos)
            if it is None:
                return
            row = it.row()
            it0 = table.item(row, 0)
            ea = it0.data(Qt.UserRole) if it0 else None
            name_item = table.item(row, name_col) if name_col is not None else None
            name = name_item.text() if name_item else ""
            menu = QtWidgets.QMenu(table)
            a_jump = menu.addAction("Jump to %#x" % ea) if ea else None
            a_cn = menu.addAction("Copy name")
            a_ca = menu.addAction("Copy address") if ea else None
            menu.addSeparator()
            a_rn = menu.addAction(
                "Rename type (propagate)..." if as_type else "Rename...")
            chosen = menu.exec(table.viewport().mapToGlobal(pos))
            if chosen is None:
                return
            if chosen is a_jump and ea:
                jump(ea)
            elif chosen is a_cn:
                clip(name)
            elif chosen is a_ca and ea:
                clip("%#x" % ea)
            elif chosen is a_rn and ea is not None:
                def done(newname):
                    if name_item:
                        name_item.setText(newname)
                ask_rename(name, as_type, ea, done)
        table.customContextMenuRequested.connect(on_menu)

    def make_search(table):
        edit = QtWidgets.QLineEdit(parent)
        edit.setPlaceholderText("Filter (substring, case-insensitive)...")

        def on_text(txt):
            txt = txt.lower().strip()
            for r in range(table.rowCount()):
                if not txt:
                    table.setRowHidden(r, False)
                    continue
                match = False
                for c in range(table.columnCount()):
                    it = table.item(r, c)
                    if it and txt in it.text().lower():
                        match = True
                        break
                table.setRowHidden(r, not match)
        edit.textChanged.connect(on_text)
        return edit

    root_layout = QtWidgets.QVBoxLayout(parent)
    root_layout.setContentsMargins(4, 4, 4, 4)

    # ---- top toolbar ----
    toolbar = QtWidgets.QHBoxLayout()
    ov = data.overview()
    title = QtWidgets.QLabel(
        "<b>NativeAOT</b>  RTR @ %s  fmt v%d.%d (%s)  |  %d types  |  %d methods  |  "
        "%d strings" % (
            HEX(ov["rtr_address"]), ov["version"][0], ov["version"][1],
            rtr_layout_label(ov["runtime"]), ov["total_types"],
            ov["methods_renamed"], ov["n_strings"]))
    toolbar.addWidget(title)
    toolbar.addStretch(1)
    btn_refresh = QtWidgets.QPushButton("↻ Refresh names", parent)
    btn_refresh.setToolTip("Re-read names from the IDB (after Lumina / FLIRT / "
                           "manual renames) without re-running analysis")
    toolbar.addWidget(btn_refresh)
    btn_rerun = QtWidgets.QPushButton("Re-run Analysis", parent)
    toolbar.addWidget(btn_rerun)
    root_layout.addLayout(toolbar)

    # ea -> widget-item indexes used for live name synchronisation
    method_items = {}        # function ea -> Methods-table name QTableWidgetItem
    string_items = {}        # frozen-string ea -> Strings-table label item
    type_name_items = {}     # MT ea -> Types-table name item
    tree_items_by_ea = {}    # MT ea -> [QTreeWidgetItem, ...]

    tabs = QtWidgets.QTabWidget(parent)
    root_layout.addWidget(tabs)

    # ===================== Overview tab =====================
    ov_widget = QtWidgets.QWidget(parent)
    ov_l = QtWidgets.QVBoxLayout(ov_widget)
    info = QtWidgets.QTextBrowser(parent)
    info.document().setDefaultStyleSheet(DOC_CSS)
    dist = ov["kind_dist"]
    dist_html = ", ".join("%s: %d" % (k, v) for k, v in sorted(dist.items(), key=lambda x: -x[1]))
    _layout = rtr_layout_label(ov["runtime"])
    _hint = rtr_dotnet_hint(ov["version"][0])
    _hint_html = ("&nbsp;- likely %s" % _hint) if _hint else ""
    info.setHtml(
        "<h2>.NET Native AOT</h2>"
        "<table cellpadding=4>"
        "<tr><td><b>ReadyToRun header</b></td><td>%s</td></tr>"
        "<tr><td><b>ReadyToRun format</b></td><td>v%d.%d &nbsp;(%s)%s</td></tr>"
        "<tr><td><b>RTR sections</b></td><td>%d</td></tr>"
        "<tr><td><b>System.Object MT</b></td><td>%s</td></tr>"
        "<tr><td><b>System.String MT</b></td><td>%s</td></tr>"
        "<tr><td><b>Method tables</b></td><td>%d</td></tr>"
        "<tr><td><b>Virtual methods named (by analyzer)</b></td><td>%d</td></tr>"
        "<tr><td><b>Frozen strings</b></td><td>%d</td></tr>"
        "<tr><td><b>Frozen arrays</b></td><td>%d</td></tr>"
        "<tr><td><b>Frozen boxed objects</b></td><td>%d</td></tr>"
        "</table>"
        "<p style='color:#888'>ReadyToRun format is the metadata format version, "
        "not the .NET product version (they do not track linearly). "
        "\"Virtual methods named (by analyzer)\" counts only methods the analyzer "
        "renamed; methods that already had symbols (e.g. from a PDB) are left "
        "untouched and not counted.</p>"
        "<p><b>Type kinds:</b> %s</p>" % (
            HEX(ov["rtr_address"]), ov["version"][0], ov["version"][1], _layout, _hint_html,
            ov["sections"], HEX(ov["object_mt"]), HEX(ov["string_mt"]),
            ov["total_types"], ov["methods_renamed"], ov["n_strings"],
            ov["n_arrays"], ov["n_objects"], dist_html))
    info.setMaximumHeight(360)
    ov_l.addWidget(info)
    ov_l.addWidget(QtWidgets.QLabel("<b>ReadyToRun section table</b>", parent))
    # section_rows: (i, type, name, flags, start, end); jump to Start column
    sec_table = make_table(
        ["#", "Type", "Name", "Flags", "Start", "End"],
        [(s[0], s[1], s[2], s[3], s[4], s[5]) for s in data.section_rows()],
        ea_col=4, hex_cols=(4, 5), numeric_cols=(0, 1))
    wire_table_jump(sec_table)
    wire_table_context(sec_table, name_col=2, as_type=False)
    ov_l.addWidget(sec_table)
    tabs.addTab(ov_widget, "Overview")

    # ===================== Type Hierarchy tab =====================
    types_widget = QtWidgets.QWidget(parent)
    types_l = QtWidgets.QVBoxLayout(types_widget)
    splitter = QtWidgets.QSplitter(Qt.Horizontal, parent)

    # left: tree
    left = QtWidgets.QWidget(parent)
    left_l = QtWidgets.QVBoxLayout(left)
    left_l.setContentsMargins(0, 0, 0, 0)
    tree_search = QtWidgets.QLineEdit(parent)
    tree_search.setPlaceholderText("Find type...")
    left_l.addWidget(tree_search)
    tree = QtWidgets.QTreeWidget(parent)
    tree.setHeaderLabels(["Type", "Kind", "Address"])
    tree.setColumnWidth(0, 280)
    tree.setAlternatingRowColors(True)
    left_l.addWidget(tree)
    splitter.addWidget(left)

    LAZY = "__lazy__"

    def make_tree_item(mt):
        it = QtWidgets.QTreeWidgetItem([disp(mt), mt.kind_str(), "%#x" % mt.address])
        it.setData(0, Qt.UserRole, mt.address)
        it.setData(0, Qt.UserRole + 1, mt)
        it.setIcon(0, kind_icon(mt.kind_str()))
        tree_items_by_ea.setdefault(mt.address, []).append(it)
        if mt.derived_types:
            placeholder = QtWidgets.QTreeWidgetItem([LAZY])
            it.addChild(placeholder)
        return it

    for root_mt in data.roots():
        tree.addTopLevelItem(make_tree_item(root_mt))

    def materialize(item):
        # Replace a lazy placeholder with the node's real children (idempotent).
        if item.childCount() == 1 and item.child(0).text(0) == LAZY:
            item.removeChild(item.child(0))
            mt = item.data(0, Qt.UserRole + 1)
            for ch in data.children(mt):
                item.addChild(make_tree_item(ch))

    def on_expand(item):
        materialize(item)
    tree.itemExpanded.connect(on_expand)

    # right: detail
    detail = QtWidgets.QTextBrowser(parent)
    detail.document().setDefaultStyleSheet(DOC_CSS)
    detail.setOpenLinks(False)
    splitter.addWidget(detail)
    splitter.setSizes([420, 520])
    types_l.addWidget(splitter)
    tabs.addTab(types_widget, "Type Hierarchy")

    # ===================== Types (flat, fully searchable) tab =====================
    flat_widget = QtWidgets.QWidget(parent)
    flat_l = QtWidgets.QVBoxLayout(flat_widget)
    trows = sorted(data.type_rows(), key=lambda r: r["name"].lower())
    ttable = make_table(
        ["Address", "Name", "Kind", "Base", "VT", "IF", "Size"],
        [(r["ea"], r["name"], r["kind"], r["base"], r["vt"], r["if"], r["size"]) for r in trows],
        ea_col=0, hex_cols=(0, 6), numeric_cols=(4, 5))
    wire_table_jump(ttable)
    wire_table_context(ttable, name_col=1, as_type=True)
    for r in range(ttable.rowCount()):
        kc = ttable.item(r, 2)
        ni = ttable.item(r, 1)
        it0 = ttable.item(r, 0)
        if kc and ni:
            ni.setIcon(kind_icon(kc.text()))
        if it0 is not None and ni is not None:
            ea = it0.data(Qt.UserRole)
            if ea is not None:
                type_name_items[ea] = ni
    flat_l.addWidget(make_search(ttable))
    flat_l.addWidget(ttable)
    tabs.addTab(flat_widget, "Types (%d)" % len(trows))

    # detail rendering + anchor navigation
    def render_detail(mt):
        d = data.type_detail(mt)
        html = ["<h3>%s</h3>" % d["name"]]
        html.append("<table cellpadding=3>")
        html.append("<tr><td><b>Kind</b></td><td>%s</td></tr>" % d["kind"])
        html.append("<tr><td><b>MethodTable</b></td><td><a href='ea:%d'>%#x</a></td></tr>" % (d["address"], d["address"]))
        if d["base"]:
            html.append("<tr><td><b>Base</b></td><td><a href='ea:%d'>%s</a></td></tr>" % (d["base_ea"], d["base"]))
        html.append("<tr><td><b>Base size</b></td><td>%#x</td></tr>" % d["base_size"])
        html.append("<tr><td><b>Hash</b></td><td>%#x</td></tr>" % (d["hash"] & 0xffffffff))
        html.append("</table>")
        if d["interfaces"]:
            html.append("<p><b>Interfaces (%d):</b><br>" % len(d["interfaces"]))
            html.append("<br>".join(
                "&nbsp;&nbsp;<a href='ea:%d'>%s</a>" % (i["ea"], i["name"]) for i in d["interfaces"]))
            html.append("</p>")
        html.append("<p><b>VTable (%d slots):</b></p>" % d["vtable_count"])
        html.append("<table cellpadding=3 width='100%'>")
        html.append("<tr><th align=left>#</th><th align=left>Method</th><th align=left>Address</th><th align=left>Declared in</th></tr>")
        for mrow in d["methods"]:
            ea = mrow["ea"]
            link = ("<a href='ea:%d'>%#x</a>" % (ea, ea)) if ea else "<i>abstract</i>"
            inh = "" if not mrow["inherited"] else (" <i>(%s)</i>" % mrow["decl"])
            html.append("<tr><td>%d</td><td>%s%s</td><td>%s</td><td>%s</td></tr>" % (
                mrow["slot"], mrow["name"], inh, link, mrow["decl"]))
        html.append("</table>")
        detail.setHtml("".join(html))

    def on_tree_select():
        items = tree.selectedItems()
        if items:
            mt = items[0].data(0, Qt.UserRole + 1)
            if mt is not None:
                render_detail(mt)
    tree.itemSelectionChanged.connect(on_tree_select)
    tree.itemDoubleClicked.connect(lambda it, col: jump(it.data(0, Qt.UserRole)))

    # tree context menu
    tree.setContextMenuPolicy(Qt.CustomContextMenu)

    def on_tree_menu(pos):
        it = tree.itemAt(pos)
        if it is None:
            return
        mt = it.data(0, Qt.UserRole + 1)
        ea = it.data(0, Qt.UserRole)
        if mt is None:
            return
        menu = QtWidgets.QMenu(tree)
        a_jump = menu.addAction("Jump to %#x" % ea) if ea else None
        a_cn = menu.addAction("Copy name")
        a_ca = menu.addAction("Copy address") if ea else None
        menu.addSeparator()
        a_rn = menu.addAction("Rename type (propagate)...")
        chosen = menu.exec(tree.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        if chosen is a_jump and ea:
            jump(ea)
        elif chosen is a_cn:
            clip(mt.name())
        elif chosen is a_ca and ea:
            clip("%#x" % ea)
        elif chosen is a_rn:
            def done(newname):
                it.setText(0, mt.name())
                render_detail(mt)
            ask_rename(mt.name(), True, ea, done)
    tree.customContextMenuRequested.connect(on_tree_menu)

    def on_detail_anchor(url):
        s = url.toString()
        if s.startswith("ea:"):
            try:
                jump(int(s[3:]))
            except Exception:
                pass
    detail.anchorClicked.connect(on_detail_anchor)

    # The tree is lazily populated (a collapsed node holds only a placeholder),
    # so a plain walk would never see types inside collapsed branches. Before
    # searching we materialize the whole tree once; matches are then revealed by
    # expanding their ancestors. Clearing the search restores the collapsed view.
    _tree_materialized = [False]

    def materialize_all():
        if _tree_materialized[0]:
            return
        stack = [tree.topLevelItem(i) for i in range(tree.topLevelItemCount())]
        while stack:
            it = stack.pop()
            materialize(it)
            for i in range(it.childCount()):
                ch = it.child(i)
                if ch.text(0) != LAZY:
                    stack.append(ch)
        _tree_materialized[0] = True

    def on_tree_search(txt):
        txt = txt.lower().strip()
        if txt:
            materialize_all()

        def walk(item):
            if item.text(0) == LAZY:
                item.setHidden(True)
                return False
            # Match against every column (Type, Kind, Address), substring + ci,
            # so the tree behaves like the table filters.
            if txt:
                hit = any(txt in item.text(c).lower()
                          for c in range(item.columnCount()))
            else:
                hit = True
            child_hit = False
            for i in range(item.childCount()):
                child_hit = walk(item.child(i)) or child_hit
            item.setHidden(bool(txt) and not hit and not child_hit)
            if txt and child_hit:
                item.setExpanded(True)
            return hit or child_hit

        for i in range(tree.topLevelItemCount()):
            walk(tree.topLevelItem(i))
        if not txt:
            tree.collapseAll()
    tree_search.textChanged.connect(on_tree_search)

    # ===================== Methods tab =====================
    methods_widget = QtWidgets.QWidget(parent)
    methods_l = QtWidgets.QVBoxLayout(methods_widget)
    mrows = sorted(data.method_rows(), key=lambda r: r["owner"].lower())
    mtable = make_table(
        ["Address", "Method", "Owner class", "Slot"],
        [(r["ea"], r["name"], r["owner"], r["slot"]) for r in mrows],
        ea_col=0, hex_cols=(0,), numeric_cols=(3,))
    wire_table_jump(mtable)
    wire_table_context(mtable, name_col=1, as_type=False)
    for r in range(mtable.rowCount()):
        it0 = mtable.item(r, 0)
        ni = mtable.item(r, 1)
        if it0 is not None and ni is not None:
            ea = it0.data(Qt.UserRole)
            if ea is not None:
                method_items[ea] = ni
    methods_l.addWidget(make_search(mtable))
    methods_l.addWidget(mtable)
    tabs.addTab(methods_widget, "Methods (%d)" % len(mrows))

    # ===================== Strings tab =====================
    strings_widget = QtWidgets.QWidget(parent)
    strings_l = QtWidgets.QVBoxLayout(strings_widget)
    srows = data.string_rows()
    stable = make_table(
        ["Address", "Length", "Text", "Label"],
        [(s["ea"], s["length"], s["text"], s["label"]) for s in srows],
        ea_col=0, hex_cols=(0,), numeric_cols=(1,))
    wire_table_jump(stable)
    wire_table_context(stable, name_col=3, as_type=False)
    for r in range(stable.rowCount()):
        it0 = stable.item(r, 0)
        li = stable.item(r, 3)
        if it0 is not None and li is not None:
            ea = it0.data(Qt.UserRole)
            if ea is not None:
                string_items[ea] = li
    strings_l.addWidget(make_search(stable))
    strings_l.addWidget(stable)
    tabs.addTab(strings_widget, "Strings (%d)" % len(srows))

    # ===================== Frozen Data tab =====================
    frozen_widget = QtWidgets.QWidget(parent)
    frozen_l = QtWidgets.QVBoxLayout(frozen_widget)
    sub = QtWidgets.QTabWidget(parent)
    arows = data.array_rows()
    atable = make_table(
        ["Address", "Array type", "Length", "Element type", "MT"],
        [(a["ea"], a["mt"], a["length"], a["elem"], a["mt_addr"]) for a in arows],
        ea_col=0, hex_cols=(0, 4), numeric_cols=(2,))
    wire_table_jump(atable)
    wire_table_context(atable, name_col=1, as_type=False)
    aw = QtWidgets.QWidget(parent)
    awl = QtWidgets.QVBoxLayout(aw)
    awl.addWidget(make_search(atable))
    awl.addWidget(atable)
    sub.addTab(aw, "Arrays (%d)" % len(arows))

    orows = data.object_rows()
    otable = make_table(
        ["Address", "Type", "MT"],
        [(o["ea"], o["mt"], o["mt_addr"]) for o in orows],
        ea_col=0, hex_cols=(0, 2))
    wire_table_jump(otable)
    wire_table_context(otable, name_col=1, as_type=False)
    owt = QtWidgets.QWidget(parent)
    owl = QtWidgets.QVBoxLayout(owt)
    owl.addWidget(make_search(otable))
    owl.addWidget(otable)
    sub.addTab(owt, "Boxed objects (%d)" % len(orows))
    frozen_l.addWidget(sub)
    tabs.addTab(frozen_widget, "Frozen Data")

    # ===================== live name synchronisation =====================
    def _live_func_name(ea):
        return best_symbol_name(ea)

    def _refresh_one(ea):
        try:
            it = method_items.get(ea)
            if it is not None:
                it.setText(_live_func_name(ea))
            sit = string_items.get(ea)
            if sit is not None:
                nm = ida_name.get_name(ea)
                if nm:
                    sit.setText(nm)
            ti = type_name_items.get(ea)
            mt = data.m.get(ea)
            if ti is not None and mt is not None:
                ti.setText(disp(mt))
            for node in tree_items_by_ea.get(ea, ()):
                if mt is not None:
                    node.setText(0, disp(mt))
        except RuntimeError:
            pass  # widget already destroyed

    def _rerender_selected_detail():
        try:
            sel = tree.selectedItems()
            if sel:
                mt = sel[0].data(0, Qt.UserRole + 1)
                if mt is not None:
                    render_detail(mt)
        except RuntimeError:
            pass

    def refresh_all():
        for ea in list(method_items.keys()):
            _refresh_one(ea)
        for ea in list(string_items.keys()):
            _refresh_one(ea)
        for ea in list(type_name_items.keys()):
            _refresh_one(ea)
        _rerender_selected_detail()

    btn_refresh.clicked.connect(lambda: refresh_all())

    # debounced auto-refresh driven by the IDB rename hook
    _dirty = set()
    _timer = QtCore.QTimer(parent)
    _timer.setSingleShot(True)
    _timer.setInterval(120)

    def _process_dirty():
        eas = list(_dirty)
        _dirty.clear()
        for ea in eas:
            _refresh_one(ea)
        _rerender_selected_detail()
    _timer.timeout.connect(_process_dirty)

    def on_external_rename(ea):
        # If the user renamed an MT label externally (e.g. "Foo_MT"), update the
        # model and propagate to the class's methods. mt.rename re-sets the same
        # label (no-op) and renames OldClass::X functions -> NewClass::X.
        mt = data.m.get(ea)
        if mt is not None:
            try:
                label = ida_name.get_name(ea)
            except Exception:
                label = None
            if label and label.endswith("_MT"):
                candidate = label[:-3]
                if candidate and candidate != mt.name():
                    try:
                        eng = load_engine()
                        if getattr(eng, "TF", None) is None:
                            eng.TF = eng.TypeFactory()
                        mt.rename(candidate)
                    except Exception:
                        pass
        if (ea in method_items or ea in string_items
                or ea in type_name_items or ea in tree_items_by_ea):
            _dirty.add(ea)
            _timer.start()

    return {
        "rerun": btn_rerun,
        "refresh_all": refresh_all,
        "on_external_rename": on_external_rename,
    }


# ===========================================================================
# PluginForm host
# ===========================================================================

_FORM = None
_MANAGER = None


def run_analysis(force=False):
    """Run (or reuse) the NativeAOT analysis; return a MethodTableManager.

    Order of preference: in-memory result -> IDB cache (instant) -> full
    analysis (which is then cached back into the IDB).
    """
    global _MANAGER
    if _MANAGER is not None and not force:
        return _MANAGER
    engine = load_engine()

    if not force:
        try:
            cached = engine.load_from_idb()
        except Exception:
            cached = None
        if cached is not None and cached.count() > 0:
            _MANAGER = cached
            return _MANAGER

    ida_kernwin.show_wait_box("NativeAOT: analyzing metadata...")
    try:
        managers = engine.run()
    finally:
        ida_kernwin.hide_wait_box()
    if not managers:
        return None
    _MANAGER = managers[0]
    try:
        engine.save_to_idb(_MANAGER)
    except Exception:
        pass
    return _MANAGER


def make_form():
    engine = load_engine()

    class BrowserForm(ida_kernwin.PluginForm):
        def OnCreate(self, form):
            self.parent = _form_to_widget(self, form)
            self._hook = None
            self._rebuild()

        def _remove_hook(self):
            if getattr(self, "_hook", None) is not None:
                try:
                    self._hook.unhook()
                except Exception:
                    pass
                self._hook = None

        def _install_hook(self, ui):
            self._remove_hook()
            try:
                self._hook = _RenameHook(ui["on_external_rename"])
                self._hook.hook()
            except Exception:
                self._hook = None

        def _rebuild(self):
            # clear existing layout
            QtWidgets, QtCore, QtGui = _import_qt()
            self._remove_hook()
            old = self.parent.layout()
            if old is not None:
                QtWidgets.QWidget().setLayout(old)
            if _MANAGER is None:
                lay = QtWidgets.QVBoxLayout(self.parent)
                lay.addWidget(QtWidgets.QLabel(
                    "No NativeAOT metadata. Click 'Run Analysis'."))
                btn = QtWidgets.QPushButton("Run Analysis")
                btn.clicked.connect(self._on_rerun)
                lay.addWidget(btn)
                lay.addStretch(1)
                return
            data = BrowserData(engine, _MANAGER)
            ui = build_browser_widget(self.parent, data)
            ui["rerun"].clicked.connect(self._on_rerun)
            self._install_hook(ui)

        def _on_rerun(self):
            # stop sync while the engine performs its own (bulk) renames
            self._remove_hook()
            run_analysis(force=True)
            self._rebuild()

        def OnClose(self, form):
            global _FORM
            self._remove_hook()
            _FORM = None

    return BrowserForm()


def open_browser():
    global _FORM
    try:
        if run_analysis(force=False) is None:
            ida_kernwin.warning(
                "NativeAOT: could not locate a ReadyToRun directory.\n"
                "This binary may not be a .NET Native AOT image, or the RTR "
                "header is in an unusual location.")
            return
        if _FORM is None:
            _FORM = make_form()
        opts = 0
        for n in ("WOPN_PERSIST", "WOPN_RESTORE"):
            opts |= getattr(ida_kernwin.PluginForm, n, 0) or getattr(ida_kernwin, n, 0)
        _FORM.Show(PLUGIN_NAME, options=opts)
    except Exception:
        ida_kernwin.warning("NativeAOT Browser failed:\n%s" % traceback.format_exc())


# ===========================================================================
# Plugin scaffolding
# ===========================================================================

class _OpenHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        open_browser()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class NativeAotBrowserPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MOD
    comment = "Browse .NET Native AOT metadata (types, methods, strings)"
    help = "Reconstructs and browses .NET Native AOT metadata."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        # No shortcut on the action itself: the hotkey is provided by the
        # plugin's wanted_hotkey (which routes to run()). Binding it in both
        # places would raise an "hotkey already in use" conflict.
        action = ida_kernwin.action_desc_t(
            ACTION_ID, PLUGIN_NAME, _OpenHandler(), None,
            "Open the .NET Native AOT metadata browser", -1)
        ida_kernwin.register_action(action)
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/", ACTION_ID, ida_kernwin.SETMENU_APP)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        open_browser()

    def term(self):
        try:
            ida_kernwin.unregister_action(ACTION_ID)
        except Exception:
            pass


def PLUGIN_ENTRY():
    return NativeAotBrowserPlugin()
