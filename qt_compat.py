"""
qt_compat.py - Qt5/Qt6 compatibility shim for ida-nativeaot.

Allows the plugin to run on IDA Pro 8.x-9.1 (PyQt5/Qt5) AND IDA Pro 9.2+ (PySide6/Qt6).
Imported by ida-nativeaot_browser.py via `from qt_compat import QtWidgets, QtCore, QtGui`.
"""
try:
    from PySide6 import QtWidgets, QtCore, QtGui
except ImportError:
    from PyQt5 import QtWidgets, QtCore, QtGui

    # PySide6 uses exec() on widgets/menus; PyQt5 uses exec_()
    # Add exec() that delegates to exec_() so the codebase can use PySide6 style
    _orig_menu_exec_ = QtWidgets.QMenu.exec_

    def _menu_exec(self, *args, **kwargs):
        return _orig_menu_exec_(self, *args, **kwargs)

    QtWidgets.QMenu.exec_ = _menu_exec
    QtWidgets.QMenu.exec = _menu_exec

    _orig_app_exec_ = QtWidgets.QApplication.exec_

    def _app_exec(self_or_nothing, *args, **kwargs):
        return _orig_app_exec_(self_or_nothing, *args, **kwargs)

    QtWidgets.QApplication.exec_ = _app_exec
    QtWidgets.QApplication.exec = _app_exec
