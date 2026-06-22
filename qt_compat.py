"""
Qt compatibility shim for IDA Pro 9.1 (PyQt5).
Provides PySide6-style imports and exec() for plugins written for IDA 9.2+.
"""
try:
    from PySide6 import QtWidgets, QtCore, QtGui
except ImportError:
    from PyQt5 import QtWidgets, QtCore, QtGui

    # PySide6 uses exec() on widgets/menus; PyQt5 uses exec_()
    # Shim: add exec() that delegates to exec_() for menu and application
    # IMPORTANT: do NOT overwrite exec_() — PyQt5's exec_() internally calls
    # self.exec(), and replacing exec would cause infinite recursion.
    _orig_menu_exec_ = QtWidgets.QMenu.exec_
    def _menu_exec(self, *args, **kwargs):
        return _orig_menu_exec_(self, *args, **kwargs)
    QtWidgets.QMenu.exec = _menu_exec

    _orig_app_exec_ = QtWidgets.QApplication.exec_
    def _app_exec(self_or_nothing, *args, **kwargs):
        return _orig_app_exec_(self_or_nothing, *args, **kwargs)
    QtWidgets.QApplication.exec = _app_exec
