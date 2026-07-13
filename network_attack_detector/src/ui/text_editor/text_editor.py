#!/usr/bin/env python3
"""
Nano-like text editor built with PyQt6.

Access restriction: only files within this script's own directory
may be read or written. Any path that resolves outside is rejected.

Keyboard shortcuts (modeled after nano):
  Ctrl+O  - Save file (WriteOut)
  Ctrl+R  - Open file (Read)
  Ctrl+X  - Exit
  Ctrl+G  - Show help
"""

import os
import sys

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QFont, QKeySequence
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QMainWindow,
    QMenuBar,
    QMessageBox,
    QPlainTextEdit,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

# ── directory guard ───────────────────────────────────────────────────────────
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _check_path(path: str) -> str:
    """Resolve *path* and raise `ValueError` if it escapes ``_BASE_DIR``."""
    real_base = os.path.realpath(_BASE_DIR)
    real_target = os.path.realpath(path)

    # If the file doesn't exist yet (common for saves), resolve its directory.
    if os.path.exists(real_target):
        check = real_target
    else:
        check = os.path.dirname(real_target) or real_target

    # commonprefix must cover the whole base — not just a partial string match.
    common = os.path.commonpath([real_base, check])
    if common != real_base:
        raise ValueError(
            f"Access denied: '{path}' is outside the allowed directory "
            f"'{_BASE_DIR}'."
        )
    return real_target


# ── main window ───────────────────────────────────────────────────────────────


class NanoEditor(QMainWindow):
    """A minimal nano-style text editor."""

    def __init__(self) -> None:
        super().__init__()
        self._current_file: str | None = None

        # -- central widget ----------------------------------------------------
        self._editor = QPlainTextEdit()
        self._editor.setFont(QFont("monospace", 12))
        self._editor.setTabStopDistance(40)  # 4-space tabs at 12px font

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._editor)
        self.setCentralWidget(central)

        # -- menus & shortcuts -------------------------------------------------
        self._build_menus()
        self._build_shortcuts()

        # -- status bar --------------------------------------------------------
        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._editor.cursorPositionChanged.connect(self._update_status)
        self._update_status()

        # -- window ------------------------------------------------------------
        self.setWindowTitle("Nano Editor")
        self.resize(900, 600)

    # ── menu bar ──────────────────────────────────────────────────────────────

    def _build_menus(self) -> None:
        bar = self.menuBar()

        # File
        file_menu = bar.addMenu("&File")

        act_open = QAction("&Open...", self)
        act_open.setShortcut(QKeySequence.StandardKey.Open)
        act_open.triggered.connect(self.open_file)
        file_menu.addAction(act_open)

        act_save = QAction("&Save", self)
        act_save.setShortcut(QKeySequence.StandardKey.Save)
        act_save.triggered.connect(self.save_file)
        file_menu.addAction(act_save)

        act_save_as = QAction("Save &As...", self)
        act_save_as.setShortcut(QKeySequence.StandardKey.SaveAs)
        act_save_as.triggered.connect(self.save_file_as)
        file_menu.addAction(act_save_as)

        file_menu.addSeparator()

        act_exit = QAction("E&xit", self)
        act_exit.setShortcut(QKeySequence("Ctrl+X"))
        act_exit.triggered.connect(self.close)
        file_menu.addAction(act_exit)

        # Help
        help_menu = bar.addMenu("&Help")
        act_help = QAction("&Shortcuts", self)
        act_help.setShortcut(QKeySequence("Ctrl+G"))
        act_help.triggered.connect(self._show_help)
        help_menu.addAction(act_help)

    # ── standalone shortcuts (nano muscle-memory) ─────────────────────────────

    def _build_shortcuts(self) -> None:
        # Ctrl+O → save (nano "WriteOut")
        save_sc = QAction(self)
        save_sc.setShortcut(QKeySequence("Ctrl+O"))
        save_sc.triggered.connect(self.save_file)
        self.addAction(save_sc)

        # Ctrl+R → open (nano "Read")
        open_sc = QAction(self)
        open_sc.setShortcut(QKeySequence("Ctrl+R"))
        open_sc.triggered.connect(self.open_file)
        self.addAction(open_sc)

    # ── status bar helpers ────────────────────────────────────────────────────

    def _update_status(self) -> None:
        fname = self._current_file or "(new file)"
        text = self._editor.toPlainText()
        lines = text.count("\n") + (0 if text.endswith("\n") else 1)
        chars = len(text)
        cursor = self._editor.textCursor()
        row = cursor.blockNumber() + 1
        col = cursor.columnNumber() + 1
        self._status.showMessage(
            f"{fname}  |  Lines: {lines}  |  Chars: {chars}"
            f"  |  Row: {row}, Col: {col}"
        )

    # ── file operations ───────────────────────────────────────────────────────

    def open_file(self, *, path: str | None = None) -> None:
        """Open a file and load its content into the editor."""
        if path is None:
            path, _ = QFileDialog.getOpenFileName(
                self, "Open File", _BASE_DIR, "All Files (*)"
            )
        if not path:
            return  # user cancelled

        try:
            safe = _check_path(path)
        except ValueError as exc:
            QMessageBox.critical(self, "Access Denied", str(exc))
            return

        try:
            with open(safe, "r", encoding="utf-8") as fh:
                content = fh.read()
        except OSError as exc:
            QMessageBox.critical(self, "Read Error", str(exc))
            return

        self._editor.setPlainText(content)
        self._current_file = safe
        self._update_status()
        self.setWindowTitle(f"Nano Editor - {os.path.basename(safe)}")

    def save_file(self) -> None:
        """Write content back to the current file, or prompt for a path."""
        if self._current_file is None:
            self.save_file_as()
            return
        self._write_to(self._current_file)

    def save_file_as(self) -> None:
        """Prompt for a save path and write."""
        path, _ = QFileDialog.getSaveFileName(
            self, "Save File As", _BASE_DIR, "All Files (*)"
        )
        if not path:
            return
        try:
            safe = _check_path(path)
        except ValueError as exc:
            QMessageBox.critical(self, "Access Denied", str(exc))
            return
        self._write_to(safe)
        self._current_file = safe
        self._update_status()
        self.setWindowTitle(f"Nano Editor - {os.path.basename(safe)}")

    def _write_to(self, path: str) -> None:
        """Write editor content to *path* (already validated)."""
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self._editor.toPlainText())
        except OSError as exc:
            QMessageBox.critical(self, "Write Error", str(exc))

    # ── help ──────────────────────────────────────────────────────────────────

    def _show_help(self) -> None:
        QMessageBox.information(
            self,
            "Keyboard Shortcuts",
            (
                "Ctrl+O  — Save file (nano: WriteOut)\n"
                "Ctrl+R  — Open file (nano: Read File)\n"
                "Ctrl+S  — Save\n"
                "Ctrl+X  — Exit\n"
                "Ctrl+G  — Show this help\n"
            ),
        )

    # ── events ────────────────────────────────────────────────────────────────

    def closeEvent(self, event) -> None:
        """Confirm exit if there are unsaved changes."""
        # For simplicity we do not track a dirty flag — just close.
        event.accept()


# ── entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    app = QApplication(sys.argv)
    editor = NanoEditor()
    editor.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
