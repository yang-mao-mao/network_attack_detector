#!/usr/bin/env python3
"""
Behavior Detection — composite window for behavior-rule management and
detection monitoring (JSON rules format).

Access restriction (per task1.md):
  - Read+Write: only files in this directory (behavior_detect/).
  - Read-only:   files elsewhere — writing outside is forbidden.

Layout
------
  +---------------------------------------------+
  |  QSplitter (horizontal, resizable)          |
  |  +--------------------+--------------------+ |
  |  |  RulePanel         |  RightSplitter     | |
  |  |  (left, width-    |  (vertical)        | |
  |  |   adjustable)     |  +--------------+  | |
  |  |                   |  | TextEditor   |  | |
  |  |  - rule list      |  | (upper)      |  | |
  |  |    + checkbox     |  +--------------+  | |
  |  |  - [+] button     |  | ResultPanel  |  | |
  |  |  - [DELETE] btn   |  | (lower)      |  | |
  |  |  - [▶] / [■]     |  |              |  | |
  |  +--------------------+  +--------------+  | |
  +---------------------------------------------+

Dependencies: PyQt6 only (per task restriction).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

# =============================================================================
# Path helpers — cross-platform (Windows / Linux)
# =============================================================================
_THIS_DIR = Path(__file__).resolve().parent  # .../src/ui/behavior_detect
_PROJECT_ROOT = _THIS_DIR.parent.parent.parent  # inner project root
_RULES_DIR = _PROJECT_ROOT / "data" / "rules"
_DEFAULT_RULES = _RULES_DIR / "behavior_rules.json"

# Allowed write directory (per access restriction)
_ALLOWED_WRITE_DIR: Path = _THIS_DIR


def _is_write_allowed(path: Path) -> bool:
    """Check whether *path* is inside the allowed write directory."""
    try:
        path.resolve().relative_to(_ALLOWED_WRITE_DIR.resolve())
        return True
    except ValueError:
        return False


# =============================================================================
# CSS / STYLE MACROS — all colours and reusable stylesheet templates
# =============================================================================
# Naming convention
#   CLR_*           – colour hex values (dark theme)
#   CSS_*           – reusable Qt stylesheet fragment ({placeholders} allowed)
#   CSS_BTN_*       – QPushButton stylesheet templates

# ── Colour palette ──────────────────────────────────────────────────────────

CLR_BG_0          = "#1e1e1e"   # deepest  — main window, table bg, editor bg
CLR_BG_1          = "#2d2d2d"   # mid-dark — panel frames, scroll bars
CLR_BG_2          = "#3c3c3c"   # mid      — input fields, hover

CLR_BORDER        = "#3e3e3e"   # subtle hairline — splitter handles, grid lines
CLR_BORDER_VIS    = "#555555"   # visible edge   — input rims, button borders

CLR_TEXT          = "#d4d4d4"   # primary body text
CLR_TEXT_MUTED    = "#888888"   # muted / placeholder / secondary text
CLR_TEXT_INVERSE  = "#ffffff"   # text on coloured backgrounds

CLR_ACCENT        = "#007acc"   # main accent  — header underlines
CLR_ACCENT_DARK   = "#094771"   # dark accent  — pressed / selected

CLR_BTN_PRIMARY   = "#0e639c"   # primary CTA background
CLR_BTN_HOVER     = "#1177bb"   # primary CTA hover

CLR_START_BG      = "#2d6e2d"   # ▶ Start   — green
CLR_START_HOVER   = "#3a8a3a"
CLR_START_PRESSED = "#1e4e1e"
CLR_STOP_BG       = "#8b3a3a"   # ■ Stop    — red
CLR_STOP_HOVER    = "#a54545"
CLR_STOP_PRESSED  = "#6e2e2e"

CLR_DELETE_BG     = "#8b0000"   # DELETE active toggle background
CLR_DELETE_HOVER  = "#a00000"
CLR_DELETE_BORDER = "#ff4444"   # DELETE active border highlight

CLR_BTN_HOVER_GREY = "#4a4a4a"  # generic button hover
CLR_SELECTION_BG  = "#264f78"   # text-editor selection highlight
CLR_MATCHED_BG    = "#3a2e2e"   # subtle red  — attack detected
CLR_CLEAN_BG      = "#2e3a2e"   # subtle green — clean traffic
CLR_SECTION_BG    = "#252525"   # header-bar background

# ── Reusable CSS templates ──────────────────────────────────────────────────

CSS_SECTION_HEADER = (
    "color: {CLR_TEXT};"
    "background-color: {CLR_SECTION_BG};"
    "padding: {padding};"
    "border-bottom: 2px solid {CLR_ACCENT};"
)

CSS_BAR_BOTTOM = (
    "background-color: {CLR_BG_1};"
    "border-top: 1px solid {CLR_BORDER};"
)

CSS_SPLITTER_HANDLE = (
    "QSplitter::handle {{ background-color: {CLR_BORDER}; }}"
)

CSS_SCROLL_AREA = (
    "QScrollArea {{ border: none; background-color: {CLR_BG_0}; }}"
    "QScrollBar:vertical {{ background: {CLR_BG_1}; width: 8px; }}"
    "QScrollBar::handle:vertical {{ background: {CLR_BORDER_VIS};"
    "border-radius: 4px; min-height: 30px; }}"
    "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}"
)

CSS_TABLE = (
    "QTableWidget {{"
    "background-color: {CLR_BG_0}; color: {CLR_TEXT};"
    "gridline-color: {CLR_BORDER}; border: 1px solid {CLR_BORDER};"
    "font-size: 12px;"
    "}}"
    "QTableWidget::item {{ padding: 4px 8px; }}"
    "QHeaderView::section {{"
    "background-color: {CLR_SECTION_BG}; color: {CLR_TEXT};"
    "padding: 5px 8px; border: none;"
    "border-bottom: 2px solid {CLR_ACCENT}; font-weight: bold;"
    "}}"
)

CSS_EDITOR = (
    "QPlainTextEdit {{"
    "background-color: {CLR_BG_0}; color: {CLR_TEXT};"
    "border: none; padding: 8px;"
    "selection-background-color: {CLR_SELECTION_BG};"
    "}}"
)

CSS_LINE_EDIT = (
    "QLineEdit {{"
    "background-color: {CLR_BG_2}; color: {CLR_TEXT};"
    "border: 1px solid {CLR_BORDER_VIS}; border-radius: 3px;"
    "padding: 4px 8px;"
    "}}"
)

# ── Button CSS templates ────────────────────────────────────────────────────

CSS_BTN_PRIMARY = (
    "QPushButton {{{padding}"
    "background-color: {CLR_BTN_PRIMARY}; color: {CLR_TEXT_INVERSE};"
    "border: none; border-radius: 4px; font-weight: bold;"
    "}}"
    "QPushButton:hover {{ background-color: {CLR_BTN_HOVER}; }}"
    "QPushButton:pressed {{ background-color: {CLR_ACCENT_DARK}; }}"
)

CSS_BTN_START = (
    "QPushButton {{{padding}"
    "background-color: {CLR_START_BG}; color: {CLR_TEXT_INVERSE};"
    "border: none; border-radius: 4px; font-weight: bold;"
    "}}"
    "QPushButton:hover {{ background-color: {CLR_START_HOVER}; }}"
    "QPushButton:pressed {{ background-color: {CLR_START_PRESSED}; }}"
)

CSS_BTN_STOP = (
    "QPushButton {{{padding}"
    "background-color: {CLR_STOP_BG}; color: {CLR_TEXT_INVERSE};"
    "border: none; border-radius: 4px; font-weight: bold;"
    "}}"
    "QPushButton:hover {{ background-color: {CLR_STOP_HOVER}; }}"
    "QPushButton:pressed {{ background-color: {CLR_STOP_PRESSED}; }}"
)

CSS_BTN_SECONDARY = (
    "QPushButton {{{padding}"
    "background-color: {CLR_BG_2}; color: {CLR_TEXT};"
    "border: 1px solid {CLR_BORDER_VIS}; border-radius: 3px; font-weight: bold;"
    "}}"
    "QPushButton:hover {{ background-color: {CLR_BTN_HOVER_GREY}; }}"
)

CSS_BTN_DELETE_OFF = (
    "QPushButton {{{padding}"
    "background-color: {CLR_BG_2}; color: {CLR_TEXT};"
    "border: 1px solid {CLR_BORDER_VIS}; border-radius: 4px; font-weight: bold;"
    "}}"
    "QPushButton:hover {{ background-color: {CLR_BTN_HOVER_GREY}; }}"
    "QPushButton:checked {{ background-color: {CLR_DELETE_BG}; }}"
)

CSS_BTN_DELETE_ON = (
    "QPushButton {{{padding}"
    "background-color: {CLR_DELETE_BG}; color: {CLR_TEXT_INVERSE};"
    "border: 2px solid {CLR_DELETE_BORDER}; border-radius: 4px; font-weight: bold;"
    "}}"
    "QPushButton:hover {{ background-color: {CLR_DELETE_HOVER}; }}"
)

CSS_BTN_AUTO_FOLLOW_ON = (
    "QPushButton {{{padding}"
    "background-color: {CLR_START_BG}; color: {CLR_TEXT_INVERSE};"
    "border: 1px solid {CLR_START_HOVER}; border-radius: 3px; font-weight: bold;"
    "}}"
    "QPushButton:hover {{ background-color: {CLR_START_HOVER}; }}"
    "QPushButton:checked {{ background-color: {CLR_START_BG}; }}"
)

CSS_BTN_AUTO_FOLLOW_OFF = (
    "QPushButton {{{padding}"
    "background-color: {CLR_BG_2}; color: {CLR_TEXT_MUTED};"
    "border: 1px solid {CLR_BORDER_VIS}; border-radius: 3px; font-weight: bold;"
    "}}"
    "QPushButton:hover {{ background-color: {CLR_BTN_HOVER_GREY}; }}"
)

CSS_APP_GLOBAL = (
    "QMainWindow {{ background-color: {CLR_BG_0}; }}"
    "QToolTip {{"
    "background-color: {CLR_BG_1}; color: {CLR_TEXT};"
    "border: 1px solid {CLR_BORDER_VIS};"
    "}}"
)

# ── Disabled-state button variants (coloured background, muted text) ───────

CSS_BTN_START_DISABLED = (
    "QPushButton {{{padding}"
    "background-color: {CLR_START_BG}; color: {CLR_TEXT_MUTED};"
    "border: none; border-radius: 4px; font-weight: bold;"
    "}}"
)

CSS_BTN_STOP_DISABLED = (
    "QPushButton {{{padding}"
    "background-color: {CLR_STOP_BG}; color: {CLR_TEXT_MUTED};"
    "border: none; border-radius: 4px; font-weight: bold;"
    "}}"
)

CSS_BTN_DELETE_DISABLED = (
    "QPushButton {{{padding}"
    "background-color: #000000; color: {CLR_TEXT_MUTED};"
    "border: 1px solid {CLR_BORDER}; border-radius: 4px; font-weight: bold;"
    "}}"
)


# =============================================================================
# RulePanel — left-side behavior-rule management
# =============================================================================
class RulePanel(QWidget):
    """Left panel: scrollable rule list with checkboxes, add/delete controls,
    and start/stop detection buttons at the very bottom.

    Populated via ``rebuild_from_json_text()`` which parses a JSON array of
    behavior-rule objects from the right-side editor.
    """

    # ── Integration signals ───────────────────────────────────────────────
    detection_started = pyqtSignal()
    detection_stopped = pyqtSignal()
    rule_added    = pyqtSignal(dict)          # new rule dict
    rule_deleted  = pyqtSignal(str)           # rule_id
    rule_toggled  = pyqtSignal(str, bool)     # rule_id, checked

    # Behavior-rule field names (matching behavior_rules.json)
    FIELD_NAMES = [
        "rule_id", "name", "category", "level", "event_type",
        "window_seconds", "threshold", "group_by", "condition",
        "enabled", "description", "suggestion",
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rules: list[dict[str, Any]] = []
        self._rule_widgets: dict[str, QWidget] = {}
        self._checkboxes: dict[str, QCheckBox] = {}
        self._delete_mode: bool = False
        self._delete_button: QPushButton | None = None
        self._rebuilding: bool = False
        self._has_rules: bool = False
        self._detection_active: bool = False

        self._build_ui()

    # ── UI construction ─────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QLabel("Behavior Rule List")
        header.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        header.setStyleSheet(CSS_SECTION_HEADER.format(
            CLR_TEXT=CLR_TEXT, CLR_SECTION_BG=CLR_SECTION_BG,
            CLR_ACCENT=CLR_ACCENT, padding="8px 12px"))
        layout.addWidget(header)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setStyleSheet(CSS_SCROLL_AREA.format(
            CLR_BG_0=CLR_BG_0, CLR_BG_1=CLR_BG_1, CLR_BORDER_VIS=CLR_BORDER_VIS))

        self._rule_container = QWidget()
        self._rule_container.setStyleSheet(f"background-color: {CLR_BG_0};")
        self._rule_layout = QVBoxLayout(self._rule_container)
        self._rule_layout.setContentsMargins(4, 4, 4, 4)
        self._rule_layout.setSpacing(2)
        self._rule_layout.addStretch()
        self._scroll.setWidget(self._rule_container)
        layout.addWidget(self._scroll, stretch=1)

        layout.addWidget(self._build_button_bar())
        self._update_button_states()

    def _build_button_bar(self) -> QWidget:
        bar = QWidget()
        bar.setStyleSheet(CSS_BAR_BOTTOM.format(CLR_BG_1=CLR_BG_1, CLR_BORDER=CLR_BORDER))
        outer = QVBoxLayout(bar)
        outer.setContentsMargins(8, 6, 8, 6)
        outer.setSpacing(6)

        row1 = QHBoxLayout(); row1.setSpacing(8)

        self._btn_add = QPushButton("＋")
        self._btn_add.setToolTip("Add a new behavior rule")
        self._btn_add.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self._btn_add.setStyleSheet(CSS_BTN_PRIMARY.format(
            padding="padding: 6px 18px;", CLR_BTN_PRIMARY=CLR_BTN_PRIMARY,
            CLR_TEXT_INVERSE=CLR_TEXT_INVERSE, CLR_BTN_HOVER=CLR_BTN_HOVER,
            CLR_ACCENT_DARK=CLR_ACCENT_DARK))
        self._btn_add.clicked.connect(self._on_add_rule)
        row1.addWidget(self._btn_add)

        self._delete_button = QPushButton("DELETE")
        self._delete_button.setToolTip("Click to enter delete mode, then click a rule name")
        self._delete_button.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self._delete_button.setCheckable(True)
        self._delete_button.toggled.connect(self._on_delete_toggled)
        self._update_delete_button_style(False)
        row1.addWidget(self._delete_button)
        row1.addStretch()
        outer.addLayout(row1)

        row2 = QHBoxLayout(); row2.setSpacing(8)

        self._btn_start = QPushButton("▶ Start Detection")
        self._btn_start.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self._btn_start.setStyleSheet(CSS_BTN_START.format(
            padding="padding: 8px 20px;", CLR_START_BG=CLR_START_BG,
            CLR_TEXT_INVERSE=CLR_TEXT_INVERSE, CLR_START_HOVER=CLR_START_HOVER,
            CLR_START_PRESSED=CLR_START_PRESSED))
        self._btn_start.clicked.connect(self._on_start)
        row2.addWidget(self._btn_start)

        self._btn_stop = QPushButton("■ Stop Detection")
        self._btn_stop.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self._btn_stop.setStyleSheet(CSS_BTN_STOP.format(
            padding="padding: 8px 20px;", CLR_STOP_BG=CLR_STOP_BG,
            CLR_TEXT_INVERSE=CLR_TEXT_INVERSE, CLR_STOP_HOVER=CLR_STOP_HOVER,
            CLR_STOP_PRESSED=CLR_STOP_PRESSED))
        self._btn_stop.clicked.connect(self._on_stop)
        row2.addWidget(self._btn_stop)
        row2.addStretch()
        outer.addLayout(row2)

        return bar

    def _update_delete_button_style(self, active: bool) -> None:
        if active:
            self._delete_button.setStyleSheet(CSS_BTN_DELETE_ON.format(
                padding="padding: 6px 14px;", CLR_DELETE_BG=CLR_DELETE_BG,
                CLR_TEXT_INVERSE=CLR_TEXT_INVERSE, CLR_DELETE_BORDER=CLR_DELETE_BORDER,
                CLR_DELETE_HOVER=CLR_DELETE_HOVER))
        else:
            self._delete_button.setStyleSheet(CSS_BTN_DELETE_OFF.format(
                padding="padding: 6px 14px;", CLR_BG_2=CLR_BG_2, CLR_TEXT=CLR_TEXT,
                CLR_BORDER_VIS=CLR_BORDER_VIS, CLR_BTN_HOVER_GREY=CLR_BTN_HOVER_GREY,
                CLR_DELETE_BG=CLR_DELETE_BG))

    # ── Rule population ─────────────────────────────────────────────────────

    def clear_rules(self) -> None:
        self._rebuilding = True
        try:
            for _, widget in list(self._rule_widgets.items()):
                self._rule_layout.removeWidget(widget)
                widget.deleteLater()
            self._rule_widgets.clear()
            self._checkboxes.clear()
            self._rules.clear()
            for i in reversed(range(self._rule_layout.count())):
                item = self._rule_layout.itemAt(i)
                if item is not None:
                    w = item.widget()
                    if w is not None and isinstance(w, QLabel):
                        self._rule_layout.removeWidget(w)
                        w.deleteLater()
        finally:
            self._rebuilding = False
        self._has_rules = False
        self._update_button_states()

    def rebuild_from_json_text(self, text: str) -> None:
        """Parse *text* as a JSON array of behavior rules and rebuild the UI."""
        self.clear_rules()
        self._rebuilding = True
        try:
            if not text.strip():
                self._add_placeholder_row("(no rules — open a rules JSON file)")
                return
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                self._add_placeholder_row("(invalid JSON — check syntax)")
                return

            # Support both a top-level array and a single object
            if isinstance(data, list):
                rules = data
            elif isinstance(data, dict):
                rules = [data]
            else:
                self._add_placeholder_row("(JSON root must be an array or object)")
                return

            for obj in rules:
                if not isinstance(obj, dict):
                    continue
                if not obj.get("rule_id") and not obj.get("name"):
                    continue
                self._rules.append(obj)
                self._add_rule_row(obj)

            if not self._rules:
                self._add_placeholder_row("(no valid rule objects found)")
        finally:
            self._rebuilding = False
        self._has_rules = len(self._rules) > 0
        self._update_button_states()

    def _add_placeholder_row(self, text: str) -> None:
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color: {CLR_TEXT_MUTED}; padding: 8px;")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._rule_layout.insertWidget(self._rule_layout.count() - 1, lbl)

    def _add_rule_row(self, rule: dict[str, Any]) -> None:
        rule_id = str(rule.get("rule_id", ""))
        name = str(rule.get("name", rule_id) or "???")
        enabled = bool(rule.get("enabled", True))

        row_widget = QWidget()
        row_widget.setStyleSheet("background-color: transparent;")
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(4, 2, 8, 2)
        row_layout.setSpacing(6)

        cb = QCheckBox()
        cb.setChecked(enabled)
        cb.setToolTip(f"Enable/disable rule: {name}")
        cb.setStyleSheet(f"color: {CLR_TEXT};")
        if self._rebuilding:
            cb.blockSignals(True)
        cb.toggled.connect(lambda checked, rid=rule_id: self.rule_toggled.emit(rid, checked))
        row_layout.addWidget(cb)

        name_lbl = QLabel(name)
        name_lbl.setFont(QFont("Segoe UI", 10))
        name_lbl.setStyleSheet(f"color: {CLR_TEXT}; padding: 3px 0;")
        name_lbl.setCursor(Qt.CursorShape.PointingHandCursor)
        name_lbl.mousePressEvent = lambda _, rid=rule_id: self._on_rule_name_clicked(rid)
        row_layout.addWidget(name_lbl, stretch=1)

        cat = str(rule.get("category", ""))
        if cat:
            cat_lbl = QLabel(cat)
            cat_lbl.setFont(QFont("Segoe UI", 8))
            cat_lbl.setStyleSheet(
                f"color: {CLR_TEXT_MUTED}; background-color: {CLR_BG_2};"
                f"border-radius: 3px; padding: 1px 6px;")
            row_layout.addWidget(cat_lbl)

        self._rule_widgets[rule_id] = row_widget
        self._checkboxes[rule_id] = cb
        insert_at = self._rule_layout.count() - 1
        self._rule_layout.insertWidget(insert_at, row_widget)

    # ── Button handlers ─────────────────────────────────────────────────────

    def _on_add_rule(self) -> None:
        dlg = _AddRuleDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            rule = dlg.get_rule()
        except Exception as exc:
            QMessageBox.warning(self, "Add Rule Failed",
                                f"Could not read the rule form:\n{exc}")
            return

        rule_id = str(rule.get("rule_id", "")).strip()
        rule_name = str(rule.get("name", "")).strip()

        if not rule_id:
            existing_ids = {str(r.get("rule_id", "")) for r in self._rules}
            n = 1
            while f"BEH-{n:04d}" in existing_ids:
                n += 1
            rule["rule_id"] = f"BEH-{n:04d}"
            rule_id = rule["rule_id"]
        if not rule_name:
            rule["name"] = rule_id

        # Sanitise strings
        for key in list(rule.keys()):
            val = rule[key]
            if isinstance(val, str) and len(val) > 4096:
                rule[key] = val[:4093] + "…"

        existing_ids = {str(r.get("rule_id", "")) for r in self._rules}
        if rule_id in existing_ids:
            QMessageBox.warning(self, "Duplicate Rule ID",
                                f"A rule with ID '{rule_id}' already exists.")
            return

        self._rules.append(rule)
        self._add_rule_row(rule)
        self.rule_added.emit(rule)

    def _on_delete_toggled(self, checked: bool) -> None:
        self._delete_mode = checked
        self._update_delete_button_style(checked)

    def _on_rule_name_clicked(self, rule_id: str) -> None:
        if self._delete_mode:
            self._delete_rule(rule_id)
            self._delete_mode = False
            self._delete_button.setChecked(False)
            self._update_delete_button_style(False)

    def _delete_rule(self, rule_id: str) -> None:
        self._rules = [r for r in self._rules if str(r.get("rule_id", "")) != rule_id]
        widget = self._rule_widgets.pop(rule_id, None)
        if widget is not None:
            self._rule_layout.removeWidget(widget)
            widget.deleteLater()
        self._checkboxes.pop(rule_id, None)
        if not self._rules:
            self._add_placeholder_row("(no rules remaining)")
        self.rule_deleted.emit(rule_id)

    def _on_start(self) -> None:
        print("behavior_detector_is_on")
        self.detection_started.emit()

    def _on_stop(self) -> None:
        print("behavior_detector_is_off")
        self.detection_stopped.emit()

    # ── Button state management ─────────────────────────────────────────────

    def set_detection_active(self, active: bool) -> None:
        """Update detection state and refresh all button styles."""
        self._detection_active = active
        self._update_button_states()

    def _update_button_states(self) -> None:
        """Apply the correct enabled-state and stylesheet to every button
        based on the current combination of *_has_rules* and
        *_detection_active*.
        """
        pad = "padding: 8px 20px;"
        if self._detection_active:
            # Detection is running — only Stop is clickable
            self._btn_start.setEnabled(False)
            self._btn_start.setStyleSheet(CSS_BTN_START_DISABLED.format(
                padding=pad, CLR_START_BG=CLR_START_BG,
                CLR_TEXT_MUTED=CLR_TEXT_MUTED))
            self._btn_stop.setEnabled(True)
            self._btn_stop.setStyleSheet(CSS_BTN_STOP.format(
                padding=pad, CLR_STOP_BG=CLR_STOP_BG,
                CLR_TEXT_INVERSE=CLR_TEXT_INVERSE,
                CLR_STOP_HOVER=CLR_STOP_HOVER,
                CLR_STOP_PRESSED=CLR_STOP_PRESSED))
            self._btn_add.setEnabled(False)
            self._delete_button.setEnabled(False)
            self._delete_button.setStyleSheet(CSS_BTN_DELETE_DISABLED.format(
                padding="padding: 6px 14px;", CLR_TEXT_MUTED=CLR_TEXT_MUTED,
                CLR_BORDER=CLR_BORDER))
        elif self._has_rules:
            # Rules are loaded, detection is idle — Start is clickable
            self._btn_start.setEnabled(True)
            self._btn_start.setStyleSheet(CSS_BTN_START.format(
                padding=pad, CLR_START_BG=CLR_START_BG,
                CLR_TEXT_INVERSE=CLR_TEXT_INVERSE,
                CLR_START_HOVER=CLR_START_HOVER,
                CLR_START_PRESSED=CLR_START_PRESSED))
            self._btn_stop.setEnabled(False)
            self._btn_stop.setStyleSheet(CSS_BTN_STOP_DISABLED.format(
                padding=pad, CLR_STOP_BG=CLR_STOP_BG,
                CLR_TEXT_MUTED=CLR_TEXT_MUTED))
            self._btn_add.setEnabled(True)
            self._delete_button.setEnabled(True)
            self._update_delete_button_style(False)
        else:
            # No rules loaded — everything is disabled (grey text)
            self._btn_start.setEnabled(False)
            self._btn_start.setStyleSheet(CSS_BTN_START_DISABLED.format(
                padding=pad, CLR_START_BG=CLR_START_BG,
                CLR_TEXT_MUTED=CLR_TEXT_MUTED))
            self._btn_stop.setEnabled(False)
            self._btn_stop.setStyleSheet(CSS_BTN_STOP_DISABLED.format(
                padding=pad, CLR_STOP_BG=CLR_STOP_BG,
                CLR_TEXT_MUTED=CLR_TEXT_MUTED))
            self._btn_add.setEnabled(True)
            self._delete_button.setEnabled(False)
            self._delete_button.setStyleSheet(CSS_BTN_DELETE_DISABLED.format(
                padding="padding: 6px 14px;", CLR_TEXT_MUTED=CLR_TEXT_MUTED,
                CLR_BORDER=CLR_BORDER))

    # ── Public helpers ──────────────────────────────────────────────────────

    def get_enabled_rule_ids(self) -> list[str]:
        return [rid for rid, cb in self._checkboxes.items() if cb.isChecked()]

    def get_all_rules(self) -> list[dict[str, Any]]:
        return list(self._rules)


# =============================================================================
# _AddRuleDialog — form for adding a new behavior rule
# =============================================================================
class _AddRuleDialog(QDialog):
    FIELDS = [
        ("rule_id", "Rule ID"),
        ("name", "Name"),
        ("category", "Category"),
        ("level", "Level"),
        ("event_type", "Event Type"),
        ("window_seconds", "Window (seconds)"),
        ("threshold", "Threshold"),
        ("group_by", "Group By (comma-sep)"),
        ("description", "Description"),
        ("suggestion", "Suggestion"),
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add New Behavior Rule")
        self.setMinimumWidth(420)
        self._inputs: dict[str, QLineEdit] = {}
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()
        for key, label in self.FIELDS:
            le = QLineEdit()
            le.setStyleSheet(CSS_LINE_EDIT.format(
                CLR_BG_2=CLR_BG_2, CLR_TEXT=CLR_TEXT, CLR_BORDER_VIS=CLR_BORDER_VIS))
            self._inputs[key] = le
            form.addRow(label, le)
        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addSpacing(12)
        layout.addWidget(buttons)
        self.setStyleSheet(f"background-color: {CLR_BG_1}; color: {CLR_TEXT};")

    def get_rule(self) -> dict[str, Any]:
        rule: dict[str, Any] = {}
        for key, _ in self.FIELDS:
            try:
                raw = self._inputs[key].text()
            except (KeyError, AttributeError):
                raw = ""
            if not isinstance(raw, str):
                raw = str(raw)
            rule[key] = raw.strip()

        # Convert numeric fields
        for num_key in ("window_seconds", "threshold"):
            val = rule.get(num_key, "")
            try:
                rule[num_key] = int(val) if val else 0
            except ValueError:
                rule[num_key] = 0

        # group_by as list
        gb = rule.get("group_by", "")
        rule["group_by"] = [x.strip() for x in gb.split(",") if x.strip()] if gb else []

        rule.setdefault("enabled", True)
        rule.setdefault("condition", {})
        return rule


# =============================================================================
# ResultPanel — right-lower detection-results table
# =============================================================================
class ResultPanel(QWidget):
    COLUMNS = [
        ("packet_id", "Packet ID"),
        ("matched", "Matched"),
        ("alerts", "Alerts"),
        ("engine_name", "Engine"),
        ("cost_ms", "Cost (ms)"),
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._results: list[Any] = []
        self._auto_follow: bool = True
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        bar = QWidget()
        bar.setStyleSheet(CSS_SECTION_HEADER.format(
            CLR_TEXT=CLR_TEXT, CLR_SECTION_BG=CLR_SECTION_BG,
            CLR_ACCENT=CLR_ACCENT, padding="4px 10px 4px 6px"))
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(10, 4, 6, 4)

        title = QLabel("Detection Results")
        title.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {CLR_TEXT};")
        bar_layout.addWidget(title)
        bar_layout.addStretch()

        btn_clear = QPushButton("CLEAR")
        btn_clear.setToolTip("Remove all detection results")
        btn_clear.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        btn_clear.setStyleSheet(CSS_BTN_SECONDARY.format(
            padding="padding: 3px 12px;", CLR_BG_2=CLR_BG_2, CLR_TEXT=CLR_TEXT,
            CLR_BORDER_VIS=CLR_BORDER_VIS, CLR_BTN_HOVER_GREY=CLR_BTN_HOVER_GREY))
        btn_clear.clicked.connect(self.clear_results)
        bar_layout.addWidget(btn_clear)

        self._btn_auto_follow = QPushButton("AUTO_FOLLOW ✓")
        self._btn_auto_follow.setToolTip("Auto-scroll to newest — click to toggle")
        self._btn_auto_follow.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        self._btn_auto_follow.setCheckable(True)
        self._btn_auto_follow.setChecked(True)
        self._btn_auto_follow.toggled.connect(self._on_auto_follow_toggled)
        self._update_auto_follow_style(True)
        bar_layout.addWidget(self._btn_auto_follow)
        layout.addWidget(bar)

        self._stack = QStackedWidget()
        self._stack.addWidget(self._build_table_page())
        self._stack.addWidget(self._build_placeholder_page())
        self._stack.setCurrentIndex(1)
        layout.addWidget(self._stack, stretch=1)

    def _update_auto_follow_style(self, active: bool) -> None:
        if active:
            self._btn_auto_follow.setText("AUTO_FOLLOW ✓")
            self._btn_auto_follow.setStyleSheet(CSS_BTN_AUTO_FOLLOW_ON.format(
                padding="padding: 3px 12px;", CLR_START_BG=CLR_START_BG,
                CLR_TEXT_INVERSE=CLR_TEXT_INVERSE, CLR_START_HOVER=CLR_START_HOVER))
        else:
            self._btn_auto_follow.setText("AUTO_FOLLOW ✗")
            self._btn_auto_follow.setStyleSheet(CSS_BTN_AUTO_FOLLOW_OFF.format(
                padding="padding: 3px 12px;", CLR_BG_2=CLR_BG_2,
                CLR_TEXT_MUTED=CLR_TEXT_MUTED, CLR_BORDER_VIS=CLR_BORDER_VIS,
                CLR_BTN_HOVER_GREY=CLR_BTN_HOVER_GREY))

    def _on_auto_follow_toggled(self, checked: bool) -> None:
        self._auto_follow = checked
        self._update_auto_follow_style(checked)
        if checked and self._table.rowCount() > 0:
            self._table.scrollToBottom()

    def _build_table_page(self) -> QWidget:
        container = QWidget()
        cl = QVBoxLayout(container)
        cl.setContentsMargins(4, 0, 4, 4)
        self._table = QTableWidget(0, len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels([c[1] for c in self.COLUMNS])
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        hdr = self._table.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.setStyleSheet(CSS_TABLE.format(
            CLR_BG_0=CLR_BG_0, CLR_TEXT=CLR_TEXT, CLR_BORDER=CLR_BORDER,
            CLR_SECTION_BG=CLR_SECTION_BG, CLR_ACCENT=CLR_ACCENT))
        cl.addWidget(self._table)
        return container

    def _build_placeholder_page(self) -> QWidget:
        container = QWidget()
        container.setStyleSheet(f"background-color: {CLR_BG_0};")
        lay = QHBoxLayout(container)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl = QLabel("no bad behavior detected")
        lbl.setFont(QFont("Segoe UI", 14))
        lbl.setStyleSheet(f"color: {CLR_TEXT_MUTED};")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(lbl)
        return container

    def add_result(self, result: Any) -> None:
        self._results.append(result)
        self._append_row(result)
        self._stack.setCurrentIndex(0)
        if self._auto_follow:
            self._table.scrollToBottom()

    def add_results(self, results: list[Any]) -> None:
        for r in results:
            self._results.append(r)
            self._append_row(r)
        if self._results:
            self._stack.setCurrentIndex(0)
        if self._auto_follow:
            self._table.scrollToBottom()

    def clear_results(self) -> None:
        self._results.clear()
        self._table.setRowCount(0)
        self._stack.setCurrentIndex(1)

    def _append_row(self, result: Any) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._set_cell(row, 0, str(getattr(result, "packet_id", "—")))
        self._set_cell(row, 1, "✓" if getattr(result, "matched", False) else "✗")
        alerts = getattr(result, "alerts", []) or []
        alert_n = len(alerts)
        if alert_n == 0:
            self._set_cell(row, 2, "—")
        else:
            item = self._set_cell(row, 2, f"{alert_n} alert(s)")
            if item:
                item.setToolTip("\n".join(
                    f"[{getattr(a, 'level', '?')}] {getattr(a, 'rule_name', '?')}"
                    for a in alerts))
        self._set_cell(row, 3, str(getattr(result, "engine_name", "") or "—"))
        cost = getattr(result, "cost_ms", 0.0)
        self._set_cell(row, 4, f"{cost:.2f}" if cost else "—")

    def _set_cell(self, row: int, col: int, text: str) -> QTableWidgetItem | None:
        item = QTableWidgetItem(text)
        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        item.setForeground(QColor(CLR_TEXT))
        self._table.setItem(row, col, item)
        return item


# =============================================================================
# BehaviorDetectWindow — the composite main window
# =============================================================================
class BehaviorDetectWindow(QMainWindow):
    """Top-level window: left rule panel | right upper editor | right lower results.

    The editor (right-upper) is the **source of truth** — it holds a JSON
    array of behavior-rule objects.  The left RulePanel shows a parsed view.
    Add / delete / toggle operations modify the JSON text directly, and manual
    edits in the editor sync back after a debounce delay.
    """

    _RULE_FIELDS = RulePanel.FIELD_NAMES

    def __init__(self, auto_open: bool = True) -> None:
        super().__init__()
        self.setWindowTitle("Behavior Detection — Network Attack Detector")
        self.resize(1200, 750)

        self._json_path: Path | None = None
        self._modified: bool = False
        self._sync_locked: bool = False
        self._detection_active: bool = False
        self._simulation_timer: QTimer | None = None
        self._sim_counter: int = 0

        # Reference to StatisticWindow — set by MainWindow after construction
        self._stat_window: Any | None = None

        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(600)
        self._debounce_timer.timeout.connect(self._sync_rules_from_editor)

        self._build_ui()
        self._connect_signals()
        if auto_open:
            QTimer.singleShot(100, self._prompt_open_rules_file)

    # ── StatisticWindow integration ─────────────────────────────────────────

    def set_statistic_window(self, stat_window: Any) -> None:
        """Receive a reference to the :class:`StatisticWindow` so that detection
        results (alerts) can be forwarded to the statistics dashboard."""
        self._stat_window = stat_window

    # ── UI construction ─────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._h_splitter = QSplitter(Qt.Orientation.Horizontal)
        self._h_splitter.setHandleWidth(3)
        self._h_splitter.setStyleSheet(CSS_SPLITTER_HANDLE.format(CLR_BORDER=CLR_BORDER))
        self._rule_panel = RulePanel()
        self._h_splitter.addWidget(self._rule_panel)

        self._v_splitter = QSplitter(Qt.Orientation.Vertical)
        self._v_splitter.setHandleWidth(3)
        self._v_splitter.setStyleSheet(CSS_SPLITTER_HANDLE.format(CLR_BORDER=CLR_BORDER))
        self._editor_panel = self._build_editor_panel()
        self._v_splitter.addWidget(self._editor_panel)
        self._result_panel = ResultPanel()
        self._v_splitter.addWidget(self._result_panel)
        self._v_splitter.setSizes([350, 350])
        self._h_splitter.addWidget(self._v_splitter)
        self._h_splitter.setSizes([360, 840])
        self.setCentralWidget(self._h_splitter)

    def _build_editor_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        bar = QWidget()
        bar.setStyleSheet(CSS_SECTION_HEADER.format(
            CLR_TEXT=CLR_TEXT, CLR_SECTION_BG=CLR_SECTION_BG,
            CLR_ACCENT=CLR_ACCENT, padding="4px 10px"))
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(10, 4, 8, 4)

        self._editor_title = QLabel("Rules File — none")
        self._editor_title.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self._editor_title.setStyleSheet(f"color: {CLR_TEXT};")
        bar_layout.addWidget(self._editor_title)
        bar_layout.addStretch()

        btn_open = QPushButton("Open…")
        btn_open.setToolTip("Open a behavior rules JSON file")
        btn_open.setStyleSheet(CSS_BTN_SECONDARY.format(
            padding="padding: 4px 14px;", CLR_BG_2=CLR_BG_2, CLR_TEXT=CLR_TEXT,
            CLR_BORDER_VIS=CLR_BORDER_VIS, CLR_BTN_HOVER_GREY=CLR_BTN_HOVER_GREY))
        btn_open.clicked.connect(self._prompt_open_rules_file)
        bar_layout.addWidget(btn_open)

        self._btn_save = QPushButton("Save")
        self._btn_save.setStyleSheet(CSS_BTN_PRIMARY.format(
            padding="padding: 4px 14px;", CLR_BTN_PRIMARY=CLR_BTN_PRIMARY,
            CLR_TEXT_INVERSE=CLR_TEXT_INVERSE, CLR_BTN_HOVER=CLR_BTN_HOVER,
            CLR_ACCENT_DARK=CLR_ACCENT_DARK))
        self._btn_save.clicked.connect(self._on_editor_save)
        bar_layout.addWidget(self._btn_save)
        layout.addWidget(bar)

        self._text_edit = QPlainTextEdit()
        self._text_edit.setFont(QFont("monospace", 11))
        self._text_edit.setTabStopDistance(40)
        self._text_edit.setStyleSheet(CSS_EDITOR.format(
            CLR_BG_0=CLR_BG_0, CLR_TEXT=CLR_TEXT, CLR_SELECTION_BG=CLR_SELECTION_BG))
        self._text_edit.textChanged.connect(self._on_editor_text_changed)
        layout.addWidget(self._text_edit, stretch=1)
        return panel

    # ── File dialog ─────────────────────────────────────────────────────────

    def _prompt_open_rules_file(self) -> None:
        rules_dir = str(_RULES_DIR) if _RULES_DIR.exists() else str(_THIS_DIR)
        path_str, _ = QFileDialog.getOpenFileName(
            self, "Open Rules File", rules_dir,
            "JSON Files (*.json);;All Files (*)")
        if not path_str:
            if self._json_path is None:
                self._text_edit.setPlainText(
                    "# No rules file selected.\n"
                    "# Click 'Open…' to choose a JSON rules file.\n")
                self._rule_panel.rebuild_from_json_text("")
            return
        self._load_file(Path(path_str))

    def _load_file(self, path: Path) -> None:
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(self, "Read Error", str(exc))
            return
        self._sync_locked = True
        try:
            self._text_edit.setPlainText(content)
            self._json_path = path.resolve()
            self._modified = False
            self._editor_title.setText(f"Rules File — {path.name}")
            self._rule_panel.rebuild_from_json_text(content)
        finally:
            self._sync_locked = False

    # ── Sync: Editor → Rules (debounced) ────────────────────────────────────

    def _on_editor_text_changed(self) -> None:
        if self._sync_locked:
            return
        self._modified = True
        self._debounce_timer.start()

    def _sync_rules_from_editor(self) -> None:
        if self._sync_locked:
            return
        text = self._text_edit.toPlainText()
        self._rule_panel.rebuild_from_json_text(text)

    # ── Sync: Rules → Editor (immediate) ────────────────────────────────────

    def _on_rule_added(self, rule: dict[str, Any]) -> None:
        self._sync_locked = True
        try:
            text = self._text_edit.toPlainText()
            rules = self._parse_json_safe(text)
            rules.append(rule)
            new_text = json.dumps(rules, indent=2, ensure_ascii=False)
            self._text_edit.setPlainText(new_text)
            self._modified = True
        finally:
            self._sync_locked = False

    def _on_rule_deleted(self, rule_id: str) -> None:
        self._sync_locked = True
        try:
            text = self._text_edit.toPlainText()
            rules = self._parse_json_safe(text)
            rules = [r for r in rules if str(r.get("rule_id", "")) != rule_id]
            new_text = json.dumps(rules, indent=2, ensure_ascii=False)
            self._text_edit.setPlainText(new_text)
            self._modified = True
        finally:
            self._sync_locked = False
        self._sync_rules_from_editor()

    def _on_rule_toggled_from_panel(self, rule_id: str, checked: bool) -> None:
        self._sync_locked = True
        try:
            text = self._text_edit.toPlainText()
            rules = self._parse_json_safe(text)
            for r in rules:
                if str(r.get("rule_id", "")) == rule_id:
                    r["enabled"] = checked
                    break
            new_text = json.dumps(rules, indent=2, ensure_ascii=False)
            self._text_edit.setPlainText(new_text)
            self._modified = True
        finally:
            self._sync_locked = False

    @staticmethod
    def _parse_json_safe(text: str) -> list[dict[str, Any]]:
        """Parse JSON text; return a list (empty on failure)."""
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            return [data]
        return []

    # ── Save logic ──────────────────────────────────────────────────────────

    def _on_editor_save(self) -> None:
        content = self._text_edit.toPlainText()
        if self._json_path is not None and self._is_default_rules_file(self._json_path):
            save_path = self._prompt_save_as_user_rules()
            if save_path is None:
                return
        elif self._json_path is not None and _is_write_allowed(self._json_path):
            save_path = self._json_path
        else:
            save_path = self._prompt_save_as_user_rules()
            if save_path is None:
                return
        try:
            save_path.write_text(content, encoding="utf-8")
            self._json_path = save_path
            self._modified = False
            self._editor_title.setText(f"Rules File — {save_path.name}")
        except OSError as exc:
            QMessageBox.critical(self, "Save Error", str(exc))

    def _is_default_rules_file(self, path: Path) -> bool:
        try:
            return path.resolve() == _DEFAULT_RULES.resolve()
        except OSError:
            return False

    def _prompt_save_as_user_rules(self) -> Path | None:
        n = self._next_user_rules_num()
        default_name = f"user_rules{n}.json"
        default_path = str(_RULES_DIR / default_name)
        path_str, _ = QFileDialog.getSaveFileName(
            self, "Save Rules File As", default_path,
            "JSON Files (*.json);;All Files (*)")
        if not path_str:
            return None
        return Path(path_str)

    @staticmethod
    def _next_user_rules_num() -> int:
        if not _RULES_DIR.exists():
            return 1
        max_n = 0
        pattern = re.compile(r"^user_rules(\d+)\.json$", re.IGNORECASE)
        for child in _RULES_DIR.iterdir():
            if child.is_file():
                m = pattern.match(child.name)
                if m:
                    max_n = max(max_n, int(m.group(1)))
        return max_n + 1

    # ── Close event ─────────────────────────────────────────────────────────

    def closeEvent(self, event) -> None:
        if self._modified and self._text_edit.toPlainText().strip():
            answer = QMessageBox.question(
                self, "Unsaved Changes",
                "The rules file has been modified.\n\n"
                "Do you want to save your changes before closing?",
                QMessageBox.StandardButton.Save
                | QMessageBox.StandardButton.Discard
                | QMessageBox.StandardButton.Cancel)
            if answer == QMessageBox.StandardButton.Save:
                self._on_editor_save()
                if self._modified:
                    event.ignore()
                    return
            elif answer == QMessageBox.StandardButton.Cancel:
                event.ignore()
                return
        self._stop_detection()
        event.accept()

    # ── Signal wiring ───────────────────────────────────────────────────────

    def _connect_signals(self) -> None:
        self._rule_panel.detection_started.connect(self._start_detection)
        self._rule_panel.detection_stopped.connect(self._stop_detection)
        self._rule_panel.rule_added.connect(self._on_rule_added)
        self._rule_panel.rule_deleted.connect(self._on_rule_deleted)
        self._rule_panel.rule_toggled.connect(self._on_rule_toggled_from_panel)

    # ── Detection control ───────────────────────────────────────────────────

    def _start_detection(self) -> None:
        if self._detection_active:
            return
        self._detection_active = True
        self._sim_counter = 0
        self._rule_panel.set_detection_active(True)
        self._simulation_timer = QTimer(self)
        self._simulation_timer.timeout.connect(self._generate_mock_result)
        self._simulation_timer.start(1500)

    def _stop_detection(self) -> None:
        self._detection_active = False
        self._rule_panel.set_detection_active(False)
        if self._simulation_timer is not None:
            self._simulation_timer.stop()
            self._simulation_timer = None

    def _generate_mock_result(self) -> None:
        self._sim_counter += 1

        class _MockAlert:
            def __init__(self, level, rule_name, category):
                self.level = level; self.rule_name = rule_name; self.category = category

        class _MockResult:
            def __init__(self, i):
                self.packet_id = f"PKT-{1000 + i:04d}"
                self.matched = (i % 5 == 0)
                self.alerts = ([
                    _MockAlert("Medium", "Port scan detection", "Port Scan"),
                    _MockAlert("High", "Brute force login", "Brute Force"),
                ] if self.matched else [])
                self.engine_name = "behavior_engine"
                self.cost_ms = round(0.3 + (i * 0.05), 2)

        try:
            from core.models import DetectionResult, Alert, AlertLevel, AttackCategory
            result = DetectionResult(
                packet_id=f"PKT-{1000 + self._sim_counter:04d}",
                matched=(self._sim_counter % 5 == 0),
                alerts=([
                    Alert(alert_id=f"ALERT-{self._sim_counter:04d}", timestamp=0.0,
                          category=AttackCategory.PORT_SCAN, level=AlertLevel.MEDIUM,
                          src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=54321, dst_port=80,
                          protocol="TCP", rule_id="BEH-2001", rule_name="Port scan detection",
                          evidence="20+ ports scanned in 60s",
                          description="Same source IP touches many ports")
                ] if self._sim_counter % 5 == 0 else []),
                engine_name="behavior_engine",
                cost_ms=round(0.3 + self._sim_counter * 0.05, 2))
            # Forward alerts to the statistics dashboard
            if self._stat_window is not None:
                for alert in result.alerts:
                    self._stat_window.add_alert(alert)
        except ImportError:
            result = _MockResult(self._sim_counter)
        self._result_panel.add_result(result)


# =============================================================================
# Entry point
# =============================================================================
def main() -> None:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(CSS_APP_GLOBAL.format(
        CLR_BG_0=CLR_BG_0, CLR_BG_1=CLR_BG_1,
        CLR_TEXT=CLR_TEXT, CLR_BORDER_VIS=CLR_BORDER_VIS))
    window = BehaviorDetectWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
