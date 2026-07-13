#!/usr/bin/env python3
"""
Feature Detection — composite window for rule management and detection monitoring.

Access restriction (per task2.md):
  - Read+Write: files in this directory (feature_detect/) AND ../../data/rules/.
  - Read-only:   files elsewhere — writing outside the allowed dirs is forbidden.

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

import csv
import io
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
# Path helpers — cross-platform (the "two sets of commands" for Windows/Linux)
# =============================================================================
# On Windows paths use backslashes; on Linux they use forward slashes.
# pathlib.Path handles both transparently, so the same code works everywhere.

_THIS_DIR = Path(__file__).resolve().parent  # .../src/ui/feature_detect

# Directory layout:
#   .../network_attack_detector/          ← outer (git repo root)
#       └── network_attack_detector/      ← inner (Python project root)
#           ├── src/ui/feature_detect/    ← WE ARE HERE
#           └── data/rules/               ← rules live here
#
# From feature_detect/ we go up 3 levels to reach the inner project root.

_PROJECT_ROOT = _THIS_DIR.parent.parent.parent  # inner network_attack_detector/
_RULES_DIR = _PROJECT_ROOT / "data" / "rules"    # allowed write directory
_DEFAULT_RULES = _RULES_DIR / "signature_rules.csv"

# Allowed write directories (per task2.md access restriction)
_ALLOWED_WRITE_DIRS: tuple[Path, ...] = (_THIS_DIR, _RULES_DIR)


def _is_write_allowed(path: Path) -> bool:
    """Check whether *path* is inside an allowed write directory."""
    rp = path.resolve()
    for d in _ALLOWED_WRITE_DIRS:
        try:
            rp.relative_to(d.resolve())
            return True
        except ValueError:
            pass
    return False


# =============================================================================
# CSS / STYLE MACROS — all colours and reusable stylesheet templates
# =============================================================================
#
# Every colour and every reusable CSS snippet used across this file is defined
# in this single continuous block so that the visual theme can be adjusted in
# one place without hunting through widget code.
#
# Naming convention
# ─────────────────
#   CLR_*           – colour hex values (dark theme, consistent with shell.py)
#   CSS_*           – reusable Qt stylesheet fragment (may contain {placeholders})
#   CSS_BTN_*       – QPushButton stylesheet templates
#
# Usage in widget code:
#   widget.setStyleSheet(CSS_TABLE)                     # static string
#   widget.setStyleSheet(CSS_BTN_PRIMARY.format(         # template + overrides
#       padding="6px 18px", font_size="14px"
#   ))

# ── Colour palette ──────────────────────────────────────────────────────────

# Background hierarchy (three depths)
CLR_BG_0          = "#1e1e1e"   # deepest  — main window, table bg, editor bg
CLR_BG_1          = "#2d2d2d"   # mid-dark — panel frames, scroll bars, tabs
CLR_BG_2          = "#3c3c3c"   # mid      — input fields, dropdowns, hover

# Borders
CLR_BORDER        = "#3e3e3e"   # subtle hairline — splitter handles, grid lines
CLR_BORDER_VIS    = "#555555"   # visible edge   — input rims, button borders

# Text
CLR_TEXT          = "#d4d4d4"   # primary body text
CLR_TEXT_MUTED    = "#888888"   # muted / placeholder / secondary text
CLR_TEXT_INVERSE  = "#ffffff"   # text on coloured backgrounds

# Accent (blue family)
CLR_ACCENT        = "#007acc"   # main accent  — header underlines, active tab
CLR_ACCENT_DARK   = "#094771"   # dark accent  — selection highlight, pressed

# Primary action button (blue)
CLR_BTN_PRIMARY   = "#0e639c"   # primary CTA background
CLR_BTN_HOVER     = "#1177bb"   # primary CTA hover

# Start / Stop button colours (green / red semantic pair)
CLR_START_BG      = "#2d6e2d"   # ▶ Start   — green
CLR_START_HOVER   = "#3a8a3a"
CLR_START_PRESSED = "#1e4e1e"
CLR_STOP_BG       = "#8b3a3a"   # ■ Stop    — red
CLR_STOP_HOVER    = "#a54545"
CLR_STOP_PRESSED  = "#6e2e2e"

# Delete button
CLR_DELETE_BG     = "#8b0000"   # DELETE active toggle background
CLR_DELETE_HOVER  = "#a00000"
CLR_DELETE_BORDER = "#ff4444"   # DELETE active border highlight

# Generic button hover (neutral grey)
CLR_BTN_HOVER_GREY = "#4a4a4a"

# Selection / highlight
CLR_SELECTION_BG  = "#264f78"   # text-editor selection highlight

# Result-row tinting
CLR_MATCHED_BG    = "#3a2e2e"   # subtle red  — attack detected
CLR_CLEAN_BG      = "#2e3a2e"   # subtle green — clean traffic

# Section headers
CLR_SECTION_BG    = "#252525"   # header-bar background


# ── Reusable CSS templates ──────────────────────────────────────────────────

# Section / panel header bars (title, editor toolbar, result-panel bar)
CSS_SECTION_HEADER = (
    "color: {CLR_TEXT};"
    "background-color: {CLR_SECTION_BG};"
    "padding: {padding};"
    "border-bottom: 2px solid {CLR_ACCENT};"
)

# Bottom button bar (rule-panel bottom, etc.)
CSS_BAR_BOTTOM = (
    "background-color: {CLR_BG_1};"
    "border-top: 1px solid {CLR_BORDER};"
)

# QSplitter handles
CSS_SPLITTER_HANDLE = (
    "QSplitter::handle {{ background-color: {CLR_BORDER}; }}"
)

# QScrollArea — invisible border, dark scrollbar
CSS_SCROLL_AREA = (
    "QScrollArea {{ border: none; background-color: {CLR_BG_0}; }}"
    "QScrollBar:vertical {{ background: {CLR_BG_1}; width: 8px; }}"
    "QScrollBar::handle:vertical {{ background: {CLR_BORDER_VIS};"
    "border-radius: 4px; min-height: 30px; }}"
    "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}"
)

# QTableWidget — dark grid, white text
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

# QPlainTextEdit — monospace code / CSV editor
CSS_EDITOR = (
    "QPlainTextEdit {{"
    "background-color: {CLR_BG_0}; color: {CLR_TEXT};"
    "border: none; padding: 8px;"
    "selection-background-color: {CLR_SELECTION_BG};"
    "}}"
)

# QLineEdit — dark input field
CSS_LINE_EDIT = (
    "QLineEdit {{"
    "background-color: {CLR_BG_2}; color: {CLR_TEXT};"
    "border: 1px solid {CLR_BORDER_VIS}; border-radius: 3px;"
    "padding: 4px 8px;"
    "}}"
)

# ── Button CSS templates (each returns a full QPushButton block) ────────────

# Blue primary button (Save, +, etc.)
CSS_BTN_PRIMARY = (
    "QPushButton {{{padding}"
    "background-color: {CLR_BTN_PRIMARY}; color: {CLR_TEXT_INVERSE};"
    "border: none; border-radius: 4px;"
    "font-weight: bold;"
    "}}"
    "QPushButton:hover {{ background-color: {CLR_BTN_HOVER}; }}"
    "QPushButton:pressed {{ background-color: {CLR_ACCENT_DARK}; }}"
)

# Green Start Detection button
CSS_BTN_START = (
    "QPushButton {{{padding}"
    "background-color: {CLR_START_BG}; color: {CLR_TEXT_INVERSE};"
    "border: none; border-radius: 4px;"
    "font-weight: bold;"
    "}}"
    "QPushButton:hover {{ background-color: {CLR_START_HOVER}; }}"
    "QPushButton:pressed {{ background-color: {CLR_START_PRESSED}; }}"
)

# Red Stop Detection button
CSS_BTN_STOP = (
    "QPushButton {{{padding}"
    "background-color: {CLR_STOP_BG}; color: {CLR_TEXT_INVERSE};"
    "border: none; border-radius: 4px;"
    "font-weight: bold;"
    "}}"
    "QPushButton:hover {{ background-color: {CLR_STOP_HOVER}; }}"
    "QPushButton:pressed {{ background-color: {CLR_STOP_PRESSED}; }}"
)

# Neutral "Open…" / secondary button (grey, bordered)
CSS_BTN_SECONDARY = (
    "QPushButton {{{padding}"
    "background-color: {CLR_BG_2}; color: {CLR_TEXT};"
    "border: 1px solid {CLR_BORDER_VIS}; border-radius: 3px;"
    "font-weight: bold;"
    "}}"
    "QPushButton:hover {{ background-color: {CLR_BTN_HOVER_GREY}; }}"
)

# DELETE button — inactive state
CSS_BTN_DELETE_OFF = (
    "QPushButton {{{padding}"
    "background-color: {CLR_BG_2}; color: {CLR_TEXT};"
    "border: 1px solid {CLR_BORDER_VIS}; border-radius: 4px;"
    "font-weight: bold;"
    "}}"
    "QPushButton:hover {{ background-color: {CLR_BTN_HOVER_GREY}; }}"
    "QPushButton:checked {{ background-color: {CLR_DELETE_BG}; }}"
)

# DELETE button — active (delete-mode) state
CSS_BTN_DELETE_ON = (
    "QPushButton {{{padding}"
    "background-color: {CLR_DELETE_BG}; color: {CLR_TEXT_INVERSE};"
    "border: 2px solid {CLR_DELETE_BORDER}; border-radius: 4px;"
    "font-weight: bold;"
    "}}"
    "QPushButton:hover {{ background-color: {CLR_DELETE_HOVER}; }}"
)

# AUTO_FOLLOW toggle — active (green)
CSS_BTN_AUTO_FOLLOW_ON = (
    "QPushButton {{{padding}"
    "background-color: {CLR_START_BG}; color: {CLR_TEXT_INVERSE};"
    "border: 1px solid {CLR_START_HOVER}; border-radius: 3px;"
    "font-weight: bold;"
    "}}"
    "QPushButton:hover {{ background-color: {CLR_START_HOVER}; }}"
    "QPushButton:checked {{ background-color: {CLR_START_BG}; }}"
)

# AUTO_FOLLOW toggle — inactive (grey)
CSS_BTN_AUTO_FOLLOW_OFF = (
    "QPushButton {{{padding}"
    "background-color: {CLR_BG_2}; color: {CLR_TEXT_MUTED};"
    "border: 1px solid {CLR_BORDER_VIS}; border-radius: 3px;"
    "font-weight: bold;"
    "}}"
    "QPushButton:hover {{ background-color: {CLR_BTN_HOVER_GREY}; }}"
)

# ── App-level / global stylesheet ───────────────────────────────────────────

CSS_APP_GLOBAL = (
    "QMainWindow {{ background-color: {CLR_BG_0}; }}"
    "QToolTip {{"
    "background-color: {CLR_BG_1}; color: {CLR_TEXT};"
    "border: 1px solid {CLR_BORDER_VIS};"
    "}}"
)


# =============================================================================
# RulePanel — left-side rule management
# =============================================================================
class RulePanel(QWidget):
    """Left panel: scrollable rule list with checkboxes, add/delete controls,
    and start/stop detection buttons at the very bottom.

    The panel is populated via ``rebuild_from_csv_text()``, which parses CSV
    text (typically the contents of the right-side editor) and creates one row
    per valid rule.  Rule add / delete / toggle operations emit signals that
    the owning window uses to keep the editor text in sync.
    """

    # =========================================================================
    # Signals — integration points for external detection modules
    # =========================================================================
    #
    # │  SIGNAL               │  PAYLOAD        │  PURPOSE
    # │  ──────────────────── │  ────────────── │  ──────────────────────
    # │  detection_started     │  (none)          │  User pressed ▶ Start
    # │  detection_stopped     │  (none)          │  User pressed ■ Stop
    # │  rule_added            │  dict            │  New rule appended (full CSV row)
    # │  rule_deleted          │  str             │  rule_id of removed rule
    # │  rule_toggled          │  str, bool       │  rule_id, enabled/disabled
    #
    # HOW TO INTEGRATE EXTERNAL DETECTION CODE
    # ────────────────────────────────────────
    # Other team members should connect to ``detection_started`` and
    # ``detection_stopped`` to start/stop their detection engines.  The
    # recommended pattern (demonstrated in FeatureDetectWindow) is:
    #
    #   rule_panel.detection_started.connect(your_detector.start)
    #   rule_panel.detection_stopped.connect(your_detector.stop)
    #
    # When your detector produces a ``DetectionResult``, feed it directly
    # to the result panel:
    #
    #   result_panel.add_result(detection_result)   # one row per call
    #
    # To read which rules are enabled, call:
    #
    #   rule_panel.get_enabled_rule_ids()   # → list[str]
    #   rule_panel.get_all_rules()          # → list[dict]
    #
    # SIGNAL FLOW (end-to-end)
    # ────────────────────────
    #   [▶ Start] → RulePanel._on_start()
    #            → prints "feature_detector_is_on"
    #            → emits detection_started
    #            → FeatureDetectWindow._start_detection()
    #            → QTimer → _generate_mock_result()
    #            → ResultPanel.add_result() → table row
    #
    #   Replace _generate_mock_result() with your real detector output
    #   to switch from simulation to live detection.
    # =========================================================================

    # Signals emitted to the outside world
    detection_started = pyqtSignal()
    detection_stopped = pyqtSignal()
    rule_added = pyqtSignal(dict)          # new rule data dict
    rule_deleted = pyqtSignal(str)         # rule_id of deleted rule
    rule_toggled = pyqtSignal(str, bool)   # rule_id, checked

    # ── CSV field names (must match signature_rules.csv header) ────────────
    FIELD_NAMES = [
        "rule_id", "name", "category", "level", "protocol",
        "match_type", "pattern", "target_fields", "nocase",
        "enabled", "description", "suggestion",
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rules: list[dict[str, Any]] = []          # parsed rule rows
        self._rule_widgets: dict[str, QWidget] = {}      # rule_id → row widget
        self._checkboxes: dict[str, QCheckBox] = {}      # rule_id → checkbox
        self._delete_mode: bool = False
        self._delete_button: QPushButton | None = None
        self._rebuilding: bool = False                   # guard during rebuild

        self._build_ui()
        # Rules are loaded externally via rebuild_from_csv_text().

    # ── UI construction ─────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # -- header -----------------------------------------------------------
        header = QLabel("Rule List")
        header.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        header.setStyleSheet(CSS_SECTION_HEADER.format(
            CLR_TEXT=CLR_TEXT, CLR_SECTION_BG=CLR_SECTION_BG,
            CLR_ACCENT=CLR_ACCENT, padding="8px 12px",
        ))
        layout.addWidget(header)

        # -- scrollable rule list ---------------------------------------------
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setStyleSheet(CSS_SCROLL_AREA.format(
            CLR_BG_0=CLR_BG_0, CLR_BG_1=CLR_BG_1,
            CLR_BORDER_VIS=CLR_BORDER_VIS,
        ))

        self._rule_container = QWidget()
        self._rule_container.setStyleSheet(
            f"background-color: {CLR_BG_0};")
        self._rule_layout = QVBoxLayout(self._rule_container)
        self._rule_layout.setContentsMargins(4, 4, 4, 4)
        self._rule_layout.setSpacing(2)
        self._rule_layout.addStretch()  # push rows to the top
        self._scroll.setWidget(self._rule_container)
        layout.addWidget(self._scroll, stretch=1)

        # -- bottom button bar ------------------------------------------------
        layout.addWidget(self._build_button_bar())

    def _build_button_bar(self) -> QWidget:
        """Construct the bottom control bar: [+], [DELETE], [▶ Start], [■ Stop]."""
        bar = QWidget()
        bar.setStyleSheet(CSS_BAR_BOTTOM.format(
            CLR_BG_1=CLR_BG_1, CLR_BORDER=CLR_BORDER))
        outer = QVBoxLayout(bar)
        outer.setContentsMargins(8, 6, 8, 6)
        outer.setSpacing(6)

        # Row 1 — Add & Delete
        row1 = QHBoxLayout()
        row1.setSpacing(8)

        # [+] button
        self._btn_add = QPushButton("＋")
        self._btn_add.setToolTip("Add a new rule")
        self._btn_add.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self._btn_add.setStyleSheet(CSS_BTN_PRIMARY.format(
            padding="padding: 6px 18px;",
            CLR_BTN_PRIMARY=CLR_BTN_PRIMARY,
            CLR_TEXT_INVERSE=CLR_TEXT_INVERSE,
            CLR_BTN_HOVER=CLR_BTN_HOVER,
            CLR_ACCENT_DARK=CLR_ACCENT_DARK,
        ))
        self._btn_add.clicked.connect(self._on_add_rule)
        row1.addWidget(self._btn_add)

        # [DELETE] toggle button
        self._delete_button = QPushButton("DELETE")
        self._delete_button.setToolTip(
            "Click to enter delete mode, then click a rule name to remove it"
        )
        self._delete_button.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self._delete_button.setCheckable(True)
        self._delete_button.toggled.connect(self._on_delete_toggled)
        self._update_delete_button_style(False)
        row1.addWidget(self._delete_button)

        row1.addStretch()
        outer.addLayout(row1)

        # Row 2 — Start / Stop
        row2 = QHBoxLayout()
        row2.setSpacing(8)

        self._btn_start = QPushButton("▶ Start Detection")
        self._btn_start.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self._btn_start.setStyleSheet(CSS_BTN_START.format(
            padding="padding: 8px 20px;",
            CLR_START_BG=CLR_START_BG,
            CLR_TEXT_INVERSE=CLR_TEXT_INVERSE,
            CLR_START_HOVER=CLR_START_HOVER,
            CLR_START_PRESSED=CLR_START_PRESSED,
        ))
        self._btn_start.clicked.connect(self._on_start)
        row2.addWidget(self._btn_start)

        self._btn_stop = QPushButton("■ Stop Detection")
        self._btn_stop.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self._btn_stop.setStyleSheet(CSS_BTN_STOP.format(
            padding="padding: 8px 20px;",
            CLR_STOP_BG=CLR_STOP_BG,
            CLR_TEXT_INVERSE=CLR_TEXT_INVERSE,
            CLR_STOP_HOVER=CLR_STOP_HOVER,
            CLR_STOP_PRESSED=CLR_STOP_PRESSED,
        ))
        self._btn_stop.clicked.connect(self._on_stop)
        self._btn_stop.setEnabled(False)  # no detection running initially
        row2.addWidget(self._btn_stop)

        row2.addStretch()
        outer.addLayout(row2)

        return bar

    def _update_delete_button_style(self, active: bool) -> None:
        """Change DELETE button appearance based on toggle state."""
        if active:
            self._delete_button.setStyleSheet(CSS_BTN_DELETE_ON.format(
                padding="padding: 6px 14px;",
                CLR_DELETE_BG=CLR_DELETE_BG,
                CLR_TEXT_INVERSE=CLR_TEXT_INVERSE,
                CLR_DELETE_BORDER=CLR_DELETE_BORDER,
                CLR_DELETE_HOVER=CLR_DELETE_HOVER,
            ))
        else:
            self._delete_button.setStyleSheet(CSS_BTN_DELETE_OFF.format(
                padding="padding: 6px 14px;",
                CLR_BG_2=CLR_BG_2, CLR_TEXT=CLR_TEXT,
                CLR_BORDER_VIS=CLR_BORDER_VIS,
                CLR_BTN_HOVER_GREY=CLR_BTN_HOVER_GREY,
                CLR_DELETE_BG=CLR_DELETE_BG,
            ))

    # ── rule population (driven externally by editor sync) ─────────────────

    def clear_rules(self) -> None:
        """Remove every rule row from the UI and internal model."""
        self._rebuilding = True
        try:
            for _, widget in list(self._rule_widgets.items()):
                self._rule_layout.removeWidget(widget)
                widget.deleteLater()
            self._rule_widgets.clear()
            self._checkboxes.clear()
            self._rules.clear()

            # Remove any lingering placeholder labels
            for i in reversed(range(self._rule_layout.count())):
                item = self._rule_layout.itemAt(i)
                if item is not None:
                    w = item.widget()
                    if w is not None and isinstance(w, QLabel):
                        self._rule_layout.removeWidget(w)
                        w.deleteLater()
        finally:
            self._rebuilding = False

    def rebuild_from_csv_text(self, text: str) -> None:
        """Parse *text* as CSV and rebuild the entire rule-list UI.

        Rows that fail to parse are silently skipped — only well-formed rule
        rows appear in the left panel.  The raw text (including comments and
        malformed lines) remains intact in the editor.
        """
        self.clear_rules()
        self._rebuilding = True
        try:
            if not text.strip():
                self._add_placeholder_row("(no rules — open a rules CSV file)")
                return

            try:
                reader = csv.DictReader(io.StringIO(text))
            except csv.Error:
                self._add_placeholder_row("(unable to parse CSV)")
                return

            if reader.fieldnames is None:
                self._add_placeholder_row("(no CSV header found)")
                return

            row_count = 0
            for row in reader:
                # Skip rows that lack the minimum required fields
                if not row.get("rule_id") and not row.get("name"):
                    continue
                row = {k: v.strip() if isinstance(v, str) else v
                       for k, v in row.items()}
                self._rules.append(row)
                self._add_rule_row(row)
                row_count += 1

            if row_count == 0:
                self._add_placeholder_row("(no valid rule rows found)")
        finally:
            self._rebuilding = False

    def _add_placeholder_row(self, text: str) -> None:
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color: {CLR_TEXT_MUTED}; padding: 8px;")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        # Insert before the stretch
        self._rule_layout.insertWidget(self._rule_layout.count() - 1, lbl)

    def _add_rule_row(self, rule: dict[str, Any]) -> None:
        """Create one row: [checkbox] rule_name  (with click-to-delete support)."""
        rule_id = rule.get("rule_id", "")
        name = rule.get("name", rule_id) or "???"
        enabled = str(rule.get("enabled", "true")).strip().lower() in ("true", "1", "yes")

        row_widget = QWidget()
        row_widget.setStyleSheet("background-color: transparent;")
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(4, 2, 8, 2)
        row_layout.setSpacing(6)

        # Checkbox — block signals during rebuild to avoid feedback loops
        cb = QCheckBox()
        cb.setChecked(enabled)
        cb.setToolTip(f"Enable/disable rule: {name}")
        cb.setStyleSheet(f"color: {CLR_TEXT};")
        if self._rebuilding:
            cb.blockSignals(True)
        cb.toggled.connect(lambda checked, rid=rule_id: self.rule_toggled.emit(rid, checked))
        row_layout.addWidget(cb)

        # Rule name label — clickable for delete mode
        name_lbl = QLabel(name)
        name_lbl.setFont(QFont("Segoe UI", 10))
        name_lbl.setStyleSheet(f"color: {CLR_TEXT}; padding: 3px 0;")
        name_lbl.setCursor(Qt.CursorShape.PointingHandCursor)
        name_lbl.mousePressEvent = lambda _, rid=rule_id: self._on_rule_name_clicked(rid)
        row_layout.addWidget(name_lbl, stretch=1)

        # Category badge
        cat = rule.get("category", "")
        if cat:
            cat_lbl = QLabel(cat)
            cat_lbl.setFont(QFont("Segoe UI", 8))
            cat_lbl.setStyleSheet(
                f"color: {CLR_TEXT_MUTED}; background-color: {CLR_BG_2};"
                f"border-radius: 3px; padding: 1px 6px;"
            )
            row_layout.addWidget(cat_lbl)

        self._rule_widgets[rule_id] = row_widget
        self._checkboxes[rule_id] = cb

        # Insert before the stretch item at the end
        insert_at = self._rule_layout.count() - 1
        self._rule_layout.insertWidget(insert_at, row_widget)

    # ── button handlers ─────────────────────────────────────────────────────

    def _on_add_rule(self) -> None:
        """Open the Add-Rule dialog, validate input, and emit ``rule_added``.

        This method is robust against **any** user input — empty fields,
        special characters, extremely long strings, Unicode, duplicate IDs,
        and malformed data are all handled gracefully without crashing.
        """
        dlg = _AddRuleDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        try:
            rule = dlg.get_rule()
        except Exception as exc:
            QMessageBox.warning(
                self, "Add Rule Failed",
                f"Could not read the rule form:\n{exc}"
            )
            return

        # --- validate required fields -------------------------------------------
        rule_id = rule.get("rule_id", "").strip()
        rule_name = rule.get("name", "").strip()

        if not rule_id:
            # Auto-generate a rule_id when the user leaves it blank
            existing_ids = {r.get("rule_id", "") for r in self._rules}
            n = 1
            while f"USR-{n:04d}" in existing_ids:
                n += 1
            rule["rule_id"] = f"USR-{n:04d}"
            rule_id = rule["rule_id"]

        if not rule_name:
            rule["name"] = rule_id  # fall back to rule_id as display name

        # --- sanitise string fields (truncate extremely long values) ------------
        for key in list(rule.keys()):
            val = rule[key]
            if isinstance(val, str):
                if len(val) > 4096:
                    rule[key] = val[:4093] + "…"
                # Replace characters that could break CSV
                rule[key] = val.replace("\n", " ").replace("\r", " ")

        # --- check for duplicate rule_id ----------------------------------------
        existing_ids = {r.get("rule_id", "") for r in self._rules}
        if rule_id in existing_ids:
            QMessageBox.warning(
                self, "Duplicate Rule ID",
                f"A rule with ID '{rule_id}' already exists.\n"
                f"Please choose a different Rule ID."
            )
            return

        # --- success ------------------------------------------------------------
        self._rules.append(rule)
        self._add_rule_row(rule)
        self.rule_added.emit(rule)

    def _on_delete_toggled(self, checked: bool) -> None:
        """Enter or leave delete mode."""
        self._delete_mode = checked
        self._update_delete_button_style(checked)

    def _on_rule_name_clicked(self, rule_id: str) -> None:
        """Handle click on a rule name label."""
        if self._delete_mode:
            self._delete_rule(rule_id)
            # Exit delete mode after one deletion
            self._delete_mode = False
            self._delete_button.setChecked(False)
            self._update_delete_button_style(False)

    def _delete_rule(self, rule_id: str) -> None:
        """Remove a rule by *rule_id* from both the model and the UI."""
        # Remove from model
        self._rules = [r for r in self._rules
                       if r.get("rule_id", "") != rule_id]

        # Remove from UI
        widget = self._rule_widgets.pop(rule_id, None)
        if widget is not None:
            self._rule_layout.removeWidget(widget)
            widget.deleteLater()
        self._checkboxes.pop(rule_id, None)

        # Update placeholder if no rules remain
        if not self._rules:
            self._add_placeholder_row("(no rules remaining)")

        self.rule_deleted.emit(rule_id)

    def _on_start(self) -> None:
        """Handler for the ▶ Start Detection button.

        Prints ``feature_detector_is_on`` to stdout, then emits
        ``detection_started`` so that downstream consumers (e.g. the
        detection engine, FeatureDetectWindow) can react.

        **Integration note for other team members:**
        Connect your external detection function to the
        ``detection_started`` signal on this panel.  The signal is
        emitted here, after the console print.  See the signal
        documentation at the top of this class for the full flow.
        """
        print("feature_detector_is_on")
        self.detection_started.emit()

    def _on_stop(self) -> None:
        """Handler for the ■ Stop Detection button.

        Prints ``feature_detector_is_off`` to stdout, then emits
        ``detection_stopped``.  Connect your external detector's stop
        / teardown routine to ``detection_stopped``.
        """
        print("feature_detector_is_off")
        self.detection_stopped.emit()

    # ── detection-state button management ──────────────────────────────────

    def set_detection_active(self, active: bool) -> None:
        """Enable or disable buttons based on whether detection is running.

        When detection is **active** the user must not be able to modify
        rules or start another detection; only Stop is available.

        When detection is **idle** the opposite applies — rule management
        and Start are available, but Stop is disabled (nothing to stop).
        """
        self._btn_add.setEnabled(not active)
        self._delete_button.setEnabled(not active)
        self._btn_start.setEnabled(not active)
        self._btn_stop.setEnabled(active)

    # ── public helpers ──────────────────────────────────────────────────────

    def get_enabled_rule_ids(self) -> list[str]:
        """Return rule_ids whose checkboxes are checked."""
        return [rid for rid, cb in self._checkboxes.items() if cb.isChecked()]

    def get_all_rules(self) -> list[dict[str, Any]]:
        return list(self._rules)


# =============================================================================
# _AddRuleDialog — simple form for adding a new rule
# =============================================================================
class _AddRuleDialog(QDialog):
    """Modal dialog to collect fields for a new signature rule."""

    FIELDS = [
        ("rule_id", "Rule ID"),
        ("name", "Name"),
        ("category", "Category"),
        ("level", "Level"),
        ("protocol", "Protocol"),
        ("match_type", "Match Type"),
        ("pattern", "Pattern"),
        ("target_fields", "Target Fields"),
        ("description", "Description"),
        ("suggestion", "Suggestion"),
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add New Rule")
        self.setMinimumWidth(420)
        self._inputs: dict[str, QLineEdit] = {}
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        form = QFormLayout()
        for key, label in self.FIELDS:
            le = QLineEdit()
            le.setStyleSheet(CSS_LINE_EDIT.format(
                CLR_BG_2=CLR_BG_2, CLR_TEXT=CLR_TEXT,
                CLR_BORDER_VIS=CLR_BORDER_VIS))
            self._inputs[key] = le
            form.addRow(label, le)

        # Sensible defaults
        self._inputs["enabled"] = QLineEdit("true")  # hidden default
        self._inputs["nocase"] = QLineEdit("true")

        layout.addLayout(form)

        # Button box
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addSpacing(12)
        layout.addWidget(buttons)

        self.setStyleSheet(f"background-color: {CLR_BG_1}; color: {CLR_TEXT};")

    def get_rule(self) -> dict[str, Any]:
        """Return the entered fields as a rule dict.

        Robust against any input: empty strings are kept as-is (the caller
        handles validation), Unicode is preserved, and leading/trailing
        whitespace is stripped.
        """
        rule: dict[str, Any] = {}
        for key, _ in self.FIELDS:
            try:
                raw = self._inputs[key].text()
            except (KeyError, AttributeError):
                raw = ""
            # Normalise to string and strip whitespace
            if not isinstance(raw, str):
                raw = str(raw)
            rule[key] = raw.strip()
        # Sensible defaults for rows that were not in the form
        rule.setdefault("enabled", "true")
        rule.setdefault("nocase", "true")
        rule.setdefault("target_fields", "")
        return rule


# =============================================================================
# ResultPanel — right-lower detection-results table
# =============================================================================
class ResultPanel(QWidget):
    """Table display of ``DetectionResult`` objects (from core.models).

    When empty the panel shows a centred "no bad behavior detected" label.

    Control buttons
    ---------------
    **CLEAR** — one-click clear of all results (resets to placeholder).

    **AUTO_FOLLOW** — toggle button; when active (default) the table
    automatically scrolls to the newest row on every insert.  Click to
    pause (freeze the current view), click again to resume following.
    """

    COLUMNS = [
        ("packet_id", "Packet ID"),
        ("matched", "Matched"),
        ("alerts", "Alerts"),
        ("engine_name", "Engine"),
        ("cost_ms", "Cost (ms)"),
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._results: list[Any] = []   # DetectionResult instances
        self._auto_follow: bool = True  # default: auto-scroll to latest

        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # -- header bar (title + buttons) ------------------------------------
        bar = QWidget()
        bar.setStyleSheet(CSS_SECTION_HEADER.format(
            CLR_TEXT=CLR_TEXT, CLR_SECTION_BG=CLR_SECTION_BG,
            CLR_ACCENT=CLR_ACCENT, padding="4px 10px 4px 6px",
        ))
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(10, 4, 6, 4)

        title = QLabel("Detection Results")
        title.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {CLR_TEXT};")
        bar_layout.addWidget(title)

        bar_layout.addStretch()

        # CLEAR button
        btn_clear = QPushButton("CLEAR")
        btn_clear.setToolTip("Remove all detection results")
        btn_clear.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        btn_clear.setStyleSheet(CSS_BTN_SECONDARY.format(
            padding="padding: 3px 12px;",
            CLR_BG_2=CLR_BG_2, CLR_TEXT=CLR_TEXT,
            CLR_BORDER_VIS=CLR_BORDER_VIS,
            CLR_BTN_HOVER_GREY=CLR_BTN_HOVER_GREY,
        ))
        btn_clear.clicked.connect(self.clear_results)
        bar_layout.addWidget(btn_clear)

        # AUTO_FOLLOW toggle button
        self._btn_auto_follow = QPushButton("AUTO_FOLLOW ✓")
        self._btn_auto_follow.setToolTip(
            "Auto-scroll to newest result — click to toggle off"
        )
        self._btn_auto_follow.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        self._btn_auto_follow.setCheckable(True)
        self._btn_auto_follow.setChecked(True)
        self._btn_auto_follow.toggled.connect(self._on_auto_follow_toggled)
        self._update_auto_follow_style(True)
        bar_layout.addWidget(self._btn_auto_follow)

        layout.addWidget(bar)

        # -- stacked: table / placeholder -------------------------------------
        self._stack = QStackedWidget()
        self._stack.addWidget(self._build_table_page())
        self._stack.addWidget(self._build_placeholder_page())
        self._stack.setCurrentIndex(1)
        layout.addWidget(self._stack, stretch=1)

    def _update_auto_follow_style(self, active: bool) -> None:
        """Update AUTO_FOLLOW button appearance to reflect toggle state."""
        if active:
            self._btn_auto_follow.setText("AUTO_FOLLOW ✓")
            self._btn_auto_follow.setStyleSheet(CSS_BTN_AUTO_FOLLOW_ON.format(
                padding="padding: 3px 12px;",
                CLR_START_BG=CLR_START_BG,
                CLR_TEXT_INVERSE=CLR_TEXT_INVERSE,
                CLR_START_HOVER=CLR_START_HOVER,
            ))
        else:
            self._btn_auto_follow.setText("AUTO_FOLLOW ✗")
            self._btn_auto_follow.setStyleSheet(CSS_BTN_AUTO_FOLLOW_OFF.format(
                padding="padding: 3px 12px;",
                CLR_BG_2=CLR_BG_2, CLR_TEXT_MUTED=CLR_TEXT_MUTED,
                CLR_BORDER_VIS=CLR_BORDER_VIS,
                CLR_BTN_HOVER_GREY=CLR_BTN_HOVER_GREY,
            ))

    def _on_auto_follow_toggled(self, checked: bool) -> None:
        """Toggle auto-scroll behaviour."""
        self._auto_follow = checked
        self._update_auto_follow_style(checked)
        # If re-enabled, immediately scroll to the latest row
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
            CLR_BG_0=CLR_BG_0, CLR_TEXT=CLR_TEXT,
            CLR_BORDER=CLR_BORDER, CLR_SECTION_BG=CLR_SECTION_BG,
            CLR_ACCENT=CLR_ACCENT,
        ))
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

    # ── public API ──────────────────────────────────────────────────────────

    def add_result(self, result: Any) -> None:
        """Append one DetectionResult and show the table.

        If ``_auto_follow`` is enabled (default), the table automatically
        scrolls to the newest row.
        """
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
        """Remove all rows and return to the placeholder view."""
        self._results.clear()
        self._table.setRowCount(0)
        self._stack.setCurrentIndex(1)

    # ── internals ───────────────────────────────────────────────────────────

    def _append_row(self, result: Any) -> None:
        """Render one DetectionResult as a table row."""
        row = self._table.rowCount()
        self._table.insertRow(row)

        # packet_id
        self._set_cell(row, 0, str(getattr(result, "packet_id", "—")))
        # matched
        self._set_cell(row, 1, "✓" if getattr(result, "matched", False) else "✗")
        # alerts — count + tooltip
        alerts = getattr(result, "alerts", []) or []
        alert_n = len(alerts)
        if alert_n == 0:
            self._set_cell(row, 2, "—")
        else:
            item = self._set_cell(row, 2, f"{alert_n} alert(s)")
            if item:
                item.setToolTip("\n".join(
                    f"[{getattr(a, 'level', '?')}] {getattr(a, 'rule_name', '?')}"
                    for a in alerts
                ))
        # engine_name
        self._set_cell(row, 3, str(getattr(result, "engine_name", "") or "—"))
        # cost_ms
        cost = getattr(result, "cost_ms", 0.0)
        self._set_cell(row, 4, f"{cost:.2f}" if cost else "—")

    def _set_cell(self, row: int, col: int, text: str) -> QTableWidgetItem | None:
        """Create, style, and set a table-widget item."""
        item = QTableWidgetItem(text)
        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        item.setForeground(QColor(CLR_TEXT))
        self._table.setItem(row, col, item)
        return item


# =============================================================================
# FeatureDetectWindow — the composite main window
# =============================================================================
class FeatureDetectWindow(QMainWindow):
    """Top-level window hosting the three resizable sub-panels.

    The right-upper text editor is the **source of truth** for rule data.
    The left RulePanel shows a parsed view of the editor content.
    Rule add / delete / toggle on the left directly modifies the editor text,
    and manual edits in the editor are reflected in the rule list after a
    short debounce delay.
    """

    # CSV field names — must match the header of signature_rules.csv
    _CSV_FIELDNAMES = [
        "rule_id", "name", "category", "level", "protocol",
        "match_type", "pattern", "target_fields", "nocase",
        "enabled", "description", "suggestion",
    ]

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Feature Detection — Network Attack Detector")
        self.resize(1200, 750)

        # File state
        self._csv_path: Path | None = None
        self._modified: bool = False
        self._sync_locked: bool = False          # guard against feedback loops

        # Detection simulation state
        self._detection_active: bool = False
        self._simulation_timer: QTimer | None = None
        self._sim_counter: int = 0

        # Debounce timer for editor → rules sync
        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(600)     # 600 ms after last keystroke
        self._debounce_timer.timeout.connect(self._sync_rules_from_editor)

        self._build_ui()
        self._connect_signals()

        # Show file dialog on startup (task2 requirement)
        QTimer.singleShot(100, self._prompt_open_rules_file)

    # ── UI construction ─────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        """Assemble the complete layout: left panel | right (upper | lower)."""
        # -- main horizontal splitter -----------------------------------------
        self._h_splitter = QSplitter(Qt.Orientation.Horizontal)
        self._h_splitter.setHandleWidth(3)
        self._h_splitter.setStyleSheet(CSS_SPLITTER_HANDLE.format(
            CLR_BORDER=CLR_BORDER))

        # Left panel — rule management
        self._rule_panel = RulePanel()
        self._h_splitter.addWidget(self._rule_panel)

        # Right vertical splitter
        self._v_splitter = QSplitter(Qt.Orientation.Vertical)
        self._v_splitter.setHandleWidth(3)
        self._v_splitter.setStyleSheet(CSS_SPLITTER_HANDLE.format(
            CLR_BORDER=CLR_BORDER))

        # Right-upper — text editor for rules CSV
        self._editor_panel = self._build_editor_panel()
        self._v_splitter.addWidget(self._editor_panel)

        # Right-lower — detection results
        self._result_panel = ResultPanel()
        self._v_splitter.addWidget(self._result_panel)

        # Give the two right sub-panels roughly equal space
        self._v_splitter.setSizes([350, 350])

        self._h_splitter.addWidget(self._v_splitter)

        # Default left-panel width ≈ 30% of window
        self._h_splitter.setSizes([360, 840])

        self.setCentralWidget(self._h_splitter)

    def _build_editor_panel(self) -> QWidget:
        """Right-upper panel: toolbar (Open / Save) + QPlainTextEdit.

        Uses QPlainTextEdit — the same core widget that text_editor/text_editor.py
        builds its NanoEditor around.
        """
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header bar
        bar = QWidget()
        bar.setStyleSheet(CSS_SECTION_HEADER.format(
            CLR_TEXT=CLR_TEXT, CLR_SECTION_BG=CLR_SECTION_BG,
            CLR_ACCENT=CLR_ACCENT, padding="4px 10px",
        ))
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(10, 4, 8, 4)

        self._editor_title = QLabel("Rules File — none")
        self._editor_title.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self._editor_title.setStyleSheet(f"color: {CLR_TEXT};")
        bar_layout.addWidget(self._editor_title)

        bar_layout.addStretch()

        # Open button — launches native file dialog at ../../data/rules/
        btn_open = QPushButton("Open…")
        btn_open.setToolTip("Open a rules CSV file")
        btn_open.setStyleSheet(CSS_BTN_SECONDARY.format(
            padding="padding: 4px 14px;",
            CLR_BG_2=CLR_BG_2, CLR_TEXT=CLR_TEXT,
            CLR_BORDER_VIS=CLR_BORDER_VIS,
            CLR_BTN_HOVER_GREY=CLR_BTN_HOVER_GREY,
        ))
        btn_open.clicked.connect(self._prompt_open_rules_file)
        bar_layout.addWidget(btn_open)

        # Save button
        self._btn_save = QPushButton("Save")
        self._btn_save.setStyleSheet(CSS_BTN_PRIMARY.format(
            padding="padding: 4px 14px;",
            CLR_BTN_PRIMARY=CLR_BTN_PRIMARY,
            CLR_TEXT_INVERSE=CLR_TEXT_INVERSE,
            CLR_BTN_HOVER=CLR_BTN_HOVER,
            CLR_ACCENT_DARK=CLR_ACCENT_DARK,
        ))
        self._btn_save.clicked.connect(self._on_editor_save)
        bar_layout.addWidget(self._btn_save)

        layout.addWidget(bar)

        # The text editor
        self._text_edit = QPlainTextEdit()
        self._text_edit.setFont(QFont("monospace", 11))
        self._text_edit.setTabStopDistance(40)
        self._text_edit.setStyleSheet(CSS_EDITOR.format(
            CLR_BG_0=CLR_BG_0, CLR_TEXT=CLR_TEXT,
            CLR_SELECTION_BG=CLR_SELECTION_BG,
        ))
        # Connect editor changes → debounced rule-list sync
        self._text_edit.textChanged.connect(self._on_editor_text_changed)
        layout.addWidget(self._text_edit, stretch=1)

        return panel

    # ── File dialog ─────────────────────────────────────────────────────────

    def _prompt_open_rules_file(self) -> None:
        """Pop up a native file-manager dialog opened at *../../data/rules/*
        so the user can pick a CSV rule file to load.

        Implements task2 requirement: "弹出一个Windows文件管理器（或linux的
        文件管理器）的窗口，打开的是../../data/rules这个文件夹"
        """
        # Ensure the directory exists
        rules_dir = str(_RULES_DIR) if _RULES_DIR.exists() else str(_THIS_DIR)

        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Open Rules File",
            rules_dir,
            "CSV Files (*.csv);;All Files (*)",
        )
        if not path_str:
            # User cancelled — if no file is loaded yet show placeholder
            if self._csv_path is None:
                self._text_edit.setPlainText(
                    "# No rules file selected.\n"
                    "# Click 'Open…' to choose a CSV rules file.\n"
                )
                self._rule_panel.rebuild_from_csv_text("")
            return

        self._load_file(Path(path_str))

    # ── File loading ────────────────────────────────────────────────────────

    def _load_file(self, path: Path) -> None:
        """Load *path* into the editor and rebuild the rule list."""
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(self, "Read Error", str(exc))
            return

        self._sync_locked = True
        try:
            self._text_edit.setPlainText(content)
            self._csv_path = path.resolve()
            self._modified = False
            self._editor_title.setText(f"Rules File — {path.name}")
            # Parse and populate the rule list
            self._rule_panel.rebuild_from_csv_text(content)
        finally:
            self._sync_locked = False

    # ── Sync: Editor → Rules (debounced) ────────────────────────────────────

    def _on_editor_text_changed(self) -> None:
        """(debounced) When the user types in the editor, re-parse rules."""
        if self._sync_locked:
            return
        self._modified = True
        self._debounce_timer.start()  # restart the 600 ms timer

    def _sync_rules_from_editor(self) -> None:
        """Parse the editor content and rebuild the rule list.

        Lines that don't parse as valid CSV rule rows are kept in the editor
        but won't appear in the left panel — implementing \"如果我在文件里写入
        某些字符，就应该对那一行检测那是否是个规则\".
        """
        if self._sync_locked:
            return
        text = self._text_edit.toPlainText()
        self._rule_panel.rebuild_from_csv_text(text)

    # ── Sync: Rules → Editor (immediate) ────────────────────────────────────

    def _on_rule_added(self, rule: dict[str, Any]) -> None:
        """Append a new CSV row to the editor text."""
        self._sync_locked = True
        try:
            line = self._rule_dict_to_csv_line(rule)
            text = self._text_edit.toPlainText()
            if text and not text.endswith("\n"):
                text += "\n"
            text += line + "\n"
            self._text_edit.setPlainText(text)
            self._modified = True
        finally:
            self._sync_locked = False

    def _on_rule_deleted(self, rule_id: str) -> None:
        """Remove the CSV row with *rule_id* from the editor text."""
        self._sync_locked = True
        try:
            text = self._text_edit.toPlainText()
            new_lines: list[str] = []
            # Use csv.reader to properly handle quoted fields
            try:
                reader = csv.DictReader(io.StringIO(text))
                fieldnames = reader.fieldnames
                if fieldnames is None:
                    fieldnames = self._CSV_FIELDNAMES
                # Keep the original header line
                lines = text.splitlines(keepends=True)
                if lines:
                    new_lines.append(lines[0])  # header
                    for row in reader:
                        if row.get("rule_id", "") != rule_id:
                            new_lines.append(
                                self._rule_dict_to_csv_line(row) + "\n"
                            )
            except csv.Error:
                # If we can't parse, fall back to simple line removal
                lines = text.splitlines(keepends=True)
                for line in lines:
                    if rule_id not in line:
                        new_lines.append(line)
            self._text_edit.setPlainText("".join(new_lines))
            self._modified = True
        finally:
            self._sync_locked = False
        # Re-sync the rule list after the editor update
        self._sync_rules_from_editor()

    def _on_rule_toggled_from_panel(self, rule_id: str, checked: bool) -> None:
        """Update the 'enabled' field for *rule_id* in the editor text."""
        self._sync_locked = True
        try:
            text = self._text_edit.toPlainText()
            try:
                reader = csv.DictReader(io.StringIO(text))
                fieldnames = reader.fieldnames
                if fieldnames is None:
                    fieldnames = self._CSV_FIELDNAMES
                new_lines: list[str] = []
                lines = text.splitlines(keepends=True)
                if lines:
                    new_lines.append(lines[0])  # header
                    for row in reader:
                        if row.get("rule_id", "") == rule_id:
                            row["enabled"] = "true" if checked else "false"
                        new_lines.append(
                            self._rule_dict_to_csv_line(row) + "\n"
                        )
                self._text_edit.setPlainText("".join(new_lines))
            except csv.Error:
                pass  # leave editor unchanged
            self._modified = True
        finally:
            self._sync_locked = False

    def _rule_dict_to_csv_line(self, rule: dict[str, Any]) -> str:
        """Convert a rule dict to a single CSV line (without trailing newline)."""
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=self._CSV_FIELDNAMES,
            extrasaction="ignore",
        )
        # Ensure all fieldnames are present
        full: dict[str, str] = {}
        for fn in self._CSV_FIELDNAMES:
            full[fn] = str(rule.get(fn, ""))
        writer.writerow(full)
        return output.getvalue().rstrip("\r\n")

    # ── Save logic ──────────────────────────────────────────────────────────

    def _on_editor_save(self) -> None:
        """Save editor content.  If the original file is *signature_rules.csv*
        inside ``../../data/rules/``, prompt the user to save as a new
        ``user_rules{N}.csv`` file instead (per task2 requirement).
        """
        content = self._text_edit.toPlainText()

        # Determine the save path
        if self._csv_path is not None and self._is_default_rules_file(self._csv_path):
            # Prompt to save-as a user rules file
            save_path = self._prompt_save_as_user_rules()
            if save_path is None:
                return  # user cancelled
        elif self._csv_path is not None and _is_write_allowed(self._csv_path):
            save_path = self._csv_path
        else:
            # No file open or path not writeable — prompt for save location
            save_path = self._prompt_save_as_user_rules()
            if save_path is None:
                return

        # Perform the write
        try:
            save_path.write_text(content, encoding="utf-8")
            self._csv_path = save_path
            self._modified = False
            self._editor_title.setText(f"Rules File — {save_path.name}")
        except OSError as exc:
            QMessageBox.critical(self, "Save Error", str(exc))

    def _is_default_rules_file(self, path: Path) -> bool:
        """Check whether *path* is the built-in signature_rules.csv."""
        try:
            return path.resolve() == _DEFAULT_RULES.resolve()
        except OSError:
            return False

    def _prompt_save_as_user_rules(self) -> Path | None:
        """Determine the next ``user_rules{N}.csv`` filename and show a
        save dialog defaulting to that name inside ``../../data/rules/``.
        """
        # Find next available N
        n = self._next_user_rules_num()
        default_name = f"user_rules{n}.csv"
        default_path = str(_RULES_DIR / default_name)

        path_str, _ = QFileDialog.getSaveFileName(
            self,
            "Save Rules File As",
            default_path,
            "CSV Files (*.csv);;All Files (*)",
        )
        if not path_str:
            return None
        return Path(path_str)

    @staticmethod
    def _next_user_rules_num() -> int:
        """Scan ``_RULES_DIR`` for ``user_rules*.csv`` and return the next N."""
        if not _RULES_DIR.exists():
            return 1
        max_n = 0
        pattern = re.compile(r"^user_rules(\d+)\.csv$", re.IGNORECASE)
        for child in _RULES_DIR.iterdir():
            if child.is_file():
                m = pattern.match(child.name)
                if m:
                    n = int(m.group(1))
                    if n > max_n:
                        max_n = n
        return max_n + 1

    # ── Close event ─────────────────────────────────────────────────────────

    def closeEvent(self, event) -> None:
        """If the editor has unsaved modifications, prompt to save before
        closing.  For the default *signature_rules.csv* this routes through
        the save-as prompt (per task2 requirement)."""
        if self._modified and self._text_edit.toPlainText().strip():
            answer = QMessageBox.question(
                self,
                "Unsaved Changes",
                "The rules file has been modified.\n\n"
                "Do you want to save your changes before closing?",
                QMessageBox.StandardButton.Save
                | QMessageBox.StandardButton.Discard
                | QMessageBox.StandardButton.Cancel,
            )
            if answer == QMessageBox.StandardButton.Save:
                self._on_editor_save()
                if self._modified:  # save was cancelled
                    event.ignore()
                    return
            elif answer == QMessageBox.StandardButton.Cancel:
                event.ignore()
                return

        # Stop detection if running
        self._stop_detection()
        event.accept()

    # ── signal wiring ───────────────────────────────────────────────────────
    #
    # CENTRAL WIRING HUB
    # ──────────────────
    # All signal → slot connections for detection and editor sync are
    # centralised here.  When integrating a real detection engine:
    #
    #   1. Keep the rule_* → _on_rule_* connections (editor sync).
    #   2. Replace or augment the detection_started / detection_stopped
    #      connections with your own slots.
    #   3. Your slot receives no arguments; read enabled rules via
    #      ``self._rule_panel.get_enabled_rule_ids()`` and push results
    #      via ``self._result_panel.add_result(result)``.

    def _connect_signals(self) -> None:
        """Wire RulePanel signals to detection simulation and editor sync."""
        # ── Detection signals ───────────────────────────────────────────
        # ★ INTEGRATION POINT: replace _start_detection / _stop_detection
        #    with your own detection-engine entry points.
        self._rule_panel.detection_started.connect(self._start_detection)
        self._rule_panel.detection_stopped.connect(self._stop_detection)
        # ── Rules → Editor sync ─────────────────────────────────────────
        self._rule_panel.rule_added.connect(self._on_rule_added)
        self._rule_panel.rule_deleted.connect(self._on_rule_deleted)
        self._rule_panel.rule_toggled.connect(self._on_rule_toggled_from_panel)

    # =========================================================================
    # Detection control — integration point for external detection engines
    # =========================================================================
    #
    # These two methods (_start_detection / _stop_detection) are the **main
    # integration hooks** where other team members should wire their real
    # detection logic.
    #
    # SIGNAL CHAIN (how the ▶ button reaches this code)
    # ─────────────────────────────────────────────────
    #   1. User clicks ▶ Start Detection  (RulePanel)
    #   2. RulePanel._on_start() prints "feature_detector_is_on"
    #   3. RulePanel emits  detection_started  signal
    #   4. FeatureDetectWindow._connect_signals() routes it here:
    #         rule_panel.detection_started.connect(self._start_detection)
    #   5. _start_detection()  (YOU ARE HERE)
    #
    # TO REPLACE THE MOCK WITH A REAL DETECTOR
    # ────────────────────────────────────────
    # Option A — Connect your own slot to the signal directly:
    #     rule_panel.detection_started.connect(your_detector.launch)
    #     rule_panel.detection_stopped.connect(your_detector.shutdown)
    #   Your detector calls  result_panel.add_result(detection_result)
    #   for every DetectionResult it produces.
    #
    # Option B — Replace the body of _start_detection / _stop_detection
    #   with your own logic.  Keep the guard (_detection_active) and
    #   feed results to  self._result_panel.add_result().
    #
    # Option C — Use a semaphore / threading.Event for synchronisation:
    #     self._detection_event = threading.Event()
    #     self._detection_thread = threading.Thread(target=your_loop)
    #     self._detection_thread.start()
    #   Use pyqtSignal (or a cross-thread Qt queued connection) to safely
    #   emit results from the worker thread back to the GUI thread.
    #
    # READING ENABLED RULES
    # ─────────────────────
    #     enabled_ids = self._rule_panel.get_enabled_rule_ids()
    #     all_rules   = self._rule_panel.get_all_rules()
    # =========================================================================

    def _start_detection(self) -> None:
        """Begin detection — currently runs a mock simulation.

        **Replace the body of this method** (or connect a different slot
        to ``detection_started``) to integrate a real detection engine.

        When your detector produces a result, call:
            ``self._result_panel.add_result(detection_result)``
        """
        if self._detection_active:
            return
        self._detection_active = True
        self._sim_counter = 0

        # Lock rule-management buttons while detection is running (task4)
        self._rule_panel.set_detection_active(True)

        # ── MOCK: replace the QTimer + _generate_mock_result below ──────────
        self._simulation_timer = QTimer(self)
        self._simulation_timer.timeout.connect(self._generate_mock_result)
        self._simulation_timer.start(1500)  # every 1.5 s
        # ─────────────────────────────────────────────────────────────────────

    def _stop_detection(self) -> None:
        """Stop detection — tear down the simulation timer.

        **Replace the body** to shut down your real detector.  The
        ``_detection_active`` flag is set before your code runs.
        """
        self._detection_active = False

        # Re-enable rule-management buttons when detection stops (task4)
        self._rule_panel.set_detection_active(False)

        # ── MOCK: stop the simulation timer ─────────────────────────────────
        if self._simulation_timer is not None:
            self._simulation_timer.stop()
            self._simulation_timer = None
        # ─────────────────────────────────────────────────────────────────────

    def _generate_mock_result(self) -> None:
        """Create a synthetic DetectionResult and feed it to the result panel."""
        self._sim_counter += 1

        class _MockAlert:
            def __init__(self, level, rule_name, category):
                self.level = level
                self.rule_name = rule_name
                self.category = category

        class _MockResult:
            def __init__(self, i):
                self.packet_id = f"PKT-{1000 + i:04d}"
                self.matched = (i % 5 == 0)
                self.alerts = (
                    [
                        _MockAlert("High", "SQL union select", "SQL Injection"),
                        _MockAlert("Medium", "Sensitive env file", "Suspicious Traffic"),
                    ]
                    if self.matched else []
                )
                self.engine_name = "signature_engine"
                self.cost_ms = round(0.5 + (i * 0.07), 2)

        try:
            from core.models import DetectionResult, Alert, AlertLevel, AttackCategory
            result = DetectionResult(
                packet_id=f"PKT-{1000 + self._sim_counter:04d}",
                matched=(self._sim_counter % 5 == 0),
                alerts=(
                    [
                        Alert(
                            alert_id=f"ALERT-{self._sim_counter:04d}",
                            timestamp=0.0,
                            category=AttackCategory.SQL_INJECTION,
                            level=AlertLevel.HIGH,
                            src_ip="10.0.0.1",
                            dst_ip="10.0.0.2",
                            src_port=54321,
                            dst_port=80,
                            protocol="HTTP",
                            rule_id="SIG-1001",
                            rule_name="SQL union select",
                            evidence="union select found in payload",
                            description="Detect SQL injection using union select",
                        )
                    ]
                    if self._sim_counter % 5 == 0 else []
                ),
                engine_name="signature_engine",
                cost_ms=round(0.5 + self._sim_counter * 0.07, 2),
            )
        except ImportError:
            result = _MockResult(self._sim_counter)

        self._result_panel.add_result(result)


# =============================================================================
# Entry point
# =============================================================================
def main() -> None:
    """Launch the feature-detection composite window."""
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    app.setStyleSheet(CSS_APP_GLOBAL.format(
        CLR_BG_0=CLR_BG_0, CLR_BG_1=CLR_BG_1,
        CLR_TEXT=CLR_TEXT, CLR_BORDER_VIS=CLR_BORDER_VIS,
    ))

    window = FeatureDetectWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()