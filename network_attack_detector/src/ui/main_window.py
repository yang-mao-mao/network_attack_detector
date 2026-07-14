#!/usr/bin/env python3
"""
Main window with a vertical icon bar (left sidebar) and a stacked content area.

Access restriction (per task1.md):
  - Read+Write: only main_window.py.
  - Read-only:   all other files — writing outside is forbidden.

Layout
------
  +---------------------------------------------+
  |  QHBoxLayout                                |
  |  +----------+-----------------------------+ |
  |  | SideBar  | QStackedWidget (content)    | |
  |  | (QScroll |                             | |
  |  |  Area)   | 0: BehaviorDetectWindow     | |
  |  |          | 1: FeatureDetectWindow      | |
  |  | [B]      | 2: PacketCaptureWindow      | |
  |  | [F]      | 3: ShellWindow              | |
  |  | [P]      | 4: StatisticWindow          | |
  |  | [Sh]     | 5: NanoEditor               | |
  |  | [St]     |                             | |
  |  | [T]      |                             | |
  |  +----------+-----------------------------+ |
  +---------------------------------------------+

Dependencies: PyQt6 only (per task restriction).
"""

from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QColor, QFont, QIcon, QEnterEvent, QPaintEvent, QPainter
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QMainWindow,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

# ── imports of sub-page windows ──────────────────────────────────────────────
from behavior_detect.behavior_detector import BehaviorDetectWindow
from feature_detect.feature_detect import FeatureDetectWindow
from packet_capture.packet_capture import PacketCaptureWindow
from shell.shell import ShellWindow
from statistic.statistic import StatisticWindow
from text_editor.text_editor import NanoEditor

# ── constants ────────────────────────────────────────────────────────────────
SIDEBAR_WIDTH = 60
BUTTON_SIZE = QSize(50, 50)
SIDEBAR_BG = QColor(30, 30, 30)          # black-ish background
LETTER_COLOR_DEFAULT = QColor(128, 128, 128)  # grey
LETTER_COLOR_ACTIVE = QColor(255, 255, 255)   # white
BUTTON_BG_DEFAULT = QColor(30, 30, 30)        # same as sidebar
BUTTON_BG_ACTIVE = QColor(0, 100, 200)         # blue
BUTTON_BG_HOVER = QColor(60, 60, 60)           # lighter on hover

# ── button descriptor ────────────────────────────────────────────────────────
BUTTONS = [
    {"label": "B",  "tooltip": "behavior_detect", "cls": BehaviorDetectWindow},
    {"label": "F",  "tooltip": "feature_detect",  "cls": FeatureDetectWindow},
    {"label": "P",  "tooltip": "packet_capture",  "cls": PacketCaptureWindow},
    {"label": "Sh", "tooltip": "shell",            "cls": ShellWindow},
    {"label": "St", "tooltip": "statistic",        "cls": StatisticWindow},
    {"label": "T",  "tooltip": "text_editor",      "cls": NanoEditor},
]


# =============================================================================
# SideBarButton — a square button that draws a letter (or image) at its centre
# =============================================================================
class SideBarButton(QPushButton):
    """A square sidebar button.

    States:
      * default   – grey letter on sidebar-bg
      * hover     – white letter on hover-bg
      * active    – white letter on blue bg (the page this button controls is visible)
    """

    def __init__(self, label: str, tooltip: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._label = label
        self._tooltip_text = tooltip
        self._active = False
        self._hovered = False
        self._image_path: str | None = None  # reserved for future fig/ images

        self.setFixedSize(BUTTON_SIZE)
        self.setToolTip(self._tooltip_text)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        # Make the button flat — we custom-paint everything.
        self.setStyleSheet("border: none;")

    # ── public API ───────────────────────────────────────────────────────

    def set_active(self, active: bool) -> None:
        """Toggle the *pressed* / *current-page* visual state."""
        if self._active != active:
            self._active = active
            self.update()

    def set_image(self, path: str | None) -> None:
        """Set an external image path for the button face (future use)."""
        self._image_path = path
        self.update()

    # ── event overrides ──────────────────────────────────────────────────

    def enterEvent(self, event: QEnterEvent | None) -> None:
        self._hovered = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event: QEnterEvent | None) -> None:
        self._hovered = False
        self.update()
        super().leaveEvent(event)

    # ── painting ─────────────────────────────────────────────────────────

    def paintEvent(self, _event: QPaintEvent | None) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Background colour
        if self._active:
            bg = BUTTON_BG_ACTIVE
        elif self._hovered:
            bg = BUTTON_BG_HOVER
        else:
            bg = BUTTON_BG_DEFAULT
        painter.fillRect(self.rect(), bg)

        # Foreground — image if available, otherwise the label text
        if self._image_path and Path(self._image_path).exists():
            icon = QIcon(self._image_path)
            pixmap = icon.pixmap(self.size() - QSize(12, 12))
            x = (self.width() - pixmap.width()) // 2
            y = (self.height() - pixmap.height()) // 2
            painter.drawPixmap(x, y, pixmap)
        else:
            if self._active or self._hovered:
                colour = LETTER_COLOR_ACTIVE
            else:
                colour = LETTER_COLOR_DEFAULT
            font = QFont("monospace", 13, QFont.Weight.Bold)
            painter.setFont(font)
            painter.setPen(colour)
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self._label)

        painter.end()


# =============================================================================
# SideBar — the vertical scrollable button strip
# =============================================================================
class SideBar(QScrollArea):
    """A vertically-scrollable bar that hosts :class:`SideBarButton` instances."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._buttons: list[SideBarButton] = []

        # Scroll-area settings
        self.setFixedWidth(SIDEBAR_WIDTH)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setWidgetResizable(True)
        self.setStyleSheet(f"background-color: {SIDEBAR_BG.name()}; border: none;")

        # Inner widget that holds the buttons
        inner = QWidget()
        inner.setStyleSheet(f"background-color: {SIDEBAR_BG.name()};")
        self._layout = QVBoxLayout(inner)
        self._layout.setContentsMargins(5, 5, 5, 5)
        self._layout.setSpacing(2)
        self._layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.setWidget(inner)

    # ── public API ───────────────────────────────────────────────────────

    def add_button(self, label: str, tooltip: str) -> SideBarButton:
        """Create and append a button. Returns it for signal wiring."""
        btn = SideBarButton(label, tooltip)
        self._buttons.append(btn)
        self._layout.addWidget(btn, alignment=Qt.AlignmentFlag.AlignHCenter)
        return btn

    def buttons(self) -> list[SideBarButton]:
        return self._buttons


# =============================================================================
# MainWindow
# =============================================================================
class MainWindow(QMainWindow):
    """The application shell: sidebar + stacked content pages."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Network Attack Detector")
        self.resize(1280, 800)

        # ── central widget ───────────────────────────────────────────────
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ── sidebar ──────────────────────────────────────────────────────
        self._sidebar = SideBar()
        root_layout.addWidget(self._sidebar)

        # ── stacked pages ────────────────────────────────────────────────
        self._stack = QStackedWidget()
        self._stack.setStyleSheet("background-color: #1e1e1e;")
        root_layout.addWidget(self._stack, 1)  # stretch factor = 1 → takes remaining space

        # ── populate buttons + pages ─────────────────────────────────────
        self._btn_to_index: dict[SideBarButton, int] = {}
        for idx, spec in enumerate(BUTTONS):
            btn = self._sidebar.add_button(spec["label"], spec["tooltip"])
            btn.clicked.connect(self._make_click_handler(idx))
            self._btn_to_index[btn] = idx

            # Instantiate the page window
            page: QWidget = spec["cls"]()
            self._stack.addWidget(page)

        # ── default selection ────────────────────────────────────────────
        self._current_idx: int = 0
        self._activate_button(0)

    # ── helpers ──────────────────────────────────────────────────────────

    def _make_click_handler(self, idx: int):
        """Return a callable that switches to page *idx*."""
        def handler() -> None:
            self._switch_to(idx)
        return handler

    def _switch_to(self, idx: int) -> None:
        """Deactivate old button, activate new, show corresponding page."""
        if idx == self._current_idx:
            return
        old_btn = self._sidebar.buttons()[self._current_idx]
        old_btn.set_active(False)
        self._current_idx = idx
        self._activate_button(idx)

    def _activate_button(self, idx: int) -> None:
        """Set button *idx* as active and show its page."""
        btn = self._sidebar.buttons()[idx]
        btn.set_active(True)
        self._stack.setCurrentIndex(idx)


# =============================================================================
# main
# =============================================================================
def main() -> None:
    app = QApplication(sys.argv)
    # Use Fusion style for a consistent look across platforms.
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
