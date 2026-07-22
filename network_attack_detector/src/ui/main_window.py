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

# ── figures directory ────────────────────────────────────────────────────────
_FIGURES_DIR = Path(__file__).resolve().parent / "figures"

# ── button descriptor ────────────────────────────────────────────────────────
# image_key maps to {image_key}.png (active) and {image_key}_grey.png (inactive)
# inside the figures/ directory.
BUTTONS = [
    {"label": "B",  "tooltip": "behavior_detect", "cls": BehaviorDetectWindow,
     "image_key": "Behavior_detect"},
    {"label": "F",  "tooltip": "feature_detect",  "cls": FeatureDetectWindow,
     "image_key": "feature_detect"},
    {"label": "P",  "tooltip": "packet_capture",  "cls": PacketCaptureWindow,
     "image_key": "packet_capture"},
    {"label": "Sh", "tooltip": "shell",            "cls": ShellWindow,
     "image_key": "shell"},
    {"label": "St", "tooltip": "statistic",        "cls": StatisticWindow,
     "image_key": "statistic"},
    {"label": "T",  "tooltip": "text_editor",      "cls": NanoEditor,
     "image_key": "text_editor"},
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
        self._image_active: str | None = None    # shown when button is selected
        self._image_inactive: str | None = None  # shown when button is unselected

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

    def set_images(self, active_path: str, inactive_path: str) -> None:
        """Set the image paths for active (selected) and inactive (unselected) states.

        Args:
            active_path: path to the PNG shown when the button is selected.
            inactive_path: path to the PNG shown when the button is unselected.
        """
        self._image_active = active_path
        self._image_inactive = inactive_path
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

        # Foreground — pick the right image (active vs inactive), fall back to text
        image_path = self._image_active if self._active else self._image_inactive
        if image_path and Path(image_path).exists():
            icon = QIcon(image_path)
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

            # Wire up figure images (active = non-_grey, inactive = _grey)
            image_key: str = spec.get("image_key", spec["tooltip"])
            active_img = str(_FIGURES_DIR / f"{image_key}.png")
            inactive_img = str(_FIGURES_DIR / f"{image_key}_grey.png")
            btn.set_images(active_img, inactive_img)

            # Instantiate the page window.
            # Indices 0 (behavior) and 1 (feature) are passed auto_open=False
            # so they don't pop up a file dialog when loaded from the sidebar.
            if idx in (0, 1):
                page: QWidget = spec["cls"](auto_open=False)
            else:
                page: QWidget = spec["cls"]()
            self._stack.addWidget(page)

        # ── wire up StatisticWindow → sub-windows ─────────────────────────
        # Pass the shared StatisticWindow instance so that behavior_detect,
        # feature_detect, and packet_capture can feed real data into it
        # instead of the window generating its own mock data.
        stat_window = self._stack.widget(4)  # StatisticWindow
        stat_window.set_use_mock_data(False)  # disable synthetic data generation

        behavior_win = self._stack.widget(0)  # BehaviorDetectWindow
        if hasattr(behavior_win, "set_statistic_window"):
            behavior_win.set_statistic_window(stat_window)

        feature_win = self._stack.widget(1)  # FeatureDetectWindow
        if hasattr(feature_win, "set_statistic_window"):
            feature_win.set_statistic_window(stat_window)

        packet_win = self._stack.widget(2)  # PacketCaptureWindow
        if hasattr(packet_win, "set_statistic_window"):
            packet_win.set_statistic_window(stat_window)

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
