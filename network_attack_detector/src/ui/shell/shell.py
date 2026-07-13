import sys
import platform

from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStatusBar,
    QTabBar,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from PyQt6.QtCore import QProcess, pyqtSignal, Qt
from PyQt6.QtGui import (
    QFont,
    QTextCursor,
    QKeyEvent,
    QStandardItemModel,
    QStandardItem,
    QColor,
)

# =============================================================================
# CSS rendering model (Qt stylesheet cascade)
# =============================================================================
#
# Qt resolves visual appearance through three prioritized layers:
#
#   1. Widget-level setStyleSheet()
#      Applies to the widget's own paintEvent and its sub-controls
#      (e.g. QComboBox::drop-down, QTabBar::tab, QTabWidget::pane).
#
#   2. Item-data roles (Qt.ItemDataRole)
#      For item views (QComboBox dropdown, QTableView, etc.), data stored
#      on the model via setForeground() / setBackground() / setFont()
#      takes *priority* over CSS color/background/font on the view.
#      → CSS rules on QAbstractItemView { color: ... } are dead when
#        every item has setForeground().
#
#   3. Child-widget inheritance
#      A parent's stylesheet does NOT cascade to children in Qt.
#      Each child must have its own stylesheet or rely on the QStyle
#      (Fusion, in our case). Rules on #bar_bottom do not affect
#      the QLabel it contains.
#
# =============================================================================
# Colour palette
# =============================================================================
#
# Background hierarchy (dark theme, three depths):
CLR_BG_0 = "#1e1e1e"   # deepest  — main window, shell, tab pane, selected tab
CLR_BG_1 = "#2d2d2d"   # mid-dark — bars, unselected tabs, tooltips
CLR_BG_2 = "#3c3c3c"   # mid      — combo boxes, input fields, hover states
#
# Borders:
CLR_BORDER_SUBTLE = "#3e3e3e"   # hairline dividers — bar edges, tab separators
CLR_BORDER_VISIBLE = "#555555"  # visible edges — combo box rim, tooltip rim
#
# Text (foreground):
CLR_TEXT_PRIMARY   = "#d4d4d4"  # body text  — shell output, combo items, tooltips
CLR_TEXT_SECONDARY = "#cccccc"  # muted text — bar labels, unselected tab titles
CLR_TEXT_INVERSE   = "white"    # text sitting on a coloured background
#
# Accent (blue family):
CLR_ACCENT        = "#007acc"  # main accent  — status-bar bg, selected-tab underline
CLR_ACCENT_DARK   = "#094771"  # dark accent  — selection highlight, pressed state
CLR_BTN_PRIMARY   = "#0e639c"  # primary CTA   — Launch button
CLR_BTN_HOVER     = "#1177bb"  # primary hover — Launch button hover
#
# Semantic spot colours:
CLR_SELECTION_BG    = "#264f78"  # in-shell text-selection highlight
CLR_SHELL_UNAVAILABLE = "#d4875e"  # combo item for shells not on this OS (copper)
CLR_CLOSE_BTN       = "#000000"  # tab close "×"
CLR_CLOSE_HOVER     = "#555555"  # tab close "×" hover
CLR_CLOSE_PRESSED   = "#333333"  # tab close "×" pressed
CLR_CLOSE_HOVER_BG  = "rgba(255, 255, 255, 0.15)"  # tab close hover background


class ShellWidget(QWidget):
    """An interactive shell widget that embeds a system shell via QProcess."""

    shell_closed = pyqtSignal()

    def __init__(self, shell_name: str, shell_cmd: str, encoding: str = "utf-8",
                 parent=None):
        super().__init__(parent)
        self._shell_name = shell_name
        self._shell_cmd = shell_cmd
        self._encoding = encoding
        self._process = None
        self._input_start = 0
        self._setup_ui()
        self._setup_process()
        self._start()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # ---- Shell output area (QTextEdit) ----
        # All colours below are effective: they paint the widget directly.
        self.output_area = QTextEdit()
        self.output_area.setFont(QFont("Courier New", 10))
        self.output_area.setStyleSheet(f"""
            QTextEdit {{
                background-color: {CLR_BG_0};
                color: {CLR_TEXT_PRIMARY};
                border: none;
                padding: 8px;
                selection-background-color: {CLR_SELECTION_BG};
            }}
        """)
        self.output_area.installEventFilter(self)
        layout.addWidget(self.output_area)

    def eventFilter(self, obj, event):
        if obj == self.output_area and event.type() == event.Type.KeyPress:
            return self._handle_key_press(event)
        return super().eventFilter(obj, event)

    def _handle_key_press(self, event: QKeyEvent):
        key = event.key()
        modifiers = event.modifiers()

        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            if modifiers == Qt.KeyboardModifier.NoModifier:
                self._send_current_line()
                return True

        # Block backspace / delete before the input start position
        cursor = self.output_area.textCursor()
        if key in (Qt.Key.Key_Backspace, Qt.Key.Key_Delete):
            if cursor.position() <= self._input_start:
                return True

        # Block navigation that moves cursor before input start
        if key in (Qt.Key.Key_Left, Qt.Key.Key_Up, Qt.Key.Key_Down,
                   Qt.Key.Key_PageUp, Qt.Key.Key_PageDown, Qt.Key.Key_Home):
            return True

        # Allow right-arrow, End, and printable characters
        if key == Qt.Key.Key_End:
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.output_area.setTextCursor(cursor)
            return True

        # Ensure cursor is always at or after input_start for typing
        if cursor.position() < self._input_start:
            cursor.setPosition(self._input_start)
            self.output_area.setTextCursor(cursor)

        return False

    def _send_current_line(self):
        """Extract the current input line and send it to the process."""
        text = self.output_area.toPlainText()
        if self._input_start < len(text):
            command = text[self._input_start:]
        else:
            command = ""

        # Move to end and insert a newline for visual feedback
        cursor = self.output_area.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.output_area.setTextCursor(cursor)
        self.output_area.insertPlainText("\n")

        self._input_start = self.output_area.textCursor().position()

        if self._process and self._process.state() == QProcess.ProcessState.Running:
            self._process.write((command + "\n").encode(self._encoding,
                                                         errors="replace"))

    def _setup_process(self):
        self._process = QProcess(self)
        self._process.readyReadStandardOutput.connect(self._on_stdout)
        self._process.readyReadStandardError.connect(self._on_stderr)
        self._process.finished.connect(self._on_finished)

    def _start(self):
        """Start the shell process and show initial prompt."""
        self._process.start(self._shell_cmd)
        self._show_prompt()

    def _show_prompt(self):
        """Display a shell prompt and record the input start position."""
        cursor = self.output_area.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.output_area.setTextCursor(cursor)
        self.output_area.insertPlainText("$ ")
        self._input_start = self.output_area.textCursor().position()

    def _decode(self, data: bytes) -> str:
        """Decode bytes using the shell's encoding. Tries primary encoding first,
        falls back to utf-8 with replacement on failure."""
        try:
            return data.data().decode(self._encoding)
        except (UnicodeDecodeError, LookupError):
            return data.data().decode("utf-8", errors="replace")

    def _on_stdout(self):
        data = self._process.readAllStandardOutput()
        text = self._decode(data)
        cursor = self.output_area.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.output_area.setTextCursor(cursor)
        self.output_area.insertPlainText(text)
        self._input_start = self.output_area.textCursor().position()

    def _on_stderr(self):
        data = self._process.readAllStandardError()
        text = self._decode(data)
        cursor = self.output_area.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.output_area.setTextCursor(cursor)
        self.output_area.insertPlainText(text)
        self._input_start = self.output_area.textCursor().position()

    def _on_finished(self, _exit_code, _exit_status):
        cursor = self.output_area.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.output_area.setTextCursor(cursor)
        self.output_area.insertPlainText("\n--- Process finished ---\n")
        self._input_start = self.output_area.textCursor().position()

    @property
    def shell_name(self) -> str:
        return self._shell_name

    def stop_shell(self):
        if self._process and self._process.state() != QProcess.ProcessState.NotRunning:
            self._process.kill()


class ShellWindow(QMainWindow):
    """Main window with a top bar for shell selection, a middle tab bar,
    and a bottom status bar."""

    # name -> {cmd, platform, encoding}
    SHELLS = {
        "terminal":   {"cmd": "/bin/bash",       "platform": "Linux",   "encoding": "utf-8"},
        "cmd":        {"cmd": "cmd.exe",          "platform": "Windows", "encoding": "gbk"},
        "powershell": {"cmd": "powershell.exe",   "platform": "Windows", "encoding": "gbk"},
    }

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Attack Detector - Shell")
        self.resize(900, 600)

        self._system_name = platform.system()
        self._tab_counter = {}

        self._build_ui()

    def _build_ui(self):
        """Construct the full UI: bar_top, bar_middle, tab area, bar_bottom."""
        central = QWidget()
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # --- bar_top ---
        main_layout.addWidget(self._create_bar_top())

        # --- tab widget (bar_middle) ---
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(False)  # we supply custom close buttons
        self.tab_widget.setMovable(True)
        self.tab_widget.currentChanged.connect(self._on_tab_changed)
        # All rules below are effective — they paint the tab bar and its pane.
        self.tab_widget.setStyleSheet(f"""
            QTabWidget::pane {{
                border: none;
                background-color: {CLR_BG_0};
            }}
            QTabBar::tab {{
                background-color: {CLR_BG_1};
                color: {CLR_TEXT_SECONDARY};
                padding: 6px 10px 6px 14px;
                border-right: 1px solid {CLR_BORDER_SUBTLE};
            }}
            QTabBar::tab:selected {{
                background-color: {CLR_BG_0};
                color: {CLR_TEXT_INVERSE};
                border-bottom: 2px solid {CLR_ACCENT};
            }}
            QTabBar::tab:hover:!selected {{
                background-color: {CLR_BG_2};
            }}
        """)
        main_layout.addWidget(self.tab_widget, stretch=1)

        self.setCentralWidget(central)

        # --- bar_bottom ---
        self._build_bar_bottom()

    def _create_bar_top(self):
        """Top bar: shell selector and launch button."""
        top_widget = QWidget()
        top_widget.setObjectName("bar_top")
        # All rules below are effective — they paint the bar_top container.
        top_widget.setStyleSheet(f"""
            #bar_top {{
                background-color: {CLR_BG_1};
                border-bottom: 1px solid {CLR_BORDER_SUBTLE};
                padding: 6px 12px;
            }}
        """)
        layout = QHBoxLayout(top_widget)
        layout.setContentsMargins(12, 4, 12, 4)

        # "Select Shell:" label — own stylesheet, effective
        label = QLabel("Select Shell:")
        label.setStyleSheet(
            f"color: {CLR_TEXT_SECONDARY}; font-weight: bold;"
        )
        layout.addWidget(label)

        # ---- ComboBox (shell selector) ----
        # Pipeline:
        #   • QComboBox { ... }          → paints the closed-state widget ✔
        #   • QComboBox::drop-down { }   → paints the arrow area ✔
        #   • QComboBox QAbstractItemView { background-color, selection-bg }
        #     → paints the popup list decoration ✔
        #   • item.setForeground()       → paints each row's text (overrides
        #     CSS color on QAbstractItemView) ✔
        self.shell_combo = QComboBox()
        self.shell_combo.setStyleSheet(f"""
            QComboBox {{
                background-color: {CLR_BG_2};
                color: {CLR_TEXT_PRIMARY};
                border: 1px solid {CLR_BORDER_VISIBLE};
                border-radius: 4px;
                padding: 4px 8px;
                min-width: 200px;
            }}
            QComboBox::drop-down {{ border: none; }}
            QComboBox QAbstractItemView {{
                background-color: {CLR_BG_2};
                selection-background-color: {CLR_ACCENT_DARK};
            }}
        """)

        model = QStandardItemModel()
        for shell_key, info in self.SHELLS.items():
            display_name = f"{shell_key} - {info['platform']}"
            item = QStandardItem(display_name)
            item.setData(shell_key, Qt.ItemDataRole.UserRole)
            if info["platform"] != self._system_name:
                item.setEnabled(False)
                # setForeground overrides CSS — the only way to colour items
                item.setForeground(QColor(CLR_SHELL_UNAVAILABLE))
            else:
                item.setForeground(QColor(CLR_TEXT_PRIMARY))
            model.appendRow(item)
        self.shell_combo.setModel(model)

        # Select the first enabled item by default
        for row in range(model.rowCount()):
            if model.item(row).isEnabled():
                self.shell_combo.setCurrentIndex(row)
                break

        layout.addWidget(self.shell_combo)

        # ---- Launch button ----
        # All rules effective — they paint the QPushButton directly.
        self.btn_launch = QPushButton("Launch")
        self.btn_launch.setStyleSheet(f"""
            QPushButton {{
                background-color: {CLR_BTN_PRIMARY};
                color: {CLR_TEXT_INVERSE};
                border: none;
                border-radius: 4px;
                padding: 6px 16px;
                font-weight: bold;
            }}
            QPushButton:hover {{ background-color: {CLR_BTN_HOVER}; }}
            QPushButton:pressed {{ background-color: {CLR_ACCENT_DARK}; }}
        """)
        self.btn_launch.clicked.connect(self._on_launch_clicked)
        layout.addWidget(self.btn_launch)

        layout.addStretch()
        return top_widget

    def _build_bar_bottom(self):
        """Bottom status bar: shows system name and current shell name."""
        self.status_bar = QStatusBar()
        self.status_bar.setObjectName("bar_bottom")
        # Only background-color and padding are effective here —
        # QStatusBar delegates text rendering to its child QLabel.
        self.status_bar.setStyleSheet(f"""
            #bar_bottom {{
                background-color: {CLR_ACCENT};
                padding: 2px 8px;
            }}
        """)

        # This QLabel carries its own stylesheet — the effective text styling.
        self.label_status = QLabel()
        self.label_status.setStyleSheet(
            f"color: {CLR_TEXT_INVERSE}; font-weight: bold; padding: 0 8px;"
        )
        self.status_bar.addWidget(self.label_status, 1)

        self.setStatusBar(self.status_bar)
        self._update_status_bar(None)

    def _update_status_bar(self, shell_name: str | None):
        """Update the bottom bar with system and current shell info."""
        name = shell_name if shell_name else "None"
        self.label_status.setText(
            f"System: {self._system_name} | Shell Name: {name}"
        )

    def _create_tab_close_button(self, widget: ShellWidget) -> QPushButton:
        """Create a black 'X' close button for a tab.
        Looks up the widget's current index at click time so it stays correct
        even when tabs are reordered."""
        btn = QPushButton("✕")
        btn.setFixedSize(18, 18)
        # All rules effective — they paint a small custom QPushButton.
        btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {CLR_CLOSE_BTN};
                border: none;
                font-size: 12px;
                font-weight: bold;
                padding: 0px;
            }}
            QPushButton:hover {{
                color: {CLR_CLOSE_HOVER};
                background: {CLR_CLOSE_HOVER_BG};
                border-radius: 3px;
            }}
            QPushButton:pressed {{
                color: {CLR_CLOSE_PRESSED};
            }}
        """)
        btn.clicked.connect(
            lambda: self._on_tab_close(self.tab_widget.indexOf(widget))
        )
        return btn

    def _on_launch_clicked(self):
        """Launch a new shell in a new tab."""
        idx = self.shell_combo.currentIndex()
        item = self.shell_combo.model().item(idx)
        if item is None:
            return

        if not item.isEnabled():
            return

        shell_key = item.data(Qt.ItemDataRole.UserRole)
        shell_info = self.SHELLS.get(shell_key)
        if not shell_info:
            return

        shell_cmd = shell_info["cmd"]
        encoding = shell_info.get("encoding", "utf-8")

        # Maintain internal counter for programmatic identification (not displayed)
        count = self._tab_counter.get(shell_key, 0) + 1
        self._tab_counter[shell_key] = count

        shell_widget = ShellWidget(shell_key, shell_cmd, encoding=encoding)
        tab_idx = self.tab_widget.addTab(shell_widget, shell_key)
        self.tab_widget.setCurrentIndex(tab_idx)

        # Attach a custom close button to this tab
        close_btn = self._create_tab_close_button(shell_widget)
        self.tab_widget.tabBar().setTabButton(
            tab_idx, QTabBar.ButtonPosition.RightSide, close_btn
        )

        self._update_status_bar(shell_key)

    def _on_tab_close(self, index: int):
        """Close a tab and stop its shell."""
        widget = self.tab_widget.widget(index)
        if isinstance(widget, ShellWidget):
            widget.stop_shell()
        self.tab_widget.removeTab(index)

        current = self.tab_widget.currentWidget()
        if isinstance(current, ShellWidget):
            self._update_status_bar(current.shell_name)
        else:
            self._update_status_bar(None)

    def _on_tab_changed(self, index: int):
        """Update bar_bottom when the user switches tabs."""
        if index < 0:
            self._update_status_bar(None)
            return
        widget = self.tab_widget.widget(index)
        if isinstance(widget, ShellWidget):
            self._update_status_bar(widget.shell_name)

    def closeEvent(self, event):
        for i in range(self.tab_widget.count()):
            widget = self.tab_widget.widget(i)
            if isinstance(widget, ShellWidget):
                widget.stop_shell()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # App-level base styles — effective, paint QMainWindow & QToolTip globally.
    app.setStyleSheet(f"""
        QMainWindow {{ background-color: {CLR_BG_0}; }}
        QToolTip {{
            background-color: {CLR_BG_1};
            color: {CLR_TEXT_PRIMARY};
            border: 1px solid {CLR_BORDER_VISIBLE};
        }}
    """)

    window = ShellWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
