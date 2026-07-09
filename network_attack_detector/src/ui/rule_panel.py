"""Rule management panel for viewing, enabling, disabling, adding, and deleting rules.

Provides:
- RulePanel: QWidget with tabbed interface for signature and behavior rules,
  a filter/search bar, action buttons, and a summary label.
"""

from __future__ import annotations

from typing import Any

from PyQt6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    Qt,
    pyqtSignal,
)
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from src.core.models import AlertLevel, AttackCategory, BehaviorRule, Protocol, SignatureRule
from src.rules.rule_manager import RuleManager

# ── column definitions ────────────────────────────────────────────────────

_SIG_COLUMNS: list[tuple[str, int]] = [
    ("✓", 35),
    ("规则ID", 100),
    ("名称", 140),
    ("攻击类型", 120),
    ("等级", 60),
    ("协议", 60),
    ("匹配方式", 70),
    ("模式", 180),
    ("目标字段", 120),
    ("忽略大小写", 75),
    ("描述", 200),
    ("建议", 200),
]

_BEH_COLUMNS: list[tuple[str, int]] = [
    ("✓", 35),
    ("规则ID", 100),
    ("名称", 140),
    ("攻击类型", 120),
    ("等级", 60),
    ("事件类型", 100),
    ("时间窗口(s)", 90),
    ("阈值", 60),
    ("分组依据", 120),
    ("描述", 200),
    ("建议", 200),
]


# ── table models ──────────────────────────────────────────────────────────


class _SignatureRuleModel(QAbstractTableModel):
    """Table model for a list of :class:`SignatureRule` objects."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.rules: list[SignatureRule] = []

    def set_rules(self, rules: list[SignatureRule]) -> None:
        self.beginResetModel()
        self.rules = list(rules)
        self.endResetModel()

    def get_rules(self) -> list[SignatureRule]:
        return list(self.rules)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: B008
        return len(self.rules) if not parent.isValid() else 0

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: B008
        return len(_SIG_COLUMNS) if not parent.isValid() else 0

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # noqa: C901
        if not index.isValid():
            return None
        rule = self.rules[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            return self._display(rule, col)

        if role == Qt.ItemDataRole.CheckStateRole and col == 0:
            return Qt.CheckState.Checked if rule.enabled else Qt.CheckState.Unchecked

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (0, 4, 5, 6, 9):
                return Qt.AlignmentFlag.AlignCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter

        if role == Qt.ItemDataRole.UserRole:
            return rule

        return None

    def setData(self, index: QModelIndex, value: Any, role: int = Qt.ItemDataRole.EditRole) -> bool:  # noqa: N802
        if role == Qt.ItemDataRole.CheckStateRole and index.column() == 0:
            rule = self.rules[index.row()]
            rule.enabled = value == Qt.CheckState.Checked.value
            self.dataChanged.emit(index, index, [role])
            return True
        return False

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:  # noqa: N802
        base = super().flags(index)
        if index.column() == 0:
            return base | Qt.ItemFlag.ItemIsUserCheckable
        return base

    def _display(self, rule: SignatureRule, col: int) -> str:
        if col == 0:
            return ""
        if col == 1:
            return rule.rule_id
        if col == 2:
            return rule.name
        if col == 3:
            return rule.category.value
        if col == 4:
            return rule.level.value
        if col == 5:
            return rule.protocol.value
        if col == 6:
            return rule.match_type
        if col == 7:
            return rule.pattern[:80] + "…" if len(rule.pattern) > 80 else rule.pattern
        if col == 8:
            return ", ".join(rule.target_fields) if rule.target_fields else "-"
        if col == 9:
            return "是" if rule.nocase else "否"
        if col == 10:
            return rule.description[:80] + "…" if len(rule.description) > 80 else rule.description
        if col == 11:
            return rule.suggestion[:80] + "…" if len(rule.suggestion) > 80 else rule.suggestion
        return ""

    def headerData(  # noqa: N802
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return _SIG_COLUMNS[section][0] if section < len(_SIG_COLUMNS) else ""
        return None


class _BehaviorRuleModel(QAbstractTableModel):
    """Table model for a list of :class:`BehaviorRule` objects."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.rules: list[BehaviorRule] = []

    def set_rules(self, rules: list[BehaviorRule]) -> None:
        self.beginResetModel()
        self.rules = list(rules)
        self.endResetModel()

    def get_rules(self) -> list[BehaviorRule]:
        return list(self.rules)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: B008
        return len(self.rules) if not parent.isValid() else 0

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: B008
        return len(_BEH_COLUMNS) if not parent.isValid() else 0

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        rule = self.rules[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            return self._display(rule, col)

        if role == Qt.ItemDataRole.CheckStateRole and col == 0:
            return Qt.CheckState.Checked if rule.enabled else Qt.CheckState.Unchecked

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (0, 4, 6, 7):
                return Qt.AlignmentFlag.AlignCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter

        if role == Qt.ItemDataRole.UserRole:
            return rule

        return None

    def setData(self, index: QModelIndex, value: Any, role: int = Qt.ItemDataRole.EditRole) -> bool:  # noqa: N802
        if role == Qt.ItemDataRole.CheckStateRole and index.column() == 0:
            rule = self.rules[index.row()]
            rule.enabled = value == Qt.CheckState.Checked.value
            self.dataChanged.emit(index, index, [role])
            return True
        return False

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:  # noqa: N802
        base = super().flags(index)
        if index.column() == 0:
            return base | Qt.ItemFlag.ItemIsUserCheckable
        return base

    def _display(self, rule: BehaviorRule, col: int) -> str:
        if col == 0:
            return ""
        if col == 1:
            return rule.rule_id
        if col == 2:
            return rule.name
        if col == 3:
            return rule.category.value
        if col == 4:
            return rule.level.value
        if col == 5:
            return rule.event_type
        if col == 6:
            return str(rule.window_seconds)
        if col == 7:
            return str(rule.threshold)
        if col == 8:
            return ", ".join(rule.group_by) if rule.group_by else "-"
        if col == 9:
            return rule.description[:80] + "…" if len(rule.description) > 80 else rule.description
        if col == 10:
            return rule.suggestion[:80] + "…" if len(rule.suggestion) > 80 else rule.suggestion
        return ""

    def headerData(  # noqa: N802
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return _BEH_COLUMNS[section][0] if section < len(_BEH_COLUMNS) else ""
        return None


# ── rule panel widget ─────────────────────────────────────────────────────


class RulePanel(QWidget):
    """Rule management panel with tabs for signature and behavior rules.

    Provides search, enable/disable toggles, and batch operations.
    """

    rules_changed = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rule_manager: RuleManager | None = None
        self._setup_ui()

    # ── setup ─────────────────────────────────────────────────────────

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(6)

        # --- search bar ---
        search_bar = QHBoxLayout()

        search_bar.addWidget(QLabel("搜索:"))
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("输入规则ID、名称或模式…")
        self._search_input.textChanged.connect(self._on_search)
        search_bar.addWidget(self._search_input)

        self._enabled_only_cb = QCheckBox("仅显示启用的规则")
        self._enabled_only_cb.toggled.connect(self._on_search)
        search_bar.addWidget(self._enabled_only_cb)

        layout.addLayout(search_bar)

        # --- tab widget ---
        self._tabs = QTabWidget()

        self._sig_model = _SignatureRuleModel(self)
        from PyQt6.QtWidgets import QTableView

        self._sig_table = QTableView()
        self._sig_table.setModel(self._sig_model)
        self._sig_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._sig_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._sig_table.setAlternatingRowColors(True)
        self._sig_table.verticalHeader().setVisible(False)
        self._sig_table.horizontalHeader().setStretchLastSection(True)
        self._sig_table.setSortingEnabled(True)
        self._tabs.addTab(self._sig_table, "特征规则 (Signature)")

        self._beh_model = _BehaviorRuleModel(self)
        self._beh_table = QTableView()
        self._beh_table.setModel(self._beh_model)
        self._beh_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._beh_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._beh_table.setAlternatingRowColors(True)
        self._beh_table.verticalHeader().setVisible(False)
        self._beh_table.horizontalHeader().setStretchLastSection(True)
        self._beh_table.setSortingEnabled(True)
        self._tabs.addTab(self._beh_table, "行为规则 (Behavior)")

        layout.addWidget(self._tabs)

        # --- action buttons ---
        btn_bar = QHBoxLayout()

        self._enable_btn = QPushButton("✓ 启用选中")
        self._enable_btn.clicked.connect(self._on_enable_selected)
        btn_bar.addWidget(self._enable_btn)

        self._disable_btn = QPushButton("✗ 禁用选中")
        self._disable_btn.clicked.connect(self._on_disable_selected)
        btn_bar.addWidget(self._disable_btn)

        btn_bar.addStretch()

        self._add_btn = QPushButton("＋ 添加规则")
        self._add_btn.clicked.connect(self._on_add_rule)
        btn_bar.addWidget(self._add_btn)

        self._delete_btn = QPushButton("－ 删除选中")
        self._delete_btn.clicked.connect(self._on_delete_selected)
        btn_bar.addWidget(self._delete_btn)

        layout.addLayout(btn_bar)

        # --- summary ---
        self._summary_label = QLabel("特征规则: 0 条 (启用 0) | 行为规则: 0 条 (启用 0)")
        layout.addWidget(self._summary_label)

        self._apply_column_widths()

    def _apply_column_widths(self) -> None:
        hdr = self._sig_table.horizontalHeader()
        for i, (_, w) in enumerate(_SIG_COLUMNS):
            hdr.resizeSection(i, w)

        hdr = self._beh_table.horizontalHeader()
        for i, (_, w) in enumerate(_BEH_COLUMNS):
            hdr.resizeSection(i, w)

    # ── public API ────────────────────────────────────────────────────

    def set_rule_manager(self, manager: RuleManager) -> None:
        """Inject the rule manager and populate the tables."""
        self._rule_manager = manager
        self.refresh()

    def refresh(self) -> None:
        """Reload rules from the rule manager into both tables."""
        if self._rule_manager is None:
            return
        self._sig_model.set_rules(self._rule_manager.signature_rules)
        self._beh_model.set_rules(self._rule_manager.behavior_rules)
        self._update_summary()

    def get_modified_rules(self) -> tuple[list[SignatureRule], list[BehaviorRule]]:
        """Return current rule lists (reflecting any user edits)."""
        return self._sig_model.get_rules(), self._beh_model.get_rules()

    # ── internal helpers ──────────────────────────────────────────────

    def _current_model(self) -> _SignatureRuleModel | _BehaviorRuleModel | None:
        if self._tabs.currentIndex() == 0:
            return self._sig_model
        return self._beh_model

    def _current_table(self) -> Any:
        if self._tabs.currentIndex() == 0:
            return self._sig_table
        return self._beh_table

    def _update_summary(self) -> None:
        sig_total = len(self._sig_model.rules)
        sig_enabled = sum(1 for r in self._sig_model.rules if r.enabled)
        beh_total = len(self._beh_model.rules)
        beh_enabled = sum(1 for r in self._beh_model.rules if r.enabled)
        self._summary_label.setText(
            f"特征规则: {sig_total} 条 (启用 {sig_enabled})"
            f" | 行为规则: {beh_total} 条 (启用 {beh_enabled})"
        )

    def _selected_rule_ids(self) -> list[str]:
        table = self._current_table()
        model = self._current_model()
        if model is None:
            return []
        ids: list[str] = []
        for idx in table.selectionModel().selectedRows():
            rule = model.data(idx, Qt.ItemDataRole.UserRole)
            if rule is not None:
                ids.append(rule.rule_id)
        return ids

    # ── slots ─────────────────────────────────────────────────────────

    def _on_search(self) -> None:
        keyword = self._search_input.text().strip().lower()
        enabled_only = self._enabled_only_cb.isChecked()
        for model_cls, table in [
            (self._sig_model, self._sig_table),
            (self._beh_model, self._beh_table),
        ]:
            for row in range(model_cls.rowCount()):
                rule = model_cls.data(model_cls.index(row, 0), Qt.ItemDataRole.UserRole)
                if rule is None:
                    table.setRowHidden(row, True)
                    continue
                visible = True
                if enabled_only and not rule.enabled:
                    visible = False
                if keyword and visible:
                    # search in rule_id, name, and pattern fields
                    searchable = (
                        rule.rule_id.lower()
                        + " "
                        + rule.name.lower()
                        + " "
                        + (getattr(rule, "pattern", "") or "").lower()
                    )
                    if keyword not in searchable:
                        visible = False
                table.setRowHidden(row, not visible)

    def _on_enable_selected(self) -> None:
        if self._rule_manager is None:
            return
        for rid in self._selected_rule_ids():
            self._rule_manager.enable_rule(rid)
        self.refresh()
        self.rules_changed.emit()

    def _on_disable_selected(self) -> None:
        if self._rule_manager is None:
            return
        for rid in self._selected_rule_ids():
            self._rule_manager.disable_rule(rid)
        self.refresh()
        self.rules_changed.emit()

    def _on_delete_selected(self) -> None:
        rids = self._selected_rule_ids()
        if not rids:
            return
        reply = QMessageBox.question(
            self,
            "确认删除",
            f"确定要删除选中的 {len(rids)} 条规则吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        model = self._current_model()
        if isinstance(model, _SignatureRuleModel):
            model.set_rules([r for r in model.rules if r.rule_id not in rids])
            if self._rule_manager:
                self._rule_manager.signature_rules = model.get_rules()
        elif isinstance(model, _BehaviorRuleModel):
            model.set_rules([r for r in model.rules if r.rule_id not in rids])
            if self._rule_manager:
                self._rule_manager.behavior_rules = model.get_rules()
        self._update_summary()
        self.rules_changed.emit()

    def _on_add_rule(self) -> None:
        from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QFormLayout, QLineEdit

        dlg = QDialog(self)
        dlg.setWindowTitle("添加规则（示例占位）")
        form = QFormLayout(dlg)
        id_edit = QLineEdit()
        name_edit = QLineEdit()
        form.addRow("规则ID:", id_edit)
        form.addRow("名称:", name_edit)
        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btn_box.accepted.connect(dlg.accept)
        btn_box.rejected.connect(dlg.reject)
        form.addRow(btn_box)

        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        rid = id_edit.text().strip()
        name = name_edit.text().strip()
        if not rid or not name:
            return

        model = self._current_model()
        if isinstance(model, _SignatureRuleModel):
            new_rule = SignatureRule(
                rule_id=rid,
                name=name,
                category=AttackCategory.UNKNOWN,
                level=AlertLevel.MEDIUM,
                protocol=Protocol.HTTP,
                match_type="content",
                pattern="",
                enabled=True,
            )
            model.beginInsertRows(QModelIndex(), model.rowCount(), model.rowCount())
            model.rules.append(new_rule)
            model.endInsertRows()
            if self._rule_manager:
                self._rule_manager.signature_rules = model.get_rules()
        elif isinstance(model, _BehaviorRuleModel):
            new_rule = BehaviorRule(
                rule_id=rid,
                name=name,
                category=AttackCategory.UNKNOWN,
                level=AlertLevel.MEDIUM,
                event_type="request",
                window_seconds=60,
                threshold=10,
                enabled=True,
            )
            model.beginInsertRows(QModelIndex(), model.rowCount(), model.rowCount())
            model.rules.append(new_rule)
            model.endInsertRows()
            if self._rule_manager:
                self._rule_manager.behavior_rules = model.get_rules()

        self._update_summary()
        self.rules_changed.emit()
