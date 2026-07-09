# UI 窗口配置说明

> 负责人：成员 E  
> 本文件描述各窗口的内容、布局和功能，方便设计与修改窗口。

---

## 一、主窗口 MainWindow

**文件**: `main_window.py`  
**类名**: `MainWindow(QMainWindow)`  

### 1.1 整体布局

```
┌──────────────────────────────────────────────────────┐
│  菜单栏 (Menu Bar)                                    │
│  文件 | 抓包 | 规则 | 视图 | 帮助                        │
├──────────────────────────────────────────────────────┤
│  工具栏 (Toolbar)                                     │
│  [选择网卡 ▼] [▶ 开始抓包] [■ 停止] [⏸ 暂停] [导出]     │
├───────────────────────────┬──────────────────────────┤
│                           │                          │
│  实时流量表格              │  实时告警表格               │
│  TrafficTableView         │  AlertTableView           │
│  (左上, 占 60% 宽度)       │  (右上, 占 40% 宽度)        │
│                           │                          │
│  列: 时间|源IP|源端口|      │  列: 时间|等级|类型|        │
│       目的IP|目的端口|       │       源IP|目的IP|         │
│       协议|长度|摘要         │       规则|证据             │
│                           │                          │
├───────────────────────────┴──────────────────────────┤
│                                                      │
│  底部 Tab 页签                                       │
│  ┌─ 统计图表 ──┬── 规则管理 ──┐                        │
│  │ StatsPanel  │  RulePanel   │                        │
│  │             │              │                        │
│  │ [饼图:攻击  │  [规则表格]    │                        │
│  │  类型分布]  │  特征/行为 Tab │                        │
│  │ [柱状图:    │  启用|禁用|    │                        │
│  │  Top源IP]  │  添加|删除     │                        │
│  │ [折线图:    │              │                        │
│  │  时间趋势]  │              │                        │
│  └─────────────┴──────────────┘                        │
├──────────────────────────────────────────────────────┤
│  状态栏: 抓包状态 | 数据包计数 | 告警计数 | 运行时间        │
└──────────────────────────────────────────────────────┘
```

### 1.2 菜单栏

| 菜单 | 子项 | 快捷键 | 功能 |
|------|------|--------|------|
| 文件 | 导出告警 CSV... | Ctrl+E | 调用 `CsvExporter` 导出告警列表 |
| 文件 | 导出 HTML 报告... | Ctrl+H | 调用 `HtmlReporter` 导出 HTML 报告 |
| 文件 | 导出图表 (pyecharts)... | Ctrl+G | 使用 pyecharts 生成交互式 HTML 报告 |
| 文件 | 退出 | Alt+F4 | 停止抓包并退出 |
| 抓包 | 选择网卡 | - | 刷新并列出可用网卡 |
| 抓包 | 开始抓包 | F5 | 启动实时抓包（Scapy） |
| 抓包 | 停止抓包 | F6 | 停止实时抓包 |
| 抓包 | 打开 pcap 文件... | Ctrl+O | 加载离线 pcap 文件 |
| 规则 | 重新加载规则 | Ctrl+R | 重新从 CSV/JSON 加载规则 |
| 规则 | 导入规则... | Ctrl+I | 从外部文件导入规则 |
| 视图 | 显示/隐藏流量表 | - | 切换流量表格可见性 |
| 视图 | 显示/隐藏统计 | - | 切换统计面板可见性 |
| 视图 | 清除告警列表 | - | 清空告警表格 |
| 帮助 | 关于 | - | 显示版本和团队信息 |

### 1.3 工具栏

| 控件 | 功能 |
|------|------|
| QComboBox 网卡选择 | 列出可用网络接口，供用户选择抓包网卡 |
| QPushButton 开始/停止 | 启动或停止实时检测 |
| QPushButton 暂停/恢复 | 暂停或恢复抓包（不丢失状态） |
| QPushButton 导出 | 快捷导出当前告警为 CSV |
| QLabel 过滤器 | 显示当前 BPF 过滤器表达式 |

### 1.4 状态栏

| 字段 | 内容 |
|------|------|
| 抓包状态 | "运行中" / "已停止" / "已暂停" (带颜色指示灯) |
| 数据包计数 | 已捕获并处理的数据包总数 |
| 告警计数 | 已产生的告警总数，按 Critical/High/Medium/Low 分色 |
| 运行时间 | 本次抓包已运行的时间 (HH:MM:SS) |

### 1.5 信号与槽

| 信号来源 | 信号 | 槽函数 | 说明 |
|----------|------|--------|------|
| "开始"按钮 | clicked | `_on_start_capture()` | 启动抓包线程 |
| "停止"按钮 | clicked | `_on_stop_capture()` | 停止抓包线程 |
| EventBus | `packet_captured` | `_on_packet(packet)` | 接收新数据包，更新流量表 |
| EventBus | `alert_generated` | `_on_alert(alert)` | 接收新告警，更新告警表 |
| EventBus | `capture_error` | `_on_capture_error(err)` | 显示错误消息 |
| 定时器 | timeout | `_update_status_bar()` | 每秒刷新状态栏 |

---

## 二、实时流量表格 TrafficTableView

**文件**: `traffic_table.py`  
**类名**: 
- `TrafficTableModel(QAbstractTableModel)` — 数据模型，存储和提供 `PacketInfo` 列表
- `TrafficTableView(QTableView)` — 视图，显示表格并提供交互

### 2.1 表格列定义

| 列索引 | 列名 | 数据字段 | 宽度 | 说明 |
|--------|------|----------|------|------|
| 0 | # | 序号 | 50px | 自增序号 |
| 1 | 时间 | `timestamp` | 150px | 格式化为 `HH:MM:SS.mmm` |
| 2 | 源 IP | `src_ip` | 130px | 来源 IP 地址 |
| 3 | 源端口 | `src_port` | 70px | 来源端口号 |
| 4 | 目的 IP | `dst_ip` | 130px | 目的 IP 地址 |
| 5 | 目的端口 | `dst_port` | 70px | 目的端口号 |
| 6 | 协议 | `protocol` | 60px | TCP/UDP/HTTP/ICMP |
| 7 | 长度 | `length` | 70px | 数据包字节数 |
| 8 | 摘要 | `raw_summary` | 200px | 数据包简要描述 |

### 2.2 功能

- **自动滚动**: 新数据包到达时自动滚动到最新行
- **多选**: 支持 Ctrl/Shift 多选行
- **排序**: 点击列标题可排序（需 QSortFilterProxyModel）
- **过滤**: 支持按协议、源 IP、目的 IP 过滤（右键菜单或顶部过滤栏）
- **右键菜单**: 
  - "复制 IP" → 复制选中行的源/目的 IP
  - "过滤此源 IP" → 只显示该源 IP 的流量
  - "过滤此目的端口" → 只显示该目的端口的流量
  - "清除过滤" → 恢复显示全部
  - "查看详情" → 弹出对话框显示该包的完整 `PacketInfo`
- **最大行数**: 默认保留最近 10000 行，超出后移除旧行
- **颜色标记**: HTTP 流量行浅蓝色背景

### 2.3 接口

```python
class TrafficTableModel(QAbstractTableModel):
    def add_packet(self, packet: PacketInfo) -> None  # 添加一个数据包
    def clear(self) -> None                            # 清空所有数据
    def rowCount(self, parent=...) -> int              # Qt 模型接口
    def columnCount(self, parent=...) -> int           # Qt 模型接口
    def data(self, index, role=...) -> Any             # Qt 模型接口
    def headerData(self, section, orientation, role)   # Qt 模型接口
```

---

## 三、实时告警表格 AlertTableView

**文件**: `alert_table.py`  
**类名**:
- `AlertTableModel(QAbstractTableModel)` — 数据模型，封装 `list[Alert]`
- `AlertTableView(QTableView)` — 视图，支持颜色标记和交互

### 3.1 表格列定义

| 列索引 | 列名 | 数据字段 | 宽度 | 说明 |
|--------|------|----------|------|------|
| 0 | # | 序号 | 40px | 自增序号 |
| 1 | 时间 | `timestamp` | 150px | `YYYY-MM-DD HH:MM:SS` |
| 2 | 等级 | `level` | 60px | Critical/High/Medium/Low |
| 3 | 攻击类型 | `category` | 120px | SQL注入/XSS/端口扫描等 |
| 4 | 源 IP | `src_ip` | 130px | 攻击来源 IP |
| 5 | 目的 IP | `dst_ip` | 130px | 攻击目标 IP |
| 6 | 协议 | `protocol` | 60px | TCP/UDP/HTTP |
| 7 | 规则名称 | `rule_name` | 150px | 触发的规则名 |
| 8 | 证据 | `evidence` | 200px | 匹配到的攻击载荷摘要 |

### 3.2 功能

- **等级颜色标记**:
  - Critical → 红色背景 + 白色粗体
  - High → 浅红色背景
  - Medium → 浅黄色背景
  - Low → 浅蓝色背景
- **自动滚动**: 新告警到达时自动滚动到最新行
- **右键菜单**:
  - "查看详情" → 弹出告警详情对话框（完整 evidence, description, suggestion）
  - "复制证据" → 复制 evidence 到剪贴板
  - "忽略此 IP" → 将源 IP 加入临时白名单（当前会话有效）
- **筛选器**: 顶部下拉框支持按等级、类型过滤
- **统计摘要**: 表格上方显示 "共 X 条告警 | Critical: Y | High: Z | Medium: W | Low: V"
- **最大行数**: 默认最近 5000 条
- **声音提醒**: Critical 级别告警可选声音提示

### 3.3 接口

```python
class AlertTableModel(QAbstractTableModel):
    def add_alert(self, alert: Alert) -> None           # 添加告警
    def add_alerts(self, alerts: list[Alert]) -> None   # 批量添加
    def clear(self) -> None                              # 清空
    def get_alerts(self) -> list[Alert]                  # 获取当前所有告警
    def rowCount(...) -> int
    def columnCount(...) -> int
    def data(...) -> Any
```

---

## 四、规则管理面板 RulePanel

**文件**: `rule_panel.py`  
**类名**: `RulePanel(QWidget)`

### 4.1 布局

```
┌──────────────────────────────────────────────┐
│  [特征规则 Tab]  [行为规则 Tab]                 │
├──────────────────────────────────────────────┤
│  搜索: [________] 🔍  [仅显示启用的规则] ☑      │
├──────────────────────────────────────────────┤
│                                              │
│  特征规则表格                                  │
│  ┌──────────────────────────────────────┐    │
│  │ ID | 名称 | 类型 | 等级 | 协议 |       │    │
│  │ 匹配方式 | 模式 | 目标字段 | 启用 |     │    │
│  └──────────────────────────────────────┘    │
│                                              │
├──────────────────────────────────────────────┤
│  [添加规则] [删除选中] [启用] [禁用]            │
│  [重新加载] [导入CSV] [导出CSV]               │
└──────────────────────────────────────────────┘
```

### 4.2 特征规则表格列

| 列名 | 数据字段 | 可编辑 |
|------|----------|--------|
| 启用 | `enabled` (checkbox) | ✓ |
| 规则ID | `rule_id` | ✗ |
| 名称 | `name` | ✓ |
| 攻击类型 | `category` | ✓ (下拉) |
| 等级 | `level` | ✓ (下拉) |
| 协议 | `protocol` | ✓ (下拉) |
| 匹配方式 | `match_type` | ✓ (content/regex) |
| 模式 | `pattern` | ✓ |
| 目标字段 | `target_fields` | ✓ |
| 忽略大小写 | `nocase` (checkbox) | ✓ |
| 描述 | `description` | ✓ |

### 4.3 行为规则表格列

| 列名 | 数据字段 | 可编辑 |
|------|----------|--------|
| 启用 | `enabled` (checkbox) | ✓ |
| 规则ID | `rule_id` | ✗ |
| 名称 | `name` | ✓ |
| 攻击类型 | `category` | ✓ (下拉) |
| 等级 | `level` | ✓ (下拉) |
| 事件类型 | `event_type` | ✓ |
| 时间窗口(s) | `window_seconds` | ✓ |
| 阈值 | `threshold` | ✓ |
| 分组依据 | `group_by` | ✓ |
| 描述 | `description` | ✓ |

### 4.4 功能

- **双标签页**: 特征规则和行为规则分开显示
- **搜索过滤**: 实时搜索，匹配规则ID、名称、模式字段
- **启用/禁用**: checkbox 切换单条规则启用状态，批量启用/禁用选中规则
- **添加规则**: 弹出对话框填写规则字段后添加
- **删除规则**: 确认后删除选中规则
- **编辑规则**: 双击单元格进入编辑模式
- **重新加载**: 从 CSV/JSON 文件重新加载规则
- **导入/导出**: 支持从外部 CSV/JSON 导入/导出规则
- **规则统计**: 底部显示 "特征规则: X 条 (启用 Y) | 行为规则: Z 条 (启用 W)"

### 4.5 接口

```python
class RulePanel(QWidget):
    def set_rule_manager(self, manager: RuleManager) -> None  # 注入规则管理器
    def refresh(self) -> None                                   # 刷新表格
    def get_modified_rules(self) -> tuple[list, list]           # 获取修改后的规则
    signal: rules_changed  # 规则变更信号，通知检测引擎重载
```

---

## 五、统计面板 StatsPanel

**文件**: `stats_panel.py`  
**类名**: `StatsPanel(QWidget)`

### 5.1 布局

```
┌──────────────────────────────────────────────┐
│  [饼图: 攻击类型分布]  [柱状图: Top 10 源 IP]    │
│  (matplotlib canvas)   (matplotlib canvas)    │
│  ─────────────────────────────────────────── │
│  [折线图: 告警时间趋势 (最近 60 分钟)]            │
│  (matplotlib canvas)                          │
│  ─────────────────────────────────────────── │
│  统计摘要:                                     │
│  总告警: 128 | 总流量: 5432 | 检测率: 2.36%     │
│  最活跃攻击者: 192.168.1.100 (47次)              │
└──────────────────────────────────────────────┘
```

### 5.2 图表详细说明

#### 饼图 — 攻击类型分布
- **类型**: `matplotlib.pyplot.pie`
- **数据**: 按 `AttackCategory` 统计各类告警数量
- **显示**: 百分比标签 + 图例
- **颜色**: 使用预设调色板，每类攻击固定颜色
- **更新**: 每 5 秒或收到新告警批次时刷新

#### 柱状图 — Top 10 攻击源 IP
- **类型**: `matplotlib.pyplot.bar` (横向柱状图)
- **数据**: 按 `src_ip` 统计告警数量，取 Top 10
- **显示**: IP 在左，柱状条在右，柱上标数量
- **颜色**: 按告警最高等级渐变

#### 折线图 — 告警时间趋势
- **类型**: `matplotlib.pyplot.plot`
- **数据**: 以分钟为单位统计告警数量，展示最近 60 分钟
- **显示**: 多条折线（总告警、Critical告警、High告警）
- **颜色**: 总告警=蓝色, Critical=红色, High=橙色
- **X轴**: 时间 (HH:MM)
- **Y轴**: 告警数量

### 5.3 统计摘要区

| 指标 | 说明 |
|------|------|
| 总告警数 | 自检测开始累计告警数 |
| 总流量数 | 自检测开始累计数据包数 |
| 检测率 | 告警数 / 流量数 × 100% |
| 最活跃攻击者 | 产生最多告警的源 IP 及告警次数 |
| 最常见攻击 | 出现最多的攻击类型 |

### 5.4 接口

```python
class StatsPanel(QWidget):
    def update_with_alerts(self, alerts: list[Alert]) -> None  # 更新统计数据
    def update_with_packets(self, count: int) -> None           # 更新流量计数
    def clear(self) -> None                                      # 重置统计
    @staticmethod
    def count_by_category(alerts: list[Alert]) -> dict[str, int] # 按类型统计
    @staticmethod
    def count_by_src_ip(alerts: list[Alert]) -> dict[str, int]   # 按源IP统计
    @staticmethod
    def count_by_time(alerts: list[Alert]) -> dict[str, int]     # 按时间统计
```

---

## 六、辅助对话框

### 6.1 告警详情对话框 AlertDetailDialog
- **触发**: 双击告警行 / 右键 → "查看详情"
- **内容**: 显示单条 `Alert` 所有字段，包括完整 evidence, description, suggestion
- **按钮**: [复制] [关闭]

### 6.2 数据包详情对话框 PacketDetailDialog
- **触发**: 双击流量行 / 右键 → "查看详情"
- **内容**: 显示 `PacketInfo` 所有字段和 `HttpInfo`（如有），原始 payload 十六进制/文本预览
- **按钮**: [复制Payload] [关闭]

### 6.3 添加/编辑规则对话框 RuleEditDialog
- **触发**: 规则面板 → "添加规则" / 双击规则行
- **内容**: 根据规则类型动态生成表单，包含所有规则字段的输入控件
- **按钮**: [确定] [取消]
- **校验**: 调用 `RuleValidator` 检查字段合法性

### 6.4 导出报告对话框 ExportDialog
- **触发**: 文件 → 导出 HTML 报告...(pyecharts)
- **内容**: 
  - 选择导出范围（全部/仅选中/按时间范围）
  - 选择包含的图表类型
  - 输出路径选择
- **按钮**: [导出] [取消]

---

## 七、事件总线集成

UI 模块通过 `EventBus` 与其他模块解耦：

| 事件名 | 发送方 | 载荷类型 | 说明 |
|--------|--------|----------|------|
| `packet_captured` | 抓包模块 | `PacketInfo` | 新数据包到达 |
| `alert_generated` | 检测引擎 | `Alert` | 新告警产生 |
| `detection_result` | 检测引擎 | `DetectionResult` | 检测完成 |
| `capture_started` | 抓包模块 | `str` (interface) | 抓包已启动 |
| `capture_stopped` | 抓包模块 | `None` | 抓包已停止 |
| `capture_error` | 抓包模块 | `str` (错误信息) | 抓包出错 |
| `rules_changed` | UI (规则面板) | `None` | 规则被修改 |
| `stats_update` | UI (定时器) | `dict` | 定期统计更新 |
| `export_requested` | UI (菜单) | `dict` (导出参数) | 请求导出报告 |

---

## 八、技术约定

| 约定 | 说明 |
|------|------|
| GUI 框架 | PyQt6，用于所有窗口、表格、对话框 |
| 应用内图表 | matplotlib，嵌入到 PyQt6 的 `FigureCanvasQTAgg` |
| 导出图表 | pyecharts，生成独立的交互式 HTML 图表文件 |
| 线程模型 | 抓包在后台线程（QThread），UI 在主线程；数据通过 EventBus / 信号槽传递 |
| 数据绑定 | QAbstractTableModel 子类，直接持有数据列表引用 |
| 样式 | 使用 QSS (Qt Style Sheets) 或代码内样式 |
| i18n | 界面文本使用中文，代码标识符使用英文 |
| 最大数据量 | 流量表 ≤ 10000 行，告警表 ≤ 5000 行，超出自动淘汰旧数据 |