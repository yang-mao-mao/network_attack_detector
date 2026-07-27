# UI Module — Network Attack Detector

基于 PyQt6 的图形界面模块，提供网络攻击检测系统的完整前端。

## 目录结构

```
ui/
├── main_window.py          # 主窗口（侧边栏导航 + 页面容器）
├── behavior_detect/        # 行为检测 — 规则管理与检测监控（JSON 格式）
├── feature_detect/         # 特征检测 — 规则管理与检测监控（CSV 格式）
├── packet_capture/         # 数据包捕获 — 抓包展示与控制
├── shell/                  # 交互式 Shell — 多标签终端
├── statistic/              # 统计分析 — 攻击统计概览与 IP 排行
└── text_editor/            # 文本编辑器 — 类 Nano 编辑器
```

## 各模块说明

### `main_window.py` — 主窗口

应用程序入口，提供左侧可滚动侧边栏 + 右侧页面容器的布局。

| 组件 | 说明 |
|------|------|
| `SideBarButton` | 自定义方形按钮，支持文字 / 图片渲染，灰（默认）/ 白（悬浮 / 激活）/ 蓝（选中）三态 |
| `SideBar` | 可滚动垂直按钮条，黑色底色，按钮紧密排列 |
| `MainWindow` | 主窗口，左侧 SideBar + 右侧 `QStackedWidget`，点击按钮切换对应页面 |

导航栏按钮（从上到下）：**B** (behavior_detect) → **F** (feature_detect) → **P** (packet_capture) → **Sh** (shell) → **St** (statistic) → **T** (text_editor)

### `behavior_detect/` — 行为检测

基于 JSON 规则的行为检测模块，包含规则管理与实时检测监控。

- `behavior_detector.py` — `BehaviorDetectWindow(QMainWindow)`：左侧规则面板（RulePanel）+ 右侧文本编辑器 + 结果面板的复合窗口
- `task1.md` — 模块开发任务说明

### `feature_detect/` — 特征检测

基于 CSV 规则的特征检测模块，提供规则增删改查与检测结果展示。

- `feature_detect.py` — `FeatureDetectWindow(QMainWindow)`：左侧规则面板（RulePanel）+ 右侧文本编辑器 + 结果面板的复合窗口
- `task1.md` ~ `task4.md` — 模块开发任务说明

### `packet_capture/` — 数据包捕获

网络数据包实时捕获与展示窗口。

- `packet_capture.py` — `PacketCaptureWindow(QMainWindow)`：菜单栏 + 包列表表格 + 详情面板的分割窗口
- `task1.md` ~ `task3.md` — 模块开发任务说明

### `shell/` — 交互式 Shell

多标签终端模拟器，支持创建多个 Shell 会话。

- `shell.py` — `ShellWindow(QMainWindow)`：`ShellWidget` 嵌入 `QTabWidget`，支持多标签终端
- `task1.md` ~ `task5.md` — 模块开发任务说明

### `statistic/` — 统计分析

攻击检测数据聚合展示，提供可视化概览。

- `statistic.py` — `StatisticWindow(QMainWindow)`：
  - `AttackClockWidget` — 24 小时圆形时钟，标记攻击时间点
  - `AttackDetailPanel` — 攻击详情面板
  - `IpRankingPanel` — 攻击源 IP 排行面板
- `task1.md` — 模块开发任务说明

### `text_editor/` — 文本编辑器

类 Nano 风格的轻量文本编辑器。

- `text_editor.py` — `NanoEditor(QMainWindow)`：支持 Ctrl+O 保存、Ctrl+R 打开、Ctrl+X 退出、Ctrl+G 帮助
- `task1.md` ~ `task2.md` — 模块开发任务说明

## 依赖

- **Python** ≥ 3.10
- **PyQt6** — 唯一图形库依赖（任务限制）
- 其他项目依赖见 `requirements.txt`

## 运行

```bash
cd network_attack_detector/src/ui
python main_window.py
```
