# Network Attack Detector 使用说明

本文档面向第一次拿到本项目的使用者。不要假设本机已经安装任何 Python 包；请按下面步骤从零配置环境、安装依赖并运行程序。

## 1. 项目简介

`network_attack_detector` 是一个网络攻击检测演示系统，主要功能包括：

- 从网卡实时抓取网络数据包。
- 解析 HTTP/TCP/UDP/ICMP 等数据包信息。
- 基于特征规则检测 SQL 注入、XSS、命令注入等攻击。
- 基于行为规则检测端口扫描、爆破登录、高频请求等异常行为。
- 使用 PyQt6 图形界面展示抓包、检测结果、统计信息和报告导出。
- 提供内置演示流量，方便在没有真实攻击环境的情况下稳定演示。

项目主入口：

```text
main.py
```

## 2. 目录结构

解压或克隆项目后，主要目录如下：

```text
network_attack_detector/
├─ main.py                         主程序入口
├─ requirements.txt                Python 依赖列表
├─ config/                         配置文件
├─ data/
│  ├─ rules/                       检测规则
│  │  ├─ signature_rules.csv       特征检测规则
│  │  └─ behavior_rules.json       行为检测规则
│  └─ samples/                     演示流量和检测摘要
├─ src/                            源代码
├─ tests/                          自动化测试
└─ docs/                           项目文档
```

## 3. 运行环境要求

### 3.1 推荐环境

推荐：

```text
Windows 10/11
Python 3.10 或更高版本
```

当前项目已在 Windows 环境下验证过，核心测试结果为：

```text
56 passed
```

如果只演示内置攻击流量和 UI，安装 Python 依赖即可。

如果要使用真实网卡抓包，还需要额外安装：

```text
Npcap
```

Npcap 不是 Python 包，不能通过 `pip install` 安装。它是 Windows 下 Scapy 抓包依赖的底层抓包驱动，需要单独下载安装。安装后建议重启 PowerShell 或重启电脑。

### 3.2 Python 包依赖

项目依赖写在 `requirements.txt` 中：

```text
scapy>=2.5.0
PyYAML>=6.0.0
PyQt6>=6.6.0
matplotlib>=3.8.0
pyecharts>=2.0.0
psutil>=5.9.0
pytest>=8.0.0
```

依赖用途：

| 包名 | 用途 |
| --- | --- |
| `scapy` | 实时抓包、解析底层数据包 |
| `PyYAML` | 读取 YAML 配置文件 |
| `PyQt6` | 图形界面 |
| `matplotlib` | 图表和统计展示相关依赖 |
| `pyecharts` | 图表和报告展示相关依赖 |
| `psutil` | 枚举系统网卡 |
| `pytest` | 运行测试 |

## 4. 从零安装

以下命令默认在项目根目录执行。

先进入项目目录：

```powershell
cd path\to\network_attack_detector
```

例如：

```powershell
cd D:\选题\network_attack_detector
```

### 4.1 方案 A：使用 Python venv

如果电脑已经安装 Python，可以使用 Python 自带虚拟环境。

创建虚拟环境：

```powershell
python -m venv .venv
```

激活虚拟环境：

```powershell
.\.venv\Scripts\Activate.ps1
```

如果 PowerShell 阻止激活脚本，可临时允许当前窗口执行脚本：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

升级 pip：

```powershell
python -m pip install --upgrade pip
```

安装依赖：

```powershell
python -m pip install -r requirements.txt
```

### 4.2 方案 B：使用 Conda

如果电脑已安装 Anaconda 或 Miniconda，可以创建独立环境。

创建环境：

```powershell
conda create -n network_attack_detector python=3.11
```

激活环境：

```powershell
conda activate network_attack_detector
```

进入项目目录：

```powershell
cd path\to\network_attack_detector
```

安装依赖：

```powershell
python -m pip install -r requirements.txt
```

注意：建议使用 `python -m pip install -r requirements.txt` 安装本项目依赖，不要混用多个 Python 环境。运行程序时用哪个 `python`，依赖就必须装在哪个环境里。

## 5. 检查安装是否成功

执行：

```powershell
python -c "import PyQt6; print('PyQt6 OK'); import scapy; print('scapy OK'); import psutil; print('psutil OK')"
```

如果正常，应输出：

```text
PyQt6 OK
scapy OK
psutil OK
```

查看当前使用的 Python 解释器：

```powershell
python -c "import sys; print(sys.executable)"
```

如果程序报某个包不存在，例如：

```text
ModuleNotFoundError: No module named 'PyQt6'
```

说明当前 Python 环境没有安装依赖，请重新执行：

```powershell
python -m pip install -r requirements.txt
```

## 6. 命令行使用方法

查看帮助：

```powershell
python main.py --help
```

当前支持以下命令：

| 命令 | 说明 |
| --- | --- |
| `python main.py --self-check` | 运行最小自检，验证规则加载、HTTP 解析、检测和数据库写入 |
| `python main.py --generate-demo-data` | 生成内置演示流量和检测摘要 JSON |
| `python main.py --ui` | 打开普通图形界面 |
| `python main.py --ui-demo` | 打开图形界面并自动加载演示攻击流量 |

如果直接运行：

```powershell
python main.py
```

程序只会提示可用参数，不会启动完整功能。

## 7. 推荐快速启动流程

第一次运行建议按这个顺序：

```powershell
python main.py --self-check
python main.py --generate-demo-data
python main.py --ui-demo
```

### 7.1 自检

执行：

```powershell
python main.py --self-check
```

自检会做以下事情：

```text
加载规则 -> 构造 SQL 注入 HTTP 请求 -> 解析数据包 -> 执行检测 -> 写入 SQLite 数据库
```

正常情况下会看到类似输出：

```text
Self-check summary
Signature rules: 45
Behavior rules: 3
Packet protocol: Protocol.HTTP
Alerts: 1
- [High] SQL Injection: union select
```

`Recent packets in DB` 和 `Recent alerts in DB` 会随着多次运行而增加，这是正常现象。

### 7.2 生成演示数据

执行：

```powershell
python main.py --generate-demo-data
```

会生成：

```text
data/samples/demo_traffic.json
data/samples/demo_summary.json
```

演示数据包含：

```text
34 个数据包
5 个命中包
5 条告警
```

告警类型包括：

```text
SQL Injection
XSS
Command Injection
Port Scan
Brute Force
```

### 7.3 打开演示 UI

执行：

```powershell
python main.py --ui-demo
```

该命令会打开图形界面，并自动加载内置演示流量。

如果只是打开空界面：

```powershell
python main.py --ui
```

空界面打开后，可手动加载演示数据：

```text
P 页面 -> File -> Load Demo Data
```

## 8. 图形界面说明

主界面左侧是功能导航栏。常用页面如下：

| 左侧按钮 | 页面 | 作用 |
| --- | --- | --- |
| `P` | Packet Capture | 抓包、显示数据包、加载演示数据 |
| `F` | Feature Detection | 特征检测结果和 CSV 规则管理 |
| `B` | Behavior Detection | 行为检测结果和 JSON 规则管理 |
| `St` | Statistics | 统计展示和报告导出 |
| `Sh` | Shell | Shell 页面 |
| `T` | Text Editor | 文本编辑页面 |

### 8.1 P 页面：抓包和演示数据

进入 `P` 页面后，顶部有：

```text
File
Network
```

`File` 菜单：

| 菜单项 | 作用 |
| --- | --- |
| `Open...` | 打开文件选择框，目前主要用于选择文件 |
| `Load Demo Data` | 加载内置演示攻击流量 |

`Network` 菜单：

| 菜单项 | 作用 |
| --- | --- |
| `Start Capturing` | 选择网卡并开始抓包 |
| `Stop Capturing` | 停止抓包 |
| `PAUSE CAPTURING` | 暂停抓包 |
| `RESUME CAPTURING` | 继续抓包 |

真实抓包流程：

```text
P -> Network -> Start Capturing -> 选择正在联网的网卡
```

Windows 上通常选择：

```text
WLAN  (你的无线网卡 IP)
```

不要选择 VMware、VPN、Loopback 这类网卡，除非你明确知道自己要抓对应网络里的流量。

如果页面显示：

```text
NO TRAFFIC FOUND IN WLAN
```

说明抓包已经启动，但暂时没有收到数据包。可以打开浏览器访问网页，或者另开 PowerShell 执行：

```powershell
ping 8.8.8.8
```

如果仍然没有数据，请检查 Npcap、管理员权限和网卡选择。

### 8.2 F 页面：特征检测

`F` 页面展示特征检测结果，并提供特征规则编辑功能。

默认规则文件：

```text
data/rules/signature_rules.csv
```

典型特征检测类型：

```text
SQL Injection
XSS
Command Injection
```

演示时建议使用：

```text
P -> File -> Load Demo Data
```

或者直接用：

```powershell
python main.py --ui-demo
```

这样可以稳定看到特征检测结果。

### 8.3 B 页面：行为检测

`B` 页面展示行为检测结果，并提供行为规则编辑功能。

默认规则文件：

```text
data/rules/behavior_rules.json
```

当前行为检测规则包括：

| 规则 ID | 说明 |
| --- | --- |
| `BEH-2001` | 端口扫描检测 |
| `BEH-2002` | 爆破登录检测 |
| `BEH-2003` | 高频 HTTP 请求检测 |

行为检测不是只看单个包，而是看一段时间窗口内的流量行为。例如：

```text
同一源 IP 短时间访问多个端口 -> Port Scan
同一源 IP 多次访问登录路径 -> Brute Force
```

### 8.4 St 页面：统计和报告

`St` 页面用于展示统计结果：

- 告警时钟。
- 告警详情。
- 源 IP 排名。
- 报告导出。

点击左上角：

```text
GEN REPORT
```

可以选择：

```text
GEN CSV REPORT
GEN HTML REPORT
```

HTML 报告适合演示或提交，CSV 报告适合后续分析。

## 9. 推荐演示顺序

如果是课堂展示、答辩或给别人演示，推荐流程如下：

1. 打开演示 UI：

```powershell
python main.py --ui-demo
```

2. 在 `P` 页面展示 34 条演示数据包。

3. 切换到 `F` 页面，展示：

```text
SQL Injection
XSS
Command Injection
```

4. 切换到 `B` 页面，展示：

```text
Port Scan
Brute Force
```

5. 切换到 `St` 页面，展示统计信息。

6. 点击：

```text
GEN REPORT -> GEN HTML REPORT
```

导出 HTML 报告。

如果要展示真实抓包能力：

1. 进入 `P` 页面。
2. 点击 `Network -> Start Capturing`。
3. 选择正在联网的网卡，例如 `WLAN`。
4. 打开网页或执行 `ping 8.8.8.8`。
5. 看到数据包进入表格后，点击 `Stop Capturing`。

建议先演示真实抓包，再演示内置攻击流量。因为真实抓包证明系统能接收网络数据；内置攻击流量证明系统能稳定检测攻击。

## 10. 测试方法

运行全部测试：

```powershell
python -m pytest
```

正常情况下应看到：

```text
56 passed
```

如果测试失败，先确认依赖安装完整：

```powershell
python -m pip install -r requirements.txt
```

然后重新运行测试。

## 11. 常见问题

### 11.1 `ModuleNotFoundError: No module named ...`

说明当前 Python 环境缺少依赖。

解决：

```powershell
python -m pip install -r requirements.txt
```

确认安装到当前 Python：

```powershell
python -c "import sys; print(sys.executable)"
```

### 11.2 UI 打不开或提示 PyQt6 缺失

安装 PyQt6：

```powershell
python -m pip install PyQt6
```

或者重新安装全部依赖：

```powershell
python -m pip install -r requirements.txt
```

### 11.3 `Start Capturing` 没有网卡

先确认当前环境安装了 `psutil` 和 `scapy`：

```powershell
python -c "import psutil; import scapy; print('ok')"
```

如果报错：

```powershell
python -m pip install psutil scapy
```

然后重新启动程序。

### 11.4 能选网卡，但抓不到包

按顺序检查：

1. 是否安装 Npcap。
2. 是否使用管理员权限启动 PowerShell。
3. 是否选择了真实联网的网卡，例如 `WLAN`。
4. 当前网络是否真的有流量。
5. 安全软件或防火墙是否限制抓包。

可以用下面命令产生测试流量：

```powershell
ping 8.8.8.8
```

### 11.5 普通 UI 没有检测结果

`python main.py --ui` 打开的是空 UI。

请使用：

```powershell
python main.py --ui-demo
```

或者在 UI 中点击：

```text
P -> File -> Load Demo Data
```

### 11.6 自检中的 recent 数量越来越大

这是正常现象。`--self-check` 每次会向 `data/ids.db` 写入一条数据包和告警记录。

如果想重新开始，可以关闭程序后删除：

```text
data/ids.db
```

下次运行时程序会自动重新创建数据库。

## 12. 分享项目时的建议

上传或打包项目给别人时，建议保留：

```text
main.py
requirements.txt
config/
data/rules/
data/samples/
src/
tests/
docs/
README_使用说明.md
```

可以不上传运行缓存：

```text
__pycache__/
.pytest_cache/
data/logs/
```

`data/ids.db` 是运行数据库。如果希望别人拿到的是干净项目，可以删除它；如果希望保留你的演示运行记录，可以保留它。

如果要让对方稳定看到演示效果，请确保上传时包含：

```text
data/rules/signature_rules.csv
data/rules/behavior_rules.json
data/samples/demo_traffic.json
data/samples/demo_summary.json
```

如果缺少 `data/samples/` 中的演示文件，对方也可以运行：

```powershell
python main.py --generate-demo-data
```

重新生成。

## 13. 最短启动命令

对方拿到项目后，最短流程是：

```powershell
cd path\to\network_attack_detector
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py --ui-demo
```

如果只想验证命令行功能：

```powershell
python main.py --self-check
python main.py --generate-demo-data
python -m pytest
```
