# 基于流量分析与特征匹配的常见网络攻击检测系统

本目录下的 `network_attack_detector/` 是专题二“常见网络攻击的检测系统”的项目骨架。该骨架按五人协作方式拆分模块，已经包含可运行的最小自检流程：

```powershell
cd .\network_attack_detector
python .\main.py --self-check
```

自检流程会加载示例规则，解析一条模拟 HTTP 攻击请求，并通过特征匹配引擎生成告警，用于验证项目结构、核心数据结构和规则加载逻辑是否正常。

## 一、成员分工约定

| 成员 | 角色 | 主要职责 |
|---|---|---|
| 成员 A | 项目负责人 / 架构与集成 | 总体架构、核心数据结构、数据库、主程序、模块集成、报告统稿 |
| 成员 B | 抓包与协议解析负责人 | 网卡选择、实时抓包、pcap 读取、IP/TCP/UDP/HTTP 解析 |
| 成员 C | 规则库与特征匹配负责人 | 特征规则、规则加载、规则校验、字符串匹配、正则匹配 |
| 成员 D | 行为检测与测试场景负责人 | 暴力破解、端口扫描、高频访问检测、攻击样本和演示脚本 |
| 成员 E | 界面与可视化负责人 | GUI、实时告警、规则管理、统计图表、CSV/HTML 报告导出 |

## 二、项目结构

```text
network_attack_detector/
├── main.py
├── requirements.txt
├── config/
│   ├── app_config.yaml
│   └── logging_config.yaml
├── data/
│   ├── rules/
│   │   ├── signature_rules.csv
│   │   └── behavior_rules.json
│   ├── samples/
│   │   └── README.md
│   └── exports/
│       └── .gitkeep
├── src/
│   ├── core/
│   ├── capture/
│   ├── parser/
│   ├── rules/
│   ├── detection/
│   ├── storage/
│   ├── ui/
│   ├── report/
│   └── utils/
├── scripts/
├── tests/
└── docs/
```

## 三、文件职责与开发负责人

### 1. 项目入口与配置

| 文件 | 功能 | 负责人 |
|---|---|---|
| `network_attack_detector/main.py` | 程序入口；加载规则；初始化检测引擎；提供 `--self-check` 自检流程；后续接入 GUI 和实时抓包 | 成员 A |
| `network_attack_detector/requirements.txt` | 项目依赖清单，包括 Scapy、PyQt6、matplotlib、pytest 等 | 成员 A |
| `network_attack_detector/config/app_config.yaml` | 应用配置，包括默认规则路径、数据库路径、抓包过滤表达式、行为检测阈值 | 成员 A |
| `network_attack_detector/config/logging_config.yaml` | 日志配置，控制日志等级、格式和输出位置 | 成员 A |

### 2. 数据文件

| 文件 | 功能 | 负责人 |
|---|---|---|
| `network_attack_detector/data/rules/signature_rules.csv` | 特征检测规则库，覆盖 SQL 注入、XSS、命令执行、WebShell、敏感文件访问等 | 成员 C |
| `network_attack_detector/data/rules/behavior_rules.json` | 行为检测规则库，覆盖端口扫描、暴力破解、高频请求等 | 成员 D |
| `network_attack_detector/data/samples/README.md` | 说明测试 pcap、攻击样本和演示流量应如何存放 | 成员 D |
| `network_attack_detector/data/exports/.gitkeep` | 保留导出目录；运行后可存放 CSV/HTML 报告 | 成员 E |

### 3. 核心公共层 `src/core`

| 文件 | 功能 | 负责人 |
|---|---|---|
| `network_attack_detector/src/__init__.py` | 标记 `src` 为 Python 包 | 成员 A |
| `network_attack_detector/src/core/__init__.py` | 核心模块包初始化 | 成员 A |
| `network_attack_detector/src/core/models.py` | 定义核心数据结构：`PacketInfo`、`HttpInfo`、`SignatureRule`、`BehaviorRule`、`Alert`、`FlowState`、`DetectionResult` | 成员 A |
| `network_attack_detector/src/core/constants.py` | 定义默认路径、默认阈值、支持的匹配类型等常量 | 成员 A |
| `network_attack_detector/src/core/event_bus.py` | 简单事件分发器；后续用于检测模块和 UI 模块解耦 | 成员 A |
| `network_attack_detector/src/core/exceptions.py` | 自定义异常类型，如规则错误、抓包错误、解析错误、检测错误 | 成员 A |

### 4. 抓包层 `src/capture`

| 文件 | 功能 | 负责人 |
|---|---|---|
| `network_attack_detector/src/capture/__init__.py` | 抓包模块包初始化 | 成员 B |
| `network_attack_detector/src/capture/interface.py` | 定义抓包模块统一接口 `CaptureInterface` | 成员 B |
| `network_attack_detector/src/capture/live_capture.py` | 使用 Scapy 进行实时抓包，支持列出网卡、启动抓包、停止抓包 | 成员 B |
| `network_attack_detector/src/capture/pcap_reader.py` | 读取离线 pcap 文件，便于复现实验和答辩演示 | 成员 B |

### 5. 协议解析层 `src/parser`

| 文件 | 功能 | 负责人 |
|---|---|---|
| `network_attack_detector/src/parser/__init__.py` | 协议解析模块包初始化 | 成员 B |
| `network_attack_detector/src/parser/packet_parser.py` | 将 Scapy 原始包或原始 HTTP bytes 转换为统一 `PacketInfo` | 成员 B |
| `network_attack_detector/src/parser/http_parser.py` | 解析 HTTP method、host、url、path、query、header、body | 成员 B |
| `network_attack_detector/src/parser/payload_decoder.py` | 将 payload bytes 尽可能解码为可读文本 | 成员 B |

### 6. 规则管理层 `src/rules`

| 文件 | 功能 | 负责人 |
|---|---|---|
| `network_attack_detector/src/rules/__init__.py` | 规则模块包初始化 | 成员 C |
| `network_attack_detector/src/rules/rule_loader.py` | 从 CSV/JSON 加载特征规则和行为规则，并转换为数据结构对象 | 成员 C |
| `network_attack_detector/src/rules/rule_manager.py` | 规则列表管理，支持添加、删除、启用、禁用、查询规则 | 成员 C |
| `network_attack_detector/src/rules/rule_validator.py` | 校验规则字段完整性、匹配类型合法性、阈值合法性 | 成员 C |

### 7. 检测引擎层 `src/detection`

| 文件 | 功能 | 负责人 |
|---|---|---|
| `network_attack_detector/src/detection/__init__.py` | 检测模块包初始化 | 成员 C、成员 D |
| `network_attack_detector/src/detection/signature_engine.py` | 特征匹配引擎；支持 content 字符串匹配和 regex 正则匹配 | 成员 C |
| `network_attack_detector/src/detection/behavior_engine.py` | 行为检测引擎；实现端口扫描、暴力破解、高频请求等时间窗口检测 | 成员 D |
| `network_attack_detector/src/detection/state_tracker.py` | 维护行为检测所需的时间窗口状态，如访问端口集合、请求次数等 | 成员 D |
| `network_attack_detector/src/detection/detection_manager.py` | 统一调度特征匹配和行为检测，输出 `DetectionResult` | 成员 A |

### 8. 存储层 `src/storage`

| 文件 | 功能 | 负责人 |
|---|---|---|
| `network_attack_detector/src/storage/__init__.py` | 存储模块包初始化 | 成员 A |
| `network_attack_detector/src/storage/database.py` | SQLite 连接和建表逻辑 | 成员 A |
| `network_attack_detector/src/storage/alert_repository.py` | 告警入库和查询 | 成员 A |
| `network_attack_detector/src/storage/rule_repository.py` | 规则入库和查询，为 GUI 规则管理提供数据接口 | 成员 A、成员 C |

### 9. 界面层 `src/ui`

| 文件 | 功能 | 负责人 |
|---|---|---|
| `network_attack_detector/src/ui/__init__.py` | UI 模块包初始化 | 成员 E |
| `network_attack_detector/src/ui/main_window.py` | 主界面入口；后续接入网卡选择、开始/停止检测、流量表、告警表、规则面板、统计图 | 成员 E |
| `network_attack_detector/src/ui/alert_table.py` | 实时告警表格模型和刷新逻辑 | 成员 E |
| `network_attack_detector/src/ui/rule_panel.py` | 规则管理面板，支持展示、启用、禁用、添加、删除规则 | 成员 E |
| `network_attack_detector/src/ui/traffic_table.py` | 实时流量表格，展示源 IP、目的 IP、端口、协议、长度等 | 成员 E |
| `network_attack_detector/src/ui/stats_panel.py` | 统计面板，展示攻击类型分布、Top 源 IP、时间趋势 | 成员 E |

### 10. 报告导出层 `src/report`

| 文件 | 功能 | 负责人 |
|---|---|---|
| `network_attack_detector/src/report/__init__.py` | 报告模块包初始化 | 成员 E |
| `network_attack_detector/src/report/csv_exporter.py` | 将告警列表导出为 CSV 文件 | 成员 E |
| `network_attack_detector/src/report/html_reporter.py` | 生成简单 HTML 检测报告 | 成员 E |

### 11. 工具层 `src/utils`

| 文件 | 功能 | 负责人 |
|---|---|---|
| `network_attack_detector/src/utils/__init__.py` | 工具模块包初始化 | 成员 A |
| `network_attack_detector/src/utils/time_utils.py` | 时间戳格式化、当前毫秒时间等工具 | 成员 A |
| `network_attack_detector/src/utils/ip_utils.py` | IP 地址校验、私网地址判断等工具 | 成员 B |
| `network_attack_detector/src/utils/log_utils.py` | 日志初始化工具 | 成员 A |
| `network_attack_detector/src/utils/file_utils.py` | 路径创建、JSON 读写等文件工具 | 成员 A |

### 12. 测试、脚本和文档

| 文件 | 功能 | 负责人 |
|---|---|---|
| `network_attack_detector/tests/test_rule_loader.py` | 测试特征规则和行为规则加载 | 成员 C |
| `network_attack_detector/tests/test_signature_engine.py` | 测试 SQL 注入、XSS、命令执行等特征匹配 | 成员 C |
| `network_attack_detector/tests/test_behavior_engine.py` | 测试端口扫描、暴力破解等行为检测 | 成员 D |
| `network_attack_detector/tests/test_http_parser.py` | 测试 HTTP 请求解析 | 成员 B |
| `network_attack_detector/tests/test_packet_parser.py` | 测试 `PacketInfo` 生成逻辑 | 成员 B |
| `network_attack_detector/scripts/generate_demo_requests.py` | 生成演示用 HTTP 攻击请求文本，后续可扩展为真实请求脚本 | 成员 D |
| `network_attack_detector/docs/项目设计说明.md` | 记录总体架构、模块设计和技术路线 | 成员 A |
| `network_attack_detector/docs/接口说明.md` | 记录核心数据结构和模块接口约定 | 成员 A |
| `network_attack_detector/docs/测试说明.md` | 记录测试环境、测试样本、测试步骤和结果 | 成员 D |
| `network_attack_detector/docs/分工说明.md` | 记录五人分工、任务量和贡献说明 | 成员 A |

## 四、建议开发顺序

1. 成员 A 固定 `models.py` 中的核心数据结构，所有人围绕这些对象开发。
2. 成员 B 先保证 `PacketParser.parse_http_bytes()` 能输出 `PacketInfo`，再接入 Scapy 实时抓包。
3. 成员 C 先保证 `signature_rules.csv` 能加载并匹配 `PacketInfo`。
4. 成员 D 先用伪造 `PacketInfo` 测试行为检测，再接入真实抓包或 pcap。
5. 成员 E 先用假数据做界面，再接入真实 `Alert` 和 `PacketInfo`。

## 五、当前骨架状态

当前项目已提供：

```text
1. 核心数据结构 dataclass。
2. 示例特征规则和行为规则。
3. HTTP 请求解析。
4. 特征匹配引擎。
5. 行为检测引擎的最小实现。
6. SQLite 建表和告警存储接口。
7. CSV/HTML 报告导出接口。
8. 可运行的 main.py --self-check。
9. 基础测试文件。
```

后续需要补充：

```text
1. 更完整的 Scapy 实时抓包联调。
2. 更丰富的协议解析字段。
3. GUI 的完整 PyQt6/Tkinter 实现。
4. 更多攻击规则和 pcap 样本。
5. 更严格的误报控制和测试报告。
```

