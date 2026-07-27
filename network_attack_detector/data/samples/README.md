# Samples

本目录用于存放**测试用的数据样本**，包括内置演示流量和攻击样本。所有文件应可重现，便于自动化测试和人工演示。

---

## 目录结构

```
data/samples/
├── README.md                    # 本说明文件
├── demo_traffic.json            # 内置演示流量数据（34 个包）
├── demo_summary.json            # 内置演示流量对应的检测摘要（5 条告警）
└── attack_samples/              （可选）存放单个攻击请求文本或脚本
```

---

## 文件存放规范

### 1. 演示流量文件（内置）

| 文件名 | 格式 | 说明 | 生成方式 |
|--------|------|------|----------|
| `demo_traffic.json` | JSON | 包含 34 个模拟数据包的结构化数据（含攻击和正常流量） | `python main.py --generate-demo-data` |
| `demo_summary.json` | JSON | 包含 5 条告警摘要，用于 GUI 快速展示 | 同上 |

**用途**：GUI 中 `P -> File -> Load Demo Data` 会加载这两个文件，用于演示或无网络环境下的测试。

**注意事项**：  
- 如果文件缺失，可随时重新生成。  
- 不建议手动编辑，请使用生成命令保证格式正确。

---

### 2. 攻击样本（可选）

如果希望存放**单个 HTTP 请求的原始文本**或 **payload 列表**，可创建 `attack_samples/` 子目录：

```
attack_samples/
├── sqli_payloads.txt      # SQL 注入 payload 列表
├── xss_payloads.txt       # XSS payload 列表
├── cmd_inject.txt         # 命令注入示例
└── webshell_paths.txt     # WebShell 路径列表
```

这些文件可用于**单元测试**中的参数化测试，或作为构造演示数据的输入。

---

## 如何生成这些样本

### 生成内置演示流量

```bash
python main.py --generate-demo-data
```

执行后会自动创建 `demo_traffic.json` 和 `demo_summary.json`。

---

## 如何使用这些样本

### 在 GUI 中加载演示数据
1. 启动 GUI：`python main.py --ui-demo`（自动加载）  
   或 `python main.py --ui` 后在 `P` 页面点击 `File -> Load Demo Data`。
2. 程序会读取 `demo_traffic.json` 和 `demo_summary.json`，在流量表和告警表中展示。

---

## 注意事项

1. **版本控制**：`demo_traffic.json` 和 `demo_summary.json` 应随版本更新，确保与当前规则和检测逻辑一致。  
2. **临时文件**：不要在仓库中保留临时生成的测试文件，可使用 `.gitignore` 忽略特定模式（如 `*.tmp.json`）。
3. **可重现性**：所有样本应能通过代码或脚本重新生成，便于持续集成和回归测试。

---