[English](README.en.md) | **简体中文**

<picture>
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="assets/presentation/hero-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="assets/presentation/hero-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="assets/presentation/hero-dark.svg">
  <img src="assets/presentation/hero-light.svg" width="1000" alt="给不可信输入显式打标，沿已插桩的工具调用传播标签，列出受影响且有副作用的动作。">
</picture>

**给不可信输入显式打标，沿已插桩的工具调用传播标签，列出受影响且有副作用的动作。**

`v0.9.0` · `Python 3.12+` · [Apache-2.0](LICENSE)

[Website](https://tainttrace.lei6393.com) · [Demo record](docs/demo-results.json)

## 为什么使用

只记录动作名，很难知道某个输出是否用到了不可信内容。TaintTrace 要求接入方在边界打标，并通过 tracked 工具保留传播关系。报告按记录中的依赖和副作用标记给出复查清单，不自行判断内容是否恶意，也不自动隔离运行中的动作。

## 架构

<picture>
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="assets/presentation/architecture-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="assets/presentation/architecture-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="assets/presentation/architecture-dark.svg">
  <img src="assets/presentation/architecture-light.svg" width="1000" alt="label.py 定义标签集合，wrap.py 在同步或异步工具输入输出之间传播标签，Tracker 可记录 JSONL。graph.py 重建依赖图，quarantine.py 计算可达动作并筛选 side_effect。CLI 提供表格、图和 JSON。">
</picture>

label.py 定义标签集合，wrap.py 在同步或异步工具输入输出之间传播标签，Tracker 可记录 JSONL。graph.py 重建依赖图，quarantine.py 计算可达动作并筛选 side_effect。CLI 提供表格、图和 JSON。

示例中的 web_fetch、write_file、git_commit、send_message 都是返回字符串的模拟函数，不执行同名外部操作。核心接口见 [wrap.py](src/tainttrace/wrap.py) 与 [tracker.py](src/tainttrace/tracker.py)。

## 安装

需要 Python 3.12+。下面的全部工具函数都是本地 fixture，无网络、真实文件写入或消息发送。

```bash
git clone https://github.com/SuperMarioYL/tainttrace.git
cd tainttrace
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## 快速开始

真实执行内置 11 动作场景与一个 3 动作脚本，验证标签传播和报告。动作名称中的网络、提交或发送行为均为模拟，clean 只表示在该记录图中没有追溯到标签。

```bash
python -m tainttrace.cli demo
python examples/presentation_demo.py
```

内置 demo 无需输入文件；最小完整脚本在 [examples/presentation_demo.py](examples/presentation_demo.py)。

## 使用

使用 Tracker 上下文或 activate/deactivate 管理录制，为工具加 tracked，在不可信输入进入时调用 taint_source。report --trace FILE 重建报告；--graph 展示图，--source ID 按来源过滤。提供 trace 时必须保留真实的数据依赖和标签，不能从动作名自动推断完整影响。

## 实际 Demo

<picture>
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="assets/presentation/process-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="assets/presentation/process-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="assets/presentation/process-dark.svg">
  <img src="assets/presentation/process-light.svg" width="1000" alt="真实执行内置 11 动作场景与一个 3 动作脚本，验证标签传播和报告。动作名称中的网络、提交或发送行为均为模拟，clean 只表示在该记录图中没有追溯到标签。">
</picture>

### 内置传播场景

在模拟函数中运行 11 条动作的标签链。

```text
$ python -m tainttrace.cli demo
╭─ tainttrace demo ────────────────────────────────────────────────────────────────────────────────╮
│ Poisoned-web demo: a fetched page carried a prompt injection. Tracing how its taint propagated   │
│ through the agent's tool graph…                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
                                          Tool-call graph
┏━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ call id                ┃ tool              ┃   side-effect    ┃ depends on        ┃    taint     ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ web_fetch-1            │ web_fetch         │        —         │ —                 │    clean     │
│ web_fetch-2            │ web_fetch         │        —         │ —                 │    clean     │
│ web_fetch-3            │ web_fetch         │        —         │ —                 │    clean     │
│ summarize-4            │ summarize         │        —         │ web_fetch-2       │  ● tainted   │
│ summarize-5            │ summarize         │        —         │ web_fetch-1       │    clean     │
│ plan-6                 │ plan              │        —         │ summarize-4       │  ● tainted   │
│ write_file-7           │ write_file        │        ✓         │ plan-6            │  ● tainted   │
│ write_file-8           │ write_file        │        ✓         │ summarize-5       │    clean     │
│ git_commit-9           │ git_commit        │        ✓         │ write_file-7      │  ● tainted   │
│ read_file-10           │ read_file         │        —         │ web_fetch-3       │    clean     │
│ send_message-11        │ send_message      │        ✓         │ read_file-10      │    clean     │
└────────────────────────┴───────────────────┴──────────────────┴───────────────────┴──────────────┘

╭────────────────────────────────────────────────────────────────╮
│ 4 of 11 actions tainted  ·  2 to quarantine  ·  7 proven clean │
╰────────────────────────────────────────────────────────────────╯
Untrusted sources: web:cve-blog

                       Quarantine list — side-effecting actions to roll back
┏━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃    # ┃ call id       ┃ tool        ┃  hops ┃ tainted by   ┃ why                                  ┃
┡━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│    1 │ write_file-7  │ write_file  │     2 │ web:cve-blog │ poisoned web page (prompt injection) │
│    2 │ git_commit-9  │ git_commit  │     3 │ web:cve-blog │ poisoned web page (prompt injection) │
└──────┴───────────────┴─────────────┴───────┴──────────────┴──────────────────────────────────────┘

                    Influenced (tainted, no side effect) — review, not roll back
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ call id                     ┃ tool                   ┃        hops ┃ tainted by                  ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ summarize-4                 │ summarize              │           0 │ web:cve-blog                │
│ plan-6                      │ plan                   │           1 │ web:cve-blog                │
└─────────────────────────────┴────────────────────────┴─────────────┴─────────────────────────────┘

Proven clean (7): web_fetch-1, web_fetch-2, web_fetch-3, summarize-5, write_file-8, read_file-10,
send_message-11
```

### 最小完整脚本

3 动作中 2 条受标签影响，1 条有副作用标记。

```text
$ python examples/presentation_demo.py
{
  "total_actions": 3,
  "tainted_count": 2,
  "quarantine_count": 1,
  "clean_count": 1,
  "sources": [
    "fixture:input"
  ],
  "headline": "2 of 3 actions tainted, 1 proven clean",
  "quarantine": [
    {
      "id": "simulated_write-2",
      "name": "simulated_write",
      "side_effect": true,
      "reached_by": [
        "fixture:input"
      ],
      "reasons": [
        "explicitly labeled example"
      ],
      "hops": 1
    }
  ],
  "tainted": [
    {
      "id": "transform-1",
      "name": "transform",
      "side_effect": false,
      "reached_by": [
        "fixture:input"
      ],
      "reasons": [
        "explicitly labeled example"
      ],
      "hops": 0
    },
    {
      "id": "simulated_write-2",
      "name": "simulated_write",
      "side_effect": true,
      "reached_by": [
        "fixture:input"
      ],
      "reasons": [
        "explicitly labeled example"
      ],
      "hops": 1
    }
  ],
  "clean_ids": [
    "transform-3"
  ]
}
```

## 能力与接入

<picture>
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="assets/presentation/integrations-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="assets/presentation/integrations-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="assets/presentation/integrations-dark.svg">
  <img src="assets/presentation/integrations-light.svg" width="1000" alt="标签传播依赖被包装的数据与调用关系。未插桩路径、未标记输入或丢失标签的转换都可能让图不完整；报告里的 proven clean 不是整个系统的安全证明。">
</picture>

标签传播依赖被包装的数据与调用关系。未插桩路径、未标记输入或丢失标签的转换都可能让图不完整；报告里的 proven clean 不是整个系统的安全证明。



## 配置

side_effect=True 显式标记需关注的副作用。v0.9.0 的 report --json 成功输出时退出 0；文本模式在 quarantine 非空时退出 1，文件/格式错误退出 2。--strict 让损坏行报告原始内容，日志含敏感数据时应注意输出去向。

## 路线图与范围

当前支持显式插桩、同步/异步包装、JSONL 与按来源报告。自动框架插桩、跨会话分析和事件 dashboard 仍是后续方向；没有自动回滚器。

- 必须显式标记和插桩，不能自动追踪任意 Agent 的所有 token。
- clean 仅相对于记录图，不表示没有其他未观测影响。
- 不会自动回滚、阻断工具或证明注入已成功利用。

[Terminal recording](assets/demo.gif) · [Recording script](docs/demo.tape)

## 许可证

[Apache-2.0](LICENSE)
