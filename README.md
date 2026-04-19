## ADroid

ADroid 是一个面向 Android 恶意软件检测的图神经网络模型。项目以静态分析为基础，将 APK 程序行为抽象为函数调用图（Function Call Graph, FCG），并将恶意检测建模为图级二分类任务。与传统基于权限、API 频次或人工规则的方法相比，图表示能够更自然地保留程序结构依赖与调用上下文，有利于捕获复杂恶意行为模式。

在方法上，项目先利用 Androguard 构建调用图，再结合敏感 API 邻域与指令语义特征生成节点属性，最终采用 `GCN + SAGPool` 的层次化图表征网络进行分类。该流程可用于复现“APK 静态分析 -> 图构建 -> 图神经网络训练 -> 恶意检测评估”的完整实验链路，适合作为图安全方向的课程项目、论文原型或后续研究基线。

## 研究目标

- 从 APK 构建函数调用图（`.gml`），建立可学习的程序结构表示
- 根据敏感 API 与指令特征构建节点属性，增强行为语义信息
- 将样本组织为 TU Dataset 格式，兼容 PyTorch Geometric 图分类流程
- 使用图分类模型实现恶意/良性样本识别并输出标准评估指标

## 项目结构

```text
ADroid/
├── README.md
├── src/
│   ├── main.py          # 训练与评估入口
│   ├── dataset.py       # 自定义 TU 格式数据集加载
│   ├── networks.py      # GCN + SAGPool 网络结构
│   └── layers.py        # 自定义 SAGPool
└── dataset_prepare/
    ├── callgraph.py     # APK -> call graph(gml)
    ├── raw_data.py      # call graph -> raw 图数据
    ├── labels.py        # 节点属性构建（指令级特征）
    └── file_path.py     # 数据路径配置
```

## 环境要求

- Python 3.8+（建议 3.9/3.10）
- PyTorch（与 CUDA 版本匹配）
- PyTorch Geometric
- 其他依赖：
  - `torchmetrics`
  - `matplotlib`
  - `scikit-learn`
  - `networkx`
  - `androguard`
  - `numpy`
  - `python-dotenv`（用于自动加载 `.env`）

可参考以下方式安装（请按你本机 CUDA/CPU 环境调整 `torch` 与 `torch-geometric` 安装命令）：

```bash
pip install torch torchvision torchaudio
pip install torch-geometric
pip install torchmetrics matplotlib scikit-learn networkx androguard numpy python-dotenv
```

## 数据准备流程

### 1) 配置机制

项目已将数据路径从业务脚本中抽离到统一配置层 `dataset_prepare/file_path.py`，并采用以下覆盖优先级：

- 函数参数注入
- 环境变量
- 默认相对路径

配置键如下：

- `APK_ROOT`
- `CALLGRAPH_ROOT`
- `DATA_ROOT`
- `SENSITIVE_API_ROOT`

可选地在项目根目录提供 `.env`（参考 `.env.example`）：

```bash
APK_ROOT=./data/apk
CALLGRAPH_ROOT=./data/callgraph
DATA_ROOT=./dataset
SENSITIVE_API_ROOT=./dataset_prepare/sensitiveAPI.txt
```

说明：所有路径均支持相对路径与绝对路径。

### 2) 准备 APK 数据

APK 目录需按类别组织：

```text
apk_root/
├── benign/
│   ├── xxx.apk
│   └── ...
└── malware/
    ├── yyy.apk
    └── ...
```

### 3) 生成函数调用图

执行：

```bash
python dataset_prepare/callgraph.py
```

如需临时覆盖配置，可通过命令行注入：

```bash
python dataset_prepare/callgraph.py --apk_root ./custom/apk --callgraph_root ./custom/callgraph
```

输出目录也应是二分类结构（`benign`/`malware`），每个 APK 对应一个 `.gml` 文件。

### 4) 生成图学习数据集（TU 格式）

执行：

```bash
python dataset_prepare/raw_data.py
```

默认会在 `data_root/<dataset_name>/raw/` 下生成：

- `<dataset_name>_A.txt`
- `<dataset_name>_graph_indicator.txt`
- `<dataset_name>_graph_labels.txt`
- `<dataset_name>_node_attributes.txt`

## 训练与评估

训练入口在 `src/main.py`，默认读取：

- 数据集根目录：`DATA_ROOT`（未设置时默认 `../dataset`）
- 数据集名称：`DATASET_NAME`（未设置时默认 `MalDroid2020`）
- 模型保存路径：`MODEL_PATH`（未设置时默认 `latest.pth`）

在项目根目录执行：

```bash
python src/main.py --dataset MalDroid2020
```

训练过程中会基于验证集 loss 早停，并保存最佳模型到 `MODEL_PATH`；最后在测试集输出准确率、精确率、召回率、F1 等指标。

## 关键参数

`src/main.py` 支持常用超参数：

- `--seed`：随机种子（默认 `888`）
- `--batch_size`：批大小（默认 `128`）
- `--lr`：学习率（默认 `0.0005`）
- `--weight_decay`：权重衰减（默认 `0.0001`）
- `--nhid`：隐藏层维度（默认 `64`）
- `--pooling_ratio`：SAGPool 保留比例（默认 `0.7`）
- `--dropout_ratio`：Dropout（默认 `0.5`）
- `--epochs`：最大轮数（默认 `10000`）
- `--patience`：早停容忍轮数（默认 `50`）
- `--dataset_root`：数据集根目录（默认读取 `DATA_ROOT`）
- `--model_path`：模型保存/加载路径（默认读取 `MODEL_PATH`）

示例：

```bash
python src/main.py --dataset MalDroid2020 --batch_size 64 --lr 0.001 --nhid 128
```

## 注意事项

- `dataset_prepare/raw_data.py` 引用了 `attributes.py`（`from attributes import ...`），当前仓库未包含该文件；若你需要启用对应特征，请补充该模块或移除相关引用。
- 路径通过环境变量统一配置，不需要再修改源码中的硬编码路径。
- 首次加载 `MyDataset` 时会自动处理 raw 数据并生成 `processed/data.pt`。


