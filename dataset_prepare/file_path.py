"""
文件路径配置（环境变量方案）
优先级：函数参数 > 环境变量 > 默认相对路径
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_dotenv() -> None:
    """
    可选加载项目根目录 .env 文件。
    若未安装 python-dotenv，则仅使用系统环境变量。
    """
    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(dotenv_path=env_path, override=False)


def _resolve_path(explicit_value: Optional[str], env_key: str, default_relative: str) -> str:
    value = explicit_value if explicit_value else os.getenv(env_key)
    if value:
        return str(Path(value).expanduser().resolve())
    return str((PROJECT_ROOT / default_relative).resolve())


_load_dotenv()


@dataclass(frozen=True)
class ProjectPaths:
    apk_root: str
    callgraph_root: str
    data_root: str
    sensitive_API_root: str


def load_project_paths(
    apk_root_value: Optional[str] = None,
    callgraph_root_value: Optional[str] = None,
    data_root_value: Optional[str] = None,
    sensitive_api_root_value: Optional[str] = None,
) -> ProjectPaths:
    """
    统一配置入口，支持外部注入路径
    """
    return ProjectPaths(
        apk_root=_resolve_path(apk_root_value, "APK_ROOT", "data/apk"),
        callgraph_root=_resolve_path(callgraph_root_value, "CALLGRAPH_ROOT", "data/callgraph"),
        data_root=_resolve_path(data_root_value, "DATA_ROOT", "dataset"),
        sensitive_API_root=_resolve_path(
            sensitive_api_root_value, "SENSITIVE_API_ROOT", "dataset_prepare/sensitiveAPI.txt"
        ),
    )


# 向后兼容旧代码中的直接导入写法
_default_paths = load_project_paths()
apk_root = _default_paths.apk_root
callgraph_root = _default_paths.callgraph_root
data_root = _default_paths.data_root
sensitive_API_root = _default_paths.sensitive_API_root
