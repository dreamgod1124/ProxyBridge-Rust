# ProxyBridge Rust Implementation

这是 ProxyBridge Windows 平台的 Rust 重构版本，旨在提供更高的性能和更好的内存安全性。

## 运行环境要求
1. **管理员权限**：WinDivert 驱动加载需要管理员权限。
2. **WinDivert 驱动**：
   - 需将 `WinDivert.dll` 和 `WinDivert64.sys` 放置在与可执行文件相同的目录下。
   - 驱动版本建议使用 `2.2.2`。

## 构建与运行
```powershell
# 安装依赖
cargo build

# 运行（需管理员权限）
cargo run
```

## 当前进度
- [x] Phase 1: 核心拦截引擎（WinDivert 异步封装、多线程处理、基础收发）。
- [ ] Phase 2: 状态管理与连接维护（NAT 表映射、异步转发）。
- [ ] Phase 3: 进程识别 (ETW) 与高级规则引擎。
- [ ] Phase 4: Tauri GUI 集成。

## 目录结构
- `src/main.rs`: 核心启动逻辑与包处理主循环。
- `Cargo.toml`: 项目依赖配置。
