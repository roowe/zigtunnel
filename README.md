# gotunnel-zig

用 Zig 实现的 `gotunnel` 实验版本。项目以 Go 版本的协议、命令行参数和核心行为为参考，目标是让 Zig 客户端和服务端能够与 Go 版本互通。

> [!WARNING]
> 本项目是 **5.6 Luna Max 的 vibe coding 测试项目**，主要用于验证 AI 辅助完成 Zig 代码迁移、协议兼容和测试补全的能力。
>
> **代码未经生产环境测试，也没有经过独立安全审计。** 当前测试不能证明它适合生产部署、长期运行或承载敏感数据。请不要把它用于生产网络、重要业务或真实敏感流量。

## 功能概览

- 服务端模式：监听隧道连接，把远端链路转发到本地后端。
- 客户端模式：维护多个持久隧道，在本地监听并转发应用连接。
- 一个隧道上复用多个应用连接。
- AES-128 加密挑战、HMAC-SHA256 签名的认证握手。
- XChaCha20-IETF 流加密。
- 心跳检测、隧道断线和客户端重连。
- 连接建立失败、后端不可达、链路关闭和后端连接限制等异常处理。

## 架构

```text
本地应用 <--TCP--> gotunnel-zig 客户端
                         || 持久、认证、加密、复用
                  gotunnel-zig / gotunnel 服务端 <--TCP--> 后端服务
```

客户端和服务端可以分别使用 Zig 或 Go 实现。例如，Zig 客户端可以连接 Go 服务端，反过来也可以连接。

## 构建和运行

本项目使用 Zig 0.17 的标准库网络 API，不依赖第三方包。

```bash
# 构建
zig build

# 构建优化版本
zig build -Doptimize=ReleaseSafe
```

`-tunnels 0` 表示服务端模式；`-tunnels` 大于 0 表示客户端模式。

```bash
# 服务端：监听 8001，把链路转发到本机 1234 端口
zig build run -- \
  -listen=:8001 \
  -backend=127.0.0.1:1234 \
  -secret="your secret"

# 客户端：建立 100 条隧道，在本地 8080 端口提供入口
zig build run -- \
  -tunnels=100 \
  -listen=127.0.0.1:8080 \
  -backend=server.example.com:8001 \
  -secret="your secret"
```

命令行参数与 Go 版本保持一致：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-listen` | `:8001` | 监听地址；客户端模式下是本地应用入口 |
| `-backend` | `127.0.0.1:1234` | 服务端模式下是后端服务，客户端模式下是远端隧道服务端 |
| `-secret` | 内置默认字符串 | 认证共享密钥；两端必须一致 |
| `-tunnels` | `0` | 隧道数量；`0` 为服务端模式，正数为客户端模式 |
| `-heartbeat` | `10` | 心跳间隔，单位为秒 |
| `-timeout` | `30` | 心跳超时相关配置，单位为秒 |
| `-log` | `1` | 日志级别，数字越大日志越详细 |

## 与 Go 版本的关系和差异

### 已保持的协议和主要行为

Zig 版本复用了 Go 版本的核心线路约定：

- 隧道数据包使用小端序的 `link ID + payload length` 头部。
- 认证握手使用 16 字节 token、AES-128 加密和 HMAC-SHA256 校验。
- 认证成功后，根据 token 派生 32 字节会话密钥，并使用 XChaCha20-IETF 进行流加密。
- 控制命令负责链路创建、关闭和心跳回显。
- 客户端使用持久隧道和多个 hub 复用应用连接。

Go 和 Zig 已经分别完成过双向互通验证：

1. Go 服务端 + Zig 客户端 + TCP Echo 后端。
2. Zig 服务端 + Go 客户端 + TCP Echo 后端。

两条链路都能完成真实 TCP 数据回显。但这属于手工 smoke test，不等于完整兼容性认证。

### 实现层差异

| 领域 | Go 版本 | Zig 版本 |
| --- | --- | --- |
| 运行时 | goroutine、`net.Conn`、标准库并发模型 | Zig `std.Io`、线程和显式资源管理 |
| 内部结构 | `Hub`、`Link`、`Buffer`、`MPool` 等 Go 类型 | `Hub`、`Link`、`PacketQueue` 等 Zig 类型；不追求内部 API 一致 |
| 密钥 API | `SetCipherKey([]byte)` 会扩展短密钥、截断长密钥 | 内部会话密钥使用固定 `[32]u8`；公共 API 形态不同 |
| 控制命令扩展 | `Hub` 提供通用 `onCtrlFilter` 钩子 | 当前把客户端/服务端角色处理逻辑直接放在 Zig 的 hub 逻辑中 |
| KeepAlive | Go 会在隧道、客户端本地连接和后端连接上设置 TCP KeepAlive | 当前还没有完整配置 TCP KeepAlive |
| 拨号超时 | Go 的隧道拨号和后端拨号使用明确超时 | Zig 已有超时辅助函数，但当前 Zig 0.17 网络后端下暂未真正应用超时参数 |
| 信号处理 | 支持 `SIGHUP` 状态输出，以及 `SIGTERM`/`SIGINT` 退出 | 当前主要负责解析参数并启动服务，尚未补齐同等信号和状态行为 |
| 内存管理 | Go 垃圾回收，并使用对象池 | Zig 使用显式 allocator、队列关闭唤醒和资源释放 |

因此，Zig 版本的目标是实现**可互通的核心功能**，不是复制 Go 包的全部类型、方法和扩展接口。

## 测试

运行全部 Zig 测试：

```bash
zig build test --summary all --seed 0x5eed1234
```

运行 ReleaseSafe 配置下的测试：

```bash
zig build test \
  -Doptimize=ReleaseSafe \
  --summary all \
  --seed 0xc0ffee
```

当前 Zig 测试包含协议、认证、数据包、队列、链路、心跳、重连、并发连接、错误处理、后端连接限制和 CLI 参数解析等场景，共 49 个 `test` 声明。

`zig-0.17` 分支上的现状：47 个模块用例中 46 通过、1 个跳过（`backend rejects excess connections and recovers after release`，单槽后端下拒绝连接与链路 ID 复用会竞争，第三次 reject 可能在到达后端前就被关掉，用例会一直等不到第三次 accept；0.16 上同样复现，属于移植遗留缺陷而非编译器差异）。`zig build test` 与 `zig build` 均可通过。Go 参考版本的 `go test ./...` 当前也已通过；两边的测试数量不能直接一一对应，因为测试粒度和内部实现不同。

已覆盖的重点场景包括：

- 正确和错误共享密钥。
- 损坏或格式错误的认证挑战。
- 单连接和多连接转发。
- 心跳回显、心跳超时和隧道重连。
- 后端不可达、链路重置后的资源释放。
- 后端连接数达到限制时的拒绝和恢复。
- 写入错误、关闭唤醒和并发生产者。
- 客户端和服务端的跨语言 TCP Echo 互通。

## 当前已知缺口

这些差异目前不影响已验证的基本 Echo 互通，但会影响与 Go 版本的完整行为对齐：

1. Zig 尚未真正落实 TCP 拨号超时。
2. Zig 尚未补齐 Go 版本的 KeepAlive 设置。
3. Zig 尚未实现 `SIGHUP` 状态输出和 `SIGTERM`/`SIGINT` 优雅退出。
4. 完整的 `Server.start`、`Client.start` 进程级测试和跨语言自动化 smoke test 还没有加入 `zig build test`。
5. Zig 没有完全复制 Go 版本的 `onCtrlFilter`、`Tunnel.String`、`Buffer`/`MPool` 等内部或扩展 API。

## 安全和生产使用声明

即使本地测试全部通过，也不能推出以下结论：

- 加密协议已经完成安全审计。
- 所有平台上的网络行为都一致。
- 长时间运行不会出现资源泄漏或死锁。
- 在高并发、弱网络、NAT 或防火墙环境下稳定。
- 可以安全承载密码、令牌、个人数据或生产业务流量。

在任何生产使用之前，至少还需要完成独立安全审计、跨平台测试、压力测试、长时间运行测试、故障注入、连接超时和 KeepAlive 实现，以及完整的进程生命周期测试。

## 许可证

当前 Zig 实现沿用 Go 参考项目的实验性代码定位。许可证信息请以项目后续补充的 LICENSE 文件为准。
