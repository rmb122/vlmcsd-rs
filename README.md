# vlmcsd-rs

参考 vlmcsd 实现的 Rust KMS 模拟激活服务器, 支持 KMS V4.0, V5.0 和 V6.0.

服务端的 RPC, KMS 报文和协议专用密码算法均使用 Rust 实现. SHA-256 和 HMAC 使用 RustCrypto. 程序不链接或调用 C 版本的 vlmcsd. 第三方依赖内部使用 FFI 不受此限制.

## 本地运行

需要 Cargo 和 Rust 1.96.0. 使用 rustup 时, 项目内的工具链配置会选择对应版本.

```sh
cargo build --release --locked
./target/release/vlmcsd-rs --config ./vlmcsd.toml
```

省略 `--config` 时读取当前目录的 `vlmcsd.toml`. 文件不存在, 无法读取或内容无效时, 程序报错并退出. 支持 `--help` 和 `--version`.

程序在前台运行. 启动日志, 连接错误和激活过滤结果写入标准输出或标准错误. 激活日志包含解析后的主机名, TCP 来源 IP 和允许/拒绝结果. 使用 Ctrl-C 停止进程.

## 配置

配置在启动时读取, 修改后需要重启. 可省略字段以使用内置默认值, 未知字段会报错. 示例文件默认关闭白名单过滤; 需要过滤时, 填写主机名和 IP 规则并设置 `whitelist.enable = true`.

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `listen` | `"0.0.0.0:1688"` | 单个监听地址和 TCP 端口, IPv6 示例为 `"[::]:1688"` |
| `hwid` | `"3A1C049600B60076"` | V6 响应中的 8 字节硬件标识, 必须是 16 个十六进制字符 |
| `activation_interval_minutes` | `120` | 激活失败后的重试间隔, 单位为分钟 |
| `renewal_interval_minutes` | `10080` | 激活续期间隔, 单位为分钟 |
| `[epids]` | 上游内置 ePID | 按产品组配置服务器标识 |
| `whitelist.enable` | `false` | 仅设置为 `true` 时启用白名单过滤 |
| `whitelist.hostnames` | `[]` | 主机名正则白名单 |
| `whitelist.ips` | `[]` | TCP 来源 IP 正则白名单 |

两个时间间隔均为正的 32 位无符号整数. ePID 必须包含 1 到 63 个 UTF-16 编码单元, 且不能包含 NUL. ePID 在运行期间保持固定, 不自动随机生成.

`[epids]` 支持 `windows`, `win_china_gov`, `office2010`, `office2013`, `office2016` 和 `office2019`. 根据请求中的 KMS ID 选择产品组. 与参考实现相同, 未知 KMS ID 使用 `windows` 组, 不依据产品名称或 SKU 拒绝请求.

例如, 仅允许从本机连接且上报主机名为 `pc-01.example.local` 的客户端, 其余响应参数使用默认值:

```toml
listen = "127.0.0.1:1688"
hwid = "0123456789ABCDEF"

[whitelist]
enable = true
hostnames = ['(?i)^pc-01\.example\.local$']
ips = ['^127\.0\.0\.1$']
```

## 正则白名单

只有 `enable = true` 时才执行白名单过滤. 省略 `enable` 或设为 `false` 时跳过过滤, 即使配置了不匹配的规则也不会据此拒绝激活.

启用后, 主机名和 IP 两项都必须匹配各自名单中的至少一个正则, 才会生成激活响应. 任意一类名单为空或缺失时拒绝激活. 若只需要限制一项, 显式将另一项配置为 `['.*']`.

```toml
[whitelist]
enable = true
hostnames = ['(?i)^pc-[0-9]+\.example\.local$', '^BUILD-SERVER$']
ips = ['^192\.168\.10\.[0-9]{1,3}$', '^127\.0\.0\.1$', '^::1$']
```

- 使用 Rust [regex](https://docs.rs/regex/) 语法. 默认区分大小写, `(?i)` 可启用忽略大小写. 正则默认允许局部匹配, 使用 `^` 和 `$` 限定完整字符串. TOML 单引号字符串保留反斜杠, 适合填写正则.
- 正则在加载配置时编译和校验, 无论是否启用过滤, 非法表达式都会作为配置错误阻止启动.
- 主机名从 V4/V5/V6 请求的 `WorkstationName` 字段按 UTF-16LE 解析, 截止到第一个 NUL. 非法 UTF-16 返回无效数据错误.
- IP 来自实际 TCP 连接, 不包含端口或方括号, 不执行 DNS 查询. IPv6 使用标准压缩表示, IPv4 映射地址如 `::ffff:192.0.2.10` 按 `192.0.2.10` 匹配.
- 启用过滤时, 每次激活请求都会重新检查, 包括复用同一 TCP 连接的请求. 不匹配时返回 `0x80070005` ([E_ACCESSDENIED](https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values)), 不返回激活数据.

主机名由客户端自行上报, 不属于经过验证的身份. IP 是服务端实际看到的连接地址, 经 NAT 或容器端口转发时可能与客户端本地地址不同; 可根据激活日志中的 IP 配置规则.

## Docker

Dockerfile 使用 Rust 1.96 Alpine 构建静态程序, 最终镜像基于 scratch, 以 UID/GID `65532:65532` 运行.

```sh
docker compose up -d --build
docker compose logs -f
docker compose down
```

Compose 发布 TCP 1688, 将宿主机的 `vlmcsd.toml` 只读挂载到 `/etc/vlmcsd-rs/vlmcsd.toml`, 并设置 `restart: unless-stopped`. 修改配置后执行 `docker compose restart`. 容器内的 `listen` 应使用 `0.0.0.0:1688`, 以便通过端口映射访问. 如需更换宿主机端口, 修改 Compose 的 `ports`.

也可以直接构建并运行镜像:

```sh
docker build -t vlmcsd-rs .
docker run --rm -p 1688:1688 \
  --mount type=bind,src="$(pwd)/vlmcsd.toml",dst=/etc/vlmcsd-rs/vlmcsd.toml,readonly \
  vlmcsd-rs
```

## 协议范围

- 支持 DCE/RPC Bind, AlterContext, NDR32, NDR64 和 BTFN 协商. Bind/AlterContext 可携带 `PFC_SUPPORT_HEADER_SIGN` 能力声明, 响应会清除此位.
- 支持同一连接上的多次激活请求, TCP 分段和连续报文. 不支持 RPC 分片重组或 RPC 身份验证.
- 每个连接由独立线程处理, 读写超时为 30 秒. 接入阶段的连接重置不会终止服务; 接入错误会记录日志并退避 100 毫秒重试, 文件描述符资源释放后可恢复接入.
- 采用无状态模拟计数: 返回 `max(1, 2 * N_Policy)`, 其中 `N_Policy` 是客户端要求的最低数量. 超过 1000 的请求门槛返回无效数据错误.
- 回显客户端标识和客户端时间. 不维护客户端列表, 不检查客户端与服务器的时间差, 不需要数据库或持久化目录.
- 不包含激活客户端, 系统服务安装器或自动发现功能.

协议覆盖不等同于每个 Windows/Office 版本都经过实机验证. 自动验收使用上游 vlmcs 的协议检查功能.

## 检查与测试

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --release --locked
docker compose config --quiet
```

密码和 KMS 单元测试使用上游生成的固定报文验证 V4/V5/V6 响应, 无需 C 编译器或上游源码. 来源和生成参数见 [测试向量说明](tests/fixtures/README.md). 网络集成测试启动本项目二进制并使用临时端口, 覆盖 RPC 协商, NDR64 非零对齐填充, AlterContext 保留分片上限, 连接复用, 错误隔离, 配置覆盖和三个版本的白名单过滤. Linux 上还会验证排队连接的 TCP 重置, 以及仅降低测试服务子进程文件描述符上限后的服务存活和恢复.

如已安装上游 vlmcs, 先允许主机名 `pc-01.example.local` 和实际来源 IP, 再进行独立互通检查:

```sh
for version in 4 5 6; do
  for ndr64 in 0 1; do
    vlmcs "-$version" "-N$ndr64" -n2 -w pc-01.example.local -v 127.0.0.1:1688
  done
done
```

检查输出中是否存在 `ERROR`, `WARNING` 或 `Fatal`, 而非仅检查客户端退出码. 上游客户端仅作为独立测试工具, 不属于项目依赖.
