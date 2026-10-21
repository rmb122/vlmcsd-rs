# 上游协议测试向量

这些二进制数据由参考目录 `/tmp/vlmcsd` 的原始 C 实现生成, 不由 Rust 实现生成. 参考仓库提交为 `70e03572b254688b8c3557f898e7ebd765d29ae1`.

| 文件 | 内容 |
| --- | --- |
| `v4-request.bin`, `v4-response.bin` | V4 请求及完整响应, 分别为 252 和 160 字节 |
| `v5-request.bin`, `v5-response.bin` | V5 请求及完整响应, 分别为 260 和 228 字节 |
| `v6-request.bin`, `v6-response.bin` | V6 请求及完整响应, 均为 260 字节 |
| `entropy.bin` | 响应使用的 32 字节随机输入, 前 16 字节用于随机盐, 后 16 字节用于 V6 响应盐 |

生成时在项目外单独编译上游 `kms.c`, `crypto.c`, `crypto_internal.c` 和 `endian.c`, 使用 `IS_LIBRARY=1`, `NO_RANDOM_EPID`, `NO_LOG`, `NO_STRICT_MODES`, 并提供固定的基础响应回调. 调用上游 `CreateRequestV4`/`CreateRequestV6` 和 `CreateResponseV4`/`CreateResponseV6` 得到报文. C 生成器不参与 Cargo 构建或测试.

请求参数:

- 协议版本依次为 4.0, 5.0, 6.0.
- VM 标志为 1, 许可状态为 2, 最低客户端数量为 25.
- Application ID 为 `55c92734-d682-4d71-983e-d6ec3f16059f`.
- Client ID 的线序字节为 `01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10`.
- 客户端 FILETIME 为十进制 `133000000000000000`.
- 工作站名称为 `kms-test.example`, 其他字段为零.

固定回调回显版本, Client ID 和时间, 设置计数为 50, 激活间隔为 120 分钟, 续期间隔为 10080 分钟. ePID 为 `03612-00206-556-123727-03-1033-17763.0000-2972018`. V6 使用上游默认 HWID `3A1C049600B60076`.

在 Linux x86_64/glibc 下, 每次生成请求前执行 `srand(42)`, 每次生成响应前执行 `srand(1234)`. `entropy.bin` 来自 `srand(1234)` 后连续两次 `get16RandomBytes` 的输出. 测试直接使用已保存的随机字节, 不依赖 libc 随机数序列.

上游源文件 SHA-256:

```text
df88f6e13b584f9652bc0bba3ef3e2702170e492b9983d686abdd431477fd598  kms.c
1b91367cda1f682376ffa745d37a2e00bd710e905d36b67315a141ecbb50699e  crypto.c
57780cc735f6cb5300fafc9becb7fb0bb2212061a5768f3f074ab3528279f878  crypto_internal.c
```
