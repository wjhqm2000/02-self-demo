# Self-Demo — 云端授权发证闭环 Demo

> **软件一次联网激活，终身本地离线运行** — 用 GitHub Actions 免费算力做"云端签名机"。

## 安全架构（三层 Token 隔离）

```
┌──────────────────────────────────────────────────────────────┐
│  层次 1: 客户端 ↔ GitHub API                                  │
│  Token: 用户本地配置的 PAT（scope 仅 public_repo）              │
│  用途: repository_dispatch 触发 + 轮询 raw.githubusercontent.com │
│  泄露影响: 只能触发 workflow + 读公开文件，无法访问代码           │
├──────────────────────────────────────────────────────────────┤
│  层次 2: GHA 内部 ↔ Git push                                 │
│  Token: GITHUB_TOKEN（Action 内置，permissions: contents: write） │
│  用途: commit + push 到 license-result 分支                    │
│  泄露影响: 不可能 — 这是临时 token，只在当前 job 内有效          │
├──────────────────────────────────────────────────────────────┤
│  层次 3: GHA 内部签名                                        │
│  Key: Secrets.RSA_PRIVATE_KEY                                 │
│  用途: RSA-2048 PKCS#1 v1.5 + SHA-256 签发 LICB V2            │
│  泄露影响: 签名权落入攻击者手中 → 但 GitHub Secrets 是加密存储的   │
└──────────────────────────────────────────────────────────────┘
```

## 目录结构

```
02-self-demo/
├── .github/
│   └── workflows/
│       └── issue-license.yml     # GHA workflow
├── client/
│   ├── verify_license.py         # 验签逻辑（含 canonical_json 单一真相来源）
│   ├── hardware_fingerprint.py   # 机器指纹采集
│   └── trigger_and_fetch.py      # 客户端两阶段轮询激活流程
├── issuer/
│   └── sign_license.py           # GHA 内运行的签名脚本
└── README.md
```

## 授权文件结构（LICB V2）

签发产物是**二进制**（没有 JSON envelope），格式与 `compressed migration` 的
`license::verify_license_file_v2` 逐字节对齐：

```
"LICB" | uint16 version=2 | uint32 payload_len | uint32 sig_len=256
       | payload(canonical JSON 原始字节) | RSA-2048 PKCS#1 v1.5(SHA-256) 签名
```

payload 字段：`v` / `mid` / `card` / `iat` / `eat` / `perm` / `thr` / `bl`。
`eat` 由卡类型决定（永久卡 `eat=0 & perm=true`，天卡/分钟卡按剩余时间换算），
**不存在"默认终身"分支**。完整字段表、`eat` 规则与字节规格见文末
「卡密通验卡 + LICB V2 按天数签发」一节。

- `mid` 在签名覆盖范围内 → 绑定硬件，防拷贝
- 文件名 = `sha256(mid)[:16].lic`（防隐私泄露）
- 签名算法：**RSA-2048 + PKCS#1 v1.5 + SHA-256**（`padding.PKCS1v15()`）
- 签名原文：`canonical_json(payload)` = key-sorted, no-whitespace JSON bytes

## 本地测试（不需要 GitHub，10 分钟跑通）

### 步骤 1: 生成测试密钥对

```bash
cd 02-self-demo
pip install cryptography requests

openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

### 步骤 2: 准备 client_payload 并签名（本地跑 GHA 会跑的那份代码）

```bash
python -m issuer.sign_license \
    --private-key private.pem \
    --payload-file payload.json \
    --out a7f3b92e4c1d8a6f.lic
```

`payload.json` 示例（字段含义见文末）：

```json
{
  "mid": "<64 位小写 HEX 机器码>",
  "card_type": "day",
  "remaining_days": 15,
  "remaining_minutes": 21600,
  "hw_snapshot": {
    "disk": "0025_38E3_31C4_4AC0.",
    "board": "/32WL5Y3/CNFCW0034O00DD/",
    "mac": "CC96E529566C",
    "cpu": "GenuineIntel_13th Gen Intel(R) Core(TM) i5-13400_2c6f2",
    "uuid": "4C4C4544-0032-5710-804C-B3C04F355933"
  },
  "card_id": "be94202be69c570d",
  "key": "a7f3b92e4c1d8a6f"
}
```

会生成 **LICB V2 二进制** `a7f3b92e4c1d8a6f.lic`（14 字节头 + payload + 256 字节签名）。

### 步骤 3: 本地验签（用 C++ 侧同一实现）

```bash
# public.pem → DER（C++ 侧只读 DER）
python -c "from cryptography.hazmat.primitives import serialization as s; open('public.der','wb').write(s.load_pem_public_key(open('public.pem','rb').read()).public_bytes(s.Encoding.DER, s.PublicFormat.SubjectPublicKeyInfo))"

../compressed\ migration/src/test/test_licb_rsa.exe --verify a7f3b92e4c1d8a6f.lic public.der
# → STATUS=OK ... SCORE=100 PASS=1 RESULT=PASS
```

### 步骤 4: 故意破坏，看验签失败

```bash
# payload 任一字节改动 → STATUS=SIGNATURE_INVALID
# 用 PSS 代替 PKCS#1 v1.5 签名 → STATUS=SIGNATURE_INVALID
# mid 换成别的机器 → STATUS=MID_MISMATCH
# eat 改成过去时间 → STATUS=EXPIRED
```

### 步骤 5: 完整两阶段激活流程（本地模拟）

```bash
# 先获取本机硬件指纹
python -m client.hardware_fingerprint
# → hw_fingerprint: DESKTOP-XXX:abc123def456...
```

（完整两阶段流程需要先配 GitHub，下面讲。）

---

## GitHub 仓库配置（真实部署）

### 1. 创建公开仓库

在 GitHub 上创建一个 **Public** 仓库（比如叫 `license-signer`）。

**为什么必须 Public？**
- `raw.githubusercontent.com` 对 Private 仓库需要 Token，客户端拿不到
- 仓库里只有 workflow + 公钥，无商业代码 → Public 无风险

### 2. 生成生产密钥对

```bash
# 本地机器上执行
openssl genrsa -out private_prod.pem 2048
openssl rsa -in private_prod.pem -pubout -out public_prod.pem

# ⚠️ 把 private_prod.pem 安全保存！不要提交到 git，不要上传任何地方！
```

### 3. 配置仓库 Secret

仓库 → Settings → Secrets and variables → Actions → **New repository secret**:

| Name | Value |
|------|-------|
| `RSA_PRIVATE_KEY` | 粘贴 `private_prod.pem` 的**完整内容**（包括 `-----BEGIN RSA PRIVATE KEY-----` 头尾） |
| `DEMO_HMAC_SECRET` | 一个随机字符串（轻量防刷密钥），例如 `openssl rand -hex 32` 的输出 |

> **同步要求**：`DEMO_HMAC_SECRET` 必须和 [trigger_and_fetch.py](client/trigger_and_fetch.py) 里硬编码的 `DEMO_HMAC_SECRET` 常量**完全一致**，否则 GHA 会拒绝签名（HMAC 校验失败）。部署前请把代码里的默认值 `change-me-self-demo-hmac-v1` 改成你的随机值。

### 4. 推送代码

把 `02-self-demo/` 整个目录推到 GitHub 仓库的 main 分支：

```bash
cd 02-self-demo
git init
git add -A
git commit -m "feat: license signer demo"
git branch -M main
git remote add origin https://github.com/{你的用户名}/{仓库名}.git
git push -u origin main
```

GitHub 会自动识别 `.github/workflows/issue-license.yml`。

### 5. 生成客户端 PAT（scope 仅 public_repo）

GitHub → Settings → Developer settings → **Personal access tokens** → **Tokens (classic)** → Generate new token:

- **Note**: 写 `self-demo license trigger`
- **Expiration**: 选 90 天或自定义
- **Select scopes**: 只勾 **`public_repo`**（一个 scope 足够，不能多勾）

生成后**立刻拷贝保存** — 只会显示一次。

### 6. 客户端本地 config.json

```bash
mkdir -p ~/.self-demo
```

在 `~/.self-demo/config.json` 里填入（**不要提交这个文件到 git**）：

```json
{
    "github_pat": "ghp_xxxxxxxxxxxxxxxxxxxx",
    "repo_owner": "你的GitHub用户名",
    "repo_name": "license-signer",
    "public_key_path": "C:/Users/你/路径到public_prod.pem",
    "customer_id": "order-20261023-001",
    "tier": "pro",
    "card_code": "你的卡密"
}
```

### 7. 运行激活

```bash
python -m client.trigger_and_fetch
```

预期输出：

```
device mid     : <64 位 HEX>
filename key   : abc123def4567890
hw snapshot    : {"board":...,"cpu":...,"disk":...,"mac":...,"uuid":...}
customer       : order-20261023-001
tier           : pro

[step 2] 卡密通验卡...
  验卡通过 ✓  card_type=day  剩余 15 天
  remaining_days=15 remaining_minutes=21600
[phase 1] triggering GitHub Actions workflow...
  dispatch accepted by GitHub. Polling run status...
  phase 1: waiting for GHA run #123456789 to finish (timeout 180s)...
    run status=queued, conclusion=None
    run status=in_progress, conclusion=None
    run status=completed, conclusion=success
  GHA run succeeded ✓

[phase 2] fetching .lic file from raw.githubusercontent.com...
  phase 2: waiting for .lic file at raw URL (timeout 60s)...
    HTTP 404 — file not yet propagated, retrying...
    .lic file fetched (HTTP 200, 1.2 KB bytes)

[phase 3] verifying signature + persisting license...
  verified ✓ — saved to C:\Users\你\.self-demo\license.lic

Activation complete.  This machine is now licensed for lifetime offline use.
```

激活成功后，每次软件启动时：

```bash
python -m client.verify_license --public-key public_prod.pem
# → OK   : valid license for app 'self-demo'
```

## 关键设计细节

| 细节 | 实现 |
|------|------|
| **Git push 并发冲突** | workflow 里是 retry 循环：fetch + rebase + push，3 次重试，每次间隔 5 秒 |
| **raw.githubusercontent.com CDN 缓存** | 每次请求加 `?t={int(time.time())}` 防缓存 |
| **两阶段轮询** | 先等 GHA run conclusion == success（180s），再轮询 raw URL（60s）吸收 CDN 延迟 |
| **文件名哈希化** | `sha256(hw_fingerprint)[:16].hex()` — 防隐私泄露，同一机器重复激活幂等覆盖 |
| **canonical_json 单一真相来源** | sign_license.py 从 client.verify_license import，两边绝对不 copy |
| **时钟容差放宽** | ISSUED_AT_LEEWAY = 10 分钟（Arnas-Verify 原 5 分钟） |
| **签名覆盖范围** | 只签 payload，不签 version/algorithm/signature 自身 |
| **验证顺序** | 先验签 → 后验业务（加密优先） |

## 依赖

```bash
pip install cryptography requests
```

- `cryptography` — RSA-2048 PKCS#1 v1.5 签名/验签
- `requests` — GitHub API 调用 + raw URL 下载

## 借鉴来源

| 组件 | 来源项目 |
|------|---------|
| canonical_json + RSA 签名/验签 | [Arnas-Verify](https://github.com/) + compressed migration |
| LICB V2 二进制容器 + PKCS#1 v1.5 验签 | compressed migration（DELIVERABLE §15） |
| 验证顺序（加密优先） | Arnas-Verify + licensing-1.0.0 token-format §7 |
| mid / bl 硬件绑定 + 硬件评分 | compressed migration（fingerprint / license_score） |
| `eat=0 + perm=true` 永久表示 | compressed migration（LICB payload 字段表） |
| raw.githubusercontent.com 免 Token 下载 | Haptique 架构改进 |
| SHA-256 哈希化文件名 | 本次安全修正 |

## 安全限制（坦诚告知）

1. **PAT 可以触发 repository_dispatch 并读公开 raw 文件** — scope 只勾 `public_repo`，泄露也无害
2. **GITHUB_TOKEN 是临时 token** — 用户拿不到，安全
3. **RSA_PRIVATE_KEY 存储在 GitHub Secrets** — 加密，但 GitHub 员工理论上能访问；对于个人开发者 Demo 足够
4. **无撤销机制** — 泄露的 license 在有效期内都有效（永久卡无到期日），与 tera-pilot 相同选择
5. **客户端本地时钟被篡改** — 过期检查绕过风险（同所有离线授权方案）
6. **客户端二进制被反编译替换验签逻辑** — 签名保护不能完全防逆向

## 故障排查

**Issue: `signature verification failed`**
- 检查 sign_license.py 和 verify_license.py 用的是同一个 canonical_json
- 检查签名原文 vs 验签原文的字节一致性（可以加 `print(canonical_json(payload))` 对比）
- 最常见原因：Python 版本差异导致的 json.dumps 行为不同 → 确保都是 Python 3.11+

**Issue: GHA run 里 `NO .lic FILE FOUND`**
- 检查 RSA_PRIVATE_KEY Secret 是否正确配置
- 检查 CLIENT_PAYLOAD 环境变量注入（在 workflow 里 echo 看原始 JSON）

**Issue: raw URL 长时间 404**
- 检查 workflow 的 Git push 步骤是否成功
- GitHub CDN 全球传播最长 5 分钟 → 多等一会儿
- 或者手动打开 URL 看 GitHub 返回什么

**Issue: GHA Git push 多次重试失败**
- 看 push 步骤的详细日志
- 如果是 rebase conflict，检查 license-result 分支历史

---

## 卡密通验卡 + LICB V2 按天数签发（2026-10-24 增量）

上面「授权文件结构（LICB V2）」之前的历史版本（JSON envelope + PSS）**已废弃**：
现在签发产物是 C++ 客户端可直接验证的 **LICB V2 二进制**，签名算法改为
**RSA-2048 PKCS#1 v1.5 + SHA-256**（`padding.PKCS1v15()`，不再用 PSS）。

### 新产品流程

```
config.json(card_code + 本机硬件)
  → 采集 5 项硬件快照 → mid
  → 卡密通验卡（GET check.php，MD5 响应签名 + 120s 时间戳容差）
       ↓ 失败：打印原因并中止，绝不触发 GitHub（fail-closed）
  → repository_dispatch 上送 client_payload（含 HMAC auth）
  → GHA 校验 HMAC → 按 card_type 计算 eat → 签 LICB V2
  → callback 拉取 .lic（二进制）→ 客户端本地验签 → 原样落盘
```

### config.json 新增必填项

```json
{
    "github_pat": "ghp_xxxxxxxxxxxxxxxxxxxx",
    "repo_owner": "你的GitHub用户名",
    "repo_name": "license-signer",
    "public_key_path": "C:/Users/你/路径到public_prod.der",
    "customer_id": "order-20261023-001",
    "tier": "pro",
    "card_code": "你的卡密"
}
```

| 键 | 说明 |
|---|---|
| `card_code` | **必填**。卡密通卡密，仅用于本地验卡；不会原样上送 GitHub（上送的是 `sha256(card_code)[:16]`） |
| `public_key_path` | 建议改成 DER 格式（`.der`），与 C++ 侧 `verify_license_file_v2` 同源；PEM 也兼容 |

### client_payload 字段（客户端 → GHA）

| 字段 | 类型 | 说明 |
|---|---|---|
| `mid` | string | 64 位小写 HEX 机器码 = `sha256("D:...|B:...|M:...|C:...|U:...")` |
| `card_type` | string | `permanent` / `day` / `minute` / `bypass` |
| `remaining_days` | int | 天卡剩余天数（`card_type=day` 时必须为正整数） |
| `remaining_minutes` | int | 剩余总分钟（`card_type=minute` 时必须为正整数） |
| `hw_snapshot` | object | `{disk, board, mac, cpu, uuid}`，缺失值为 `"NAN"`，与 C++ 基线同格式 |
| `card_id` | string | `sha256(card_code)[:16]`，写入 V2 payload 的 `card` 字段 |
| `key` | string | `sha256(mid)[:16]`，作为 `.lic` 文件名 |
| `customer_id` / `tier` | string | 仅用于日志与运营记录，不进入 V2 payload |
| `auth` | string | `HMAC-SHA256(DEMO_HMAC_SECRET, canonical_json(除 auth 外全部字段))` |

`auth` 覆盖**全部业务字段**（旧版只覆盖 4 个字段），任何字段被改都会导致 GHA 拒签。

### eat 计算规则（服务端，无任何写死天数）

| card_type | eat | perm |
|---|---|---|
| `permanent` | `0` | `true` |
| `day` | `iat + remaining_days * 86400` | `false` |
| `minute` | `iat + remaining_minutes * 60` | `false` |
| `bypass` | `iat + 3 * 86400`（宽限） | `false` |

`sign_license.py` 对 payload 做严格 schema 校验：`card_type` 必须是上述四值之一，
`day` 必须带正整数 `remaining_days`，`minute` 必须带正整数 `remaining_minutes`，
`hw_snapshot` 必须恰好包含 5 个非空字符串字段。**缺字段或类型不符直接拒签，
绝不默认按终身处理。**

### LICB V2 二进制格式（与 C++ 侧约定，小端）

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0x0000 | 4 | MAGIC `"LICB"` |
| 0x0004 | 2 | VERSION = `2` (uint16) |
| 0x0006 | 4 | PAYLOAD_LENGTH = N (uint32) |
| 0x000A | 4 | SIG_LENGTH = 256 (uint32) |
| 0x000E | N | payload = `canonical_json(...)` 原始字节 |
| 0x000E+N | 256 | RSA-2048 PKCS#1 v1.5 + SHA-256 原始签名 |

payload JSON 字段：`v`(=2) / `mid` / `card` / `iat` / `eat` / `perm` / `thr`(=50) / `bl`。
payload 内不允许出现数组（C++ `mini_json` 不支持）。客户端拿到文件后**只验签、
不重序列化**，因此签发侧的 canonical 序列化必须与
[verify_license.py](client/verify_license.py) 的 `canonical_json`
（key 排序 + 紧凑分隔符 + UTF-8）逐字节一致。

> `verify_license.py` 的 `canonical_json` 是唯一序列化真相，签发侧
> `sign_license.py` 直接 import，**两边不允许各写一份**。

### 本地造证（跨项目闭环测试）

```bash
python -m issuer.sign_license \
    --private-key ../compressed\ migration/src/test/keys/test_only_private_1.pem \
    --payload-file payload.json \
    --out out.lic

# 用 C++ 侧验签（上一阶段产出的测试程序）
../compressed\ migration/src/test/test_licb_rsa.exe --verify out.lic \
    ../compressed\ migration/src/test/keys/test_only_public_1.der
# → STATUS=OK ... SCORE=100 PASS=1 RESULT=PASS
```

