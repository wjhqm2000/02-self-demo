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
│  用途: RSA-PSS-SHA256 签名                                    │
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

## Payload 结构

```json
{
  "version": 1,
  "algorithm": "RSA-PSS-SHA256",
  "payload": {
    "app_id": "self-demo",
    "hw_fingerprint": "<sha256(原始指纹) hex — 脱敏，非明文>",
    "customer_id": "<sha256(订单号) hex — 脱敏，非明文>",
    "tier": "pro",
    "issued_at": "2026-10-23T12:00:00Z",
    "expires_at": null,
    "features": { "unlock_all": true },
    "nonce": "<base64url 16 bytes>"
  },
  "signature": "<base64 RSA-PSS signature over canonical_json(payload)>"
}
```

- `expires_at: null` = 永不过期（终身离线）
- `hw_fingerprint` 在签名覆盖范围内 → 绑定硬件，防拷贝
- 文件名 = `sha256(hw_fingerprint)[:16].lic`（防隐私泄露）
- 签名算法：**RSA-PSS + MGF1(SHA256) + salt=MAX_LENGTH + SHA256**
- 签名原文：`canonical_json(payload)` = key-sorted, no-whitespace JSON bytes

## 本地测试（不需要 GitHub，10 分钟跑通）

### 步骤 1: 生成测试密钥对

```bash
cd 02-self-demo
pip install cryptography requests

openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

### 步骤 2: 模拟签名（本地跑 GHA 会跑的那份代码）

```bash
python -m issuer.sign_license \
    --private-key private.pem \
    --hw-fp "DESKTOP-TEST:MAC0011223344:CPUi7" \
    --key "a7f3b92e4c1d8a6f" \
    --customer "order-local-test" \
    --tier pro
```

会生成 `a7f3b92e4c1d8a6f.lic`。

### 步骤 3: 本地验签

```bash
python -m client.verify_license \
    --license a7f3b92e4c1d8a6f.lic \
    --public-key public.pem \
    --app-id self-demo \
    --hw-fp "DESKTOP-TEST:MAC0011223344:CPUi7"
# → OK   : valid license for app 'self-demo'
```

### 步骤 4: 故意破坏，看验签失败

```bash
# 改一下 .lic 里的 signature 字段 → 验签失败
# 改一下 hw_fingerprint → 验签失败
# 改一下 expires_at 为过去日期 → 过期失败
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
    "tier": "pro"
}
```

### 7. 运行激活

```bash
python -m client.trigger_and_fetch
```

预期输出：

```
hw_fingerprint: DESKTOP-XXX-abc123def456
filename key   : abc123def4567890
customer       : order-20261023-001
tier           : pro

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

- `cryptography` — RSA-PSS 签名/验签
- `requests` — GitHub API 调用 + raw URL 下载

## 借鉴来源

| 组件 | 来源项目 |
|------|---------|
| canonical_json + RSA-PSS 签名/验签 | [Arnas-Verify](https://github.com/) |
| envelope 结构 (version/algorithm/payload/signature) | Arnas-Verify |
| 验证顺序（加密优先） | Arnas-Verify + licensing-1.0.0 token-format §7 |
| hw_fingerprint 硬件绑定 | Haptique |
| expires_at=null 永不过期 | tera-pilot |
| raw.githubusercontent.com 免 Token 下载 | Haptique 架构改进 |
| SHA-256 哈希化文件名 | 本次安全修正 |

## 安全限制（坦诚告知）

1. **PAT 可以触发 repository_dispatch 并读公开 raw 文件** — scope 只勾 `public_repo`，泄露也无害
2. **GITHUB_TOKEN 是临时 token** — 用户拿不到，安全
3. **RSA_PRIVATE_KEY 存储在 GitHub Secrets** — 加密，但 GitHub 员工理论上能访问；对于个人开发者 Demo 足够
4. **无撤销机制** — 泄露的 license 直到过期都有效（我们设成永不过期），与 tera-pilot 相同选择
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
