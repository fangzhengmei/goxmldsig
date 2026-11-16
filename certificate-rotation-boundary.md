# 固定可信证书集合在 SSO 轮换下的匹配语义与边界分析

仓库：`github.com/russellhaering/goxmldsig`（分支 task/104，HEAD `10e2e65`）
分析日期：2026-11-16
配套探针：`rotation_probe_test.go`（本地生成的证书样本，可用 `go test -run TestRotationProbe -v .` 复现）

---

## 1. 源码证据：证书匹配的实际语义

### 1.1 验证入口与信任模型

`ValidationContext.Validate`（validate.go:568）的流程是：

1. `findSignature` 定位引用顶层元素的 `Signature`（validate.go:404–506）；
2. `verifyCertificate` 从签名与 `CertificateStore` 中选出**一张**可信证书（validate.go:508–564）；
3. `validateSignature` 用该证书验签并校验摘要（validate.go:257–373）。

信任锚由 `X509CertificateStore.Certificates()` 提供（keystore.go:19–21），`MemoryX509CertificateStore` 只是原样返回 `Roots` 切片（keystore.go:23–29）。**没有任何链式构建、CRL/OCSP、KeyUsage/ExtendedKeyUsage 检查**（validate.go 全文无 `Verify(`、`KeyUsage` 调用）。

### 1.2 `verifyCertificate` 的四条匹配规则（validate.go:508–564）

```go
// 规则一：KeyInfo 存在时，只取第一张 X509Certificate（validate.go:518–533）
if len(sig.KeyInfo.X509Data.X509Certificates) == 0 || ... [0].Data == "" {
    return nil, errors.New("missing X509Certificate within KeyInfo")
}
// 规则二：KeyInfo 缺省时，仅当 roots 恰好一张才回退使用它（validate.go:534–541）
if len(roots) == 1 { untrustedCert = roots[0] } else { return nil, errors.New("Missing x509 Element") }
// 规则三：逐字节相等匹配（validate.go:543–552）
for i, root := range roots { if root.Equal(untrustedCert) { rootIdx = i } }
if rootIdx == -1 { return nil, errors.New("Could not verify certificate against trusted certs") }
// 规则四：有效期检查（含端点），时钟来自 ctx.Clock（validate.go:559–561）
if now.Before(trustedCert.NotBefore) || now.After(trustedCert.NotAfter) {
    return nil, errors.New("Cert is not valid at this time")
}
```

要点：

- **`x509.Certificate.Equal` 是 DER 字节相等**，不是主体相等、不是公钥相等、不是 SKI 相等。同主体不同公钥、甚至同公钥但序列号/有效期不同的续期证书，都视为不同证书。
- **KeyInfo 只是"选择器"**：匹配成功后用于验签的是 `roots[rootIdx]`（信任库中的副本，validate.go:555），不是 KeyInfo 里的证书。攻击者无法通过 KeyInfo 注入信任库之外的公钥——这是该模型最重要的安全性质。
- **有效期检查含端点**：`now == NotBefore` 与 `now == NotAfter` 都判为有效（`Before`/`After` 均为严格不等）。
- **时钟可注入**：`ctx.Clock` 为 nil 时退化为真实系统时钟（clock.go:19–25）；测试用 `NewFakeClockAt`（validate_test.go:252）。
- 验签算法由签名文档里的 `SignatureMethod` 决定，映射到 `x509.SignatureAlgorithm` 后调 `cert.CheckSignature`（validate.go:271–289），不检查证书自身的签名算法强度。

### 1.3 与通用 PKI 链验证的区别

| 维度 | 通用 PKI（如 `x509.Certificate.Verify`） | 本库（固定可信集合） |
|---|---|---|
| 信任锚语义 | 根 CA，可签发任意下级 | 逐字节固定的**终端证书本身**（`Roots` 命名有误导性） |
| 链构建 | 有（中间证书、AIA 等） | 无；KeyInfo 中第二张及以后的证书被忽略（validate.go:520 只取 `[0]`） |
| 身份匹配 | 主体名/SAN/DNS 名 | 不涉及；DER 全等即身份 |
| 吊销 | CRL/OCSP | 无；等效手段是**从 `Roots` 中删除** |
| 有效期 | 链上每张都查 | 只查匹配到的那一张，且含端点 |
| 密钥轮换 | 新证由同一 CA 签发即自动受信 | **不会**自动受信；必须把新证 DER 加入 `Roots` |
| 续期（同密钥新证） | 通常仍可信 | **误拒**：DER 不同即不匹配（见 §2 D1） |

结论：这是一个"证书钉扎（pinning）+ 有效期"模型，不是 PKI。轮换的全部负担在**信任库的运营**上。

---

## 2. 观察：本地证书样本探针结果

探针（`rotation_probe_test.go`）生成以下自签样本（RSA-2048）：

- `old`：CN=sso.example.com，密钥 K1，有效期 `[T0, T0+90d]`
- `new`：CN=sso.example.com（**同主体**），密钥 K2，有效期 `[T0+60d, T0+150d]`——与 old 重叠 30 天，模拟轮换窗口
- `renew`：CN=sso.example.com，**同密钥 K1**，序列号/有效期不同（`[T0+80d, T0+170d]`），模拟同密钥续期
- `rogue`：CN=sso.example.com，攻击者密钥 K3，不在信任库
- `CA`/`leaf`：CA 签发叶子，检验是否存在隐式链信任

签名文档由本库 `SigningContext.SignEnveloped` 生成（签名后重序列化再解析，原因见 §3.1），验证时钟用 `NewFakeClockAt` 固定。

### 2.1 轮换时间线（KeyInfo 齐全）

| 用例 | 时刻 | 信任库 | 文档签名证 | 结果 | 解读 |
|---|---|---|---|---|---|
| A1 | T0+30d | {old} | old | ✅ | 稳态 |
| A2 | T0+30d | {old,new} | old | ✅ | **预发布新证不影响旧证**——安全的第一步 |
| A3 | T0+30d | {old,new} | new | ❌ `Cert is not valid at this time` | 新证 NotBefore 未到，即使已入库也不能用 |
| A4 | T0+75d | {old,new} | old | ✅ | 重叠窗口内旧证继续可用 |
| A5 | T0+75d | {old,new} | new | ✅ | 重叠窗口内新证可用——**切换点** |
| A6 | T0+75d | {old} | new | ❌ `Could not verify certificate against trusted certs` | 未先入新证就切换 IdP → 误拒 |
| A7 | T0+100d | {old,new} | old | ❌ `Cert is not valid at this time` | 旧证过期后即使仍在库、签名密码学有效也拒绝 |
| A8 | T0+100d | {new} | new | ✅ | 轮换完成态 |

### 2.2 有效期边界（含端点）

| 用例 | 时刻 | 结果 |
|---|---|---|
| B1 | `t == NotBefore` | ✅ 有效 |
| B2 | `t == NotBefore − 1s` | ❌ `Cert is not valid at this time` |
| B3 | `t == NotAfter` | ✅ 有效 |
| B4 | `t == NotAfter + 1s` | ❌ `Cert is not valid at this time` |

### 2.3 缺省 KeyInfo

| 用例 | 信任库 | 结果 |
|---|---|---|
| C1 | {old}（单根） | ✅ 回退用唯一根验签 |
| C2 | {old,new}（多根） | ❌ `Missing x509 Element` |

**轮换窗口内信任库必然 ≥2 张，此时缺省 KeyInfo 的文档一律被拒**——轮换期 IdP 必须带 KeyInfo（本库签名器总是带，sign.go:277–282）。

### 2.4 同密钥续期 / 同主体异钥 / CA 误用

| 用例 | 场景 | 结果 | 判据含义 |
|---|---|---|---|
| D1 | 库{old}，文档内嵌同密钥续期证 renew | ❌ `Could not verify certificate against trusted certs` | **误拒判据**：`Equal` 逐字节，同密钥续期也必须重新分发证书 |
| D2 | 库{old,renew} | ✅ | 续期证入库后恢复 |
| D3 | 库{old}，同主体异钥 rogue | ❌ 同上 | **不存在按主体的信任扩大**——主体名不参与匹配 |
| D4 | 库{CA}，文档内嵌 CA 签发的 leaf | ❌ 同上 | **不存在链式信任扩大**——`Roots` 里放 CA 不会信托其签发的证书 |

另测得 `certOld.Equal(certRenew) == false`、`certOld.Equal(certNew) == false`，从 Go 语义上确认 D1/D3 的根因。

### 2.5 轮换窗口配置建议（由上述判据推出）

设旧证有效期 `[B₀, E₀]`，计划切换时刻为 S：

1. **签发新证**：令 `NotBefore_new ≤ S`（建议 `NotBefore_new = S − Δ`，Δ 为时钟偏差余量；注意 B1/B2 的含端点语义，整秒边界无灰色地带）。
2. **预发布（S 之前）**：把新证 DER 追加进 SP 信任库，旧证保留（A2 证明无害；A3 证明新证未到 NotBefore 不会被误用）。
3. **切换（S）**：IdP 改用新密钥签名。重叠窗口 `[max(B₀, NotBefore_new), E₀]` 内双证均可验证（A4/A5）。
4. **收尾（> E₀）**：旧证过期后验证自动失败（A7），此时可从库中移除旧证；移除本身即"吊销"等效操作。

**信任扩大的判据（本模型下全部为"无"）**：主体相同不扩大（D3）、同一 CA 签发不扩大（D4）、同密钥续期不扩大（D1）。唯一扩大途径是运营方显式把证书 DER 加进 `Roots`；KeyInfo 无法注入信任（§1.2，验签用库中副本）。

**误拒的判据**：① 信任库缺少文档 KeyInfo 首张证书的逐字节拷贝（A6、D1）；② `now ∉ [NotBefore, NotAfter]`（A3、A7、B2、B4），含 IdP 用过期证书继续签名、SP 时钟漂移、以及 `ctx.Clock` 未设置时默认真实时钟与测试期望不符；③ 多根信任库 + 缺省 KeyInfo（C2）。

---

## 3. 缺口与风险

### 3.1 `SignEnveloped` 产物的内存形态无法通过自身验证（签名↔验证往返缺陷）

- `SignEnveloped` 直接 `ret.Child = append(ret.Child, sig)`（sign.go:299–301），绕过 etree 的 `AddChild`，`sig` 的 `parent`/`index` 字段保持零值。
- etree v1.7.0 的 `Element.dup` **原样拷贝 `index`**（etree.go:1340），`RemoveChild` 信任 `t.Index()`（etree.go:861–866）。
- 于是 `Validate` → `transform` → `removeElementAtPath`（validate.go:82–102）在移除 enveloped 签名时按陈旧索引 0 删除了**错误的兄弟节点**（探针中 `<child>` 被删、`<ds:Signature>` 保留），摘要必然不匹配，报 `Signature could not be verified`。
- 实证：同一签名文档，内存直接 `Validate` 失败；**重序列化再解析后** `Validate` 成功（解析器会重建索引）。现有测试全部从字符串解析文档，因此从未覆盖这条内存往返路径。
- 影响：任何"签名后立即在同进程验证"的用法（自检、测试、代理）会得到假阴性。修复方向：`SignEnveloped` 改用 `ret.AddChild(sig)`，或 `removeElementAtPath` 改用 `RemoveChildAt(path[0])`。

### 3.2 其他缺口

- **KeyInfo 多证书只取第一张**（validate.go:520）：IdP 在 KeyInfo 中同时携带新旧两证（部分产品的轮换做法）时，若第一张恰好是未入库的那张，即使第二张在库中也会误拒。
- **缺省 KeyInfo 的报错误导**：多根时报 `Missing x509 Element`（validate.go:539），实际问题不是文档缺元素而是无法消歧。
- **`contains()` 是死代码**（validate.go:375–382）：与 `verifyCertificate` 内联的 Equal 循环重复，无调用方。
- **无吊销语义**：证书泄露后唯一手段是改信任库并全量发布；库本身无版本/生效时间元数据。
- **有效期含端点 + 秒级精度**：`NotAfter` 当秒签发的断言仍有效，依赖时钟同步；`ctx.Clock` 为 nil 时静默使用真实时钟（clock.go:19–25），多实例部署时各节点时钟偏差会直接转化为 §2.5 中 Δ 的取值要求。
- **有效期检查作用于库中副本而非 KeyInfo 副本**：两者 DER 相等故当前等价，但这是隐式假设；若未来改为指纹匹配则会行为漂移。
