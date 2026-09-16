# AIGC 元数据隐式标识实现规范

> 落地 GB 45438—2025 所需的确切字段名、各容器写入位置、以及实测验证结论。
> 本文是 [`research-2026-09.md`](./research-2026-09.md) §7 待核实项第 1 条的结案。
>
> 技术内容引自全国网络安全标准化技术委员会秘书处发布的 6 项网络安全标准实践指南。
> **来源：全国网络安全标准化技术委员会秘书处。** 指南 PDF 声明"未经秘书处书面授权，
> 不得以任何方式抄袭、翻译"，故本仓库**不收录 PDF 原文**，仅记录实现所必需的技术要点。
> 原文获取方式见 §6。

---

## 1. 结论摘要

| 问题 | 结论 | 依据 |
|---|---|---|
| 字段名是什么 | `Label` `ContentProducer` `ProduceID` `ReservedCode1` `ContentPropagator` `PropagateID` `ReservedCode2` | TC260-PG-20257A 等，**一手** |
| 载荷格式 | 单个 JSON 字符串，7 个键，顺序如上 | 同上，**一手** |
| 是否要 Base64 | **不要**。6 份指南全文无任何针对该字段值的 Base64 要求 | 全文检索，**实测** |
| MP4 写在哪 | `moov.udta.meta`，key 进 `.keys`、value 进 `.ilst` | TC260-PG-20257A §6.1.1，**一手 + 实测落位一致** |
| 标准给的 ffmpeg 命令能用吗 | 能，但**漏掉 `-movflags use_metadata_tags` 会静默丢标识** | **实测** |

---

## 2. 字段定义

七个字段，构成一个 JSON 字符串：

```json
{"Label":"value1","ContentProducer":"value2","ProduceID":"value3","ReservedCode1":"value4","ContentPropagator":"value5","PropagateID":"value6","ReservedCode2":"value7"}
```

| 字段 | 必选 | 含义 | 由谁填 |
|---|---|---|---|
| `Label` | 必选 | 标识内容是否为 AI 生成合成，取值示例 `"1"` | 生成方 |
| `ContentProducer` | 必选 | AI 生产方的业务标识 | 生成方 |
| `ProduceID` | 必选 | AI 生产方的文件标识 | 生成方 |
| `ReservedCode1` | 可选 | 生成方提供的防篡改标识 | 生成方 |
| `ContentPropagator` | 可选 | AI 传播方的业务标识 | 传播平台 |
| `PropagateID` | 可选 | AI 传播方的文件标识 | 传播平台 |
| `ReservedCode2` | 可选 | 传播方提供的防篡改标识 | 传播平台 |

> **字段名与 JSON 结构来自 TC260 实践指南原文（一手）。**
> **必选/可选划分与语义描述来自腾讯云数据万象官方文档**（厂商官方，但非标准原文）——
> 实践指南正文只写 `value1`…`value7` 占位符，把字符串定义指向 GB 45438—2025 附录 E b)，
> 而国标全文需另行获取（见 §7 未决项）。

### 2.1 关于 Base64：一个会写错的坑

腾讯云文档写"所有字段值必须经过 URL 安全的 Base64 编码"。**这条不能照抄。**

腾讯的接口是 HTTP 头传参：

```
Pic-Operations: imageMogr2/AIGCMetadata/Label/<Label>/ContentProducer/<ContentProducer>/...
```

参数在**以斜杠分隔的 URL 路径里**，值不编码就会破坏路径结构——所以 Base64 是**它那个接口的传输层要求**，不是落盘格式，也不是标准要求。

已对 6 份实践指南全文检索 `Base64` / `编码方式` / `UTF-8`：**唯一命中在第 5 份（安全防护技术指南）里，讲的是 X.509 证书的 DER 编码，与本字段无关。**

**结论：写入文件的是明文 JSON 字符串。**

---

## 3. 各容器写入位置

### 3.1 视频（TC260-PG-20257A）

| 容器 | 存储位置 | 写入方式 |
|---|---|---|
| **MP4 / MOV**（BMFF） | `moov.udta.meta` | key `AIGC` 写入 `moov.udta.meta.keys`；JSON 串写入 `moov.udta.meta.ilst` |
| **FLV** | `script.onMetaData` | 在 `onMetaData` 中写入键 `"AIGC"` 及 JSON 串 |
| **MKV / WebM**（Matroska） | `root.Segment.Tags.Tag.SimpleTag` | `TagName` = `AIGC`；`TagString` = JSON 串 |
| **AVI**（RIFF） | `LIST/INFO` 块 | 在 `LIST/INFO` 内建自定义子块，ID = `AIGC`，Value = JSON 串 |
| 其他格式 | XMP | 见 §3.4 |

### 3.2 音频（TC260-PG-202510A）

| 容器 | 存储位置 |
|---|---|
| **WAV**（RIFF） | 插入 Subchunk，`SubchunkID` = `AIGC`，JSON 串写入 `SubchunkData` |
| **MP3** | ID3v2 的 `TXXX` 帧（user defined text information frame），Description 写 `AIGC`，帧内容写 JSON 串 |
| OGG / FLAC / M4A | 见指南附录 C/D/E |
| 其他格式 | XMP |

### 3.3 图片（TC260-PG-20259A）

图片**统一走 XMP**，按格式决定 XMP packet 落点：

| 格式 | 写入位置 |
|---|---|
| JPEG/JPG | `APP1` 中标签名为 `XMP` 的字段 |
| PNG | 类型为 `iTXt` 的 XMP 字段 |
| TIFF | `IFD0`，tag `0x2BC`，Field type `7` |
| GIF | `Application Extension` 中的 XMP packet |
| WebP | 标签名为 `XMP` 的字段 |
| HEIF/HEIC | 参考 ISO/IEC 23008-12 |

### 3.4 XMP 通用方案（视频/音频的兜底 + 图片的主方案）

```xml
<TC260:AIGC>{"Label":"value1","ContentProducer":"value2","ProduceID":"value3","ReservedCode1":"value4","ContentPropagator":"value5","PropagateID":"value6","ReservedCode2":"value7"}</TC260:AIGC>
```

- 命名空间前缀：`TC260`
- 命名空间 URI：`http://www.tc260.org.cn/ns/AIGC/1.0/`
- **该命名空间已有其他内容时，应按属性更新，不应整体覆盖。**

### 3.5 文本（TC260-PG-20258A，供参考）

OOXML：`docProps/custom.xml` 里 `Properties/property`，`name="AIGC"`，子元素 `lpwstr` 放 JSON 串。

---

## 4. 实测验证

环境：ffmpeg 7.0.2（johnvansickle 静态构建，经 `imageio-ffmpeg` 分发）。

### 4.1 MP4 写入 —— 通过

标准附录 A 给的命令可用：

```bash
ffmpeg -i input.mp4 \
  -metadata AIGC='{"Label":"1","ContentProducer":"...","ProduceID":"...","ReservedCode1":"","ContentPropagator":"","PropagateID":"","ReservedCode2":""}' \
  -movflags use_metadata_tags \
  -c copy output.mp4
```

读回：`ffmpeg -i output.mp4` 即可看到 `AIGC : {...}`。

**落位核验**：解析输出文件的 box 结构，确认 `moov` → `udta` → `meta` → `keys` → `ilst` 链齐全，
且 key 以 `mdtaAIGC` 形式存于 keys box —— **与指南 §6.1.1 要求一致**。

### 4.2 漏掉 `-movflags use_metadata_tags` —— 静默丢失 ⚠️

```bash
ffmpeg -i input.mp4 -metadata AIGC='{...}' -c copy output.mp4   # 不加 movflags
```

**不报错、不告警、退出码 0，但标识根本没写进去。**

这是本次调研里最值得记住的一条：合规失败是**静默**的。任何实现都必须在写入后**读回校验**，
不能以 ffmpeg 退出码为准。

### 4.3 MKV 的 `-movflags` —— 指南疑似复制粘贴错误

指南附录 C（MKV）的示例命令里带了 `-movflags use_metadata_tags`。但 `movflags` 是
**MP4/MOV 复用器的选项**，对 Matroska 无意义。实测：带与不带，MKV 标签都能正常写入读出。

**结论：MKV 场景该参数可省略，带上也无害。按行为而非按字面照抄。**

### 4.4 AVI —— 原生 ffmpeg 写不了 ⚠️

指南附录 D 明确给出：需要给 ffmpeg **打源码补丁**，在 `libavformat/riff.c` 的
`ff_riff_info_conv[]` 和 `libavformat/riffenc.c` 的 `riff_tags[]` 中各加一行把 `AIGC`
加入白名单，才能写入 AVI 的 `LIST/INFO`。

**换句话说：用发行版自带的 ffmpeg 无法给 AVI 打合规标识。** 要么自行按 RIFF 结构
手写字节（指南附录 D 给了伪代码），要么避开 AVI。对短视频管线而言，避开即可。

---

## 5. 对实现的直接含义

1. **主路径只需覆盖 MP4**（竖屏短视频的事实标准），MKV/FLV 作为可选，**AVI 直接不支持并明确报错**，比假装支持要诚实。
2. **写入必须配读回校验**，因为失败是静默的（§4.2）。
3. **JSON 明文，不要 Base64**（§2.1）。
4. **XMP 写入要合并而非覆盖**命名空间（§3.4）。
5. 隐式标识只是合规的一半。**显式标识**（画面角标 ≥2 秒、文字高度 ≥ 画面最短边 5%）是另一半，
   且本环境实测 ffmpeg 静态构建**禁用了 `drawtext`**，应统一走 libass/ASS —— 顺带还能做逐字卡拉OK 高亮。
   > 显式标识的具体数值来自二手技术解读，**尚未从国标原文核实**，见 §7。

---

## 6. 原文获取方式

6 份实践指南由网安标委秘书处于 **2025-08-28** 发布，公告页：

- 公告：`https://www.tc260.org.cn/tc260/tzgg/202508/49b6d19ee5374bc4962e1ac427a5b390.shtml`
- 附件 1（清单 PDF）：`https://www.tc260.org.cn/zgwabwtzggfile/1756394049246098437/1756394049246098437.pdf`
- 附件 2（6 份指南全文，RAR）：`https://www.tc260.org.cn/zgwabwtzggfile/1756396168261019065/1756396168261019065.rar`

> 注意：站点对失效/直链路径一律返回首页 HTTP 200，很容易把首页 HTML 误存成 PDF。
> 下载后务必 `file` 校验类型。附件为 RAR5，`libarchive` ≥3.7 可解。

6 份清单：

| 编号 | 名称 |
|---|---|
| TC260-PG-20257A | 文件元数据隐式标识 **视频文件** |
| TC260-PG-20258A | 文件元数据隐式标识 文本文件 |
| TC260-PG-20259A | 文件元数据隐式标识 **图片文件** |
| TC260-PG-202510A | 文件元数据隐式标识 **音频文件** |
| TC260-PG-202511A | 文件元数据隐式标识 安全防护技术指南 |
| TC260-PG-202512A | 人工智能生成合成内容检测 第 1 部分：框架 |

视频文件指南起草单位包括**北京快手科技、北京抖音信息服务、中国电子技术标准化研究院、阿里云计算**等
—— 即平台方自己参与制定，平台侧的读取实现大概率与此一致。

---

## 7. 仍未核实

1. **GB 45438—2025 附录 E 原文**：字段的取值域（如 `Label` 除 `"1"` 外还有哪些合法值）、
   `ContentProducer` 到底填名称还是统一编码。目前语义描述依赖腾讯云官方文档转述。
   国标全文公开入口：`https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=F32EA2A561F1886CD8D606513512D547`
   （该页需浏览器在线预览，本次未取到正文）。
2. **服务提供者编码规则**：另有 TC260-PG-2025NA《…标识服务提供者编码规则》处于征求意见阶段，
   会直接决定 `ContentProducer` 怎么填，需跟进是否已正式发布。
3. **显式标识的精确数值**（≥2 秒、≥5% 最短边、角落位置）仍为二手来源，需以国标原文为准。
