# 厦门税务软安SCA解决方案 - Design Spec

> Human-readable design narrative — rationale, audience, style, color choices, content outline. Read once by downstream roles for context.
>
> Machine-readable execution contract: `spec_lock.md` (color / typography / icon / image short form). Executor re-reads `spec_lock.md` before every SVG page to resist context-compression drift. Keep both in sync; on divergence, `spec_lock.md` wins.

## I. Project Information

| Item | Value |
| ---- | ----- |
| **Project Name** | 厦门税务软安SCA解决方案 |
| **Canvas Format** | PPT 16:9 (1280×720) |
| **Page Count** | 12 |
| **Design Style** | editorial + pyramid mode |
| **Target Audience** | 厦门税务局领导、信息化管理部门负责人 |
| **Use Case** | 软件供应链安全建设方案汇报 |
| **Content Strategy** | 自由构建——无源文档约束，基于用户确认的12页结构和技术要点适度延展 |
| **Created Date** | 2026-06-21 |

---

## II. Canvas Specification

| Property | Value |
| -------- | ----- |
| **Format** | PPT 16:9 |
| **Dimensions** | 1280×720 |
| **viewBox** | `0 0 1280 720` |
| **Margins** | 左右 60px, 上下 50px |
| **Content Area** | 1160×620 (从 60,50 到 1220,670) |

---

## III. Visual Theme

### Theme Style

- **Mode**: `pyramid` — 结论先行，MECE论证结构，面向决策者
- **Visual style**: `editorial` — 杂志级排版，栏线分割，衬线/无衬线层次对比
- **Theme**: Light theme
- **Tone**: 专业、正式、权威，政务方案风格

### Color Scheme

> Source: derived from template `厦门税务SCA方案技术交流.pptx` theme palette + user confirmation.

| Role | HEX | Purpose |
| ---- | --- | ------- |
| **Background** | `#FFFFFF` | Page background |
| **Secondary bg** | `#F5F7FA` | Card background, section background |
| **Primary** | `#20A675` | Title decorations, key sections, icons |
| **Accent** | `#6096E6` | Data highlights, key information, links |
| **Secondary accent** | `#FFC000` | Secondary emphasis, key callouts |
| **Body text** | `#2D2D2D` | Main body text |
| **Secondary text** | `#445469` | Captions, annotations |
| **Tertiary text** | `#8F8F8F` | Supplementary info, footers |
| **Border/divider** | `#E0E0E0` | Card borders, divider lines, hairline rules |
| **Success** | `#51BA94` | Positive indicators |
| **Warning** | `#FFC000` | Issue markers |

### AI Image Strategy

- **Image Rendering**: `editorial` — magazine-style infographic look
- **Image Palette**: `cool-corporate` — stable, professional, restrained; white ≈60%, green #20A675 ≈25%, blue #6096E6 ≈10%, gold #FFC000 ≈5%

### Gradient Scheme

```xml
<!-- Title gradient -->
<linearGradient id="titleGradient" x1="0%" y1="0%" x2="100%" y2="0%">
  <stop offset="0%" stop-color="#20A675"/>
  <stop offset="100%" stop-color="#6096E6"/>
</linearGradient>

<!-- Background decorative gradient -->
<radialGradient id="bgDecor" cx="85%" cy="15%" r="40%">
  <stop offset="0%" stop-color="#20A675" stop-opacity="0.08"/>
  <stop offset="100%" stop-color="#20A675" stop-opacity="0"/>
</radialGradient>
```

---

## IV. Typography System

### Font Plan

**Typography direction**: 政务 editorial 风格 — SimHei 黑体标题 + SimSun 宋体正文（方案二 contrast）

| Role | Font Stack | Size (px) |
|------|-----------|-----------|
| **Cover title** | `SimHei, "Microsoft YaHei", sans-serif` | 72 |
| **Page title** | `SimHei, "Microsoft YaHei", sans-serif` | 36 |
| **Subtitle** | `"Microsoft YaHei", sans-serif` | 24 |
| **Body** | `SimSun, "Times New Roman", serif` | 22 |
| **Emphasis** | `SimHei, "Microsoft YaHei", sans-serif` | 22 |
| **Annotation** | `"Microsoft YaHei", sans-serif` | 14 |
| **Page number** | `"Microsoft YaHei", sans-serif` | 12 |

> PPT-safe: all stacks end with pre-installed fonts. Title stacks lead with Windows-preinstalled `SimHei`; body stacks lead with `SimSun`. Cross-platform fallback: `"Microsoft YaHei"` for CJK sans, `"Times New Roman"` for Latin serif.

### Formula Rendering Policy

`text-only` — 本方案不含数学公式，保留文本可编辑。

---

## V. Layout Principles

### Page Structure
- **Header zone**: 60,50 to 1220,110 (title area, 60px tall)
- **Content zone**: 60,110 to 1220,660 (main content, 550px tall)
- **Footer zone**: 60,660 to 1220,720 (page number, source line, 60px tall)

### Layout Pattern Library
- **Single column centered**: Covers, conclusions
- **Asymmetric split (3:7)**: Icon/visual left, text right — for capability pages
- **Three-column**: Parallel capability cards
- **Top-band + bottom columns**: Challenge overview pages
- **Z-pattern alternating**: Process/flow pages (tax implementation plan)
- **Full-bleed + floating text**: Cover page with AI-generated atmosphere image

### Spacing
- Card gap: 24px
- Column gap: 40px
- Title-to-content gap: 32px
- Body line-height: 1.6 (35px at 22px body)

---

## VI. Icon Usage Spec

- **Library**: `tabler-outline` (linear stroke, airy, refined)
- **Stroke width**: `2`
- **Inventory**: shield-check, code, search, database, bug, alert-triangle, git-branch, brain, certificate, api, settings, chart-bar, building-bank, package, file-check, terminal-2, robot, cloud-lock, shield-search, bell-ringing, radar, target-arrow, binary-tree

---

## VII. Visualization Reference List

Catalog read: 71 templates.

| Page | Template | Path | Summary-quote (verbatim) | Usage |
| ---- | -------- | ---- | ------------------------ | ----- |
| P02 | radar | templates/charts/radar.svg | "Pick for multi-dimensional capability assessment / profile comparison across 4-8 axes. Skip for simple 1-2 dimension comparison (use bar_chart)." | AI时代供应链威胁雷达：多维度威胁评估（开源大模型/MCP/Skill/二进制等） |
| P09 | process_flow | templates/charts/process_flow.svg | "Pick for 3-5 sequential process steps with directional flow where the reader must follow the procedure. Skip if steps are independent or unordered (use vertical_pillars)." | 厦门税务SCA落地方案：开发→测试→采购→运维全流程嵌入 |

Runners-up considered:
- `vertical_pillars` | rejected for P02: only 4 axes needed, radar is better for threat profile comparison
- `chevron_chain_with_tail` | rejected for P09: process flow with labels needs more space
- `timeline_horizontal` | rejected for P09: process is cyclical not timeline-based

---

## VIII. Image Resource List

> Decided per confirmation h: AI-generated images for cover + key atmospheric pages (`editorial` × `cool-corporate`).
> Layout patterns from `references/image-layout-patterns.md`.

| Filename | Dimensions | Ratio | Layout suggestion | Layout pattern | Purpose | Type | Acquire Via | Status | Reference |
|----------|-----------|-------|-------------------|----------------|---------|------|-------------|--------|-----------|
| cover_bg.png | 1280×720 | 1.78 | Full-bleed background + floating title overlay | #1 full-bleed background with floating title | Cover atmosphere background | Background | ai | Pending | Digital security shield concept over abstract government-tech visual; calm center zone for title overlay; green #20A675 and white tones dominate; editorial magazine-grade infographic aesthetic |
| challenges_bg.png | 1280×720 | 1.78 | Full-bleed with scrim + overlaid content cards | #42 background image + glassmorphism UI panels + #29 two-stop scrim | P02 threat landscape atmosphere | Background | ai | Pending | Abstract visualization of AI-era software supply chain: data streams, code branches, robot/AI nodes, MCP connectors; dark undertones with green #20A675 highlight lines; editorial rendering |

---

## IX. Content Outline

### P01 | Cover
- **Page rhythm**: `anchor`
- **Layout**: Full-bleed AI image + floating title overlay
- **Cover impact**: 主标题直接点明方案价值——"AI时代软件供应链安全新防线"，以政务科技感的抽象安全防护图形为封面背景，绿色渐变标题居中悬浮
- **Title**: 厦门税务 · 软安SCA解决方案
- **Subtitle**: AI时代的软件供应链安全治理
- **Footer**: 软安科技 | 2026.06

### P02 | AI时代政务软件供应链安全新挑战
- **Page rhythm**: `dense`
- **Layout**: 顶部标题栏 + 左侧威胁雷达图 + 右侧三大挑战卡片
- **Title**: AI开源浪潮下，政务软件供应链面临全新安全威胁
- **Takeaway**: 开源大模型、MCP、Skill等新型开源形态正在快速进入税务信息化场景，传统SCA检测手段已无法覆盖
- **Content blocks**:
  - 挑战一：AI开源项目激增——大模型/MCP/Skill等新型开源形态缺乏安全管控
  - 挑战二：二进制盲区——开发商交付的二进制制品无源码可审，成分不可见
  - 挑战三：合规压力升级——软件物料清单(SBOM)与许可证合规成为监管刚需
- **Visualization**: radar chart — 威胁雷达图（4轴：开源形态多样性 / 二进制不可见性 / 合规紧迫度 / 攻击面广度）

### P03 | 软安SCA产品概述
- **Page rhythm**: `breathing`
- **Layout**: 居中产品定位 + 底部三列核心数据卡片
- **Title**: 源兮SCA — AI时代全场景软件成分分析平台
- **Takeaway**: 20+语言检测 × 100T+知识库 × 0% Java误报，为政务软件供应链提供全栈透明
- **Content blocks**:
  - 20+语言覆盖 | 从传统Java/Python到AI框架PyTorch/TensorFlow
  - 100T+数据库 | 全球最大开源知识库，覆盖开源大模型/MCP/Skill组件
  - 二进制+源码双模 | 同时支持源码和二进制制品成分分析
  - Java 0%误报 / C/C++ <10%误报 | 业界领先的检测精准度

### P04 | 核心能力一：AI时代新威胁检测
- **Page rhythm**: `dense`
- **Layout**: 左侧场景图 + 右侧三段式能力说明
- **Title**: 覆盖AI时代的全量开源风险——从大模型到MCP、Skill
- **Takeaway**: 业界首个将开源大模型、MCP工具链、Skill插件纳入成分分析的SCA平台
- **Content blocks**:
  - 开源大模型检测：识别Llama/Qwen/DeepSeek等模型组件及供应链依赖
  - MCP/Skill覆盖：MCP服务端、Skill插件的开源依赖与许可证识别
  - AI框架深度分析：PyTorch/TensorFlow/JAX等框架及模型权重文件成分解析
  - 与传统SCA无缝融合：AI组件与传统开源组件在同一平台统一管控

### P05 | 核心能力二：检测技术领先 + 二进制成分分析
- **Page rhythm**: `dense`
- **Layout**: 三列卡片并列 + 底部二进制分析流程图
- **Title**: 源码+二进制双模检测，100T+数据库驱动
- **Takeaway**: 支持源码和二进制两种分析模式，解决开发商交付二进制制品的成分盲区
- **Content blocks**:
  - 源码分析引擎：跨文件跨函数追踪，20+语言全覆盖
  - 二进制分析引擎：100+格式支持，无源码场景下提取组件指纹
  - 100T+知识库：全球最大开源组件库，覆盖3000万+组件版本
  - 开发商交付场景：税务系统采购的二进制软件包，直接扫描成分+漏洞+许可证
- **Visualization**: binary-tree — 二进制分析流程图（input → 反编译 → 指纹提取 → 知识库匹配 → output）

### P06 | 核心能力三：漏洞深度分析 + 快速修复
- **Page rhythm**: `dense`
- **Layout**: 左右非对称分栏（4:6），左漏洞发现流程 + 右修复能力卡片
- **Title**: 不只是发现漏洞——深度分析、精准定位、协助快速修复
- **Takeaway**: 从CVE检出到修复方案推荐，全栈漏洞闭环管理
- **Content blocks**:
  - 漏洞深度分析：CVSS评分、影响范围评估、利用条件分析
  - 可达路径追踪：从漏洞组件追溯到实际调用链路，过滤不可达漏洞
  - AI修复建议：基于上下文的修复方案推荐，含版本升级路径和兼容性评估
  - 修复闭环：漏洞发现→影响分析→修复建议→修复验证，全程可追溯

### P07 | 核心能力四：安全预警 + 资产快速盘点
- **Page rhythm**: `dense`
- **Layout**: 上半部分预警时间线 + 下半部分资产盘点仪表盘
- **Title**: 主动预警、快速盘点——让安全团队先于攻击者行动
- **Takeaway**: 实时监控全球漏洞情报，一键盘点全量软件资产安全状态
- **Content blocks**:
  - 实时预警：对接全球CVE/NVD/CNVD情报源，组件级精准推送
  - 资产快速盘点：自动发现所有在用开源组件，生成全量资产清单
  - 风险优先级排序：基于CVSS+业务影响的双维度评分模型
  - 应急响应：0day漏洞爆发时，分钟级定位受影响资产范围

### P08 | 核心能力五：MCP/API/定制化嵌入
- **Page rhythm**: `dense`
- **Layout**: 三列场景卡片 + 底部API能力矩阵
- **Title**: MCP标准接口 + 全量API + 深度定制——让SCA无缝嵌入税务开发场景
- **Takeaway**: 提供MCP协议集成、RESTful全量API、以及UI/流程/策略全方位定制能力
- **Content blocks**:
  - MCP标准集成：通过MCP协议对接税务现有DevOps工具链（IDE/CI/CD/代码仓库）
  - 全量API开放：200+ RESTful API端点，覆盖扫描/查询/报表/策略管理全流程
  - 深度定制：UI品牌化、扫描策略自定义、报告模板定制、审批流程适配
  - 嵌入式安全：开发人员在IDE中实时获得SCA告警，安全左移到编码阶段

### P09 | 厦门税务SCA落地方案
- **Page rhythm**: `dense`
- **Layout**: 全流程横向流程图（开发→测试→上线→运维）+ 各阶段SCA嵌入点
- **Title**: 厦门税务SCA全流程嵌入——从代码到运维的安全闭环
- **Takeaway**: 在税务软件开发、采购、测试、运维四个阶段嵌入SCA检测，实现全生命周期供应链安全
- **Content blocks**:
  - 开发阶段：IDE插件+MCP集成，编码时实时成分分析
  - 采购阶段：二进制SCA扫描，开发商交付物上架前强制检测
  - 测试阶段：CI/CD流水线集成，自动化安全门禁
  - 运维阶段：持续监控+资产盘点，新漏洞实时预警
- **Visualization**: process_flow — 四阶段流程图，每阶段标注SCA能力嵌入点

### P10 | 服务保障体系
- **Page rhythm**: `dense`
- **Layout**: 三列服务卡片 + 底部SLA承诺条
- **Title**: 从产品到服务——全方位保障厦门税务SCA落地
- **Takeaway**: 不只是交付产品，提供实施、培训、运维、应急全周期服务
- **Content blocks**:
  - 实施服务：环境部署、策略调优、与现有DevOps工具链集成
  - 培训赋能：管理员培训+开发人员安全编码培训
  - 技术支持：7×24小时响应、定期巡检、版本升级
  - 应急响应：0day漏洞爆发时4小时内提供应急方案

### P11 | 方案优势总结
- **Page rhythm**: `breathing`
- **Layout**: 居中主结论 + 五列优势要点（紧凑图标+一句话）
- **Title**: 软安SCA——为厦门税务构建AI时代的软件供应链安全防线
- **Takeaway**: 全场景覆盖 × 领先检测技术 × 深度漏洞分析 × 实时预警盘点 × 无缝嵌入——五位一体
- **Content blocks**:
  - AI时代全覆盖：开源大模型/MCP/Skill+传统组件，一个平台
  - 技术领先：100T+知识库，Java 0%误报，业界标杆
  - 漏洞闭环：发现→分析→修复→验证，全流程自动化
  - 主动防御：实时预警+资产秒级盘点，先于攻击者
  - 无缝嵌入：MCP+API+定制，融入税务现有开发体系

### P12 | 封底
- **Page rhythm**: `anchor`
- **Layout**: 居中致谢 + 联系信息
- **Closing impact**: "为厦门税务软件供应链安全保驾护航"——以简洁有力的承诺语收尾
- **Content**: 谢谢 + 软安科技联系方式

---

## X. Speaker Notes Requirements

- **Total duration**: 25-30 minutes
- **Notes style**: Formal（正式汇报风格）
- **Purpose**: Persuade（说服决策者采纳方案）
- **File naming**: `notes/01_cover.md` ~ `notes/12_closing.md`

---

## XI. Technical Constraints Reminder

- No `<foreignObject>`, no `rgba()`, no `<style>` / `class`
- No icon library mixing (tabler-outline only)
- SVG viewBox: `0 0 1280 720`
- Per-page spec_lock re-read required before each page generation
- Color values from spec_lock.md only — no invented HEX
