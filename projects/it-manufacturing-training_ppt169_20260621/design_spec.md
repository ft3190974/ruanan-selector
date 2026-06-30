# IT制造行业解决方案培训 - Design Spec

> Human-readable design narrative.

## I. Project Information

| Item | Value |
| ---- | ----- |
| **Project Name** | IT制造行业解决方案培训 |
| **Canvas Format** | PPT 16:9 (1280×720) |
| **Page Count** | 14 |
| **Design Style** | instructional + soft-rounded |
| **Target Audience** | 软安科技销售团队、售前工程师 |
| **Use Case** | 内部培训，掌握IT制造行业产品推介 |
| **Content Strategy** | 自由构建——基于知识库行业映射，适度延展场景细节 |
| **Created Date** | 2026-06-21 |

---

## II. Canvas Specification

| Property | Value |
| -------- | ----- |
| **Format** | PPT 16:9 |
| **Dimensions** | 1280×720 |
| **viewBox** | `0 0 1280 720` |
| **Margins** | 左右 60px, 上下 50px |
| **Content Area** | 1160×620 |

---

## III. Visual Theme

- **Mode**: `instructional` — 分解→排序→讲授，一页一概念
- **Visual style**: `soft-rounded` — 圆角卡片 rx 14，柔和阴影，亲近培训氛围
- **Theme**: Light theme
- **Tone**: 专业、亲和、教学导向

| Role | HEX | Purpose |
| ---- | --- | ------- |
| **Background** | `#FFFFFF` | Page background |
| **Secondary bg** | `#F5F7FA` | Card backing |
| **Primary** | `#20A675` | Titles, icons, key highlights |
| **Accent** | `#6096E6` | Secondary emphasis |
| **Secondary accent** | `#FFC000` | Callouts, warnings |
| **Body text** | `#2D2D2D` | Main body |
| **Secondary text** | `#667580` | Captions |
| **Border** | `#E0E0E0` | Card borders |

---

## IV. Typography System

| Role | Font Stack | Size |
|------|-----------|------|
| **Cover title** | `"Microsoft YaHei", sans-serif` | 56 |
| **Page title** | `"Microsoft YaHei", sans-serif` | 32 |
| **Subtitle** | `"Microsoft YaHei", sans-serif` | 20 |
| **Body** | `"Microsoft YaHei", sans-serif` | 22 |
| **Card title** | `"Microsoft YaHei", sans-serif` | 18 |
| **Annotation** | `"Microsoft YaHei", sans-serif` | 14 |
| **Page number** | `"Microsoft YaHei", sans-serif` | 12 |

Formula: `text-only`

---

## V. Layout Principles

- Cards: rx 14, padding 28px, gutters 24px, shadow filter for gentle elevation
- Content zone: 60,100 to 1220,660
- Card grid: 2-4 columns, even spacing

---

## VI. Icon Usage Spec

- Library: `tabler-outline`, stroke-width: 2
- Inventory: device-mobile, router, robot, shield-check, code, search, database, bug, file-certificate, chart-bar, users, building, brain, api, settings, package, git-branch, target-arrow, alert-triangle, lock

---

## VII. Visualization Reference List

Catalog read: 71 templates.

| Page | Template | Path | Summary-quote | Usage |
| ---- | -------- | ---- | ------------- | ----- |
| P02 | vertical_pillars | charts/vertical_pillars.svg | "Pick for 3-5 parallel pillars..." | 3大细分领域并列展示 |
| P06 | matrix_2x2 | charts/matrix_2x2.svg | "Pick for 2-axis quadrant..." | 行业×产品矩阵 |

---

## VIII. Image Resource List

No images — pure layout design.

---

## IX. Content Outline

### P01 | Cover
- **Rhythm**: `anchor`
- **Title**: 软安科技产品解决方案培训
- **Subtitle**: IT制造行业 · 销售&售前赋能

### P02 | IT制造行业全景
- **Rhythm**: `dense`
- **Title**: IT制造行业：三大细分领域
- **Content**: 消费电子 / 网络安防设备 / 具身智能 — 三列卡片，每列：行业定义+代表产品+安全诉求

### P03 | 消费电子
- **Rhythm**: `dense`
- **Title**: 消费电子：需求痛点与软安解决方案
- **Content**: 痛点（固件安全/开源组件风险/无线协议攻击面）→ 方案组合（BAT+SCA+FUZZ+CodingHawk）

### P04 | 网络安防设备
- **Rhythm**: `dense`
- **Title**: 网络安防设备：需求痛点与软安解决方案
- **Content**: 痛点（设备固件/通信协议/二进制交付物）→ 方案组合（BAT+FUZZ+SAST+GuardFox）

### P05 | 具身智能
- **Rhythm**: `dense`
- **Title**: 具身智能：需求痛点与软安解决方案
- **Content**: 痛点（AI模型安全/传感器固件/实时OS漏洞）→ 方案组合（SAST+SCA+BAT+GuardFox）

### P06 | 行业×产品推荐矩阵
- **Rhythm**: `dense`
- **Title**: 一页速查：行业×产品推荐矩阵
- **Content**: 3行×6列矩阵表，标注强推/可选/不适用

### P07 | 产品核心卖点速记卡
- **Rhythm**: `dense`
- **Title**: 六大产品核心卖点速记
- **Content**: 6张迷你卡片，每张：产品名+品牌名+一句话+关键数字

### P08 | 测试服务组合拳
- **Rhythm**: `dense`
- **Title**: 10项测试服务如何搭配
- **Content**: 安全测试6项 + 审计咨询4项，按行业场景标注推荐组合

### P09 | 案例一：消费电子
- **Rhythm**: `dense`
- **Title**: 案例一：某手机品牌固件安全检测
- **Content**: 提问式场景→思考→解答→产品组合推演

### P10 | 案例二：网络安防设备
- **Rhythm**: `dense`
- **Title**: 案例二：某安防厂商交换机安全审计
- **Content**: 提问式场景→思考→解答→产品组合推演

### P11 | 案例三：具身智能
- **Rhythm**: `dense`
- **Title**: 案例三：某机器人公司AI+固件安全需求
- **Content**: 提问式场景→思考→解答→产品组合推演

### P12 | 案例四：综合型客户
- **Rhythm**: `dense`
- **Title**: 案例四：某电子制造集团全产品线安全需求
- **Content**: 综合场景→多产品组合推演→报价思路

### P13 | 竞品对比
- **Rhythm**: `dense`
- **Title**: 竞品对比与差异化优势
- **Content**: 逐产品 vs 竞品对比表

### P14 | 总结与行动指南
- **Rhythm**: `breathing`
- **Title**: 带走这三句话
- **Content**: 三大行动指南，简洁有力收尾

---

## X. Speaker Notes Requirements

- Duration: 60-90 minutes training session
- Style: Conversational / interactive
- Purpose: Instruct + Enable

---

## XI. Technical Constraints

- No foreignObject, rgba, style, class
- tabler-outline only
- viewBox: 0 0 1280 720
