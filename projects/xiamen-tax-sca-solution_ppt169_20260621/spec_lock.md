## canvas
- viewBox: 0 0 1280 720
- format: PPT 16:9

## mode
- mode: pyramid

## visual_style
- visual_style: editorial

## colors
- bg: #FFFFFF
- secondary_bg: #F5F7FA
- primary: #20A675
- accent: #6096E6
- secondary_accent: #FFC000
- text: #2D2D2D
- text_secondary: #445469
- text_tertiary: #8F8F8F
- border: #E0E0E0
- success: #51BA94
- warning: #FFC000
- image_rendering: editorial
- image_palette: cool-corporate

## typography
- font_family: "Microsoft YaHei", Arial, sans-serif
- title_family: SimHei, "Microsoft YaHei", sans-serif
- body_family: SimSun, "Times New Roman", serif
- body: 22
- cover_title: 72
- title: 36
- subtitle: 24
- annotation: 14
- page_number: 12

## icons
- library: tabler-outline
- stroke_width: 2
- inventory: shield-check, code, search, database, bug, alert-triangle, git-branch, brain, certificate, api, settings, chart-bar, building-bank, package, file-check, terminal-2, robot, cloud-lock, shield-search, bell-ringing, radar, target-arrow, binary-tree

## images
- cover_bg: images/cover_bg.png
- challenges_bg: images/challenges_bg.png

## page_rhythm
- P01: anchor
- P02: dense
- P03: breathing
- P04: dense
- P05: dense
- P06: dense
- P07: dense
- P08: dense
- P09: dense
- P10: dense
- P11: breathing
- P12: anchor

## page_charts
- P02: radar
- P09: process_flow

## forbidden
- Mixing icon libraries
- rgba()
- `<style>`, `class`, `<foreignObject>`, `textPath`, `@font-face`, `<animate*>`, `<script>`, `<iframe>`, `<symbol>`+`<use>`
- `<g opacity>` (set opacity on each child element individually)
- HTML named entities in text (`&nbsp;`, `&mdash;`, `&copy;`, `&ndash;`, `&reg;`, `&hellip;`, `&bull;` …) — write as raw Unicode
