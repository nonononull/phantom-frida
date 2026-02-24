# phantom-frida 排错记录

## 检索关键字
- `phantom-frida`
- `github actions`
- `frida 17.6.1`
- `frida 17.7.2`
- `gh run download timeout`

## 2026-02-24 构建记录
- 场景：手动触发 `build.yml`，目标版本 `17.6.1`
- Run ID：`22342078468`
- Run URL：`https://github.com/nonononull/phantom-frida/actions/runs/22342078468`
- 初始状态：`in_progress`（前置步骤成功，进入 Clone Frida）

## 2026-02-24 构建记录（17.7.2）
- 场景：手动触发 `build.yml`，目标版本 `17.7.2`
- Run ID：`22342325517`
- Run URL：`https://github.com/nonononull/phantom-frida/actions/runs/22342325517`
- 结论：`success`（`build` job 10m39s 完成）
- 产物目录：`tmp/phantom-frida/artifacts/22342325517`
- 产物示例：
  - `ajeossida-server-17.7.2/ajeossida-server-17.7.2-android-arm64.gz`
  - `ajeossida-server-17.7.2-uncompressed/ajeossida-server-17.7.2-android-arm64`

## 2026-02-24 排错记录（下载超时）
1. 现象：`gh run download 22342325517` 在本地命令默认超时（约 124 秒）被终止。
2. 原因：CLI 下载体积较大，调用超时时间设置过短，非 workflow 构建失败。
3. 处理：将命令超时调整到 900 秒后重试下载。
4. 验证：重试后下载成功，目录内产物命名包含 `17.7.2`。
5. 关联 Run：`22342325517`

## 常见问题模板（新增时按此格式）
1. 现象：
2. 原因：
3. 处理：
4. 验证：
5. 关联 Run：
