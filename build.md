# phantom-frida 构建说明

## 目标
通过 GitHub Actions 构建自定义 Frida Server（当前默认版本：`17.6.1`）。

## 前置条件
- 已 fork 仓库到个人账号
- 已安装并登录 GitHub CLI（`gh auth status` 正常）

## 工作流
- 手动构建：`.github/workflows/build.yml`
- 定时构建：`.github/workflows/scheduled-build.yml`

## 手动触发（推荐）
```bash
gh workflow run build.yml -R <github-user>/phantom-frida -f frida_version=17.6.1
```

## 查看运行状态
```bash
gh run list -R <github-user>/phantom-frida --workflow build.yml --limit 5
gh run view <run-id> -R <github-user>/phantom-frida
```

## 获取产物
构建成功后在 Actions Run 的 Artifacts 中下载：
- `<custom_name>-server-<frida_version>`（压缩包）
- `<custom_name>-server-<frida_version>-uncompressed`（未压缩二进制）
