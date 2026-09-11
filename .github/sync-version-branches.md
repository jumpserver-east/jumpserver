# 同步上游版本及开发分支

工作流：`.github/workflows/sync-version-branches.yml`，部署分支：`docker-build`。

- 源仓库：`https://github.com/jumpserver/jumpserver.git`。
- 目标仓库：`jumpserver-east/jumpserver`（工作流 checkout 配置的 `origin`）。
- 版本分支同步和开发分支镜像同步共用每周一次的定时任务：每周一 UTC 00:17，即北京时间 08:17。GitHub 的定时任务可能延迟。
- 支持手动运行，`dry_run` 默认勾选；定时运行会实际同步。
- 修改工作流或脚本的 push / pull request 仅运行本地 Git 集成测试。

## 分支规则

版本分支白名单正则：`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+)?(-lts)?$`。

匹配 `v4.10.14-lts`、`v3.10.23-lts`、`v3.10.0-7-lts`、`v5.0.0`。
目标不存在的版本分支会创建；已有版本分支仅进行 fast-forward 更新。
若目标存在上游没有的提交，则跳过并写入运行摘要。

`dev`、`v3`、`v4`、`v5` 使用单独的镜像同步逻辑：创建缺失分支，已有分支直接
对齐 upstream 的提交 SHA，**丢弃 origin 中上游不存在的提交**，包括回退领先分支和
覆盖已分叉的历史。只有这四个精确名称允许强制更新，使用绑定本次读取到的
origin SHA 的 `--force-with-lease`；若同步期间有人更新或创建了目标分支，
本次推送失败，下一次运行会重新读取并对齐。dry-run 会显示
`Would Mirror upstream (discard origin-only commits)` 及独立的 `mirror` 计数。

忽略 `main`、`master`、`docker-build`、`v6`、`v4.10`、`dev-test`、
`v3.10.21-lts-hthx`、`pr@...` 等分支，以及所有 tag。
推送失败会使工作流失败，并继续处理其余匹配分支。
不会删除目标分支或向上游写入；上游不存在的分支保留原状。

## 首次运行

1. 将工作流、脚本、测试文件提交并推送到默认分支 `docker-build`。
2. 在 fork 的 Actions 页面启用工作流。
3. 选择 **Sync upstream branches → Run workflow**，分支选 `docker-build`，
   保持 `dry_run` 勾选，检查运行 Summary 中的 `Would Create` / `Would Update` /
   `Would Mirror upstream` 清单。
4. 取消 `dry_run` 后手动运行，即可立即同步；此后由定时任务继续同步。

默认使用具有 `contents: write` 权限的 `GITHUB_TOKEN`。如果上游版本提交涉及
`.github/workflows` 变更，GitHub 可能拒绝推送；此时在目标仓库的
**Settings → Secrets and variables → Actions** 中设置 `SYNC_BRANCHES_TOKEN`：
使用仅授权此仓库、具有 **Contents: Read and write** 及 **Workflows: Read and write**
权限的 fine-grained PAT，或具有 `repo` / `workflow` scope 的 classic PAT。
工作流会自动优先使用该 secret；组织策略或分支保护也需允许目标分支写入。
`dev`、`v3`、`v4`、`v5` 如受分支保护或 ruleset 限制，还需允许该同步身份强制更新。

使用默认 `GITHUB_TOKEN` 推送不会触发其他 push/create 工作流。使用 PAT 推送可能触发
仓库现有的 `build-component-image.yml`（监听分支创建）及其他事件工作流。

## 本地验证

```bash
python3 .github/scripts/test_sync_version_branches.py
DRY_RUN=true bash .github/scripts/sync-version-branches.sh
```

集成测试使用临时本地 Git 仓库，不连接 GitHub。第二条命令需要完整 Git 历史和
正确的 `origin`，会读取真实远程并获取提交，但不推送；结果同时输出到终端及
`GITHUB_STEP_SUMMARY`（如果设置）。
