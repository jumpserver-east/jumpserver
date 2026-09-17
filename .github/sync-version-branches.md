# 同步上游版本及开发分支

工作流：`.github/workflows/sync-version-branches.yml`，部署分支：`docker-build`。
该分支只存放自有 Actions、构建配置、脚本及说明；应用源码保留在 `dev`、`v3`、`v4`、
`v5` 和版本分支中。EE 镜像构建会单独检出指定源码到 `source/`。

- 源仓库：`https://github.com/jumpserver/jumpserver.git`。
- 目标仓库：`jumpserver-east/jumpserver`（工作流 checkout 配置的 `origin`）。
- 版本分支同步和开发分支镜像同步共用每周一次的定时任务：每周一 UTC 00:17，即北京时间 08:17。GitHub 的定时任务可能延迟。
- 支持手动运行，`dry_run` 默认勾选；定时运行会实际同步。
- 修改工作流或脚本的 push / pull request 会运行本地 Git 集成测试，不执行分支同步。
- `docker-build` 的相关 push、定时运行、非 dry-run 手动运行还会在仓库级停用明确列出的上游工作流；dry-run 和 pull request 不修改工作流状态。详见 [工作流策略](workflow-policy.md)。

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
分支保护或并发更新导致的推送失败会使工作流失败，并继续处理其余匹配分支。
若 origin 拒绝身份认证或仓库写权限（如 HTTP 401/403），立即停止，避免对剩余分支
重复使用无效凭据；运行摘要会注明未继续处理。
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

### HTTP 403 / Permission denied 排查

若日志出现 `Permission to jumpserver-east/jumpserver.git denied to Nickyang00`
以及 HTTP 403，表示本次推送凭据没有获得目标仓库的写入许可；这不是版本分支名
或 Docker 构建配置的问题。`Unchanged` 只表示 SHA 相同、未尝试推送，不能证明有写权限。

工作流的运行摘要会显示使用 `SYNC_BRANCHES_TOKEN` 还是 `GITHUB_TOKEN`，不会输出
token 值。只要 `SYNC_BRANCHES_TOKEN` 存在且非空，就会覆盖默认 token；推送失败时
不会自动回退。工作流中的 `permissions: contents: write` **只授权 `GITHUB_TOKEN`**，
不能提升 PAT 或其所属账号的权限。

使用 `SYNC_BRANCHES_TOKEN` 时依次检查：

1. PAT 所属账号（上述日志中为 `Nickyang00`）通过组织团队或仓库协作者获得
   `jumpserver-east/jumpserver` 的 **Write** 或更高权限；PAT 不能赋予账号本身没有的权限。
2. Fine-grained PAT 的 **Resource owner** 为 `jumpserver-east`，已选择目标
   `jumpserver` 仓库，且 **Contents**、**Workflows** 均为 **Read and write**。
   如组织要求审批，token 必须已获批准，不能处于 pending 状态。
3. 若使用 classic PAT，需包含 `repo` 和 `workflow` scope，组织策略允许使用该类
   token，且在组织要求 SAML SSO 时通过 **Configure SSO** 完成授权。
4. Token 未过期或撤销；在目标仓库的 **Settings → Secrets and variables → Actions**
   更新 `SYNC_BRANCHES_TOKEN`，然后重新运行工作流。不要把 token 写入源码或日志。

如有意改用默认 `GITHUB_TOKEN`，可移除该 secret；但上游提交涉及工作流文件时仍可能
需要上述 PAT，且默认 token 的推送不会触发后续镜像构建。dry-run 只验证读取和同步计划，
不能验证推送权限、工作流文件写权限或分支保护；实际写入需非 dry-run 运行验证。

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
