# Fork 工作流策略

`docker-build` 是专用的 Actions 配置分支，只保留本仓库新增的 8 个文件：

- `.github/workflows/build-component-image.yml`
- `.github/workflows/sync-version-branches.yml`
- `.github/scripts/sync-version-branches.sh`
- `.github/scripts/test_sync_version_branches.py`
- `.github/docker-bake.hcl`
- `.github/Dockerfile.xpack-placeholder`
- `.github/sync-version-branches.md`
- `.github/workflow-policy.md`

应用代码、根目录 Dockerfile、依赖清单、上游文档、模板以及继承的工作流均从
此分支移除。EE 构建从本分支读取配置，再将选定应用分支、tag 或提交单独检出到
`source/`；`Dockerfile`、`Dockerfile-ee` 及应用依赖来自该源码引用。
`docker-build` 自身不作为应用源码自动构建；手动构建也需选择含应用源码的引用。

对比 `upstream/dev...docker-build` 的提交历史，本仓库独立新增两个工作流：

| 工作流 | 首次添加的提交 | 用途 |
| --- | --- | --- |
| `build-component-image.yml` | `0894b078b8` | 构建 EE 镜像，推送 GHCR 和阿里云 |
| `sync-version-branches.yml` | `88a73fd212` | 同步上游版本分支和 `dev/v3/v4/v5` |

`cleanup-branches.yml` 从上游继承；本仓库的 `ee8dd37135` 仅注释了其定时触发，
没有新增清理工作流。本次清理已将这些继承文件从默认分支移除。

## 其他分支上的构建触发依赖

`docker-build` 不保留 `jms-generic-action-handler.yml` 文件。它仍存在于上游镜像
源码分支中，并保持仓库级启用，接收这些分支的 push 事件；默认分支的
`build-component-image.yml` 通过 `workflow_run` 监听它，并排除 `docker-build`。
如果在仓库级停用它，这条自动镜像构建链会失去 push 触发入口。
该依赖仍执行上游的 `jumpserver/action-generic-handler`，并非空的事件中转。

GitHub 系统管理的 `Dependency Graph` 也保持原状。

## 停用范围

`sync-version-branches.yml` 的 `disable-inherited-workflows` 任务使用
`GITHUB_TOKEN` 的 `actions: write` 权限，通过 GitHub API 停用下列 17 个工作流，
并回读确认 `disabled_manually` 状态：

- `build-ansible-executor.yml`
- `build-base-image.yml`
- `build-python-image.yml`
- `check-compilemessages.yml`
- `cleanup-branches.yml`
- `discord-release.yml`
- `docs-release.yml`
- `issue-close-require.yml`
- `issue-close.yml`
- `issue-comment.yml`
- `issue-open.yml`
- `issue-recent-alert.yml`
- `issue-untimely-alert.yml`
- `jms-build-test.yml`
- `release-drafter.yml`
- `sync-gitee.yml`
- `translate-readme.yml`

停用作用于整个 fork 仓库，包括 `v3` 和版本分支，不改动这些分支的提交。
因此分支继续与上游精确同步，同名的继承工作流仍保持停用。
若 GitHub 将已移除的工作流标记为 `deleted`，策略直接跳过该不可运行项。
继承文件只保留在源码分支及历史提交中；新增的其他工作流不会被这一明确名单误停用。

默认分支修改同步工作流或脚本的 push 会执行策略；每周同步及非 dry-run 手动运行
也会重复检查。pull request 和 dry-run 不修改 GitHub 的工作流状态。
如需重新启用名单内的任务，先移除名单项，再在 GitHub Actions 页面启用它。
