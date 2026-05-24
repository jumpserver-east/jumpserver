# AGENTS.md

## 当前逻辑

本项目在命令过滤 ACL 中新增 `人脸+审批` 动作，对应后端动作值为 `face_review`。

当前逻辑不是通过全局开关控制，也不在原有审批接口里追加人脸前置流程：

1. 命令 ACL 动作为 `review` 时，KoKo 调用原审批接口。
2. 命令 ACL 动作为 `face_review` 时，KoKo 调用独立的人脸审批接口。
3. 人脸审批接口先触发拍照系统，等待拍照系统回调并完成人脸比对。
4. 人脸比对通过后，复用现有命令审批工单。
5. 人脸比对失败、拍照失败、回调超时或 AI 平台异常时，不创建审批工单，命令被阻断。

核心接口分工：

```text
普通审批:
POST /api/v1/acls/command-filter-acls/command-review/

人脸+审批:
POST /api/v1/acls/command-filter-acls/command-face-review/

拍照系统回调:
POST /api/v1/authentication/camera/photo/callback/
```

`FACE_VERIFY_ENABLED` 已废弃，不应再作为配置项或流程判断条件。

## 组件边界

JumpServer 负责：

- 提供普通命令审批接口。
- 提供独立的人脸+审批接口。
- 根据会话、命令、命令过滤 ACL 创建人脸核验记录。
- 获取拍照系统 token。
- 调用拍照系统触发摄像头抓拍。
- 暴露 `/api/v1/authentication/camera/photo/callback/` 给拍照系统回调。
- 接收 `sign`、`faceStr`、`photoStr` 并调用 AI 人脸平台比对。
- 人脸比对通过后复用现有 `ApplyCommandTicket` 命令复核工单。
- 向 KoKo 返回工单状态查询和关闭接口。
- 在命令审计接口中返回人脸比对摘要。

JumpServer 不负责：

- 直接解析终端输入流。
- 直接决定命令何时写入目标资产连接。
- 现场摄像头采集实现。
- AI 人脸算法实现。
- 通过全局配置开关决定是否启用人脸核验。

## 涉及代码目录

主要目录和当前职责：

- `apps/acls/const.py`
  - `ActionChoices.face_review = 'face_review'` 定义 `人脸+审批` 动作。
- `apps/acls/serializers/base.py`
  - 命令 ACL 表单允许 `face_review`。
  - 登录 ACL、登录资产 ACL 等非命令 ACL 排除 `face_review`。
  - `review` 和 `face_review` 都要求配置有效审批人。
- `apps/acls/models/base.py`
  - 保存 ACL 时校验 `review`、`face_review` 必须存在审批人。
- `apps/acls/api/command_acl.py`
  - `command_review` 保持原有纯审批逻辑。
  - `command_face_review` 执行人脸核验，通过后再创建原有审批工单。
- `apps/acls/models/command_acl.py`
  - `CommandFilterACL.create_command_review_ticket` 继续负责创建命令审批工单。
- `apps/authentication/models/command_face_verify.py`
  - `CommandFaceVerifyRecord` 保存人脸核验任务、状态、图片路径、AI 比对结果和关联工单。
- `apps/authentication/services/camera.py`
  - 提取用户身份证号。
  - 获取拍照系统 token。
  - 调用拍照系统触发拍照。
  - 等待回调结果。
- `apps/authentication/api/camera.py`
  - 拍照系统回调入口。
  - 保存回调图片。
  - 调用 AI 人脸平台比对。
- `apps/authentication/services/face.py`
  - 封装 AI 人脸平台 accessToken 获取、签名、图片加密和 1:1 比对。
- `apps/authentication/services/face_image.py`
  - 解码并保存 `faceStr`、`photoStr`。
- `apps/authentication/serializers/camera.py`
  - 校验拍照系统回调参数。
- `apps/authentication/urls/api_urls.py`
  - 注册拍照回调路由。
- `apps/terminal/api/session/command.py`
  - 查询命令审计时聚合人脸核验记录。
- `apps/terminal/serializers/command.py`
  - 命令审计返回 `face_verify` 摘要。
- `apps/jumpserver/conf.py`
  - 定义拍照系统和 AI 人脸平台默认配置。
- `apps/jumpserver/settings/custom.py`
  - 将拍照系统和 AI 人脸平台配置导出到 Django settings。
- `config_example.yml`
  - 示例配置包含拍照系统和 AI 人脸平台参数，不包含 `FACE_VERIFY_ENABLED`。

## 数据模型

当前新增模型：

```text
CommandFaceVerifyRecord
```

当前主要字段：

```text
id
sign
session_id
user_id
asset_id
account_id
cmd_filter_acl_id
ticket_id
run_command
machine_ip
user_name
id_number_masked
status
score
threshold
ai_response
face_image_path
photo_image_path
face_image_sha256
photo_image_sha256
face_image_size
photo_image_size
error_message
date_callback
date_compared
date_finished
org_id
date_created
date_updated
```

状态：

```text
created
token_failed
camera_call_failed
waiting_photo
photo_received
comparing
passed
failed
timeout
error
```

边界要求：

- `faceStr` 和 `photoStr` 不长期直接存数据库大字段，只保存图片路径、哈希和大小。
- 日志不得输出完整 `faceStr`、`photoStr`、身份证号。
- `sign` 必须唯一，用于拍照系统回调定位任务。
- 回调接口需要幂等：同一个 `sign` 重复回调时不能重复触发工单。
- 人脸比对通过后才写入 `ticket_id`。

## 接口逻辑

### 1. 普通审批

KoKo 在 ACL 动作为 `review` 时调用：

```text
POST /api/v1/acls/command-filter-acls/command-review/
```

入参：

```json
{
  "session_id": "会话 ID",
  "cmd_filter_acl_id": "命令过滤 ACL ID",
  "run_command": "待执行命令"
}
```

处理顺序：

1. `CommandReviewSerializer` 校验 `session_id`、`cmd_filter_acl_id`、`run_command`。
2. 查询会话、命令 ACL、组织信息。
3. 调用 `create_command_review_ticket` 创建原有命令审批工单。
4. 返回 `check_ticket_api`、`close_ticket_api`、`ticket_detail_page_url`、`assignees` 等工单信息。

该接口不触发拍照，不等待回调，不调用 AI 人脸平台。

### 2. 人脸+审批

KoKo 在 ACL 动作为 `face_review` 时调用：

```text
POST /api/v1/acls/command-filter-acls/command-face-review/
```

入参同普通审批接口：

```json
{
  "session_id": "会话 ID",
  "cmd_filter_acl_id": "命令过滤 ACL ID",
  "run_command": "待执行命令"
}
```

处理顺序：

1. `CommandReviewSerializer` 校验请求参数。
2. 查询 `terminal.Session`，拿到操作人、资产、账号、组织、当前用户登录 IP。
3. 创建 `CommandFaceVerifyRecord`，状态为 `created`。
4. 从用户 `comment` 字段提取身份证号，写入脱敏后的 `id_number_masked`。
5. 调用拍照系统鉴权接口获取 token。
6. 调用拍照系统抓拍接口，获取 `sign`。
7. 保存 `sign`，状态改为 `waiting_photo`。
8. 等待拍照系统回调，等待时间由 `CAMERA_PHOTO_TIMEOUT_SECONDS` 控制。
9. 回调接口保存图片并调用 AI 人脸平台比对。
10. 如果状态变为 `passed`，调用 `create_command_review_ticket` 创建审批工单。
11. 将 `ticket_id` 写回人脸核验记录。
12. 返回原有工单信息给 KoKo。
13. 如果拍照失败、回调超时、AI 比对失败或比对不通过，则返回错误，不创建工单。

当前错误码：

```text
face_verify_token_failed
face_verify_camera_failed
face_verify_photo_timeout
face_verify_compare_failed
face_verify_rejected
```

### 3. 拍照参数来源

调用拍照系统时，参数按以下规则传递：

```text
machineIp -> 当前用户登录 IP，即 Session.remote_addr
userName  -> 用户的 name 字段
idNumber  -> 从用户 comment 字段中提取的身份证号
```

身份证提取规则：

```text
\d{17}[\dXx]
```

处理要求：

- 提取到的身份证号统一转大写，即末位 `x` 转为 `X`。
- 如果 `comment` 中不存在身份证号，流程失败。
- 如果 `comment` 中出现多个身份证号，流程失败，避免误传。
- 日志中只允许打印脱敏身份证，例如 `350***********123X`。
- 人脸核验记录只保存脱敏值，不保存完整身份证明文。

### 4. 获取拍照系统 token

外部接口：

```text
POST <CAMERA_SYSTEM_BASE_URL>/auth/outerLogin
```

请求体：

```json
{
  "signData": "CAMERA_SYSTEM_SIGN_DATA"
}
```

成功响应：

```json
{
  "code": 200,
  "msg": null,
  "data": {
    "expires_in": 60,
    "token": "xxx"
  }
}
```

处理要求：

- token 按 `expires_in` 和 `CAMERA_TOKEN_CACHE_SECONDS` 缓存，过期前主动刷新。
- `code != 200` 或无 `data.token` 时视为失败。

### 5. 触发摄像头拍照

外部接口：

```text
GET <CAMERA_SYSTEM_BASE_URL>/cs/external/machine/callCamera
```

请求头：

```text
Authorization: Bearer <token>
```

URL 参数：

```json
{
  "machineIp": "Session.remote_addr",
  "userName": "用户 name 字段",
  "idNumber": "从用户 comment 提取出的身份证号"
}
```

成功响应：

```json
{
  "msg": "操作成功！",
  "code": 200,
  "data": {
    "sign": "a3f1ca6c-a822-460d-9f80-c9474131c4ac"
  }
}
```

处理要求：

- `sign` 必须写入人脸核验记录。
- `code != 200` 或 `data.sign` 为空时视为拍照触发失败。
- 失败时禁止命令执行，不进入人工审批。

### 6. 拍照系统回调堡垒机

堡垒机提供接口：

```text
POST /api/v1/authentication/camera/photo/callback/
```

鉴权：

```text
Authorization: Signature ...
```

请求体：

```json
{
  "sign": "a3f1ca6c-a822-460d-9f80-c9474131c4ac",
  "faceStr": "xxxxx",
  "photoStr": "xxxxx"
}
```

接口处理：

1. 校验调用方为已认证的 AccessKey HTTP Signature 请求。
2. 校验 `sign`、`faceStr`、`photoStr` 非空。
3. 根据 `sign` 锁定并查询 `CommandFaceVerifyRecord`。
4. 如果不存在，返回 404。
5. 如果任务已不是 `waiting_photo`，返回幂等成功，消息为 `photo already pushed`。
6. 解码并保存 `faceStr`、`photoStr`。
7. 记录图片路径、sha256、大小。
8. 状态改为 `photo_received`。
9. 调用 AI 人脸平台比对。
10. 保存分数、阈值、AI 响应摘要。
11. 比对通过则状态改为 `passed`。
12. 比对不通过则状态改为 `failed`。
13. AI 调用异常则状态改为 `error`。

响应：

```json
{
  "code": 200,
  "msg": "ok",
  "data": {
    "sign": "a3f1ca6c-a822-460d-9f80-c9474131c4ac",
    "status": "passed",
    "score": 91.2,
    "threshold": 80,
    "face_image_size": 12345,
    "photo_image_size": 12345
  }
}
```

### 7. AI 人脸平台比对

当前内部 service：

```text
authentication.services.face.FaceClient
```

主要能力：

```text
get_access_token()
compare(face_image_path, photo_image_path, seq)
```

当前接口路径：

```text
POST <AI_FACE_BASE_URL>/openapi/resource/getAccessToken
POST <AI_FACE_BASE_URL>/openapi/face/compare
```

鉴权和加密：

- 请求体使用 SM3/SM2 生成 `X-Face-Data-Sign`。
- 请求头包含 `X-Face-Clientid`。
- 比对请求包含 `X-Face-AccessToken`。
- 如果配置了 `AI_FACE_AGENT_ID`，比对请求包含 `X-Face-AgentId`。
- 图片读取后 base64，再使用 SM4 加密。

比对结果要求：

- 必须能得到是否通过。
- 优先使用 AI 响应中的通过标记。
- 如果没有通过标记但有分数，则用 `AI_FACE_PASS_THRESHOLD` 判断。
- AI 平台不可用或响应无法判断时默认禁止执行命令。

### 8. 审计命令记录

命令记录 API：

```text
GET /api/v1/terminal/commands/
```

新增返回字段：

```json
{
  "face_verify": {
    "sign": "a3f1ca6c-a822-460d-9f80-c9474131c4ac",
    "status": "passed",
    "score": 91.2,
    "threshold": 80,
    "ticket_id": "工单 ID",
    "date_compared": "2026-05-21T10:00:00+08:00"
  }
}
```

匹配逻辑：

- 通过命令记录的 `session_id` 和命令内容查询人脸核验记录。
- 不依赖命令文本全局唯一性。

## 配置项

当前有效配置：

```yaml
CAMERA_SYSTEM_BASE_URL: http://25.86.163.14:18080
CAMERA_SYSTEM_SIGN_DATA: ""
CAMERA_TOKEN_CACHE_SECONDS: 3600
CAMERA_PHOTO_TIMEOUT_SECONDS: 60
AI_FACE_BASE_URL: ""
AI_FACE_APP_ID: ""
AI_FACE_SIGN_KEY: ""
AI_FACE_SM4_KEY: ""
AI_FACE_AGENT_ID: "123456789"
AI_FACE_ACCESS_TOKEN: ""
AI_FACE_TOKEN_CACHE_SECONDS: 3600
AI_FACE_PASS_THRESHOLD: 80
```

配置说明：

- `CAMERA_SYSTEM_BASE_URL`：拍照系统地址。
- `CAMERA_SYSTEM_SIGN_DATA`：拍照系统鉴权接口请求体中的 `signData`。
- `CAMERA_TOKEN_CACHE_SECONDS`：拍照系统 token 最大缓存时间。
- `CAMERA_PHOTO_TIMEOUT_SECONDS`：人脸+审批接口等待回调的最长时间。
- `AI_FACE_BASE_URL`：AI 人脸平台地址。
- `AI_FACE_APP_ID`：AI 人脸平台 client id。
- `AI_FACE_SIGN_KEY`：AI 人脸平台 SM2 私钥。
- `AI_FACE_SM4_KEY`：AI 人脸平台图片加密密钥。
- `AI_FACE_AGENT_ID`：AI 人脸平台代理标识，可为空。
- `AI_FACE_ACCESS_TOKEN`：固定 accessToken，可为空；为空时自动调用 token 接口获取。
- `AI_FACE_TOKEN_CACHE_SECONDS`：AI accessToken 最大缓存时间。
- `AI_FACE_PASS_THRESHOLD`：AI 响应没有明确通过标记时使用的分数阈值。

废弃配置：

```yaml
FACE_VERIFY_ENABLED
```

## 本地测试建议

拍照系统和 AI 人脸平台在本地开发环境不可用时，优先使用本地模拟服务做端到端测试：

1. 模拟拍照系统的 `/auth/outerLogin` 和 `/cs/external/machine/callCamera`。
2. `callCamera` 返回一个唯一 `sign`。
3. 模拟服务拿到 `sign` 后，调用堡垒机 `/api/v1/authentication/camera/photo/callback/` 推送 `faceStr`、`photoStr`。
4. 模拟 AI 平台的 `/openapi/resource/getAccessToken` 和 `/openapi/face/compare`。
5. 分别返回通过、不通过、异常、超时场景，验证堡垒机侧状态和错误码。

也可以使用 API 工具单独调用堡垒机接口做分段测试：

- 先调用 `command-face-review` 创建人脸核验任务并触发拍照。
- 再用回调接口按 `sign` 推送照片。
- 如果要避开外部系统，仍需要通过模拟服务或 mock 配置让拍照和 AI 调用可控。

## 验收标准

- Lina 命令 ACL 动作包含 `人脸+审批`。
- `review` 规则只走 `/command-review/`，不触发拍照。
- `face_review` 规则走 `/command-face-review/`。
- 拍照系统收到 `machineIp`、`userName`、`idNumber`。
- 拍照系统能回调 `/api/v1/authentication/camera/photo/callback/`。
- 人脸比对失败时不创建人工审批工单，命令被禁止。
- 人脸比对成功后创建现有命令复核工单。
- 工单审批通过后 KoKo 放行命令。
- 工单审批拒绝后 KoKo 禁止命令。
- 命令审计记录中能看到人脸核验状态、分数、时间和关联工单。
- 配置中不再出现 `FACE_VERIFY_ENABLED`。
