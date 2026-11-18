# FlareDrive-R2

跑在 Cloudflare Pages 上的私有网盘：前端是免构建的 Vue 单文件组件，后端是 Pages Functions，文件存在 R2，账户存在 D1。

> 基于 [longern/FlareDrive](https://github.com/longern/FlareDrive)、[ljxi/Cloudflare-R2-oss](https://github.com/ljxi/Cloudflare-R2-oss) 和 [willow-god/FlareDrive-R2](https://github.com/willow-god/FlareDrive-R2)。

## 功能

- **文件管理**：上传（大于 100 MB 自动分片）、下载、复制、移动、重命名文件、递归删除文件夹、多选批量操作、全局搜索
- **预览**：图片、视频、全景图预览；图片和视频自动生成缩略图，也可以对已有文件"重新生成缩略图"
- **账户**：D1 数据库账户（加盐哈希、可自助改密码、独立的管理员标记），兼容旧版环境变量账户
- **权限**：按目录授权，读写 / 只读账户，公开目录（GUEST）
- **签名链接**：私有文件通过带过期时间的 HMAC 签名 URL 访问，分享链接可设置有效期
- **WebDAV**：`/dav/` 可以挂载到 Windows、macOS、rclone 等客户端
- **离线下载**：输入一个 URL，由服务端下载并保存到当前目录
- **登录限制**（可选）：连续输错密码后临时锁定

## 目录

- [快速部署](#快速部署)
- [环境变量和绑定](#环境变量和绑定)
- [账户和权限](#账户和权限)
- [签名链接](#签名链接)
- [WebDAV](#webdav)
- [离线下载](#离线下载)
- [用命令行上传](#用命令行上传)
- [接口一览](#接口一览)
- [安全说明](#安全说明)
- [从旧版本升级](#从旧版本升级)
- [自定义界面](#自定义界面)
- [常见问题](#常见问题)

## 快速部署

需要一个已开通 R2 的 Cloudflare 账号，以及本地的 Node.js（用来运行 `wrangler`）。

### 1. 创建 R2 存储桶

在 R2 控制台新建一个存储桶。**不要开启公开访问**：所有文件读取都经过 Pages Functions 里的 R2 绑定，存储桶保持私有即可。

### 2. 部署 Pages

1. Fork 本仓库
2. Cloudflare Pages → 创建项目 → 连接到 Git → 选择仓库
3. 构建设置：构建命令填 `mkdir -p dist && cp -r index.html assets _headers _redirects favicon.ico robots.txt 404.html _routes.json dist/`，输出目录填 `dist/`

> **为什么输出目录必须是 `dist/`？** 如果发布目录是仓库根目录，`utils/`、`scripts/`、`migrations/`、`docs/` 下的源码和内部文件会作为静态文件被匿名访问（整个鉴权模型和签名代码都会公开）。仓库里有 `_routes.json` + 对应的 Function 做兜底拦截（访问这些路径返回 404），但这只是权宜之计；正确做法是把发布目录设为 `dist/`，只发布静态文件。`functions/` 目录始终留在仓库根目录，Pages 会自动把它编译成 Functions。

### 3. 绑定 R2

Pages 项目 → Settings → Functions → R2 bucket bindings，变量名填 `BUCKET`，选择刚才的存储桶。

### 4. 创建 D1 数据库和第一个管理员

```bash
wrangler d1 create flaredrive-users
wrangler d1 execute flaredrive-users --file=./migrations/0001_create_users.sql --remote
```

Pages 项目 → Settings → Functions → D1 database bindings，变量名填 `DB`。

数据库里保存的是加盐哈希，不能手写 SQL 插入密码。用仓库自带的脚本生成第一个管理员：

```bash
node scripts/create-admin-sql.js admin "一个强密码" > admin.sql
wrangler d1 execute flaredrive-users --file=./admin.sql --remote
rm admin.sql        # 里面有密码哈希，用完删掉
```

脚本的第三个参数是目录权限（默认 `*`），加 `--readonly` 创建只读账户。

### 5. 重新部署

绑定和环境变量修改后需要重新部署一次才会生效（Deployments → Retry deployment）。

## 环境变量和绑定

| 名称 | 类型 | 必需 | 说明 |
| --- | --- | --- | --- |
| `BUCKET` | R2 绑定 | 是 | 存放文件的存储桶 |
| `DB` | D1 绑定 | 推荐 | 账户数据库。不绑定时只能使用环境变量账户 |
| `LOGIN_ATTEMPTS` | KV 绑定 | **是** | 登录失败次数限制（5 次失败后锁定 30 分钟）。**不绑定时登录限流完全关闭**（同一账号/IP 可无限尝试密码），服务端会在日志里报 `[SECURITY] LOGIN_ATTEMPTS KV 未绑定`。绑定后无需其他配置 |
| `GUEST` | 变量 | 否 | 公开目录，逗号分隔，例如 `public/`。这些目录下的文件凭直链即可下载 |
| `GUEST_LIST` | 变量 | 否 | 设为 `true` 时，未登录访客也可以浏览 `GUEST` 目录的文件列表。默认关闭 |
| `SIGNING_SECRET` | 变量（建议加密） | 否 | 签名链接的密钥。不设置时自动生成并保存在存储桶内部 |
| `SHARE_LINK_MAX_TTL` | 变量 | 否 | 分享链接的最长有效期（秒），默认 `2592000`（30 天） |
| `FETCH_MAX_SIZE` | 变量 | 否 | 离线下载单个文件的大小上限（字节），默认 `268435456`（256 MiB） |
| `QRCODE_API` | 变量 | 否 | 二维码生成接口，用于桌面端分享，例如 `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=` |
| `用户名:密码` | 变量 | 否 | 旧版环境变量账户，见下文 |

## 账户和权限

### 权限模型

| 操作 | 条件 |
| --- | --- |
| 读文件 | 文件在 `GUEST` 目录下；或带有效的签名链接；或已登录且目录权限匹配 |
| 浏览目录 | 已登录且目录权限匹配。未登录访客只有在 `GUEST_LIST=true` 时才能浏览 `GUEST` 目录 |
| 写（上传、删除、移动、离线下载） | 必须登录，账户不是只读，并且目录权限匹配。`GUEST` 目录对已登录的可写账户开放写入，**未登录永远不能写** |
| 管理账户 | D1 中 `is_admin = 1` 的账户 |

目录权限是前缀匹配，写法是以 `/` 结尾的目录名，多个用逗号分隔；`*` 表示全部目录。目录权限和管理员是两回事：`*` 只表示能读写所有目录，不表示能创建账户。

### D1 账户（推荐）

管理员创建账户：

```bash
curl -X POST https://你的域名/api/auth/register \
  -u 'admin:管理员密码' \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "至少6位的密码",
    "permissions": ["personal/", "work/"],
    "isReadOnly": false,
    "isAdmin": false
  }'
```

用户名已存在时返回 `409` 和 `{"code": "USERNAME_TAKEN"}`。

用户自己修改密码：登录后点右上角用户菜单里的"修改密码"，或者：

```bash
curl -X POST https://你的域名/api/auth/change-password \
  -u 'alice:旧密码' \
  -H "Content-Type: application/json" \
  -d '{ "newPassword": "新密码" }'
```

密码使用 PBKDF2-SHA256（10 万次迭代、每个用户独立的盐）哈希后保存。

### 环境变量账户（旧版，兼容保留）

| 变量名 | 值 | 含义 |
| --- | --- | --- |
| `user1:123456` | `user1/,shared/` | 可读写这两个目录 |
| `viewer:123456:r` | `shared/` | 只读 |
| `admin:123456` | `*` | 可读写所有目录（不是账户管理员） |

环境变量账户的密码是明文、改密码需要重新部署，并且没有账户管理权限。D1 和环境变量里有同名账户时优先匹配 D1。

## 签名链接与分享

除 `GUEST` 目录外，`/raw/` 下的文件不能匿名访问。浏览器的 `<img>`、`<video>` 和全景图查看器无法携带登录信息，所以用签名链接：

```
/raw/docs/report.pdf?token=<载荷>.<HMAC-SHA256 签名>
```

- **应用内**（缩略图、预览、全景图、下载）：文件列表接口为当前目录签发一个令牌，有效期 12 到 24 小时，只覆盖该目录和缩略图。
- **分享链接**：右键 → 分享，得到一条短链接 `https://你的域名/share/<10 位随机 ID>`。有效期 1 / 7 / 30 天或长期有效，可选访问密码和下载次数上限；分享页保留预览（图片/视频/音频），下载按钮在同一页。下载次数按下载请求计数，预览不计入。
- **脚本**：也可以直接带 `Authorization: Basic` 请求 `/raw/`。

分享记录存在内部前缀 `_$flaredrive$/shares/` 下，是一条 JSON（目标文件、过期时间、密码哈希、下载上限、已下载次数、创建者），不能通过 `/raw/` 或文件列表读到。管理入口在右上角菜单 → 管理分享链接，可以查看各条分享的有效期和下载次数、复制链接、逐条撤销（删除记录后链接立即失效）。只有创建者和管理员能看到/撤销一条分享。

用接口创建分享链接：

```bash
curl -X POST https://你的域名/api/shares \
  -u 'alice:密码' -H "Content-Type: application/json" \
  -d '{ "key": "work/report.pdf", "days": 7, "password": "可选", "maxDownloads": 10 }'
# {"id":"aB3dE5fG7h","url":"https://你的域名/share/aB3dE5fG7h","expiresAt":1790000000,...}
```

**撤销**：在管理页点撤销，或 `DELETE /api/shares/<id>`。修改分享选项重新生成时，上一条同文件分享会被自动替换，不会在管理页堆积。

**旧版 HMAC 签名链接**（`POST /api/sign`，返回 `/raw/...?token=...`）继续可用，已发出的链接不受影响；但它在过期前无法单独撤销，需要让所有已发出的链接立即失效时，修改 `SIGNING_SECRET`（没有设置过的话，设置一个即可）并重新部署。

**注意**：应用内的地址带的是"目录级"令牌。请用"分享"生成分享链接，不要把预览窗口地址栏里的地址直接发给别人——拿到它的人在令牌过期前可以读取同一目录下任何知道文件名的文件。

## WebDAV

地址：`https://你的域名/dav/`，用网盘账户登录（D1 账户或环境变量账户都可以）。权限和网页端完全一致，不提供匿名访问。

| 客户端 | 用法 |
| --- | --- |
| macOS 访达 | 前往 → 连接服务器 → `https://你的域名/dav/` |
| Windows | 映射网络驱动器 → `https://你的域名/dav/` |
| rclone | `rclone config` 选择 `webdav`，vendor 选 `other` |
| curl | `curl -u alice:密码 -T file.txt https://你的域名/dav/work/file.txt` |

支持的方法：`OPTIONS` `PROPFIND` `GET` `HEAD` `PUT` `DELETE` `MKCOL` `COPY` `MOVE`。`LOCK` / `UNLOCK` / `PROPPATCH` 返回 405：本站不提供真正的锁定，以前返回的假成功已去掉，客户端会按"不支持锁定"继续写入。单个目录超过 2 万个对象时，`PROPFIND` / `COPY` / `MOVE` / `DELETE` 返回 507（目录过大，请分目录操作），不会对不完整的对象集合执行操作。

限制：

- 单次上传最大约 100 MB（Cloudflare 对请求体的限制，免费版）。更大的文件请用网页端或[分片上传脚本](#用命令行上传)。
- R2 没有原生的移动和重命名。`MOVE` / `COPY` 先把全部内容写到目标下的临时目录、全部成功后再逐个提交到最终位置、最后才删除源，不是原子操作；文件很多的目录可能超出单个请求的子请求数限制（免费版 50 次，付费版 1000 次），此时会返回 507，源目录保持不变。
- 目标已存在时：`Overwrite: F` 返回 412；否则在新内容完整提交之后才清理旧目标（替换，不会合并两个目录）。唯一无法完全避免的残留风险：R2 没有目录级原子替换，提交阶段中途失败时目标可能已被部分更新（暂存阶段失败则目标完全不受影响）。
- 通过 WebDAV 上传的图片和视频没有缩略图，可以在网页端右键"重新生成缩略图"。

## 离线下载

有写权限的账户点右下角 `+` → 离线下载，输入 `http/https` 链接，服务端会把文件下载到当前目录。同名文件不会被覆盖，会保存为 `name (1).ext`。

```bash
curl -X POST https://你的域名/api/write/fetch \
  -u 'alice:密码' -H "Content-Type: application/json" \
  -d '{ "url": "https://example.com/file.zip", "dir": "work/" }'
```

限制：

- 默认上限 256 MiB（`FETCH_MAX_SIZE`）。目标服务器没有返回 `Content-Length` 时，文件要先读进内存，上限为 64 MB。流式下载也逐字节计数，谎报 `Content-Length` 的服务端超限时会被中途截断。
- 拒绝内网、本机、链路本地地址、`*.pages.dev` 和本站注册域名下的全部子域名，重定向的每一跳都会重新检查，最多跟随 5 次。注意：Workers 无法做 DNS 查询，这里只能检查 URL 字符串——一个解析到内网地址的域名是拦不住的；但 Workers 的出口是 Cloudflare 边缘网络、不是用户内网，且没有元数据服务，这层防护已够用。
- 下载期间请求保持打开，页面需要等待完成。

## 用命令行上传

小于 100 MB 的文件：

```bash
curl -u "alice:$FLARE_PASS" -X PUT \
  -H "Content-Type: image/png" \
  --data-binary @photo.png \
  "https://你的域名/api/write/items/photos/photo.png"
```

路径中的空格和中文需要做百分号编码。没有带 `Content-Type` 时服务端会按后缀猜测。

大于 100 MB 的文件要分片，流程是 `POST ?uploads` 取得 `uploadId` → 逐片 `PUT ?uploadId=..&partNumber=N` 并记录响应头里的 `ETag` → `POST ?uploadId=..` 提交 `{"parts":[{"partNumber":1,"etag":"..."}]}`。

要让一个新目录在网页上显示出来，上传一个空的 `目录/_$folder$` 标记对象即可（WebDAV 的 `MKCOL` 会自动创建）。

## 接口一览

| 路径 | 方法 | 说明 | 权限 |
| --- | --- | --- | --- |
| `/api/auth/login` | POST | 登录校验 | 公开 |
| `/api/auth/change-password` | POST | 修改自己的密码 | 已登录（D1 账户） |
| `/api/auth/register` | POST | 创建账户 | 管理员 |
| `/api/auth/unban`、`/api/auth/ban-status` | POST | 登录锁定管理 | 管理员 |
| `/api/auth/check-write-permission` | POST | 查询某目录是否可写 | 公开（只返回是否） |
| `/api/children/<目录>` | GET | 列目录，同时返回应用内签名令牌 | 读 |
| `/api/sign` | POST | 生成分享链接 | 读 |
| `/api/write/items/<路径>` | PUT / POST / DELETE | 上传、分片上传、删除、复制（`x-amz-copy-source`）、`?fixMetadata` | 写 |
| `/api/write/fetch` | POST | 离线下载 | 写 |
| `/raw/<路径>` | GET / HEAD | 读取文件，支持 Range | 读 |
| `/dav/<路径>` | WebDAV | 见上文 | 读 / 写 |

所有接口都使用 HTTP Basic 认证（`Authorization: Basic base64(用户名:密码)`）。

## 安全说明

- **未登录不能写**。`GUEST` 只授予读权限。
- **目录枚举**：未登录默认不能列目录；`/raw/` 对没有权限的请求统一返回 404，不区分"不存在"和"无权限"。
- **上传内容不可信**：`/raw/` 和 `/dav/` 的所有响应都带 `X-Content-Type-Options: nosniff` 和 `Content-Security-Policy: sandbox`；html、svg、xml、js 类型或后缀的文件强制以附件下载。上传的网页不会在本站域名下执行脚本。
- **CSRF**：写接口的 401 不返回 `WWW-Authenticate`（WebDAV 除外，客户端需要它），并校验 `Origin`，跨站请求返回 403。不带 `Origin` 的 curl、脚本和 WebDAV 客户端不受影响。
- **内部目录**：`_$flaredrive$/` 下只有 `thumbnails/` 可以通过接口访问，且缩略图文件名必须是 `<sha1>.png`。
- **复制**：复制源需要读权限，不能借"复制"读取其他目录的文件。
- **凭据缓存**：通过校验的账户在同一个运行实例内缓存 30 秒以减少 PBKDF2 开销。修改密码后，旧密码在其他实例上最多还能使用 30 秒。
- **静态资源响应头**：`_headers` 为静态文件加上 HSTS、`X-Frame-Options`、CSP 等，并去掉默认的 `Access-Control-Allow-Origin: *`。CDN 脚本和样式带 SRI 哈希（见 `index.html`）；字体 CSS（static.zeoseven.com）没有 SRI——该域名在当前构建环境不可达，如需锁定请自行取哈希补上。CSP 含 `unsafe-inline`/`unsafe-eval`：本应用没有构建步骤，SFC 在浏览器里运行时编译，收紧需要先上构建步骤。
- **登录凭据存 localStorage**：有意为之（换标签页不用重新登录）；同源脚本注入仍是风险面，上面 CSP + 上传文件强制下载就是对应的缓解。

发现安全问题请提交 issue 或直接联系仓库维护者。

## 从旧版本升级

这个版本修复了几个严重问题，升级后行为有变化：

1. **访客不能再写入 `GUEST` 目录**。此前任何人不登录就可以对 `GUEST` 目录上传、覆盖、删除文件。升级后请检查这些目录里有没有不是你放进去的文件。
2. **未登录不能再浏览 `GUEST` 目录**。需要保留旧行为时设置 `GUEST_LIST=true`。目录下的文件仍然可以凭直链下载，所以不要在 `GUEST` 目录里放不想公开的文件。
3. **私有文件的直链失效**。以前复制出去的 `/raw/...` 链接（非 `GUEST` 目录）现在返回 404，需要重新"复制链接"生成带签名的链接。
4. **`GUEST=*` 不再等于完全开放写入**，只表示所有文件公开可读。
5. **删除了 `/api/write/s3/` 和 `/api/buckets`**。这两个接口没有做任何认证，配置了 `AWS_ACCESS_KEY_ID` 的部署会把 S3 凭据的全部能力暴露给匿名访客。前端从未使用它们。如果你配置过 `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `CF_ACCOUNT_ID`，可以删除这些变量，并建议在 Cloudflare 控制台轮换这个 API 令牌。
6. **不带冒号的账户串不再匹配环境变量**。此前 `Authorization: Basic base64("GUEST")` 会被当成一个拥有 `GUEST` 目录写权限的账户。
7. 目录权限按完整目录名匹配：权限 `docs` 等同于 `docs/`，不再匹配 `docs-private/`。

## 自定义界面

没有构建步骤，直接改文件：

- 背景图：`assets/App.vue` 里的 `backgroundImageUrl`
- 页脚链接：`assets/Footer.vue` 里 `data()` 的几个 URL
- 样式：`assets/main.css`

快捷键：`Ctrl+A` 多选，`Ctrl+V` 粘贴，`Esc` 退出多选或关闭预览，`Delete` 删除选中项；预览时 `←` `→` 切换，`+` `-` 缩放，`R` 旋转，`0` 重置。

本地运行：

```bash
npm install
npm run dev        # 即 wrangler pages dev . --r2 BUCKET；需要 D1 时用新版 wrangler 并加上 --d1 DB
```

## 常见问题

**登录后图片和缩略图不显示**
签名令牌随文件列表下发，刷新页面即可。页面开着超过一天后令牌会过期，同样刷新即可。

**视频没有缩略图 / 缩略图是黑的**
右键 → 重新生成缩略图。生成时会依次取开头、10%、25%、50%、75% 位置的画面，选最亮的一张（遇到足够亮的画面就停止）。浏览器无法解码的编码（例如部分 HEVC）生成不了缩略图。

**上传失败，提示没有权限**
检查账户不是只读，并且目录权限以 `/` 结尾、覆盖了目标目录。未登录不能上传。

**WebDAV 客户端反复要求输入密码**
确认地址以 `/dav/` 结尾并使用 HTTPS。Windows 默认拒绝对 HTTP 地址使用 Basic 认证。

**修改环境变量或绑定后没有生效**
需要重新部署。

**文件夹不能重命名**
R2 没有原生的重命名，网页端没有提供这个功能。可以通过 WebDAV 的 `MOVE` 完成，注意它不是原子操作。

## License

MIT
