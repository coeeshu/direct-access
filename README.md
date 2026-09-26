# direct-access（dsite）

有的时候有些服务需要直连，所以用这个脚本搞一下。

服务器上的 Docker 服务平时通过 Cloudflare Tunnel（橙云）对外。`dsite` 可以再给它们加一个**灰云（仅 DNS）直连域名**，并统一完成服务器防护。整个过程在一个中文菜单（whiptail TUI）里操作。

- **直连站点**：自动列出本机的 Docker 服务端口，包括 host 网络的容器；选一个服务、填一个域名，就生成 Nginx 反向代理和 Let's Encrypt 证书。每个站点的直连可以单独开关。
- **限流**：每个站点单独设置请求频率、并发数和请求体上限。预设有 New API 网关、API/AI 服务（流式长连接）和普通网站三种；也可以给登录、注册这类路径单独设置更严格的限流。
- **防火墙**：ufw（服务器已在运行 firewalld 时改用 firewalld），默认拒绝所有入站，自动放行 SSH、80、443。启用后 180 秒内没确认 SSH 还能登录，会自动恢复原来的规则，防止把自己锁在外面。
- **fail2ban**：封禁 SSH 暴力破解，以及频繁触发限流的 IP，重复违规的封禁时间逐次加长。
- **系统加固**：内核网络参数、自动安装安全更新，可选禁止 root 直接 SSH 登录。
- **SSH 爆破记录**：每天有哪些 IP 在试密码、试了哪些用户名、有没有被封；可以每天自动保存一份。

不会修改容器、Compose、数据库、Cloudflare Tunnel，也不改 SSH 端口和密码登录方式。

## 安装

以 root 身份（先 `su` 或 `sudo -i`）执行：

```bash
curl -fsSL https://raw.githubusercontent.com/coeeshu/direct-access/main/install.sh | bash
```

安装后输入 `dsite` 打开菜单。

要求：Debian / Ubuntu 这类使用 apt 和 systemd 的 Linux，root 权限。

## 使用

| 命令 | 作用 |
| --- | --- |
| `dsite` | 打开菜单 |
| `dsite list` | 列出直连站点 |
| `dsite on 站点名` / `dsite off 站点名` | 开启 / 关闭某个站点的直连 |
| `dsite status` | 状态与诊断 |
| `dsite check` | 环境检查（只读） |
| `dsite ssh-report 7d` | 最近 7 天的 SSH 登录 / 爆破记录（也可以用 `today`、`yesterday`、`30d`） |
| `dsite update` | 更新到最新版 |

第一次使用：

1. 菜单 1「环境检查」：只读，查看端口、防火墙、Docker 服务。
2. 云厂商安全组的**入方向**放行 TCP 80、443（菜单 12 有详细说明）。
3. 菜单 2「服务器首次部署」：依次安装依赖、配置防火墙、fail2ban、系统加固，然后添加第一个站点。
4. 以后要加新服务：先在 Cloudflare 添加一条 A 记录指向服务器 IP，代理状态选「仅 DNS」（灰云），再用菜单 3「添加直连站点」。

## 文件位置

| 路径 | 内容 |
| --- | --- |
| `/etc/direct-sites/` | 全局设置、每个站点的配置 |
| `/etc/nginx/conf.d/direct-sites-http.conf`、`/etc/nginx/sites-available/direct-site*.conf` | 生成的 Nginx 配置 |
| `/etc/fail2ban/jail.d/direct-sites.local` | fail2ban 规则 |
| `/var/backups/direct-sites/` | 每次修改前的备份 |
| `/var/log/direct-sites/ssh/` | 每日 SSH 记录 |

Nginx、fail2ban、sshd 的配置检查不通过时，会自动恢复本次修改前的文件。

## 开发

```bash
python3 -B -m unittest test_direct_access -v
shellcheck -s bash -S warning direct-access.sh install.sh
```

测试只在临时目录里生成配置，不会修改系统。

## 鸣谢

感谢 [LINUX DO](https://linux.do/) 社区。
