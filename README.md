# 莓桃工作台

粉白色个人接单工作台，已升级为 Supabase 自动多端同步版。

## 云同步完成前只需要做两件事

### 1. 初始化数据库

在 Supabase 项目中打开 **SQL Editor**，新建 Query，把仓库里的 `supabase_setup.sql` 全部复制进去，然后点击 **Run**。

这个脚本会：
- 创建 `workspaces` 表
- 开启 Row Level Security
- 让每个账号只能读写自己的工作台
- 开启 Realtime，同一账号多设备自动同步

### 2. 配置登录回跳网址

在 Supabase 打开 **Authentication → URL Configuration**。

- Site URL: `https://jiaj200405-cmd.github.io/berry-workbench/`
- Redirect URLs: 添加 `https://jiaj200405-cmd.github.io/berry-workbench/**`

之后即可在工作台页面用邮箱 + 密码注册和登录。

## 使用效果

- 同一个账号：手机 / 电脑 / iPad 自动同步。
- 不同账号：数据完全分开。
- 工作台标题也会跟随账号同步。
- 浏览器里仍保留本地缓存作为临时备份。
- 第一次登录时如果检测到旧版本地数据，会询问是否迁移到当前云账号。

## 安全边界

网页中使用的是 Supabase Publishable Key，它本来就是给前端浏览器使用的。不要把 Supabase Secret Key 或 service_role key 放进网页或公开仓库。


## 当前数据库维护（2026-09-20）

生产库权限已经收口到：

`migrations/2026-09-20_final_permission_lockdown.sql`

这个文件统一处理：
- 美工注册与 7 天通用邀请码
- 普通美工角色 / 资料 / 顾客码补齐
- 到期美工只读
- 顾客端不误伤
- 顾客预算、顾客专属码、顾客聊天、美工好友与好友聊天的服务端权限
- 清理旧注册 trigger 与旧 Owner-only RLS

`invite_setup.sql` 现在只是旧版兼容清理入口，不再创建旧注册逻辑。

`database_setup_current.sql` 只作为核心结构参考；完整新环境还需要按日期运行 `migrations/`，最后运行最终权限收口 migration。
