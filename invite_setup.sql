-- LEGACY FILE · 已停用
-- 旧版 invite_setup.sql 曾创建 trg_require_invite_on_signup，
-- 会与当前注册系统重复处理邀请码，并可能导致：
--   Database error saving new user
--
-- 当前注册逻辑统一由：
--   public.handle_new_user_access()
--   trg_handle_new_user_access
-- 负责。
--
-- 如果误运行过旧版，本文件现在只负责清理旧 trigger / function，
-- 不再创建任何旧邀请码结构。

begin;

drop trigger if exists trg_require_invite_on_signup
on auth.users;

drop function if exists public.consume_invite_on_signup();

commit;

select
  'OK' as status,
  'Legacy invite trigger removed; current signup flow is unchanged.' as detail;
