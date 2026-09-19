-- 莓桃工作台：每分钟调用 DDL 推送 Edge Function
-- 前提：
-- 1) 已运行 2026-09-19_push_reminders.sql
-- 2) 已部署 Edge Function：send-due-reminders
-- 3) 已配置 VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY / VAPID_SUBJECT
--
-- 本文件按 Supabase 官方推荐方式使用 Cron + pg_net + Vault。
-- 只运行一次。

create extension if not exists pg_cron;
create extension if not exists pg_net;

-- 把项目 URL 与 publishable key 放进 Vault。
-- publishable key 本身不是服务端秘密，但放 Vault 可以避免 Cron SQL 到处复制它。
select vault.create_secret(
  'https://cwzeknrjetwbczqgmdit.supabase.co',
  'berry_push_project_url'
);

select vault.create_secret(
  'sb_publishable_kI3ZY_VCFSHIn1sVm1xJ1Q_b9zZAGV2',
  'berry_push_publishable_key'
);

select cron.schedule(
  'berry-ddl-push-every-minute',
  '* * * * *',
  $$
  select net.http_post(
    url := (
      select decrypted_secret
      from vault.decrypted_secrets
      where name = 'berry_push_project_url'
      order by created_at desc
      limit 1
    ) || '/functions/v1/send-due-reminders',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'apikey', (
        select decrypted_secret
        from vault.decrypted_secrets
        where name = 'berry_push_publishable_key'
        order by created_at desc
        limit 1
      )
    ),
    body := '{}'::jsonb,
    timeout_milliseconds := 5000
  ) as request_id;
  $$
);

-- 检查任务：
-- select jobid, jobname, schedule, active from cron.job
-- where jobname = 'berry-ddl-push-every-minute';

-- 查看最近执行结果：
-- select * from cron.job_run_details
-- order by start_time desc
-- limit 20;
