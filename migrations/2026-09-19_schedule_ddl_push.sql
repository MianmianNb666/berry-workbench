-- 莓桃工作台：每分钟调用 DDL 推送 Edge Function
-- 前提：
-- 1) 已运行 2026-09-19_push_reminders.sql
-- 2) 已部署 Edge Function：send-due-reminders
-- 3) 已配置 Edge Function Secrets：
--    VAPID_PUBLIC_KEY
--    VAPID_PRIVATE_KEY
--    VAPID_SUBJECT
--    CRON_SECRET
--
-- 重要：下面的 YOUR_CRON_SECRET 必须和 Edge Function 的 CRON_SECRET 完全一致。
-- 只运行一次。

create extension if not exists pg_cron;
create extension if not exists pg_net;

-- 保存项目 URL 和 Cron 密钥到 Vault。
select vault.create_secret(
  'https://cwzeknrjetwbczqgmdit.supabase.co',
  'berry_push_project_url'
);

select vault.create_secret(
  'YOUR_CRON_SECRET',
  'berry_push_cron_secret'
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
      'x-cron-secret', (
        select decrypted_secret
        from vault.decrypted_secrets
        where name = 'berry_push_cron_secret'
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
-- select jobid, jobname, schedule, active
-- from cron.job
-- where jobname = 'berry-ddl-push-every-minute';

-- 查看最近执行结果：
-- select *
-- from cron.job_run_details
-- order by start_time desc
-- limit 20;
