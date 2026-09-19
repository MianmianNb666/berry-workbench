import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import {
  buildPushPayload,
  type PushSubscription,
  type VapidKeys,
} from "npm:@block65/webcrypto-web-push@2.0.0";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const VAPID_PUBLIC_KEY = Deno.env.get("VAPID_PUBLIC_KEY")!;
const VAPID_PRIVATE_KEY = Deno.env.get("VAPID_PRIVATE_KEY")!;
const VAPID_SUBJECT =
  Deno.env.get("VAPID_SUBJECT") ||
  "https://mianmiannb666.github.io/berry-workbench/";
const CRON_SECRET = Deno.env.get("CRON_SECRET")!;

const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const vapid: VapidKeys = {
  subject: VAPID_SUBJECT,
  publicKey: VAPID_PUBLIC_KEY,
  privateKey: VAPID_PRIVATE_KEY,
};

type Reminder = {
  id: string;
  user_id: string;
  order_id: string;
  order_name: string;
  reminder_type: "1d" | "3h" | "custom";
  due_at: string;
  remind_at: string;
  message: string;
};

type StoredSubscription = {
  endpoint: string;
  p256dh: string;
  auth: string;
};

export default {
  async fetch(req: Request): Promise<Response> {
    if (req.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    if (!CRON_SECRET || req.headers.get("x-cron-secret") !== CRON_SECRET) {
      return new Response("Unauthorized", { status: 401 });
    }

    if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
      return Response.json(
        { ok: false, error: "VAPID secrets are not configured" },
        { status: 500 },
      );
    }

    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

    const { data: reminders, error: reminderError } = await supabase
      .from("order_reminders")
      .select(
        "id,user_id,order_id,order_name,reminder_type,due_at,remind_at,message",
      )
      .is("sent_at", null)
      .lte("remind_at", now.toISOString())
      .gte("remind_at", oneHourAgo.toISOString())
      .order("remind_at", { ascending: true })
      .limit(100);

    if (reminderError) {
      console.error("Failed to fetch reminders", reminderError);
      return Response.json(
        { ok: false, error: reminderError.message },
        { status: 500 },
      );
    }

    let sent = 0;
    let failed = 0;
    let noDevice = 0;

    for (const reminder of (reminders || []) as Reminder[]) {
      const { data: subscriptions, error: subscriptionError } = await supabase
        .from("push_subscriptions")
        .select("endpoint,p256dh,auth")
        .eq("user_id", reminder.user_id);

      if (subscriptionError) {
        console.error("Failed to fetch subscriptions", reminder.id, subscriptionError);
        failed += 1;
        continue;
      }

      if (!subscriptions?.length) {
        noDevice += 1;
        continue;
      }

      let delivered = 0;

      for (const row of subscriptions as StoredSubscription[]) {
        const subscription: PushSubscription = {
          endpoint: row.endpoint,
          expirationTime: null,
          keys: {
            p256dh: row.p256dh,
            auth: row.auth,
          },
        };

        try {
          const payload = await buildPushPayload(
            {
              data: {
                title: "🍓 莓桃工作台",
                body: reminder.message,
                tag: "berry-reminder-" + reminder.id,
                url: "./",
              },
              options: {
                ttl: 60 * 60,
                urgency: "high",
                topic: ("berry-" + reminder.id).slice(0, 32),
              },
            },
            subscription,
            vapid,
          );

          const response = await fetch(subscription.endpoint, payload);

          if (response.ok) {
            delivered += 1;
            continue;
          }

          if (response.status === 404 || response.status === 410) {
            await supabase
              .from("push_subscriptions")
              .delete()
              .eq("endpoint", row.endpoint);
          } else {
            console.error(
              "Push service rejected notification",
              response.status,
              reminder.id,
            );
          }
        } catch (error) {
          console.error("Push send failed", reminder.id, error);
        }
      }

      if (delivered > 0) {
        const { error: updateError } = await supabase
          .from("order_reminders")
          .update({ sent_at: new Date().toISOString() })
          .eq("id", reminder.id)
          .is("sent_at", null);

        if (updateError) {
          console.error("Failed to mark reminder sent", reminder.id, updateError);
        } else {
          sent += 1;
        }
      } else {
        failed += 1;
      }
    }

    return Response.json({
      ok: true,
      checked: reminders?.length || 0,
      sent,
      failed,
      noDevice,
      at: now.toISOString(),
    });
  },
};
