const MAX_EMBED_DESCRIPTION = 4_000;

function truncate(value, maxLength = MAX_EMBED_DESCRIPTION) {
  const text = String(value ?? "");
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}

function auditTitle(action) {
  return String(action || "updated")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function auditPayload(log) {
  const details = log.details ?? null;
  const detailJson = JSON.stringify(details, null, 2);
  const summary = [
    `**Admin:** ${log.admin_name || "Tidak diketahui"}`,
    `**Aksi:** ${log.action || "updated"}`,
    `**Entitas:** ${log.entity_type || "unknown"} #${log.entity_id || "-"}`,
    `**Waktu:** ${log.created_at || new Date().toISOString()}`,
    details ? `**Detail:**\n\`\`\`json\n${truncate(detailJson, 3_600)}\n\`\`\`` : "**Detail:** tidak ada",
  ].join("\n");

  return {
    username: "Riverra Audit Log",
    allowed_mentions: { parse: [] },
    embeds: [{
      title: `Audit: ${auditTitle(log.action)}`,
      description: truncate(summary),
      color: 0xD4AF37,
      timestamp: log.created_at || new Date().toISOString(),
      footer: { text: `Audit ID: ${log.id || "baru"}` },
    }],
  };
}

async function postWebhook(webhookUrl, payload) {
  const response = await fetch(`${webhookUrl}?wait=true`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error(`Discord webhook gagal (${response.status})`);
  }
}

async function sendAuditLog(log) {
  const webhookUrl = process.env.DISCORD_AUDIT_WEBHOOK_URL;
  if (!webhookUrl) throw new Error("DISCORD_AUDIT_WEBHOOK_URL belum dikonfigurasi.");
  await postWebhook(webhookUrl, auditPayload(log));
  return { sent: true };
}

async function sendAuditHistory(logs) {
  const webhookUrl = process.env.DISCORD_AUDIT_WEBHOOK_URL;
  if (!webhookUrl) throw new Error("DISCORD_AUDIT_WEBHOOK_URL belum dikonfigurasi.");
  if (!Array.isArray(logs) || logs.length === 0) return 0;

  // Discord accepts up to 10 embeds per webhook message. Batching keeps a
  // one-time history sync within normal webhook rate limits.
  for (let index = 0; index < logs.length; index += 10) {
    const batch = logs.slice(index, index + 10);
    await postWebhook(webhookUrl, {
      username: "Riverra Audit Log",
      allowed_mentions: { parse: [] },
      embeds: batch.map((log) => auditPayload(log).embeds[0]),
    });
  }
  return logs.length;
}

module.exports = { sendAuditHistory, sendAuditLog };
