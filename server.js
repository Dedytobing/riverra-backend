require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { sendAuditLog } = require("./src/services/discord-webhook.service");
const JWT_SECRET = process.env.JWT_SECRET;

const app = express();

const FRONTEND_ORIGIN = process.env.FRONTEND_URL;
const isProduction = process.env.NODE_ENV === "production";
const ACCESS_COOKIE = "riverra_access";
const REFRESH_COOKIE = "riverra_refresh";
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET || JWT_SECRET;

function parseCookies(header = "") {
  return Object.fromEntries(header.split(";").map(part => {
    const index = part.indexOf("=");
    return index < 0 ? ["", ""] : [part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1).trim())];
  }).filter(([key]) => key));
}

function cookieOptions(maxAge) {
  return `Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=${isProduction ? "None" : "Lax"}${isProduction ? "; Secure" : ""}`;
}

function tokenHash(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function setSessionCookies(res, user) {
  const access = jwt.sign({ ...user, type: "access" }, JWT_SECRET, { expiresIn: "15m" });
  const sessionId = crypto.randomUUID();
  const refresh = jwt.sign({ id: user.id, type: "refresh", jti: sessionId }, REFRESH_SECRET, { expiresIn: "30d" });
  const { error } = await supabase.from("admin_sessions").insert({
    id: sessionId,
    admin_id: user.id,
    refresh_token_hash: tokenHash(refresh),
    expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
  });
  if (error) throw error;
  res.setHeader("Set-Cookie", [
    `${ACCESS_COOKIE}=${encodeURIComponent(access)}; ${cookieOptions(15 * 60)}`,
    `${REFRESH_COOKIE}=${encodeURIComponent(refresh)}; ${cookieOptions(30 * 24 * 60 * 60)}`,
  ]);
}

function clearSessionCookies(res) {
  res.setHeader("Set-Cookie", [
    `${ACCESS_COOKIE}=; ${cookieOptions(0)}`,
    `${REFRESH_COOKIE}=; ${cookieOptions(0)}`,
  ]);
}

app.use(
  cors({
    origin: FRONTEND_ORIGIN,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());

const requestCounts = new Map();
app.set("trust proxy", 1);
app.use((req, res, next) => {
  const key = `${req.ip}:${req.path}`;
  const now = Date.now();
  const current = requestCounts.get(key) || { count: 0, reset: now + 60_000 };
  if (now > current.reset) { current.count = 0; current.reset = now + 60_000; }
  current.count += 1;
  requestCounts.set(key, current);
  const limit = req.path.startsWith("/api/auth") || req.path.includes("upload") ? 30 : 300;
  if (current.count > limit) return res.status(429).json({ success: false, message: "Terlalu banyak permintaan. Coba lagi nanti." });
  next();
});
const rateLimitCleanup = setInterval(() => {
  const now = Date.now();
  for (const [key, value] of requestCounts) {
    if (value.reset < now) requestCounts.delete(key);
  }
}, 60_000);
rateLimitCleanup.unref();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);
const STAFF_ROLES = ["SuperAdmin", "PJ Ime", "PJ Hope", "PJ GP", "PJ SM", "Member"];
const LEGACY_ROLE_MAP = { "Super Admin": "SuperAdmin", "PJ Server": "PJ Ime", "PJ Universal": "PJ Hope" };
const VALID_PERMISSIONS = new Set(["administrator", "audit.view", "server.manage", "roles.add", "roles.edit", "roles.delete", "gallery.add", "gallery.edit", "gallery.delete", "members.add", "members.edit", "members.delete"]);
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

function auth(req, res, next) {
  try {
    const cookies = parseCookies(req.headers.cookie);
    const token = req.headers.authorization?.replace(/^Bearer\s+/i, "") || cookies[ACCESS_COOKIE];
    if (!token)
      return res
        .status(401)
        .json({ success: false, message: "Login diperlukan." });
    req.admin = jwt.verify(token, JWT_SECRET);
    if (req.admin.type && req.admin.type !== "access") throw new Error("Token type tidak valid");
    next();
  } catch {
    return res
      .status(401)
      .json({ success: false, message: "Token tidak valid atau kedaluwarsa." });
  }
}
function isSuperAdminRecord(admin) {
  return admin?.primary_role === "SuperAdmin" || admin?.role === "SuperAdmin" || admin?.role === "Super Admin" || (admin?.roles || []).includes("SuperAdmin");
}

async function loadAdmin(req, res, next) {
  try {
    const { data, error } = await supabase.from("admin_users")
      .select("id,name,email,role,primary_role,roles,permissions,is_active,discord_avatar,discord_id")
      .eq("id", req.admin.id).single();
    if (error || !data?.is_active || !(data.primary_role || data.role)) return res.status(403).json({ success: false, message: "Akses admin tidak aktif." });
    req.admin = { ...req.admin, ...data, roles: data.roles || [], permissions: data.permissions || [], role: data.primary_role || data.role, avatar: data.discord_avatar, discordId: data.discord_id };
    next();
  } catch (error) { next(error); }
}

const allow = (...permissions) => [loadAdmin, (req, res, next) => {
  const grants = new Set(req.admin.permissions || []);
  if (isSuperAdminRecord(req.admin) || grants.has("administrator") || permissions.some((permission) => grants.has(permission))) return next();
  return res.status(403).json({ success: false, message: "Akses ditolak." });
}];
const superAdminOnly = [loadAdmin, (req, res, next) => isSuperAdminRecord(req.admin) ? next() : res.status(403).json({ success: false, message: "Hanya SuperAdmin yang dapat mengatur akses." })];
async function audit(admin, action, entityType, entityId, details = null) {
  const { data, error } = await supabase
    .from("audit_logs")
    .insert({
      admin_id: admin.id,
      admin_name: admin.name,
      action,
      entity_type: entityType,
      entity_id: String(entityId),
      details,
    })
    .select()
    .single();
  if (error) throw error;

  await deliverAuditLog(data);
  return data;
}
async function updateAuditDelivery(log, values) {
  const { error } = await supabase.from("audit_logs").update(values).eq("id", log.id);
  if (error) throw error;
}
async function deliverAuditLog(log) {
  const attempts = Number(log.discord_delivery_attempts || 0) + 1;
  try {
    await sendAuditLog(log);
    await updateAuditDelivery(log, { discord_sent_at: new Date().toISOString(), discord_delivery_attempts: attempts, discord_last_error: null });
    return true;
  } catch (error) {
    // Delivery failure must not undo a website update. Keep it in the retry queue.
    try {
      await updateAuditDelivery(log, { discord_delivery_attempts: attempts, discord_last_error: String(error.message || "Discord delivery failed").slice(0, 1000) });
    } catch (statusError) {
      console.error("Audit delivery status update failed:", statusError.message);
    }
    console.error("Discord audit notification failed:", error.message);
    return false;
  }
}
app.get("/api/audit-logs", auth, allow("audit.view"), async (req,res)=>{const {data,error}=await supabase.from("audit_logs").select("*").order("created_at",{ascending:false}).limit(500);if(error)return res.status(500).json({success:false,message:error.message});res.json({success:true,data})});
app.get("/api/audit-logs/discord-status", auth, allow("administrator"), async (req, res) => {
  const { count, error } = await supabase.from("audit_logs").select("id", { count: "exact", head: true }).is("discord_sent_at", null);
  if (error) return res.status(500).json({ success: false, message: error.message });
  res.json({ success: true, pending: count || 0 });
});
app.post("/api/audit-logs/discord-sync", auth, allow("administrator"), async (req, res) => {
  try {
    const pageSize = 500;
    const pendingLogs = [];
    for (let start = 0; ; start += pageSize) {
      const { data, error } = await supabase
        .from("audit_logs")
        .select("*")
        .is("discord_sent_at", null)
        .order("created_at", { ascending: true })
        .range(start, start + pageSize - 1);
      if (error) throw error;
      pendingLogs.push(...(data || []));
      if (!data || data.length < pageSize) break;
    }
    let sent = 0;
    let failed = 0;
    for (const log of pendingLogs) {
      if (await deliverAuditLog(log)) sent += 1;
      else failed += 1;
    }
    const message = sent === 0 && failed === 0 ? "Tidak ada audit log pending untuk dikirim." : `${sent} audit log terkirim${failed ? `, ${failed} masih gagal.` : "."}`;
    res.json({ success: true, message, sent, failed });
  } catch (error) {
    res.status(502).json({ success: false, message: error.message || "Sinkronisasi Discord gagal." });
  }
});
app.get("/api/backups/members", auth, allow("administrator"), async (req,res)=>{const {data,error}=await supabase.from("members").select("*").order("id");if(error)return res.status(500).json({success:false,message:error.message});res.json({success:true,backup:{version:1,created_at:new Date().toISOString(),members:data}})});
app.post("/api/backups/members/restore", auth, allow("administrator"), async (req,res)=>{try{const rows=req.body?.members;if(!Array.isArray(rows)||rows.length>10000)return res.status(400).json({success:false,message:"Format backup tidak valid."});const {data,error}=await supabase.rpc("restore_members_backup",{p_rows:rows,p_actor:req.admin.name});if(error)throw error;await audit(req.admin,"restored","members","all",{count:data?.length||0});res.json({success:true,message:"Backup berhasil dipulihkan.",data:data||[]})}catch(e){res.status(500).json({success:false,message:"Restore gagal. Tidak ada perubahan yang diterapkan."})}});

app.get("/api/auth/discord", (req, res) => {
  const state = jwt.sign({ purpose: "discord_oauth" }, JWT_SECRET, { expiresIn: "10m" });
  const params = new URLSearchParams({ client_id: process.env.DISCORD_CLIENT_ID, redirect_uri: DISCORD_REDIRECT_URI, response_type: "code", scope: "identify email", state });
  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});
app.get("/api/auth/discord/callback", async (req, res) => {
  try {
    const state = jwt.verify(req.query.state, JWT_SECRET);
    if (state.purpose !== "discord_oauth" || !req.query.code) throw new Error("OAuth Discord tidak valid.");
    const tokenResponse = await fetch("https://discord.com/api/oauth2/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: process.env.DISCORD_CLIENT_ID, client_secret: process.env.DISCORD_CLIENT_SECRET, grant_type: "authorization_code", code: req.query.code, redirect_uri: DISCORD_REDIRECT_URI }) });
    const discordToken = await tokenResponse.json();
    if (!tokenResponse.ok) throw new Error(discordToken.error_description || "Gagal mengambil token Discord.");
    const profileResponse = await fetch("https://discord.com/api/users/@me", { headers: { Authorization: `Bearer ${discordToken.access_token}` } });
    const profile = await profileResponse.json();
    if (!profileResponse.ok) throw new Error("Gagal mengambil profil Discord.");
    const avatarExtension = profile.avatar?.startsWith("a_") ? "gif" : "png";
    const avatar = profile.avatar ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.${avatarExtension}?size=256` : null;
    const bannerExtension = profile.banner?.startsWith("a_") ? "gif" : "png";
    const banner = profile.banner ? `https://cdn.discordapp.com/banners/${profile.id}/${profile.banner}.${bannerExtension}?size=600` : null;
    const avatarDecoration = profile.avatar_decoration_data || null;
    const nameplate = profile.collectibles?.nameplate || null;
    const primaryGuild = profile.primary_guild || null;
    const discordProfile = {
      discord_username: profile.username,
      discord_global_name: profile.global_name || null,
      discord_avatar: avatar,
      discord_banner: banner,
      discord_accent_color: profile.accent_color || null,
      discord_avatar_decoration: avatarDecoration?.asset || null,
      discord_avatar_decoration_sku_id: avatarDecoration?.sku_id || null,
      discord_nameplate: nameplate?.asset || null,
      discord_nameplate_sku_id: nameplate?.sku_id || null,
      discord_nameplate_palette: nameplate?.palette || null,
      discord_primary_guild_id: primaryGuild?.identity_guild_id || null,
      discord_primary_guild_tag: primaryGuild?.tag || null,
      discord_primary_guild_badge: primaryGuild?.badge || null,
      discord_primary_guild_enabled: primaryGuild?.identity_enabled ?? null,
      discord_profile_updated_at: new Date().toISOString(),
    };
    let { data: admin } = await supabase.from("admin_users").select("*").eq("discord_id", profile.id).maybeSingle();
    if (!admin) {
      const result = await supabase.from("admin_users").insert({ discord_id: profile.id, name: profile.global_name || profile.username, email: profile.email || `${profile.id}@discord.local`, ...discordProfile, role: null, is_active: false }).select("*").single();
      if (result.error) throw result.error; admin = result.data;
    } else {
      const result = await supabase.from("admin_users").update({ name: profile.global_name || profile.username, email: profile.email || admin.email, ...discordProfile }).eq("id", admin.id).select("*").single();
      if (result.error) throw result.error; admin = result.data;
    }
    if (!admin.is_active || !(admin.primary_role || admin.role)) return res.redirect(`${FRONTEND_URL}/admin?auth_error=${encodeURIComponent("Akun Discord terdaftar, tetapi belum disetujui Super Admin.")}`);
    const user = { id: admin.id, name: admin.name, email: admin.email, role: admin.primary_role || admin.role, primary_role: admin.primary_role || admin.role, roles: admin.roles || [], permissions: admin.permissions || [], avatar: admin.discord_avatar, discordId: admin.discord_id };
    await setSessionCookies(res, user);
    res.redirect(`${FRONTEND_URL}/admin`);
  } catch (error) {
    res.redirect(`${FRONTEND_URL}/admin?auth_error=${encodeURIComponent(error.message)}`);
  }
});

app.post("/api/auth/refresh", async (req, res) => {
  try {
    const refresh = parseCookies(req.headers.cookie)[REFRESH_COOKIE];
    if (!refresh) return res.status(401).json({ success: false, message: "Session tidak ditemukan." });
    const payload = jwt.verify(refresh, REFRESH_SECRET);
    if (payload.type !== "refresh" || !payload.jti) throw new Error("Refresh token tidak valid.");
    const { data: session, error: sessionError } = await supabase.from("admin_sessions").select("id,refresh_token_hash,expires_at,revoked_at").eq("id", payload.jti).eq("admin_id", payload.id).single();
    if (sessionError || !session || session.revoked_at || new Date(session.expires_at) <= new Date() || session.refresh_token_hash !== tokenHash(refresh)) throw new Error("Refresh token telah dicabut.");
    const { data: admin, error } = await supabase.from("admin_users").select("id,name,email,role,primary_role,roles,permissions,is_active,discord_avatar,discord_id").eq("id", payload.id).single();
    if (error || !admin?.is_active || !(admin.primary_role || admin.role)) throw new Error("Akses admin tidak aktif.");
    const { error: revokeError } = await supabase.from("admin_sessions").update({ revoked_at: new Date().toISOString() }).eq("id", session.id).is("revoked_at", null);
    if (revokeError) throw revokeError;
    await setSessionCookies(res, { id: admin.id, name: admin.name, email: admin.email, role: admin.primary_role || admin.role, primary_role: admin.primary_role || admin.role, roles: admin.roles || [], permissions: admin.permissions || [], avatar: admin.discord_avatar, discordId: admin.discord_id });
    res.json({ success: true, data: admin });
  } catch {
    clearSessionCookies(res);
    res.status(401).json({ success: false, message: "Session kedaluwarsa. Silakan masuk kembali." });
  }
});

app.post("/api/auth/logout", async (req, res) => {
  const refresh = parseCookies(req.headers.cookie)[REFRESH_COOKIE];
  if (refresh) {
    try {
      const payload = jwt.verify(refresh, REFRESH_SECRET);
      if (payload.type === "refresh" && payload.jti) await supabase.from("admin_sessions").update({ revoked_at: new Date().toISOString() }).eq("id", payload.jti);
    } catch { /* Invalid/expired cookies are cleared below. */ }
  }
  clearSessionCookies(res);
  res.json({ success: true });
});

app.all(["/api/auth/register", "/api/auth/login"], (req, res) => res.status(410).json({ success: false, message: "Login email/password dinonaktifkan. Gunakan Discord." }));

app.get("/api/auth/me", auth, loadAdmin, (req, res) =>
  res.json({ success: true, data: req.admin })
);
app.post("/api/auth/heartbeat", auth, loadAdmin, async (req,res)=>{const {error}=await supabase.from("admin_users").update({last_seen_at:new Date().toISOString()}).eq("id",req.admin.id);if(error)return res.status(500).json({success:false,message:error.message});res.json({success:true})});
app.get("/api/admins/online", auth, loadAdmin, async (req,res)=>{const cutoff=new Date(Date.now()-2*60*1000).toISOString();const {data,error}=await supabase.from("admin_users").select("id,name,email,role,primary_role,roles,discord_avatar,last_seen_at").eq("is_active",true).gte("last_seen_at",cutoff).order("last_seen_at",{ascending:false});if(error)return res.status(500).json({success:false,message:error.message});res.json({success:true,data})});
// Public directory: deliberately expose only fields that are safe to publish.
// The data is read from the same admin_users record updated by the profile endpoint,
// so a renamed profile is reflected on the next directory request without duplication.
app.get("/api/admins/directory", async (req, res) => {
  const { data, error } = await supabase
    .from("admin_users")
    .select("id,name,role,primary_role,roles,discord_id,discord_username,discord_global_name,discord_avatar,discord_banner,discord_accent_color,discord_avatar_decoration,discord_avatar_decoration_sku_id,discord_nameplate,discord_nameplate_sku_id,discord_nameplate_palette,discord_primary_guild_id,discord_primary_guild_tag,discord_primary_guild_badge,discord_primary_guild_enabled,discord_profile_updated_at")
    .eq("is_active", true)
    .not("primary_role", "is", null)
    .order("primary_role")
    .order("name");
  if (error) return res.status(500).json({ success: false, message: error.message });
  res.set("Cache-Control", "no-store");
  res.json({ success: true, data: data.map((admin) => ({
    ...admin,
    discord_profile_url: `https://discord.com/users/${admin.discord_id}`,
    discord_dm_url: `discord://-/users/${admin.discord_id}`,
  })) });
});
app.patch("/api/auth/profile", auth, loadAdmin, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    if (!name || name.length > 80) return res.status(400).json({ success:false, message:"Nama profil tidak valid." });
    const { data, error } = await supabase.from("admin_users").update({ name }).eq("id", req.admin.id).select("id,name,email,role,is_active,discord_avatar,discord_username,discord_id").single();
    if (error) throw error;
    // Keep this request's actor metadata aligned with the canonical profile record.
    req.admin.name = data.name;
    await audit(req.admin, "profile_updated", "admin", req.admin.id);
    res.json({ success:true, data });
  } catch (error) { res.status(500).json({ success:false, message:error.message }); }
});
app.get("/api/admins", auth, superAdminOnly, async (req, res) => {
  const { data, error } = await supabase
    .from("admin_users")
    .select("id,name,email,role,primary_role,roles,permissions,is_active,created_at")
    .order("created_at");
  if (error)
    return res.status(500).json({ success: false, message: error.message });
  res.json({ success: true, data: (data || []).map((account) => ({ ...account, roles: account.roles || [], permissions: account.permissions || [] })) });
});
app.patch(
  "/api/admins/:id/access",
  auth,
  superAdminOnly,
  async (req, res) => {
    try {
      if (req.params.id === String(req.admin.id))
        return res
          .status(400)
          .json({
            success: false,
            message: "Tidak dapat mengubah akses sendiri.",
          });
      const { data: target, error: targetError } = await supabase.from("admin_users")
        .select("id,role,primary_role,roles,permissions,is_active")
        .eq("id", req.params.id).single();
      if (targetError || !target) return res.status(404).json({ success: false, message: "Akun admin tidak ditemukan." });
      const primaryRole = req.body.primaryRole ?? req.body.primary_role ?? target.primary_role ?? LEGACY_ROLE_MAP[target.role] ?? target.role;
      const rolesInput = req.body.roles ?? target.roles ?? [];
      const permissionsInput = req.body.permissions ?? target.permissions ?? [];
      const isActive = typeof req.body.isActive === "boolean" ? req.body.isActive : target.is_active;
      if (!STAFF_ROLES.includes(primaryRole)) return res.status(400).json({ success: false, message: "Jabatan utama tidak valid." });
      if (!Array.isArray(rolesInput) || rolesInput.some((role) => !STAFF_ROLES.includes(role))) return res.status(400).json({ success: false, message: "Daftar jabatan tidak valid." });
      if (!Array.isArray(permissionsInput) || permissionsInput.some((permission) => !VALID_PERMISSIONS.has(permission))) return res.status(400).json({ success: false, message: "Daftar izin tidak valid." });
      const roles = [...new Set([...rolesInput, primaryRole])];
      const permissions = [...new Set(permissionsInput)];
      const willRemainSuperAdmin = primaryRole === "SuperAdmin" || roles.includes("SuperAdmin");
      if (isSuperAdminRecord(target) && (!willRemainSuperAdmin || !isActive)) {
        const { data: accounts, error: accountsError } = await supabase.from("admin_users").select("id,role,primary_role,roles,is_active").eq("is_active", true);
        if (accountsError) throw accountsError;
        if ((accounts || []).filter(isSuperAdminRecord).length <= 1) return res.status(400).json({ success: false, message: "Harus tersedia setidaknya satu SuperAdmin aktif." });
      }
      const { data, error } = await supabase.from("admin_users")
        .update({ role: primaryRole, primary_role: primaryRole, roles, permissions, is_active: isActive, updated_at: new Date().toISOString() })
        .eq("id", req.params.id)
        .select("id,name,email,role,primary_role,roles,permissions,is_active")
        .single();
      if (error) throw error;
      await audit(req.admin, "access_updated", "admin", req.params.id, { primary_role: data.primary_role, roles: data.roles, permissions: data.permissions, is_active: data.is_active });
      res.json({ success: true, data });
    } catch (e) {
      res.status(500).json({ success: false, message: e.message });
    }
  }
);
app.delete("/api/admins/:id", auth, superAdminOnly, async (req, res) => {
  if (req.params.id === String(req.admin.id))
    return res
      .status(400)
      .json({ success: false, message: "Tidak dapat menghapus akun sendiri." });
  const { data: target, error: targetError } = await supabase.from("admin_users").select("role,primary_role,roles").eq("id", req.params.id).single();
  if (targetError) return res.status(404).json({ success:false, message:"Akun admin tidak ditemukan." });
  if (isSuperAdminRecord(target)) return res.status(403).json({ success:false, message:"Akun SuperAdmin tidak dapat dihapus dari panel ini." });
  const { error } = await supabase
    .from("admin_users")
    .delete()
    .eq("id", req.params.id);
  if (error)
    return res.status(500).json({ success: false, message: error.message });
  await audit(req.admin, "deleted", "admin", req.params.id);
  res.json({ success: true, message: "Akun dihapus." });
});

function optionalId(value) {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? null : parsed;
}

function memberPayload(body) {
  const {
    firstName,
    lastName,
    gender,
    generation,
    status,
    photo,
    biography,
    occupation,
    role,
    fatherId,
    motherId,
    spouseId,
    birthDate,
    birthOrder,
    siblingType,
  } = body;

  return {
    first_name: firstName?.trim(),
    last_name: lastName?.trim() || "",
    gender,
    generation: Number.parseInt(generation, 10),
    status,
    photo: photo || "",
    biography: biography || "",
    occupation: occupation || "",
    role: role || "",
    father_id: optionalId(fatherId),
    mother_id: optionalId(motherId),
    spouse_id: optionalId(spouseId),
    birth_date: birthDate || null,
    birth_order: birthOrder ? Number.parseInt(birthOrder, 10) : null,
    sibling_type: siblingType || "full sibling",
  };
}

async function validateRelationship(payload, currentId = null) {
  const parentIds = [payload.father_id, payload.mother_id].filter(Boolean);
  if (currentId && parentIds.includes(Number(currentId))) throw new Error("Anggota tidak dapat menjadi orang tuanya sendiri.");
  if (payload.father_id && payload.mother_id && payload.father_id === payload.mother_id) throw new Error("Ayah dan ibu harus berbeda.");
  if (payload.spouse_id && currentId && payload.spouse_id === Number(currentId)) throw new Error("Anggota tidak dapat menjadi pasangannya sendiri.");
  if (parentIds.length) {
    const { data, error } = await supabase.from("members").select("id").in("id", parentIds);
    if (error) throw error;
    if (data.length !== parentIds.length) throw new Error("Relasi orang tua tidak ditemukan.");
  }
  if (payload.spouse_id) {
    const { data, error } = await supabase.from("members").select("id").eq("id", payload.spouse_id).maybeSingle();
    if (error) throw error;
    if (!data) throw new Error("Relasi pasangan tidak ditemukan.");
  }
  if (currentId) {
    const { data: ancestors, error } = await supabase.from("members").select("id,father_id,mother_id");
    if (error) throw error;
    const graph = new Map(ancestors.map(row => [row.id, row]));
    const reachesCurrentMember = startId => {
      const visited = new Set();
      const stack = [startId];
      while (stack.length) {
        const id = Number(stack.pop());
        if (!Number.isInteger(id) || id <= 0 || visited.has(id)) continue;
        if (id === Number(currentId)) return true;
        visited.add(id);
        const parent = graph.get(id);
        if (parent?.father_id) stack.push(parent.father_id);
        if (parent?.mother_id) stack.push(parent.mother_id);
      }
      return false;
    };
    for (const parentId of parentIds) {
      if (reachesCurrentMember(parentId)) throw new Error("Relasi keluarga membentuk circular reference.");
    }
  }
}

// ================================================================
// GET: Ambil seluruh anggota
// ================================================================

app.get("/api/members", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("members")
      .select("*")
      .is("deleted_at", null)
      .order("generation", { ascending: true })
      .order("birth_date", { ascending: true, nullsFirst: false })
      .order("birth_order", { ascending: true, nullsFirst: false })
      .order("id", { ascending: true });

    if (error) throw error;

    res.status(200).json({
      success: true,
      data,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
});

// ================================================================
// GET: Ambil satu anggota
// ================================================================

app.get("/api/members/:id", async (req, res) => {
  try {
    const memberId = optionalId(req.params.id);

    if (!memberId) {
      return res.status(400).json({
        success: false,
        message: "ID anggota tidak valid.",
      });
    }

    const { data, error } = await supabase
      .from("members")
      .select("*")
      .eq("id", memberId)
      .single();

    if (error) throw error;

    res.status(200).json({
      success: true,
      data,
    });
  } catch (error) {
    const status = error.code === "PGRST116" ? 404 : 500;

    res.status(status).json({
      success: false,
      message: status === 404 ? "Anggota tidak ditemukan." : error.message,
    });
  }
});

// ================================================================
// POST: Tambah anggota
// ================================================================

app.post(
  "/api/members",
  auth,
  allow("members.add"),
  async (req, res) => {
    try {
      const payload = {
        ...memberPayload(req.body),
        updated_by: req.admin.name,
        updated_at: new Date().toISOString(),
      };
      await validateRelationship(payload);

      if (!payload.first_name) {
        return res.status(400).json({
          success: false,
          message: "Nama depan wajib diisi.",
        });
      }

    if (Number.isNaN(payload.generation)) {
        return res.status(400).json({
          success: false,
          message: "Generasi harus berupa angka.",
        });
      }

      const { data: newMember, error: insertError } = await supabase
        .from("members")
        .insert([payload])
        .select()
        .single();

      if (insertError) throw insertError;
    await audit(req.admin, "created", "member", newMember.id, { member_name: `${newMember.first_name} ${newMember.last_name || ""}`.trim() });

      // Membuat relasi pasangan dua arah.
      if (payload.spouse_id) {
        const { error: spouseError } = await supabase
          .from("members")
          .update({ spouse_id: newMember.id })
          .eq("id", payload.spouse_id);

        if (spouseError) {
          console.error("Gagal memperbarui pasangan:", spouseError.message);
        }
      }

      res.status(201).json({
        success: true,
        message: "Anggota berhasil disimpan.",
        data: newMember,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message,
      });
    }
  }
);

// ================================================================
// PUT: Edit anggota
// ================================================================

app.put(
  "/api/members/:id",
  auth,
  allow("members.edit"),
  async (req, res) => {
    try {
      const memberId = optionalId(req.params.id);

      if (!memberId) {
        return res.status(400).json({
          success: false,
          message: "ID anggota tidak valid.",
        });
      }

      const payload = {
        ...memberPayload(req.body),
        updated_by: req.admin.name,
        updated_at: new Date().toISOString(),
      };
      await validateRelationship(payload, memberId);

      if (!payload.first_name) {
        return res.status(400).json({
          success: false,
          message: "Nama depan wajib diisi.",
        });
      }

      if (Number.isNaN(payload.generation)) {
        return res.status(400).json({
          success: false,
          message: "Generasi harus berupa angka.",
        });
      }

      // Ambil data lama agar relasi pasangan bisa diperbarui.
      const { data: oldMember, error: oldMemberError } = await supabase
        .from("members")
      .select("*")
        .eq("id", memberId)
        .single();

      if (oldMemberError) throw oldMemberError;

    const trackedFields = ["first_name","last_name","gender","generation","status","photo","biography","occupation","role","father_id","mother_id","spouse_id"];
    const changes = {};
    for (const field of trackedFields) {
      const before = oldMember[field] ?? null;
      const after = payload[field] ?? null;
      if (String(before) !== String(after)) changes[field] = { before, after };
    }
    if (payload.birth_order && (payload.father_id || payload.mother_id)) {
      let siblingQuery = supabase.from("members").select("id,birth_order").gte("birth_order", payload.birth_order);
      if (payload.father_id) siblingQuery = siblingQuery.eq("father_id", payload.father_id);
      if (payload.mother_id) siblingQuery = siblingQuery.eq("mother_id", payload.mother_id);
      const { data: siblings, error: siblingError } = await siblingQuery;
      if (siblingError) throw siblingError;
      for (const sibling of siblings || []) {
        const { error: shiftError } = await supabase.from("members").update({ birth_order: sibling.birth_order + 1 }).eq("id", sibling.id);
        if (shiftError) throw shiftError;
      }
    }
    const { data: updatedMember, error: updateError } = await supabase
        .from("members")
        .update(payload)
        .eq("id", memberId)
        .select()
        .single();

      if (updateError) throw updateError;
      await audit(req.admin, "edited", "member", memberId, { member_name: `${updatedMember.first_name} ${updatedMember.last_name}`.trim(), changes, changed_fields: Object.keys(changes), updated_by: req.admin.name });

      // Hapus hubungan dari pasangan sebelumnya apabila berubah.
      if (oldMember.spouse_id && oldMember.spouse_id !== payload.spouse_id) {
        await supabase
          .from("members")
          .update({ spouse_id: null })
          .eq("id", oldMember.spouse_id)
          .eq("spouse_id", memberId);
      }

      // Hubungkan pasangan baru secara dua arah.
      if (payload.spouse_id) {
        const { error: spouseError } = await supabase
          .from("members")
          .update({ spouse_id: memberId })
          .eq("id", payload.spouse_id);

        if (spouseError) throw spouseError;
      }

      res.status(200).json({
        success: true,
        message: "Data anggota berhasil diperbarui.",
        data: updatedMember,
      });
    } catch (error) {
      const status = error.code === "PGRST116" ? 404 : 500;

      res.status(status).json({
        success: false,
        message: status === 404 ? "Anggota tidak ditemukan." : error.message,
      });
    }
  }
);

// ================================================================
// DELETE: Hapus anggota
// ================================================================

app.delete(
  "/api/members/:id",
  auth,
  allow("members.delete"),
  async (req, res) => {
    try {
      const memberId = optionalId(req.params.id);

      if (!memberId) {
        return res.status(400).json({
          success: false,
          message: "ID anggota tidak valid.",
        });
      }

      const { data: member, error: findError } = await supabase
        .from("members")
        .select("*")
        .eq("id", memberId)
        .single();

      if (findError) throw findError;

      // Lepaskan referensi anggota ini dari anggota lainnya.
      const relationUpdates = [
        supabase
          .from("members")
          .update({ father_id: null })
          .eq("father_id", memberId),

        supabase
          .from("members")
          .update({ mother_id: null })
          .eq("mother_id", memberId),

        supabase
          .from("members")
          .update({ spouse_id: null })
          .eq("spouse_id", memberId),
      ];

      const relationResults = await Promise.all(relationUpdates);
      const relationError = relationResults.find((result) => result.error);

      if (relationError) {
        throw relationError.error;
      }

      const { data: deletedMember } = await supabase
        .from("members")
        .select("first_name,last_name,occupation,role,generation")
        .eq("id", memberId)
        .maybeSingle();
      const { error: deleteError } = await supabase
      .from("members")
      .update({ deleted_at: new Date().toISOString(), deleted_by: req.admin.name })
      .eq("id", memberId);

      if (deleteError) throw deleteError;
      await audit(req.admin, "deleted", "member", memberId, {
        member_name: deletedMember ? `${deletedMember.first_name} ${deletedMember.last_name || ""}`.trim() : `Member #${memberId}`,
        occupation: deletedMember?.occupation || null,
        role: deletedMember?.role || null,
        generation: deletedMember?.generation || null,
      });

      res.status(200).json({
        success: true,
        message: "Data anggota berhasil dihapus.",
        data: member,
      });
    } catch (error) {
      const status = error.code === "PGRST116" ? 404 : 500;

      res.status(status).json({
        success: false,
        message: status === 404 ? "Anggota tidak ditemukan." : error.message,
      });
    }
  }
);

// ================================================================
// Error handler
// ================================================================

app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    success: false,
    message: "Terjadi kesalahan pada server.",
  });
});
app.get("/api/members/recycle-bin", auth, allow("administrator"), async (req,res)=>{const {data,error}=await supabase.from("members").select("*").not("deleted_at","is",null).order("deleted_at",{ascending:false});if(error)return res.status(500).json({success:false,message:error.message});res.json({success:true,data})});
app.patch("/api/members/:id/restore", auth, allow("administrator"), async (req,res)=>{const {data,error}=await supabase.from("members").update({deleted_at:null,deleted_by:null}).eq("id",req.params.id).select().single();if(error)return res.status(500).json({success:false,message:error.message});await audit(req.admin,"restored","member",req.params.id);res.json({success:true,data})});

async function formatGalleryRows(rows) {
  const albumIds = [...new Set(rows.map((row) => row.album_id).filter(Boolean))];
  const userIds = [...new Set(rows.flatMap((row) => [row.created_by, row.updated_by]).filter(Boolean))];
  const [albumResult, userResult] = await Promise.all([
    albumIds.length ? supabase.from("gallery_albums").select("id,name,category_id,category_label,date_label,cover_src,description,created_at,updated_at,updated_by,created_by").in("id", albumIds) : Promise.resolve({ data: [], error: null }),
    userIds.length ? supabase.from("admin_users").select("id,name,primary_role,role").in("id", userIds) : Promise.resolve({ data: [], error: null }),
  ]);
  if (albumResult.error) throw albumResult.error;
  if (userResult.error) throw userResult.error;
  const albums = new Map((albumResult.data || []).map((album) => [album.id, album]));
  const users = new Map((userResult.data || []).map((admin) => [admin.id, admin]));
  return rows.map((row) => {
    const album = albums.get(row.album_id);
    const creator = users.get(row.created_by);
    const editor = users.get(row.updated_by);
    const uploaderName = creator?.name || (row.legacy_key ? "Riverra Archive" : "Staff");
    return {
      ...row,
      audit_by: editor?.name || uploaderName,
      uploaded_by: uploaderName,
      uploader_role: creator?.primary_role || creator?.role || null,
      audit_action: editor ? "edited" : "uploaded",
      audit_at: row.updated_at || row.created_at,
      albumId: album?.id || null,
      albumName: album?.name || null,
      albumCategoryId: album?.category_id || null,
      albumCategory: album?.category_label || null,
      albumDate: album?.date_label || null,
      albumCover: album?.cover_src || null,
      albumDescription: album?.description || "",
      albumCreatedAt: album?.created_at || null,
      albumUpdatedAt: album?.updated_at || null,
      albumUpdatedBy: album?.updated_by || null,
      publicId: row.cloud_public_id || null,
    };
  });
}

async function destroyGalleryAsset(publicId) {
  if (!publicId) return;
  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  const apiKey = process.env.CLOUDINARY_API_KEY;
  const apiSecret = process.env.CLOUDINARY_API_SECRET;
  if (!cloudName || !apiKey || !apiSecret) throw new Error("Cloudinary belum dikonfigurasi untuk menghapus file.");
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = crypto.createHash("sha1").update(`invalidate=true&public_id=${publicId}&timestamp=${timestamp}${apiSecret}`).digest("hex");
  const body = new URLSearchParams({ public_id: publicId, timestamp: String(timestamp), invalidate: "true", api_key: apiKey, signature });
  const response = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/image/destroy`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
  const result = await response.json().catch(() => null);
  if (!response.ok || !["ok", "not found"].includes(result?.result)) throw new Error(result?.error?.message || "Cloudinary gagal menghapus file.");
}

app.get("/api/gallery", async (req, res) => {
  try {
    const { data, error } = await supabase.from("gallery").select("id,name,src,caption,created_at,created_by,updated_at,updated_by,album_id,cloud_public_id,sort_order").order("sort_order", { ascending: true }).order("created_at", { ascending: false });
    if (error) throw error;
    res.set("Cache-Control", "no-store");
    res.json({ success: true, data: await formatGalleryRows(data || []) });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});
async function formatGalleryAlbums(rows) {
  const ids = [...new Set(rows.flatMap((row) => [row.created_by, row.updated_by]).filter(Boolean).map(String))];
  const { data: users, error } = ids.length ? await supabase.from("admin_users").select("id,name").in("id", ids) : { data: [], error: null };
  if (error) throw error;
  const names = new Map((users || []).map((admin) => [String(admin.id), admin.name]));
  return rows.map((row) => ({ ...row, created_by_name: names.get(String(row.created_by)) || null, updated_by_name: names.get(String(row.updated_by)) || null }));
}
app.get("/api/gallery/albums", async (req, res) => {
  try {
    const { data, error } = await supabase.from("gallery_albums").select("*").order("created_at", { ascending: false });
    if (error) throw error;
    const albums = await formatGalleryAlbums(data || []);
    if (albums.length) {
      const { data: photos, error: photoError } = await supabase.from("gallery").select("album_id,src").in("album_id", albums.map((a) => a.id)).order("created_at", { ascending: true });
      if (photoError) throw photoError;
      const covers = new Map();
      for (const photo of photos || []) if (!covers.has(photo.album_id)) covers.set(photo.album_id, photo.src);
      for (const album of albums) album.cover_src ||= covers.get(album.id) || null;
    }
    res.set("Cache-Control", "no-store");
    res.json({ success: true, data: albums });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});
app.post("/api/gallery/albums", auth, allow("gallery.add"), async (req, res) => {
  try {
    const name = String(req.body?.name || "").trim().slice(0, 120);
    const category = String(req.body?.category || "Family Legacy").trim().slice(0, 80);
    const date = String(req.body?.date || "Current Collection").trim().slice(0, 80);
    const description = String(req.body?.description || "").trim().slice(0, 500);
    const coverSrc = String(req.body?.coverSrc || "");
    const coverPublicId = String(req.body?.coverPublicId || "");
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    if (!name) return res.status(400).json({ success: false, message: "Nama album wajib diisi." });
    if (!cloudName || !coverSrc.startsWith(`https://res.cloudinary.com/${cloudName}/image/upload/`) || !/^riverra\/gallery\/[\w./-]+$/.test(coverPublicId)) return res.status(400).json({ success: false, message: "Cover album wajib berupa file Cloudinary yang valid." });
    const row = { id: crypto.randomUUID(), name, category_id: category.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 80) || "family-legacy", category_label: category, date_label: date, description, cover_src: coverSrc, cover_public_id: coverPublicId, created_by: req.admin.id };
    const { data, error } = await supabase.from("gallery_albums").insert(row).select("*").single();
    if (error) throw error;
    await audit(req.admin, "created", "gallery_album", data.id, { name });
    const [album] = await formatGalleryAlbums([data]);
    res.status(201).json({ success: true, data: album });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});
app.patch("/api/gallery/albums/:id", auth, allow("gallery.edit"), async (req, res) => {
  try {
    const id = String(req.params.id || "");
    const name = String(req.body?.name || "").trim().slice(0, 120);
    const category = String(req.body?.category || "Family Legacy").trim().slice(0, 80);
    const date = String(req.body?.date || "Current Collection").trim().slice(0, 80);
    const description = String(req.body?.description || "").trim().slice(0, 500);
    if (!name || !/^[\w-]{1,100}$/.test(id)) return res.status(400).json({ success: false, message: "ID dan nama album tidak valid." });
    const patch = { name, category_id: category.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 80) || "family-legacy", category_label: category, date_label: date, description, updated_by: req.admin.id, updated_at: new Date().toISOString() };
    const coverSrc = req.body?.coverSrc === undefined ? null : String(req.body.coverSrc || "");
    const coverPublicId = req.body?.coverPublicId === undefined ? null : String(req.body.coverPublicId || "");
    if ((coverSrc === null) !== (coverPublicId === null)) return res.status(400).json({ success: false, message: "URL dan ID cover harus dikirim bersamaan." });
    if (coverSrc !== null) {
      const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
      if (!cloudName || !coverSrc.startsWith(`https://res.cloudinary.com/${cloudName}/image/upload/`) || !/^riverra\/gallery\/[\w./-]+$/.test(coverPublicId)) return res.status(400).json({ success: false, message: "Cover album Cloudinary tidak valid." });
      patch.cover_src = coverSrc;
      patch.cover_public_id = coverPublicId;
    }
    const { data: previousAlbum, error: previousError } = await supabase.from("gallery_albums").select("cover_public_id").eq("id", id).maybeSingle();
    if (previousError) throw previousError;
    const { data, error } = await supabase.from("gallery_albums").update(patch).eq("id", id).select("*").maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ success: false, message: "Album tidak ditemukan." });
    let cleanupWarning = null;
    if (coverSrc !== null && previousAlbum?.cover_public_id && previousAlbum.cover_public_id !== coverPublicId) {
      try {
        const { data: references, error: referenceError } = await supabase.from("gallery").select("id").eq("cloud_public_id", previousAlbum.cover_public_id).limit(1);
        if (referenceError) throw referenceError;
        if (!references?.length) await destroyGalleryAsset(previousAlbum.cover_public_id);
      }
      catch (cleanupError) { cleanupWarning = `Cover baru tersimpan, tetapi cover lama belum dapat dihapus dari Cloudinary: ${cleanupError.message}`; }
    }
    await audit(req.admin, "edited", "gallery_album", id, { name });
    const [album] = await formatGalleryAlbums([data]);
    res.json({ success: true, data: album, cleanupWarning });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});
app.delete("/api/gallery/albums/:id", auth, allow("gallery.delete"), async (req, res) => {
  const id = String(req.params.id || "");
  if (!/^[\w-]{1,100}$/.test(id)) return res.status(400).json({ success: false, message: "ID album tidak valid." });
  try {
    const { data: album, error: albumError } = await supabase.from("gallery_albums").select("id,name,cover_public_id").eq("id", id).maybeSingle();
    if (albumError) throw albumError;
    if (!album) return res.status(404).json({ success: false, message: "Album tidak ditemukan." });
    const { data: photos, error: photoError } = await supabase.from("gallery").select("id,name,cloud_public_id").eq("album_id", id);
    if (photoError) throw photoError;
    const publicIds = new Set([...(photos || []).map((photo) => photo.cloud_public_id), album.cover_public_id].filter(Boolean));
    for (const publicId of publicIds) await destroyGalleryAsset(publicId);
    const { error: rowsError } = await supabase.from("gallery").delete().eq("album_id", id);
    if (rowsError) throw rowsError;
    const { error: deleteError } = await supabase.from("gallery_albums").delete().eq("id", id);
    if (deleteError) throw deleteError;
    await audit(req.admin, "deleted", "gallery_album", id, { name: album.name, photo_count: photos?.length || 0 });
    res.json({ success: true, deletedPhotos: photos?.length || 0 });
  } catch (error) { res.status(502).json({ success: false, message: error.message }); }
});
app.post("/api/gallery", auth, allow("gallery.add"), async (req, res) => {
  try {
    const name = String(req.body?.name || "").trim().replace(/[^\p{L}\p{N}._ -]/gu, "").slice(0, 120);
    const src = String(req.body?.src || "");
    const publicId = String(req.body?.publicId || "");
    const albumInput = req.body?.album || {};
    const albumId = String(albumInput.id || "").trim();
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    if (!name || !/^https:\/\//i.test(src) || !cloudName || !src.startsWith(`https://res.cloudinary.com/${cloudName}/image/upload/`)) return res.status(400).json({ success: false, message: "Nama dan URL Cloudinary foto tidak valid." });
    if (!/^riverra\/gallery\/[\w./-]+$/.test(publicId)) return res.status(400).json({ success: false, message: "ID aset Cloudinary tidak valid." });
    if (!/^[\w-]{1,100}$/.test(albumId)) return res.status(400).json({ success: false, message: "Album foto tidak valid." });
    const { data: existingAlbum, error: albumReadError } = await supabase.from("gallery_albums").select("id").eq("id", albumId).maybeSingle();
    if (albumReadError) throw albumReadError;
    if (!existingAlbum) {
      const albumName = String(albumInput.name || "Recent Uploads").trim().slice(0, 120);
      const category = String(albumInput.category || "Family Legacy").trim().slice(0, 80);
      const date = String(albumInput.date || "Current Collection").trim().slice(0, 80);
      const { error } = await supabase.from("gallery_albums").insert({ id: albumId, name: albumName, category_id: String(albumInput.categoryId || "family-legacy").slice(0, 80), category_label: category, date_label: date, description: String(albumInput.description || "").slice(0, 500), cover_src: src, created_by: req.admin.id });
      if (error) throw error;
    }
    const { data: orderRows, error: orderReadError } = await supabase.from("gallery").select("sort_order").eq("album_id", albumId).order("sort_order", { ascending: false }).limit(1);
    if (orderReadError) throw orderReadError;
    const sortOrder = (Number(orderRows?.[0]?.sort_order) || 0) + 1;
    const { data, error } = await supabase.from("gallery").insert({ name, src, caption: String(req.body?.caption || "").slice(0, 500), album_id: albumId, cloud_public_id: publicId, sort_order: sortOrder, created_by: req.admin.id }).select().single();
    if (error) throw error;
    await audit(req.admin, "created", "gallery", data.id, { name, album_id: albumId, public_id: publicId });
    const [formatted] = await formatGalleryRows([data]);
    res.status(201).json({ success: true, data: formatted });
  } catch (error) { res.status(500).json({ success: false, message: error.message || "Foto gagal disimpan." }); }
});
app.patch("/api/gallery/albums/:id/photos/order", auth, allow("gallery.edit"), async (req, res) => {
  const albumId = String(req.params.id || "");
  const photoIds = req.body?.photoIds;
  if (!/^[\w-]{1,100}$/.test(albumId) || !Array.isArray(photoIds) || photoIds.some((id) => !Number.isInteger(Number(id))) || new Set(photoIds.map(String)).size !== photoIds.length) return res.status(400).json({ success: false, message: "Daftar urutan foto tidak valid." });
  try {
    const { data: photos, error: readError } = await supabase.from("gallery").select("id").eq("album_id", albumId);
    if (readError) throw readError;
    const knownIds = new Set((photos || []).map((photo) => String(photo.id)));
    if (knownIds.size !== photoIds.length || photoIds.some((id) => !knownIds.has(String(id)))) return res.status(400).json({ success: false, message: "Foto album berubah. Muat ulang album lalu coba lagi." });
    for (let index = 0; index < photoIds.length; index += 1) {
      const { error } = await supabase.from("gallery").update({ sort_order: index, updated_by: req.admin.id, updated_at: new Date().toISOString() }).eq("id", Number(photoIds[index])).eq("album_id", albumId);
      if (error) throw error;
    }
    await audit(req.admin, "reordered", "gallery_album", albumId, { photo_count: photoIds.length });
    res.json({ success: true });
  } catch (error) { res.status(500).json({ success: false, message: error.message || "Urutan foto gagal disimpan." }); }
});
app.patch("/api/gallery/:id", auth, allow("gallery.edit"), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ success: false, message: "ID foto tidak valid." });
  const name = String(req.body?.name || "").trim().slice(0, 120);
  const caption = String(req.body?.caption || "").slice(0, 500);
  if (!name) return res.status(400).json({ success: false, message: "Judul foto wajib diisi." });
  const { data: previous, error: readError } = await supabase.from("gallery").select("id,src,album_id,cloud_public_id").eq("id", id).maybeSingle();
  if (readError) return res.status(500).json({ success: false, message: readError.message });
  if (!previous) return res.status(404).json({ success: false, message: "Foto tidak ditemukan." });
  const patch = { name, caption, updated_by: req.admin.id, updated_at: new Date().toISOString() };
  if (req.body?.src || req.body?.publicId) {
    const src = String(req.body.src || "");
    const publicId = String(req.body.publicId || "");
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    if (!cloudName || !src.startsWith(`https://res.cloudinary.com/${cloudName}/image/upload/`) || !/^riverra\/gallery\/[\w./-]+$/.test(publicId)) return res.status(400).json({ success: false, message: "File pengganti Cloudinary tidak valid." });
    patch.src = src;
    patch.cloud_public_id = publicId;
  }
  const { data, error } = await supabase.from("gallery").update(patch).eq("id", id).select().single();
  if (error) return res.status(500).json({ success: false, message: error.message });
  let cleanupWarning = null;
  if (previous.album_id && patch.src) await supabase.from("gallery_albums").update({ cover_src: data.src }).eq("id", previous.album_id).eq("cover_src", previous.src);
  if (patch.cloud_public_id && previous.cloud_public_id && patch.cloud_public_id !== previous.cloud_public_id) {
    try { await destroyGalleryAsset(previous.cloud_public_id); }
    catch (cleanupError) { cleanupWarning = `Gambar baru tersimpan, tetapi gambar lama belum dapat dihapus dari Cloudinary: ${cleanupError.message}`; }
  }
  await audit(req.admin, "edited", "gallery", id, { name });
  const [formatted] = await formatGalleryRows([data]);
  res.json({ success: true, data: formatted, cleanupWarning });
});
app.delete("/api/gallery/:id", auth, allow("gallery.delete"), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ success: false, message: "ID foto tidak valid." });
  const { data: image, error: readError } = await supabase.from("gallery").select("id,name,album_id,cloud_public_id,src").eq("id", id).maybeSingle();
  if (readError) return res.status(500).json({ success: false, message: readError.message });
  if (!image) return res.status(404).json({ success: false, message: "Foto tidak ditemukan." });
  let isAlbumCover = false;
  let nextPhoto = null;
  let keepCoverAsset = false;
  if (image.album_id) {
    const { data: album, error: albumError } = await supabase.from("gallery_albums").select("cover_src,cover_public_id").eq("id", image.album_id).maybeSingle();
    if (albumError) return res.status(500).json({ success: false, message: albumError.message });
    isAlbumCover = album?.cover_public_id ? album.cover_public_id === image.cloud_public_id : album?.cover_src === image.src;
    if (isAlbumCover) {
      const { data, error } = await supabase.from("gallery").select("id,src,cloud_public_id").eq("album_id", image.album_id).neq("id", id).order("sort_order", { ascending: true }).order("created_at", { ascending: true }).limit(1).maybeSingle();
      if (error) return res.status(500).json({ success: false, message: error.message });
      nextPhoto = data;
      if (nextPhoto) {
        const { error: coverError } = await supabase.from("gallery_albums").update({ cover_src: nextPhoto.src, cover_public_id: nextPhoto.cloud_public_id || null }).eq("id", image.album_id);
        if (coverError) return res.status(500).json({ success: false, message: `Cover tidak dapat dialihkan ke foto berikutnya: ${coverError.message}` });
      } else keepCoverAsset = true;
    }
  }
  if (!keepCoverAsset && image.cloud_public_id) {
    try {
      const { data: references, error: referenceError } = await supabase.from("gallery").select("id").eq("cloud_public_id", image.cloud_public_id).neq("id", id).limit(1);
      if (referenceError) throw referenceError;
      if (!references?.length) await destroyGalleryAsset(image.cloud_public_id);
    }
    catch (error) { return res.status(502).json({ success: false, message: error.message }); }
  }
  const { error } = await supabase.from("gallery").delete().eq("id", id);
  if (error) return res.status(500).json({ success: false, message: `File Cloudinary terhapus, tetapi catatan galeri gagal dihapus: ${error.message}` });
  await audit(req.admin, "deleted", "gallery", id, { name: image.name, cloud_public_id: image.cloud_public_id });
  res.json({ success: true });
});

app.post("/api/uploads/signature", auth, loadAdmin, (req, res) => {
  if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) return res.status(503).json({ success: false, message: "Upload belum dikonfigurasi di server." });
  const isMemberUpload = req.body?.folder === "members";
  const grants = new Set(req.admin.permissions || []);
  const permitted = isSuperAdminRecord(req.admin) || grants.has("administrator") || (isMemberUpload ? grants.has("members.add") || grants.has("members.edit") : grants.has("gallery.add") || grants.has("gallery.edit"));
  if (!permitted) return res.status(403).json({ success: false, message: "Akses unggah ditolak." });
  const timestamp = Math.floor(Date.now() / 1000);
  const folder = isMemberUpload ? "riverra/members" : "riverra/gallery";
  const params = `folder=${folder}&timestamp=${timestamp}`;
  const signature = crypto.createHash("sha1").update(`${params}${process.env.CLOUDINARY_API_SECRET}`).digest("hex");
  res.json({ success: true, data: { timestamp, folder, signature, cloudName: process.env.CLOUDINARY_CLOUD_NAME, apiKey: process.env.CLOUDINARY_API_KEY } });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(
    `Server Backend Dinasti Riverra berjalan di http://localhost:${PORT}`
  );
});

module.exports = app;
