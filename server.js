require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const JWT_SECRET = process.env.JWT_SECRET;

const app = express();

const FRONTEND_ORIGIN = process.env.FRONTEND_URL || "http://localhost:5173";
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
const ROLES = ["PJ Server", "PJ Universal", "Super Admin"];
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
const allow = (...roles) => async (req, res, next) => {
  try {
    const { data, error } = await supabase
      .from("admin_users")
      .select("id,name,email,role,is_active,discord_avatar,discord_id")
      .eq("id", req.admin.id)
      .single();
    if (error || !data?.is_active || !roles.includes(data.role)) {
      return res.status(403).json({ success: false, message: "Akses ditolak." });
    }
    req.admin = { ...req.admin, ...data, avatar: data.discord_avatar, discordId: data.discord_id };
    next();
  } catch (error) {
    next(error);
  }
};
async function audit(admin, action, entityType, entityId, details = null) {
  await supabase
    .from("audit_logs")
    .insert({
      admin_id: admin.id,
      admin_name: admin.name,
      action,
      entity_type: entityType,
      entity_id: String(entityId),
      details,
    });
}
app.get("/api/audit-logs", auth, allow("PJ Server", "PJ Universal", "Super Admin"), async (req,res)=>{const {data,error}=await supabase.from("audit_logs").select("*").order("created_at",{ascending:false}).limit(500);if(error)return res.status(500).json({success:false,message:error.message});res.json({success:true,data})});
app.get("/api/backups/members", auth, allow("Super Admin"), async (req,res)=>{const {data,error}=await supabase.from("members").select("*").order("id");if(error)return res.status(500).json({success:false,message:error.message});res.json({success:true,backup:{version:1,created_at:new Date().toISOString(),members:data}})});
app.post("/api/backups/members/restore", auth, allow("Super Admin"), async (req,res)=>{try{const rows=req.body?.members;if(!Array.isArray(rows)||rows.length>10000)return res.status(400).json({success:false,message:"Format backup tidak valid."});const {data,error}=await supabase.rpc("restore_members_backup",{p_rows:rows,p_actor:req.admin.name});if(error)throw error;await audit(req.admin,"restored","members","all",{count:data?.length||0});res.json({success:true,message:"Backup berhasil dipulihkan.",data:data||[]})}catch(e){res.status(500).json({success:false,message:"Restore gagal. Tidak ada perubahan yang diterapkan."})}});

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
    const avatar = profile.avatar ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png` : null;
    let { data: admin } = await supabase.from("admin_users").select("*").eq("discord_id", profile.id).maybeSingle();
    if (!admin) {
      const result = await supabase.from("admin_users").insert({ discord_id: profile.id, name: profile.global_name || profile.username, email: profile.email || `${profile.id}@discord.local`, discord_username: profile.username, discord_avatar: avatar, role: null, is_active: false }).select("*").single();
      if (result.error) throw result.error; admin = result.data;
    } else {
      const result = await supabase.from("admin_users").update({ name: profile.global_name || profile.username, email: profile.email || admin.email, discord_username: profile.username, discord_avatar: avatar }).eq("id", admin.id).select("*").single();
      if (result.error) throw result.error; admin = result.data;
    }
    if (!admin.is_active || !admin.role) return res.redirect(`${FRONTEND_URL}/admin?auth_error=${encodeURIComponent("Akun Discord terdaftar, tetapi belum disetujui Super Admin.")}`);
    const user = { id: admin.id, name: admin.name, email: admin.email, role: admin.role, avatar: admin.discord_avatar, discordId: admin.discord_id };
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
    const { data: admin, error } = await supabase.from("admin_users").select("id,name,email,role,is_active,discord_avatar,discord_id").eq("id", payload.id).single();
    if (error || !admin?.is_active || !admin.role) throw new Error("Akses admin tidak aktif.");
    const { error: revokeError } = await supabase.from("admin_sessions").update({ revoked_at: new Date().toISOString() }).eq("id", session.id).is("revoked_at", null);
    if (revokeError) throw revokeError;
    await setSessionCookies(res, { id: admin.id, name: admin.name, email: admin.email, role: admin.role, avatar: admin.discord_avatar, discordId: admin.discord_id });
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

app.get("/api/auth/me", auth, allow("PJ Server", "PJ Universal", "Super Admin"), (req, res) =>
  res.json({ success: true, data: req.admin })
);
app.post("/api/auth/heartbeat", auth, allow("PJ Server", "PJ Universal", "Super Admin"), async (req,res)=>{const {error}=await supabase.from("admin_users").update({last_seen_at:new Date().toISOString()}).eq("id",req.admin.id);if(error)return res.status(500).json({success:false,message:error.message});res.json({success:true})});
app.get("/api/admins/online", auth, allow("PJ Server","PJ Universal","Super Admin"), async (req,res)=>{const cutoff=new Date(Date.now()-2*60*1000).toISOString();const {data,error}=await supabase.from("admin_users").select("id,name,email,role,discord_avatar,last_seen_at").eq("is_active",true).gte("last_seen_at",cutoff).order("last_seen_at",{ascending:false});if(error)return res.status(500).json({success:false,message:error.message});res.json({success:true,data})});
app.patch("/api/auth/profile", auth, allow("PJ Server", "PJ Universal", "Super Admin"), async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    if (!name || name.length > 80) return res.status(400).json({ success:false, message:"Nama profil tidak valid." });
    const { data, error } = await supabase.from("admin_users").update({ name }).eq("id", req.admin.id).select("id,name,email,role,is_active,discord_avatar,discord_username,discord_id").single();
    if (error) throw error;
    await audit(req.admin, "profile_updated", "admin", req.admin.id);
    res.json({ success:true, data });
  } catch (error) { res.status(500).json({ success:false, message:error.message }); }
});
app.get("/api/admins", auth, allow("Super Admin"), async (req, res) => {
  const { data, error } = await supabase
    .from("admin_users")
    .select("id,name,email,role,is_active,created_at")
    .order("created_at");
  if (error)
    return res.status(500).json({ success: false, message: error.message });
  res.json({ success: true, data });
});
app.patch(
  "/api/admins/:id/access",
  auth,
  allow("Super Admin"),
  async (req, res) => {
    try {
      if (req.params.id === String(req.admin.id))
        return res
          .status(400)
          .json({
            success: false,
            message: "Tidak dapat mengubah akses sendiri.",
          });
      const { data: target, error: targetError } = await supabase.from("admin_users").select("role").eq("id", req.params.id).single();
      if (targetError) throw targetError;
      if (target.role === "Super Admin") return res.status(403).json({ success:false, message:"Sesama Super Admin tidak dapat mengubah role atau mencabut akses Super Admin lain." });
      const { role, isActive } = req.body;
      if (role && !ROLES.includes(role))
        return res
          .status(400)
          .json({ success: false, message: "Role tidak valid." });
      const { data, error } = await supabase
        .from("admin_users")
        .update({ role: role || null, is_active: role ? true : Boolean(isActive) })
        .eq("id", req.params.id)
        .select("id,name,email,role,is_active")
        .single();
      if (error) throw error;
      await audit(req.admin, "access_updated", "admin", req.params.id, { role: data.role, is_active: data.is_active });
      res.json({ success: true, data });
    } catch (e) {
      res.status(500).json({ success: false, message: e.message });
    }
  }
);
app.delete("/api/admins/:id", auth, allow("Super Admin"), async (req, res) => {
  if (req.params.id === String(req.admin.id))
    return res
      .status(400)
      .json({ success: false, message: "Tidak dapat menghapus akun sendiri." });
  const { data: target, error: targetError } = await supabase.from("admin_users").select("role").eq("id", req.params.id).single();
  if (targetError) return res.status(404).json({ success:false, message:"Akun admin tidak ditemukan." });
  if (target.role === "Super Admin") return res.status(403).json({ success:false, message:"Sesama Super Admin tidak dapat menghapus Super Admin lain." });
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
  allow("PJ Server", "PJ Universal", "Super Admin"),
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
  allow("PJ Server", "PJ Universal", "Super Admin"),
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
  allow("PJ Universal", "Super Admin"),
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
app.get("/api/members/recycle-bin", auth, allow("Super Admin"), async (req,res)=>{const {data,error}=await supabase.from("members").select("*").not("deleted_at","is",null).order("deleted_at",{ascending:false});if(error)return res.status(500).json({success:false,message:error.message});res.json({success:true,data})});
app.patch("/api/members/:id/restore", auth, allow("Super Admin"), async (req,res)=>{const {data,error}=await supabase.from("members").update({deleted_at:null,deleted_by:null}).eq("id",req.params.id).select().single();if(error)return res.status(500).json({success:false,message:error.message});await audit(req.admin,"restored","member",req.params.id);res.json({success:true,data})});

// Gallery is server-owned. The old localStorage UI remains compatible, while new clients use these endpoints.
app.get("/api/gallery", async (req, res) => {
  const { data, error } = await supabase.from("gallery").select("id,name,src,caption,created_at,created_by").order("created_at", { ascending: false });
  if (error) return res.status(500).json({ success: false, message: error.message });
  res.json({ success: true, data });
});
app.post("/api/gallery", auth, allow("PJ Universal", "Super Admin"), async (req, res) => {
  const name = String(req.body?.name || "").trim().replace(/[^\p{L}\p{N}._ -]/gu, "").slice(0, 120);
  const src = String(req.body?.src || "");
  if (!name || !/^https:\/\//i.test(src)) return res.status(400).json({ success: false, message: "Nama dan URL foto tidak valid." });
  const { data, error } = await supabase.from("gallery").insert({ name, src, caption: String(req.body?.caption || "").slice(0, 500), created_by: req.admin.id }).select().single();
  if (error) return res.status(500).json({ success: false, message: error.message });
  await audit(req.admin, "created", "gallery", data.id, { name });
  res.status(201).json({ success: true, data });
});
app.delete("/api/gallery/:id", auth, allow("PJ Universal", "Super Admin"), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ success: false, message: "ID foto tidak valid." });
  const { error } = await supabase.from("gallery").delete().eq("id", id);
  if (error) return res.status(500).json({ success: false, message: error.message });
  await audit(req.admin, "deleted", "gallery", id);
  res.json({ success: true });
});

app.post("/api/uploads/signature", auth, allow("PJ Server", "PJ Universal", "Super Admin"), (req, res) => {
  if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) return res.status(503).json({ success: false, message: "Upload belum dikonfigurasi di server." });
  const isMemberUpload = req.body?.folder === "members";
  if (!isMemberUpload && req.admin.role === "PJ Server") return res.status(403).json({ success: false, message: "PJ Server hanya dapat mengunggah foto anggota." });
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
