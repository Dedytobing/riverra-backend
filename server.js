require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);
const JWT_SECRET = process.env.JWT_SECRET;
const ROLES = ["PJ Server", "PJ Universal", "Super Admin"];

function auth(req, res, next) {
  try {
    const token = req.headers.authorization?.replace(/^Bearer\s+/i, "");
    if (!token)
      return res
        .status(401)
        .json({ success: false, message: "Login diperlukan." });
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res
      .status(401)
      .json({ success: false, message: "Token tidak valid atau kedaluwarsa." });
  }
}
const allow =
  (...roles) =>
  (req, res, next) =>
    roles.includes(req.admin.role)
      ? next()
      : res.status(403).json({ success: false, message: "Akses ditolak." });
async function audit(admin, action, entityType, entityId) {
  await supabase
    .from("audit_logs")
    .insert({
      admin_id: admin.id,
      admin_name: admin.name,
      action,
      entity_type: entityType,
      entity_id: String(entityId),
    });
}

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password || password.length < 6)
      return res
        .status(400)
        .json({ success: false, message: "Data registrasi tidak valid." });
    const { data: exists } = await supabase
      .from("admin_users")
      .select("id")
      .eq("email", email.toLowerCase())
      .maybeSingle();
    if (exists)
      return res
        .status(409)
        .json({ success: false, message: "Email sudah terdaftar." });
    const { data, error } = await supabase
      .from("admin_users")
      .insert({
        name: name.trim(),
        email: email.toLowerCase(),
        password_hash: await bcrypt.hash(password, 12),
        role: null,
        is_active: false,
      })
      .select("id,name,email,role,is_active,created_at")
      .single();
    if (error) throw error;
    res
      .status(201)
      .json({
        success: true,
        message: "Registrasi berhasil. Tunggu persetujuan Super Admin.",
        data,
      });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});
app.post("/api/auth/login", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("admin_users")
      .select("*")
      .eq("email", req.body.email?.toLowerCase())
      .single();
    if (
      error ||
      !data ||
      !(await bcrypt.compare(req.body.password || "", data.password_hash))
    )
      return res
        .status(401)
        .json({ success: false, message: "Email atau password salah." });
    if (!data.is_active)
      return res
        .status(403)
        .json({
          success: false,
          message: "Akun belum disetujui atau akses dicabut.",
        });
    const user = {
      id: data.id,
      name: data.name,
      email: data.email,
      role: data.role,
    };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: "8h" });
    res.json({ success: true, data: { token, user } });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});
app.get("/api/auth/me", auth, (req, res) =>
  res.json({ success: true, data: req.admin })
);
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
      const { role, isActive } = req.body;
      if (role && !ROLES.includes(role))
        return res
          .status(400)
          .json({ success: false, message: "Role tidak valid." });
      const { data, error } = await supabase
        .from("admin_users")
        .update({ role: role || null, is_active: Boolean(isActive) })
        .eq("id", req.params.id)
        .select("id,name,email,role,is_active")
        .single();
      if (error) throw error;
      await audit(req.admin, "access_updated", "admin", req.params.id);
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
  };
}

// ================================================================
// GET: Ambil seluruh anggota
// ================================================================

app.get("/api/members", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("members")
      .select("*")
      .order("generation", { ascending: true })
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
      await audit(req.admin, "created", "member", newMember.id);

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
        .select("id, spouse_id")
        .eq("id", memberId)
        .single();

      if (oldMemberError) throw oldMemberError;

      const { data: updatedMember, error: updateError } = await supabase
        .from("members")
        .update(payload)
        .eq("id", memberId)
        .select()
        .single();

      if (updateError) throw updateError;
      await audit(req.admin, "edited", "member", memberId);

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

      const { error: deleteError } = await supabase
        .from("members")
        .delete()
        .eq("id", memberId);

      if (deleteError) throw deleteError;
      await audit(req.admin, "deleted", "member", memberId);

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

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(
    `Server Backend Dinasti Riverra berjalan di http://localhost:${PORT}`
  );
});

module.exports = app;
