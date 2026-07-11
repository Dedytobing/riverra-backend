require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");

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
      message:
        status === 404
          ? "Anggota tidak ditemukan."
          : error.message,
    });
  }
});

// ================================================================
// POST: Tambah anggota
// ================================================================

app.post("/api/members", async (req, res) => {
  try {
    const payload = memberPayload(req.body);

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
});

// ================================================================
// PUT: Edit anggota
// ================================================================

app.put("/api/members/:id", async (req, res) => {
  try {
    const memberId = optionalId(req.params.id);

    if (!memberId) {
      return res.status(400).json({
        success: false,
        message: "ID anggota tidak valid.",
      });
    }

    const payload = memberPayload(req.body);

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

    // Hapus hubungan dari pasangan sebelumnya apabila berubah.
    if (
      oldMember.spouse_id &&
      oldMember.spouse_id !== payload.spouse_id
    ) {
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
      message:
        status === 404
          ? "Anggota tidak ditemukan."
          : error.message,
    });
  }
});

// ================================================================
// DELETE: Hapus anggota
// ================================================================

app.delete("/api/members/:id", async (req, res) => {
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
    const relationError = relationResults.find(
      (result) => result.error
    );

    if (relationError) {
      throw relationError.error;
    }

    const { error: deleteError } = await supabase
      .from("members")
      .delete()
      .eq("id", memberId);

    if (deleteError) throw deleteError;

    res.status(200).json({
      success: true,
      message: "Data anggota berhasil dihapus.",
      data: member,
    });
  } catch (error) {
    const status = error.code === "PGRST116" ? 404 : 500;

    res.status(status).json({
      success: false,
      message:
        status === 404
          ? "Anggota tidak ditemukan."
          : error.message,
    });
  }
});

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