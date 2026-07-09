require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json()); // Agar server bisa membaca format JSON dari Form

// Koneksi ke Database PostgreSQL Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// =========================================================================
// ENDPOINT 1: AMBIL SEMUA DATA ANGGOTA (GET)
// =========================================================================
app.get('/api/members', async (req, res) => {
    try {
        // Ambil semua data dari tabel members, urutkan berdasarkan generasi dan ID
        const { data, error } = await supabase
            .from('members')
            .select('*')
            .order('generation', { ascending: true })
            .order('id', { ascending: true });

        if (error) throw error;
        res.json({ success: true, data });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// =========================================================================
// ENDPOINT 2: TAMBAH ANGGOTA BARU DENGAN OTOMATISASI RELASI (POST)
// =========================================================================
app.post('/api/members', async (req, res) => {
    try {
        const { 
            firstName, lastName, gender, generation, status, 
            photo, biography, occupation, role, fatherId, motherId, spouseId 
        } = req.body; // <-- 1. PERBAIKAN: Tangkap data 'role' dari frontend form

        // Masukkan data dasar anggota baru ke dalam database Supabase
        const { data: newMember, error: insertError } = await supabase
            .from('members')
            .insert([{
                first_name: firstName,
                last_name: lastName,
                gender,
                generation: parseInt(generation),
                status,
                photo,
                biography,
                occupation,
                role: role || '', // <-- 2. PERBAIKAN: Masukkan nilai 'role' ke kolom database
                father_id: fatherId ? parseInt(fatherId) : null,
                mother_id: motherId ? parseInt(motherId) : null,
                spouse_id: spouseId ? parseInt(spouseId) : null
            }])
            .select()
            .single();

        if (insertError) throw insertError;

        const newId = newMember.id;

        // Logika otomatisasi: Jika anggota baru mendaftarkan ID Pasangan,
        // maka orang yang ditunjuk tersebut kolom pasangan-nya harus otomatis ter-update ke ID baru ini.
        if (spouseId) {
            await supabase
                .from('members')
                .update({ spouse_id: newId })
                .eq('id', spouseId);
        }

        res.status(201).json({ success: true, message: "Anggota berhasil disimpan!", data: newMember });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Endpoint untuk mengambil detail satu anggota berdasarkan ID (Dipakai oleh Sidebar)
app.get('/api/members/:id', async (req, res) => {
    try {
        const memberId = req.params.id;
        const { data, error } = await supabase
            .from('members')
            .select('*')
            .eq('id', memberId)
            .single(); // Mengambil satu objek data saja

        if (error) throw error;

        res.status(200).json({ success: true, data: data });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Jalankan Server Backend
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server Backend Dinasti Riverra berjalan di http://localhost:${PORT}`);
});