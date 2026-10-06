# Kriptosistem Klasik Berbasis Web

Tugas 1 Kriptografi (PSDKU Informatika, Universitas Sebelas Maret), semester ganjil 2026-2027.

**Anggota kelompok:** Fidela Novelia NIM L0324012, Laely Nisrina NIM L0324019, Nazwa Nur Aisyiyah Jafni NIM L0324029

## Deskripsi
Aplikasi web berbahasa JavaScript (tanpa framework dan tanpa instalasi) yang mengimplementasikan tujuh cipher klasik: Shift, Substitution, Affine, Vigenere, Hill, Permutation, dan One-Time Pad.

## Cara menjalankan
1. Unduh `index.html` dan `ciphers.js`, lalu simpan dalam satu folder yang sama.
2. Buka `index.html` menggunakan peramban (Chrome, Edge, atau Firefox).
3. Pilih mode, cipher, dan masukkan kunci, lalu klik Enkripsi atau Dekripsi.

## Fitur
- Masukan pesan dari papan ketik atau dari file.
- Mode Teks (26 huruf): hanya huruf A-Z yang diproses; angka, spasi, dan tanda baca diabaikan. Cipherteks dapat ditampilkan tanpa spasi atau dalam kelompok 5 huruf, dan dapat disimpan ke file.
- Mode File (byte): seluruh byte file, termasuk header, dienkripsi. Hasil disimpan sebagai `.dat` dengan nama dan ekstensi asli tersimpan di dalamnya, sehingga file kembali ke jenis semula saat didekripsi.
- Kunci dimasukkan pengguna dengan panjang bebas. One-Time Pad membaca kunci dari file teks huruf acak.

## Format kunci
| Cipher | Contoh kunci |
|---|---|
| Shift | `7` |
| Substitution | `KRIPTO` |
| Affine | `5,8` |
| Vigenere | `LEMON` |
| Hill | `3,3,2,5` |
| Permutation | `3,1,4,2` |
| One-Time Pad | file teks huruf acak |

## Catatan
Pada Hill dan Permutation (mode teks), sisa blok diisi huruf X sehingga hasil dekripsi dapat berakhiran X.
