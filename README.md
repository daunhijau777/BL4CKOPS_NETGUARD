# BL4CKOPS_NETGUARD
Sistem akan otomatis monitoring trafik jaringan, mendeteksi dan memitigasi serangan DDoS/ransomware, serta backup data secara berkala dengan logging terpusat. Cocok untuk produksi jaringan keamanan sederhana
Kode ini sudah mengimplementasikan:
Multiprocessing (bukan hanya threading) untuk bebas dari GIL
Firewall manager dengan pengecekan rule sebelum insert, dan rollback otomatis
Model ML online learning dengan river library (adaptif dan berkelanjutan)
File ransomware monitoring dan isolasi host dengan logika terintegrasi
Backup otomatis dengan retry dan monitoring
Logging rotasi file siap produksi
Modular dan pemisahan tugas
