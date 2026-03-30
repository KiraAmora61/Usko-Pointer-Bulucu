# KO Pointer Bulucu

KnightOnline 2602 için pointer scanner ve offset finder.

## Özellikler

- Otomatik KO bağlantısı
- Pointer scanner (assembly pattern tarama)
- KO_PTR_CHR, KO_PTR_PKT, KO_PTR_DLG pointer'ları
- Manuel pointer girişi
- Save/Load fonksiyonu

## Kullanım

1. KnightOnline.exe'yi başlat
2. PointerBulucu.exe'yi çalıştır
3. "Load Known Offsets" veya "Auto Scan" ile pointer bul

## KO Pointers

**KO 2602 Offset'leri:**
```
KO_PTR_CHR: 0x00000000  // Güncellenecek
KO_PTR_PKT: 0x00000000  // Güncellenecek
KO_PTR_DLG: 0x00000000  // Güncellenecek
```
*2602 offset'leri kısa süre içinde eklenecek.*

## Proje Yapısı

```
src/main.cpp - Ana kod
imgui/ - ImGui library
PointerBulucu.sln - VS solution
```

## Not

KnightOnline farklı versiyonlarında offset'ler değişebilir.
2602 versiyonu için offset'ler yakında eklenecek.
