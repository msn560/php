# 📂 Gelişmiş PHP Tabanlı Dosya Yöneticisi

Bu proje, modern, güvenli ve zengin özelliklere sahip, **sunucu tabanlı bir dosya yönetim sistemi**dir.  
Tek bir PHP dosyası ile kolay kurulum ve yönetim imkanı sunar. Kullanıcı profilleri, detaylı ayar yönetimi ve şık arayüzü ile kişisel veya kurumsal bulut depolama ihtiyaçlarınız için **ideal bir çözüm**dür.

![Preview]([[https://ornek-site.com/resim.png](https://raw.githubusercontent.com/msn560/php/refs/heads/main/file_manager/app.png)](https://raw.githubusercontent.com/msn560/php/refs/heads/main/file_manager/app.png))

---

## ✨ Öne Çıkan Özellikler

- 👥 **Çoklu Kullanıcı Desteği** – Admin, kullanıcı, misafir gibi farklı yetkilere sahip profiller.
- 🔐 **Profil Bazlı İzinler** – Okuma, yazma, silme ve ayar yönetimi yetkileri.
- ⚙️ **JSON Tabanlı Yapılandırma** – settings.json ve profiles.json dosyalarında kolay düzenleme.
- 📑 **Gelişmiş Dosya Desteği** – Resim, video, ses, ofis belgeleri, arşivler, kod dosyaları.
- 📤 **Sürükle ve Bırak Yükleme** – Modern yükleme arayüzü.
- 🛡️ **Güvenlik**  
  - `.htaccess` ile uploads klasörünü koruma  
  - Dizin geçişi (directory traversal) saldırılarına karşı koruma  
  - Dosya/klasör isimlerinin sanitize edilmesi
- 🎨 **Modern ve Duyarlı Arayüz**  
  - Bootstrap 5 + Font Awesome 6  
  - Karanlık tema, mobil uyumluluk  
  - Sağ tık menüsü, toplu seçim, önizleme desteği
- 🔎 **Kullanıcı Dostu Araçlar**  
  - Anlık arama  
  - Klasör oluşturma, dosya yeniden adlandırma, silme, indirme  
  - Klavye kısayolları (ör. `Ctrl+U` yükleme, `Ctrl+N` yeni klasör)  
  - Başarılı/başarısız işlemler için toast bildirimleri

---

## 🛠️ Teknoloji Yığını

- **Backend:** PHP 7.4+
- **Frontend:** HTML5, CSS3, JavaScript (ES6)
- **Framework & Kütüphaneler:** Bootstrap 5, Font Awesome 6
- **Veri Depolama:** JSON dosyaları ve dosya sistemi

---

## 🚀 Kurulum

1. **Dosyayı İndirin**  
   Bu repodaki `app5.php` dosyasını indirin.

2. **Sunucuya Yükleyin**  
   PHP destekli web sunucunuzda bir klasöre yükleyin.

3. **İzinleri Ayarlayın**  
   - Uygulama ilk çalıştırmada `settings.json`, `profiles.json` ve `uploads/` klasörünü oluşturur.  
   - Web sunucusunun (örn. `www-data`) yazma izni olduğundan emin olun.  

4. **Tarayıcıda Açın**  
   Örn: `https://siteniz.com/index.php`

---

## ⚙️ Yapılandırma ve İlk Kullanım

- **Varsayılan Profil:** `admin`  
- **Varsayılan Şifre:** `admin123`

> 🔔 **ÖNEMLİ:** İlk girişten sonra yönetici şifresini değiştirin!

### Ayarları Değiştirme
1. `admin / admin123` ile giriş yapın.  
2. Sol menüden **Settings** butonuna tıklayın.  
3. Açılan pencereden:  
   - 🔑 Yönetici şifresini değiştirin  
   - 📂 Maksimum yükleme boyutunu ayarlayın  
   - 👥 Kullanıcı profillerini ve izinlerini düzenleyin  
4. **Save Settings** ile kaydedin.

### Yapılandırma Dosyaları
- `settings.json` → Genel sistem ayarları  
- `profiles.json` → Kullanıcı profilleri, izinler ve yükleme limitleri  

---

## 📖 Kullanım

- 📤 **Dosya Yükleme**: Dosyaları sürükleyip bırakın veya tıklayın.  
- 📁 **Yeni Klasör**: "New Folder" butonu ile klasör ekleyin.  
- 🖱️ **Dosya İşlemleri**: İndirme, önizleme, yeniden adlandırma, silme.  
- ✅ **Toplu İşlemler**: Çoklu seçim ile toplu silme.  
- 🔎 **Arama**: Arama çubuğu ile dosya filtreleme.  

---

## 🛡️ Güvenlik Notları

- `uploads/` klasöründe otomatik `.htaccess` oluşturulur → PHP çalıştırılması engellenir.  
- **Varsayılan admin şifresini değiştirin.**  
- Daha güvenli kullanım için `app5.php` dosyasını web kök dizini dışında tutun.  
 
