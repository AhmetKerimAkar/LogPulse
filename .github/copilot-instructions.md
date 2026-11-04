# LogPulse Proje Kuralları ve Kodlama Standartları

LogPulse; sunucu loglarını analiz eden, Scikit-Learn Isolation Forest ile anomali tespiti yapan ve LLM ile olay müdahalesi (Incident Response) özeti oluşturan bir Python siber güvenlik uygulamasıdır.

## Kodlama Kuralları

1. **Dil ve sürüm:** Python 3.10+ standartlarını kullan.
2. **Tip tanımlamaları:** Yazılan her fonksiyonun tüm parametreleri ve dönüş değeri type annotation içermelidir (`str`, `int`, `List`, `Optional` vb.).
3. **Dokümantasyon:** Her sınıfın ve fonksiyonun hemen altında, yaptığı işi açıklayan kısa bir Türkçe docstring bulunmalıdır.
4. **Hata yönetimi:** Dosya okuma, regex ayrıştırma ve API çağrıları `try-except` bloklarıyla ele alınmalı; hatalar `logging` modülüyle kaydedilmelidir.
5. **Modülerlik:** Sorumlulukları aşağıdaki modüller arasında koru:
   - `models.py`: Yalnızca Pydantic veya dataclass veri yapılarını barındırır.
   - `parser.py`: Ham `.log` metinlerini okur ve `models.py` içindeki yapılara dönüştürür.
   - `analyzer.py`: Isolation Forest makine öğrenmesi modelini ve AI özetleme işlevlerini içerir.
   - `app.py`: Streamlit tabanlı görsel arayüz kodlarını içerir.

## Uygulama İlkeleri

- Mevcut modül sorumluluklarını ihlal edecek kodu başka bir modüle ekleme.
- Hata durumlarını sessizce yutma; uygun log seviyesini kullanarak açıkça kaydet.
- Yeni davranış eklerken mevcut davranışı koru ve ilgili testleri güncelle veya ekle.