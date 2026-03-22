# Yasal çerçeve ve kullanım amacı

## Araç tanımı

**ASENA-ANALYSIS**, yetkisiz erişim veya saldırı üretmek için değil; **savunma, eğitim ve olay sonrası log analizi** için tasarlanmıştır. Yerel makinede veya **izin verilen** laboratuvar ortamlarında (ör. DVWA) üretilen veya paylaşılan loglarla kullanılmalıdır.

Bu yazılım bir **“saldırı aracı”** değil; **analiz ve farkındalık** aracıdır.

## Türk Ceza Kanunu (bilgi notu)

TCK **Madde 243–244** ve ilgili düzenlemeler, **bilişim sistemine yetkisiz erişim**, sistemi engelleme, verileri yok etme veya değiştirme gibi fiilleri suç olarak düzenler. Bu projeyi yalnızca **yetkiniz olan sistemlerde** ve **yasal sınırlar içinde** kullanın.

Bu dosya hukuki danışmanlık değildir; tereddüt halinde uzman görüşü alın.

## KVKK / GDPR

Çıktılarda (`timeline.csv`, JSON) **PII maskeleme** ve **veri minimizasyonu** varsayılan olarak uygulanır. Üretim ortamında `hash` modu için güçlü bir `ASENA_SALT` kullanın; raporları paylaşmadan önce kurum içi politikalarınıza uyun.

## Önerilen kullanım

- `localhost` veya kapalı lab ağı  
- Açıkça izin verilen pentest / eğitim hedefleri  
- Kendi sunucularınızın erişim logları  

Yetkisiz üçüncü taraf sistemlere karşı kullanım **yasaktır** ve bu projenin amacı dışındadır.
