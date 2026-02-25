import re
import sys
import time
import urllib.request
import urllib.parse
import ssl
from urllib.parse import urlparse, parse_qs, urljoin
from playwright.sync_api import sync_playwright

# -----------------------------------------------------------------------------
# KONFİGÜRASYON
# -----------------------------------------------------------------------------
JUSTINTV_DOMAIN = "https://tvjustin.com/"

# Güncel User-Agent
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

# Kullanıcının verdiği proxy listesi (Cloudflare Workers)
PROXY_LIST = [
    "https://rapid-wave-c8e3.redfor14314.workers.dev/",
    "https://proxy.ponelat.workers.dev/",
    "https://proxy.freecdn.workers.dev/?url=",
    "https://withered-shape-3305.vadimkantorov.workers.dev/?",
    "https://wandering-sky-a896.cbracketdash.workers.dev/?",
    "https://hello-world-aged-resonance-fc8f.bokaflix.workers.dev/?apiUrl="
]

# Test için kullanılacak hedef URL (örnek bir video .m3u8 linki)
# Gerçek test, varsayılan kanalın M3U8 linki ile yapılacak.

# -----------------------------------------------------------------------------
# PROXY BULMA FONKSİYONU
# -----------------------------------------------------------------------------
def find_working_proxy(test_url, timeout=5):
    """
    Proxy listesini dener ve çalışan ilk proxy'yi döndürür.
    test_url: Proxy üzerinden erişilmek istenen asıl URL (örneğin bir .m3u8 linki)
    """
    print("\n🔍 Çalışan proxy aranıyor...")
    
    # SSL sertifika hatalarını görmezden gel (bazı worker'lar kendi sertifikalarını kullanabilir)
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    for proxy in PROXY_LIST:
        # Proxy'nin nasıl kullanılacağını belirle
        if "?url=" in proxy:
            # Parametre adı belli: ?url=
            full_url = proxy + urllib.parse.quote(test_url, safe='')
        elif "?apiUrl=" in proxy:
            full_url = proxy + urllib.parse.quote(test_url, safe='')
        elif proxy.endswith("?"):
            # Sadece soru işareti var, parametre adı yok; URL'yi direkt ekle? (nadir)
            # Örnek: https://.../?http://hedef.com  gibi kullanılabilir.
            # Biz deneme amaçlı ?url= şeklinde ekleyelim.
            full_url = proxy + "url=" + urllib.parse.quote(test_url, safe='')
        elif proxy.endswith("/"):
            # Path olarak ekle: https://proxy.com/ + hedef_url
            # Ancak bu durumda hedef URL'nin başındaki http:// veya https:// sorun çıkarabilir.
            # Genelde path olarak eklenmez, parametre olarak eklenir. 
            # Yine de ?url= parametresi ekleyelim.
            full_url = proxy + "?url=" + urllib.parse.quote(test_url, safe='')
        else:
            # Hiçbir parametre yoksa ?url= ekle
            full_url = proxy + "?url=" + urllib.parse.quote(test_url, safe='')
        
        print(f"   -> Deneniyor: {full_url[:80]}...")
        try:
            req = urllib.request.Request(full_url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, context=ssl_context, timeout=timeout) as response:
                if response.status == 200:
                    # İçeriğin başlangıcı #EXTM3U veya benzeri mi kontrol edelim
                    first_chunk = response.read(20).decode('utf-8', errors='ignore')
                    if first_chunk.startswith('#EXTM3U') or b'm3u8' in response.info().get('Content-Type', '').encode():
                        print(f"   ✅ Çalışan proxy bulundu: {proxy}")
                        return proxy
                    else:
                        # İçerik M3U8 değil ama belki yine de çalışıyordur, devam edelim
                        print(f"   ⚠️  Proxy yanıt verdi ama içerik M3U8 görünmüyor, yine de kullanılabilir.")
                        return proxy
                else:
                    print(f"   ❌ HTTP {response.status}")
        except Exception as e:
            print(f"   ❌ Hata: {e.__class__.__name__}")
            continue
    
    print("   ❌ Hiçbir proxy çalışmadı.")
    return None

# -----------------------------------------------------------------------------
# ANA FONKSİYONLAR (değişmeyen kısımlar aynen korundu)
# -----------------------------------------------------------------------------
def scrape_default_channel_info(page):
    print(f"\n📡 Varsayılan kanal bilgisi {JUSTINTV_DOMAIN} adresinden alınıyor...")
    try:
        page.goto(JUSTINTV_DOMAIN, timeout=25000, wait_until='domcontentloaded')
        iframe_selector = "iframe#customIframe"
        print(f"-> Varsayılan iframe ('{iframe_selector}') aranıyor...")
        page.wait_for_selector(iframe_selector, timeout=15000)
        iframe_element = page.query_selector(iframe_selector)
        if not iframe_element:
            print("❌ Ana sayfada 'iframe#customIframe' bulunamadı.")
            return None, None
        iframe_src = iframe_element.get_attribute('src')
        if not iframe_src:
            print("❌ Iframe 'src' özniteliği boş.")
            return None, None
        event_url = urljoin(JUSTINTV_DOMAIN, iframe_src)
        parsed_event_url = urlparse(event_url)
        query_params = parse_qs(parsed_event_url.query)
        stream_id = query_params.get('id', [None])[0]
        if not stream_id:
            print(f"❌ Event URL'sinde ({event_url}) 'id' parametresi bulunamadı.")
            return None, None
        print(f"✅ Varsayılan kanal bilgisi alındı: ID='{stream_id}', EventURL='{event_url}'")
        return event_url, stream_id
    except Exception as e:
        print(f"❌ Ana sayfaya ulaşılamadı veya iframe bilgisi alınamadı: {e.__class__.__name__} - {e}")
        return None, None

def extract_base_m3u8_url(page, event_url):
    try:
        print(f"\n-> M3U8 Base URL'i almak için Event sayfasına gidiliyor: {event_url}")
        page.goto(event_url, timeout=20000, wait_until="domcontentloaded")
        content = page.content()
        base_url_match = re.search(r"['\"](https?://[^'\"]+/checklist/)['\"]", content)
        if not base_url_match:
             base_url_match = re.search(r"streamUrl\s*=\s*['\"](https?://[^'\"]+/checklist/)['\"]", content)
        if not base_url_match:
            print(" -> ❌ Event sayfası kaynağında '/checklist/' ile biten base URL bulunamadı.")
            return None
        base_url = base_url_match.group(1)
        print(f"-> ✅ M3U8 Base URL bulundu: {base_url}")
        return base_url
    except Exception as e:
        print(f"-> ❌ Event sayfası işlenirken hata oluştu: {e}")
        return None

def scrape_all_channels(page):
    print(f"\n📡 Tüm kanallar {JUSTINTV_DOMAIN} adresinden çekiliyor...")
    channels = []
    try:
        print(f"-> Ana sayfaya gidiliyor ve ağ trafiğinin durması bekleniyor (Max 45sn)...")
        page.goto(JUSTINTV_DOMAIN, timeout=45000, wait_until='networkidle')
        print("-> Ağ trafiği durdu veya zaman aşımına yaklaşıldı.")
        print("-> DOM güncellemeleri için 5 saniye bekleniyor...")
        page.wait_for_timeout(5000)
        mac_item_selector = ".mac[data-url]"
        print(f"-> Sayfa içinde '{mac_item_selector}' elementleri var mı kontrol ediliyor...")
        elements_exist = page.evaluate(f'''() => {{
            return document.querySelector('{mac_item_selector}') !== null;
        }}''')
        if not elements_exist:
            print(f"❌ Sayfa içinde '{mac_item_selector}' elemanları bulunamadı.")
            return []
        print("-> ✅ Kanallar sayfada mevcut. Bilgiler çıkarılıyor...")
        channel_elements = page.query_selector_all(mac_item_selector)
        print(f"-> {len(channel_elements)} adet potansiyel kanal elemanı bulundu.")
        for element in channel_elements:
            name_element = element.query_selector(".takimlar")
            channel_name = name_element.inner_text().strip() if name_element else "İsimsiz Kanal"
            channel_name_clean = channel_name.replace('CANLI', '').strip()
            data_url = element.get_attribute('data-url')
            stream_id = None
            if data_url:
                try:
                    parsed_data_url = urlparse(data_url)
                    query_params = parse_qs(parsed_data_url.query)
                    stream_id = query_params.get('id', [None])[0]
                except Exception:
                    pass
            if stream_id:
                time_element = element.query_selector(".saat")
                time_str = time_element.inner_text().strip() if time_element else None
                if time_str and time_str != "CANLI":
                     final_channel_name = f"{channel_name_clean} ({time_str})"
                else:
                     final_channel_name = channel_name_clean
                channels.append({
                    'name': final_channel_name,
                    'id': stream_id
                })
        channels.sort(key=lambda x: x['name'])
        print(f"✅ {len(channels)} adet kanal bilgisi başarıyla çıkarıldı (yinelenenler dahil).")
        return channels
    except Exception as e:
        print(f"❌ Kanal listesi işlenirken hata oluştu: {e}")
        return []

def get_channel_group(channel_name):
    channel_name_lower = channel_name.lower()
    group_mappings = {
        'BeinSports': ['bein sports', 'beın sports', ' bs', ' bein '],
        'S Sports': ['s sport'],
        'Tivibu': ['tivibu spor', 'tivibu'],
        'Exxen': ['exxen'],
        'Ulusal Kanallar': ['a spor', 'trt spor', 'trt 1', 'tv8', 'atv', 'kanal d', 'show tv', 'star tv', 'trt yıldız', 'a2'],
        'Spor': ['smart spor', 'nba tv', 'eurosport', 'sport tv', 'premier sports', 'ht spor', 'sports tv', 'd smart', 'd-smart'],
        'Yarış': ['tjk tv'],
        'Belgesel': ['national geographic', 'nat geo', 'discovery', 'dmax', 'bbc earth', 'history'],
        'Film & Dizi': ['bein series', 'bein movies', 'movie smart', 'filmbox', 'sinema tv'],
        'Haber': ['haber', 'cnn', 'ntv'],
        'Diğer': ['gs tv', 'fb tv', 'cbc sport']
    }
    for group, keywords in group_mappings.items():
        for keyword in keywords:
            if keyword in channel_name_lower:
                return group
    if re.search(r'\d{2}:\d{2}', channel_name): return "Maç Yayınları"
    if ' - ' in channel_name: return "Maç Yayınları"
    return "Diğer Kanallar"

# -----------------------------------------------------------------------------
# ANA PROGRAM
# -----------------------------------------------------------------------------
def main():
    with sync_playwright() as p:
        print("🚀 Playwright ile Justin TV M3U8 Kanal İndirici Başlatılıyor (Proxy Destekli)...")
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(user_agent=USER_AGENT)
        page = context.new_page()

        # 1. Adım: Varsayılan kanaldan event URL'sini ve stream ID'sini al
        default_event_url, default_stream_id = scrape_default_channel_info(page)
        if not default_event_url:
            print("❌ Varsayılan kanal bilgisi alınamadı, işlem sonlandırılıyor.")
            browser.close()
            sys.exit(1)

        # 2. Adım: Base M3U8 URL'ini bul
        base_m3u8_url = extract_base_m3u8_url(page, default_event_url)
        if not base_m3u8_url:
            print("❌ M3U8 Base URL alınamadı, işlem sonlandırılıyor.")
            browser.close()
            sys.exit(1)

        # 3. Adım: Tüm kanalları kazı
        channels = scrape_all_channels(page)
        browser.close()  # Tarayıcıyı kapat, proxy testi için gerek yok

        if not channels:
            print("❌ Hiçbir kanal bulunamadı, işlem sonlandırılıyor.")
            sys.exit(1)

        # 4. Adım: Varsayılan kanalın tam M3U8 linkini oluştur (proxy testi için)
        test_m3u8_url = base_m3u8_url + default_stream_id + ".m3u8"
        
        # 5. Adım: Çalışan bir proxy bul
        working_proxy = find_working_proxy(test_m3u8_url)
        if working_proxy:
            print(f"\n✅ Proxy kullanılacak: {working_proxy}")
        else:
            print("\n⚠️  Hiçbir proxy çalışmadı, proxy'siz linkler oluşturulacak (büyük olasılıkla VPN gerekir).")

        # 6. Adım: M3U8 dosyasını oluştur
        m3u_content = []
        output_filename = "justintv_kanallar.m3u8"
        print(f"\n📺 {len(channels)} kanal için M3U8 linkleri oluşturuluyor...")
        created = 0

        # Başlık satırı (sadece standart #EXTM3U)
        m3u_header_lines = ["#EXTM3U"]

        for channel_info in channels:
            channel_name = channel_info['name']
            stream_id = channel_info['id']
            group_name = get_channel_group(channel_name)

            # Orijinal M3U8 linki
            original_link = f"{base_m3u8_url}{stream_id}.m3u8"

            # Proxy varsa linki proxy ile sarmala
            if working_proxy:
                if "?url=" in working_proxy:
                    final_link = working_proxy + urllib.parse.quote(original_link, safe='')
                elif working_proxy.endswith("?"):
                    final_link = working_proxy + "url=" + urllib.parse.quote(original_link, safe='')
                else:
                    # Diğer durumlar için ?url= ekle
                    final_link = working_proxy.rstrip('/') + "/?url=" + urllib.parse.quote(original_link, safe='')
            else:
                final_link = original_link

            m3u_content.append(f'#EXTINF:-1 tvg-name="{channel_name}" group-title="{group_name}",{channel_name}')
            m3u_content.append(final_link)
            created += 1

        if created > 0:
            with open(output_filename, "w", encoding="utf-8") as f:
                f.write("\n".join(m3u_header_lines))
                f.write("\n")
                f.write("\n".join(m3u_content))
            print(f"\n\n📂 {created} kanal başarıyla '{output_filename}' dosyasına kaydedildi.")
            if working_proxy:
                print("   📢 Not: Linkler proxy üzerinden yönlendirildi, VPN olmadan oynatılabilir olmalı.")
            else:
                print("   ⚠️  Proxy kullanılmadı, yayınlar VPN gerektirebilir.")
        else:
            print("\n\nℹ️  Geçerli hiçbir M3U8 linki oluşturulamadı.")

        print("\n🎉 İşlem tamamlandı!")

if __name__ == "__main__":
    main()
