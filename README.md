# Multi-Agent Cyber Threat Intelligence & Risk Analysis System

Bu proje, CVE/NVD, URLhaus ve Dread benzeri açık kaynak tehdit istihbaratı sinyallerini birleştirerek dinamik risk skoru üreten çok ajanlı bir CTI analiz prototipidir.

## Mevcut Durum

Proje artık yalnızca proposal aşamasında değildir. Mevcut kod tabanında şu parçalar bulunur:

- Go tabanlı veri toplama ajanları
- MongoDB üzerinde kalıcı veri saklama
- Python analiz ve orkestrasyon katmanı
- FastAPI tabanlı analiz API'si
- React/Vite tabanlı dashboard
- Risk skorlama, korelasyon, graph analizi ve raporlama modülleri
- Python test dosyaları

Bu haliyle proje akademik demo/prototip olarak sunulabilir. Production kullanımı için güvenlik, deployment, gözlemlenebilirlik ve gerçek veri validasyonu tarafında ek çalışma gerekir.

## Mimari

```text
Threat Sources
  ├─ NVD / CVE
  ├─ URLhaus
  └─ Dread-like source
        ↓
Go Collectors
        ↓
MongoDB
        ↓
Python Worker / Analysis Pipeline
  ├─ Risk Engine
  ├─ Correlator
  ├─ Graph Builder
  ├─ Diagnostic Agent
  └─ Recommender Agent
        ↓
FastAPI
        ↓
React Dashboard
```

## Klasör Yapısı

```text
agent-go/                 Go veri toplama ajanları
agent-python/src/         Python analiz, API, core ve reporting modülleri
agent-python/tests/       Python testleri
agent-python/frontend/    React dashboard
docker-compose.yml        MongoDB + API + frontend geliştirme ortamı
Makefile                  Sık kullanılan kurulum/test/çalıştırma komutları
.github/workflows/ci.yml  Python, Go ve frontend CI doğrulamaları
.env.example              Örnek ortam değişkenleri
```

## Güvenlik Notu

Gerçek `.env` dosyası repoya eklenmemelidir. Bu repoda yalnızca `.env.example` tutulur.

Yapılması gerekenler:

1. `.env.example` dosyasını `.env` olarak kopyalayın.
2. Gerçek `CVE_KEY`, `MONGO_URI` ve diğer değerleri `.env` içine yazın.
3. `.env` dosyasını commit etmeyin.
4. Daha önce gerçek anahtarlar paylaşılmışsa ilgili API key ve connection string değerlerini değiştirin.

```bash
cp .env.example .env
```

## Kurulum

### Python API ve Worker

```bash
cd agent-python
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

API'yi başlatmak için:

```bash
PYTHONPATH=src uvicorn api.app:app --reload
```

Worker'ı tek seferlik çalıştırmak için:

```bash
PYTHONPATH=src python src/main.py --source all --run-once
```

### Go Veri Toplama

```bash
cd agent-go
go test ./...
go run ./cmd/agent-go -source cve -limit 20
```

Desteklenen kaynaklar:

```text
cve
urlhaus
dread
```

### Frontend

```bash
cd agent-python/frontend
npm install
npm run dev
```

Frontend varsayılan olarak API'ye şu adresten bağlanır:

```text
http://127.0.0.1:8000
```

Bunu değiştirmek için `agent-python/frontend/.env` dosyasına şunu ekleyin:

```text
VITE_API_BASE=http://127.0.0.1:8000
```

## Makefile ile Hızlı Komutlar

Kök dizinden kullanılabilir:

```bash
make setup-python
make test-python
make run-api
make run-worker
make setup-frontend
make run-frontend
make build-frontend
make test-go
make docker-up
```

## Docker Compose ile Çalıştırma

Önce `.env` dosyasını oluşturun:

```bash
cp .env.example .env
```

Ardından servisleri başlatın:

```bash
docker compose up --build
```

Worker'ı ayrıca çalıştırmak için:

```bash
docker compose --profile worker up --build worker
```

Docker Compose servisleri artık özel Dockerfile dosyalarını kullanır; container her açılışta dependency kurmaz. MongoDB için healthcheck vardır ve API/worker Mongo hazır olduktan sonra başlar.

## API Örnekleri

Health check:

```bash
curl http://127.0.0.1:8000/health
```

CVE analizi:

```bash
curl -X POST http://127.0.0.1:8000/analyze/cve \
  -H "Content-Type: application/json" \
  -d '{"_id":"CVE-2026-DEMO","descriptions":[{"value":"remote code execution in vpn appliance"}]}'
```

Dashboard için analiz edilmiş bulgular:

```bash
curl http://127.0.0.1:8000/findings/top-risky?limit=10
```

## Risk Modeli

Risk skoru aşağıdaki sinyallerin birlikte değerlendirilmesiyle üretilir:

- CVSS / teknik şiddet
- URLhaus korelasyonları
- Dread benzeri tehdit sinyalleri
- Graph centrality ve edge confidence
- Zaman / güncellik etkisi
- Semantic similarity
- Opsiyonel LLM destekli açıklama ve öneriler

Model deterministik bir güvenlik kararı yerine önceliklendirme desteği sağlar. Gerçek ortamda doğrulama ve tuning gerekir.

## Testler

Python testleri:

```bash
cd agent-python
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -q -p no:ddtrace
```

veya kök dizinden:

```bash
make test-python
```

API çalışırken minimal smoke test:

```bash
cd agent-python
python scripts/smoke_api.py http://127.0.0.1:8000
```

Testler minimal ortamlarda `pymongo` bulunmadığında collection aşamasında kırılmaması için test stub'ı içerir. Bazı hazır Python ortamlarında harici `ddtrace` pytest plugin'i test sürecinin kapanışını geciktirebildiği için test komutunda `-p no:ddtrace` kullanılır. Gerçek entegrasyon testleri için MongoDB çalışır durumda olmalıdır.

## Yapılabilecek Geliştirmeler

### Kısa Vadeli

- API route'larını ayrı dosyalara bölmek
- Frontend'e filtreleme ve tarih aralığı eklemek
- Docker image'larını production için daha küçük ve non-root kullanıcıyla optimize etmek

### Orta Vadeli

- Repository pattern ile MongoDB bağımlılığını azaltmak
- Daha ayrıntılı logging ve metrics eklemek
- Risk skorunu benchmark veri setleriyle değerlendirmek
- Semantic model backend'ini production için netleştirmek
- Dashboard'a export ve karşılaştırma ekranları eklemek

### Uzun Vadeli

- Deployment ortamı için TLS, auth ve rate limiting eklemek
- Gerçek tehdit istihbaratı feed'leriyle validasyon yapmak
- Model ağırlıklarını veriyle optimize etmek
- Alerting ve scheduled ingestion eklemek

## Lisans / Kullanım

Bu proje akademik çalışma ve prototip amaçlıdır. Dark web veya üçüncü taraf kaynaklarla çalışırken ilgili kaynakların kullanım şartları, yasal sınırlar ve etik kurallar dikkate alınmalıdır.

## Author

Furkan Korkmaz

## Son Doğrulama Durumu

Bu paket hazırlanırken Python testleri şu komutla doğrulandı:

```bash
cd agent-python
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -q -p no:ddtrace
```

Sonuç:

```text
49 passed
```

Go ve frontend doğrulamaları dependency indirme gerektirdiği için internet erişimi olan ortamda şu komutlarla tekrar çalıştırılmalıdır:

```bash
make test-go
make setup-frontend
make build-frontend
```

## Analysis Engine v2

The analysis layer has been redesigned to make the project value clearer and the scoring easier to defend.

What changed:

- Lightweight NLP extraction now identifies CVE/CWE identifiers, affected products, versions, vulnerability types, attacker impact, threat terms, URLs and domains.
- Keyword retrieval is now based on normalized security entities instead of mostly raw token filtering.
- Cross-source correlation now uses an evidence gate before adding score: exact CVE matches, entity alignment, high-signal threat terms, lexical overlap, or semantic+temporal support.
- Correlation scoring uses diminishing returns so many weak matches do not overpower one strong match.
- CVE scoring now separates intrinsic NLP context from observed threat activity:
  - `base_cvss_component`
  - `nlp_context_bonus`
  - `urlhaus_correlation_bonus`
  - `dread_correlation_bonus`
  - `cross_source_bonus`
  - `graph_bonus`
  - `age_penalty`
- API results now include `evidence.nlp_entities`, which can be rendered directly in the dashboard.

The goal is not to claim a perfect ML model. The goal is to provide a transparent, explainable prioritization model where every score component can be inspected and defended.


## Dashboard analysis visibility

The frontend now renders the analysis layer directly instead of hiding it in raw JSON:

- Evidence overview metrics for CVSS, linked URLhaus/Dread records, relation count, extracted entities and high-signal terms.
- Visual score breakdown bars for CVSS, NLP context, correlation, cross-source, graph and age-penalty components.
- NLP entity chips for CVEs, CWEs, products, versions, vulnerability types, impacts, threat terms, IOCs, domains, keywords and salient phrases.
- Source contribution cards and counterfactual output for explainability.

This makes the core NLP/correlation/risk-engine behavior visible during demos and manual analysis.

