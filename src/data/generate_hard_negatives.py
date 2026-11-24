"""
Hard-Negative Benign Augmentation & Modern API Threat Dataset Generator.

Generates 5,000 diverse, realistic 'scary-looking benign' HTTP requests
and ~400 modern API attack payloads (NoSQLi, SSTI, SSRF) with zero leakage
from csic_held_out_test.parquet.

Categories:
1. International / non-English e-commerce & multilingual parameters (Spanish, French, German, Indian English).
2. Benign natural language text containing SQL, JS, and HTML keywords in normal prose.
3. Modern REST & GraphQL API payloads (nested JSON, UUIDs, ISO timestamps, JWT-like strings, markdown).
4. Benign long-payload requests (>200 tokens: bios, reviews, documentation).
5. Modern API attack payloads (NoSQLi, SSTI, SSRF).

Applies leakage-resistant Group-Aware splitting to hold out a pristine 500-sample
Hard-Negative Benign Validation Set with 0 overlapping groups.
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import random
import json
import uuid
import re
from typing import List, Dict, Any, Tuple
import pandas as pd
import numpy as np

from sklearn.model_selection import StratifiedGroupKFold
from src.pipeline.parser import parse_raw_http
from src.pipeline.feature_builder import build_features

RANDOM_SEED = 42

OUTPUT_DIR = ROOT / "data/processed"
DEV_POOL_PATH = ROOT / "data/processed/csic_dev.parquet"
AI_WAF_PATH = ROOT / "data/raw/ai_waf/train-00000-of-00001.parquet"
HTTP_PARAMS_PATH = ROOT / "data/raw/http_params/payload_train.csv"

HARD_NEG_VAL_PATH = OUTPUT_DIR / "hard_negatives_val_500.parquet"
HARD_NEG_TRAIN_PATH = OUTPUT_DIR / "hard_negatives_train.parquet"
DEV_V2_AUGMENTED_PATH = OUTPUT_DIR / "dev_v2_augmented.parquet"
DEV_V2_1_AUGMENTED_PATH = OUTPUT_DIR / "dev_v2_1_augmented.parquet"


# ============================================================================
# Vocabulary & Corpus Definitions
# ============================================================================

SPANISH_NAMES = ["José García", "María Carmen Rodríguez", "Manuel González", "Antonio Hernández", "David López", "Laura Martínez", "Francisco Pérez", "Ana Sánchez", "Javier Gómez", "Carmen Fernández", "Álvaro Núñez", "Inés Peña", "Rocío Cañizares", "Guillermo Ibáñez"]
SPANISH_CITIES = ["Madrid", "Barcelona", "Valencia", "Sevilla", "Zaragoza", "Málaga", "Murcia", "Palma de Mallorca", "Las Palmas", "Bilbao", "Alicante", "Córdoba", "Valladolid", "Vigo", "Gijón"]
SPANISH_STREETS = ["Calle Gran Vía 42", "Paseo de la Castellana 110", "Avenida Diagonal 255", "Calle Mayor 14, 3º Izq", "Rambla de Catalunya 12", "Calle Alcalá 88", "Avenida de la Constitución 5"]
SPANISH_PRODUCTS = ["Pañuelos de seda marrón", "Zapatos de cuero artesanal", "Aceite de oliva virgen extra 5L", "Cafetera exprés automática", "Jamón ibérico de bellota", "Queso manchego curado", "Vino tinto reserva Rioja", "Mochila escolar ergonómica", "Camiseta de algodón orgánico"]
SPANISH_COMMENTS = ["Por favor entregar en horario de tarde", "Dejar en conserjería si no estoy", "Llamar al timbre dos veces", "Empaquetar para regalo por favor", "Excelente calidad del producto", "Necesito factura con NIF para empresa"]

FRENCH_NAMES = ["François Dubois", "Élodie Laurent", "Guillaume Moreau", "Camille Lefèvre", "Jean-Baptiste Roux", "Hélène Fourcade", "Pierre Bonnet", "Chloé Mercier"]
FRENCH_CITIES = ["Paris", "Lyon", "Marseille", "Toulouse", "Bordeaux", "Nantes", "Strasbourg", "Lille"]
FRENCH_STREETS = ["Rue de la République 15", "Boulevard Saint-Germain 120", "Avenue des Champs-Élysées 45", "Rue Victor Hugo 8"]
FRENCH_COMMENTS = ["Livraison express souhaitée", "Laisser au gardien en cas d'absence", "Merci de bien protéger le colis", "Colis très soigné, merci"]

GERMAN_NAMES = ["Jürgen Weiß", "Günther Müller", "Klaus Schäfer", "Sabine Krämer", "Wolfgang Böhm", "Anja Schröder", "Stefan Zimmermann", "Ursula Götz"]
GERMAN_CITIES = ["Berlin", "München", "Hamburg", "Köln", "Frankfurt am Main", "Stuttgart", "Düsseldorf", "Leipzig"]
GERMAN_STREETS = ["Hauptstraße 25", "Goethestraße 14", "Schillerstraße 8", "Bahnhofstraße 52", "Münchener Straße 101"]
GERMAN_COMMENTS = ["Bitte bei den Nachbarn abgeben", "Schnellstmögliche Lieferung erwünscht", "Hinter dem Tor abstellen", "Sehr geehrte Damen und Herren, bitte um Rückmeldung"]

INDIAN_NAMES = ["Rajesh Subramanian", "Priya Venkatesh", "Amitabh Deshmukh", "Sunita Banerjee", "Vikramaditya Rao", "Ananya Chatterjee", "Karthik Sundaram", "Deepa Nambiar"]
INDIAN_CITIES = ["Bengaluru", "Mumbai", "Hyderabad", "Pune", "Chennai", "Gurugram", "Kolkata", "Noida", "Ahmedabad", "Jaipur"]
INDIAN_LANDMARKS = ["Near Hanuman Mandir, Sector 14", "Opposite City Centre Mall", "Behind Metro Station Pillar 210", "Near Tech Park Gate 2", "Beside Apollo Pharmacy"]
INDIAN_COMMENTS = ["Please call before delivery", "Do not ring the bell baby is sleeping", "Drop with security gate pass 4", "Deliver post 6 PM on weekdays"]

PROSE_SQL_SNIPPETS = [
    "How to select the best laptop from our summer catalogue",
    "O'Reilly book on 1 < 2 mathematical logic and computation",
    "Please drop by at 5pm to collect your parcel",
    "The European Union of two sets in topological analysis",
    "Insert coin to initiate arcade game credits",
    "Update your billing address in account settings",
    "Delete unwanted draft messages from mailbox",
    "Where is the nearest pickup locker situated in city centre?",
    "Table of contents for the advanced physics syllabus",
    "Group by department for the annual football tournament",
    "Order by price descending to see premium luxury suites",
    "Grant proposal submitted for marine biology conservation",
    "Alter ego superhero comic collection volume 4",
    "Select fresh organic apples from local orchards",
    "Union of railway workers announces regular schedule",
    "Create a new playlist with 80s rock ballads",
    "Drop in replacement filter for air purifier model 7",
    "Execute phase 2 of the website redesign project",
    "Having a great vacation in South America",
    "Between two worlds a novel by Arthur Miller",
    "Like father like son classic family drama",
    "Count the number of stars in the Andromeda galaxy",
    "Sum of all natural numbers up to one hundred",
    "Max value capacitor for audio amplifier power supply",
    "Min wage regulation updates for retail staff",
]

PROSE_JS_HTML_SNIPPETS = [
    "Alert me when this item returns to inventory",
    "Script for an indie short film shooting next month",
    "Fascinating documentary about the javascript programming community",
    "Window shopping along 5th avenue during winter sale",
    "Photography tutorial: image onerror handling and camera sensor clean",
    "Click here to download your digital event ticket PDF",
    "Style guide for spring seasonal wardrobe and shoes",
    "Ancient Roman form of municipal governance and law",
    "Custom wooden frame for oil painting 50x70 cm",
    "Natural body wash with lavender essence and organic oats",
    "Document outlining the terms of lease agreement",
    "Button up casual shirt with linen texture",
    "Input impedance calculations for guitar pedal circuit",
    "Head and shoulders shampoo with cooling menthol",
    "Title deed registration process in municipal council",
    "Console table with marble top for entrance hallway",
    "Location tracking permission for cab booking app",
    "Prompt delivery appreciated for anniversary celebration",
]

LONG_BIO_ESSAYS = [
    "I am an experienced research scientist with over twelve years of experience in computational linguistics and natural language processing. Throughout my career, I have published multiple peer-reviewed papers on neural machine translation, dependency parsing, and semantic role labeling. In my spare time, I enjoy landscape photography, hiking in the Alps, and mentoring undergraduate students in machine learning fundamentals. I believe in open-source software and reproducible science, and I strive to write clean, modular, and maintainable code for every project I undertake.",
    "Welcome to our independent artisan bakery founded in 2014 in downtown Valencia! We specialize in traditional sourdough bread fermented for forty-eight hours using ancient heritage wheat flours sourced directly from sustainable local farms. Every morning our bakers hand-craft croissants, pain au chocolat, rustic baguettes, and seasonal fruit tarts. We never use artificial preservatives, industrial emulsifiers, or refined white sugar. Come visit us for breakfast or order your custom celebration cakes online with doorstep delivery across the metropolitan area.",
    "Senior full-stack software engineer specializing in high-throughput distributed systems, event-driven microservices, and fault-tolerant cloud infrastructure. Proficient in Go, Python, TypeScript, Kafka, Docker, and Kubernetes. Passionate about system observability, distributed tracing, and reducing p99 latency under heavy concurrent loads. Dedicated to fostering inclusive engineering cultures, conducting constructive code reviews, and writing comprehensive unit and integration test suites that ensure continuous delivery without fear of production regressions.",
    "Comprehensive product specification and operating manual for Model 4000 Smart Air Purification System. This device incorporates true medical-grade HEPA filtration capable of capturing 99.97% of airborne particles as small as 0.3 microns, alongside an active honeycomb carbon stage designed to neutralize volatile organic compounds, kitchen odors, and pet dander. Features include ultra-quiet brushless DC motor operation below 24 decibels on sleep mode, intelligent laser particle monitoring, real-time air quality index display, and wireless remote control via iOS and Android mobile applications.",
    "Dear Customer Support Team, I am writing to express my appreciation for the prompt assistance I received regarding order reference number 8847291. The replacement glass terrarium arrived in pristine condition this morning, packaged securely with bio-degradable padding. I particularly want to commend your support representative Sarah who kept me updated throughout the logistics tracking process and promptly resolved the initial courier delay. It is rare to experience such high standards of customer care, and I will certainly recommend your online store to friends and colleagues.",
]

MODERN_ATTACKS = [
    # NoSQL Injection
    ('{"username": {"$ne": null}, "password": {"$gt": ""}}', "application/json", "nosqli"),
    ('{"email": {"$regex": "^admin.*"}, "pass": {"$ne": "123"}}', "application/json", "nosqli"),
    ('{"$where": "this.password.length > 6"}', "application/json", "nosqli"),
    ('{"user": "admin", "token": {"$exists": true}}', "application/json", "nosqli"),
    ('{"filter": {"$or": [{"role": "admin"}, {"role": "root"}]}}', "application/json", "nosqli"),
    ('username[$ne]=null&password[$ne]=null', "application/x-www-form-urlencoded", "nosqli"),
    ('filter[$gt]=&sort=asc', "application/x-www-form-urlencoded", "nosqli"),
    ('user[$regex]=^adm&auth=true', "application/x-www-form-urlencoded", "nosqli"),

    # Server-Side Template Injection (SSTI)
    ('{{7*7}}', "text/plain", "ssti"),
    ('${7*7}', "text/plain", "ssti"),
    ('<%= 7*7 %>', "text/plain", "ssti"),
    ('{{config.items()}}', "text/plain", "ssti"),
    ('{{settings.SECRET_KEY}}', "text/plain", "ssti"),
    ('{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}', "text/plain", "ssti"),
    ('${T(java.lang.Runtime).getRuntime().exec("whoami")}', "text/plain", "ssti"),
    ('#{7*7}', "text/plain", "ssti"),
    ('*{7*7}', "text/plain", "ssti"),
    ('{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen("cat /etc/passwd").read()}}', "text/plain", "ssti"),

    # Server-Side Request Forgery (SSRF)
    ('http://169.254.169.254/latest/meta-data/', "text/plain", "ssrf"),
    ('http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role', "text/plain", "ssrf"),
    ('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', "text/plain", "ssrf"),
    ('http://127.0.0.1:22/', "text/plain", "ssrf"),
    ('http://localhost:8080/admin/secrets', "text/plain", "ssrf"),
    ('http://0.0.0.0:6379/', "text/plain", "ssrf"),
    ('dict://127.0.0.1:11211/stat', "text/plain", "ssrf"),
    ('gopher://127.0.0.1:6379/_INFO%0d%0a', "text/plain", "ssrf"),
    ('http://[::1]:8080/internal-metrics', "text/plain", "ssrf"),
    ('http://169.254.169.254/metadata/v1.json', "text/plain", "ssrf"),
]


# ============================================================================
# Generator Functions
# ============================================================================

def generate_international_ecommerce(n: int, rng: random.Random) -> List[Dict[str, Any]]:
    """Generates Spanish, French, German, and Indian e-commerce requests."""
    samples = []
    locales = ["es", "fr", "de", "in"]

    for i in range(n):
        loc = locales[i % len(locales)]
        method = rng.choice(["GET", "POST"])

        if loc == "es":
            path = rng.choice(["/tienda/carrito", "/pedidos/confirmar", "/usuarios/registro", "/catalogo/buscar", "/contacto"])
            name = rng.choice(SPANISH_NAMES)
            city = rng.choice(SPANISH_CITIES)
            street = rng.choice(SPANISH_STREETS)
            prod = rng.choice(SPANISH_PRODUCTS)
            comment = rng.choice(SPANISH_COMMENTS)
            params = {
                "nombre": name,
                "direccion": street,
                "ciudad": city,
                "codigo_postal": f"{rng.randint(10000, 52999)}",
                "producto": prod,
                "comentarios": comment,
            }
        elif loc == "fr":
            path = rng.choice(["/boutique/panier", "/commande/livraison", "/compte/inscription", "/recherche"])
            params = {
                "nom": rng.choice(FRENCH_NAMES),
                "adresse": rng.choice(FRENCH_STREETS),
                "ville": rng.choice(FRENCH_CITIES),
                "code_postal": f"{rng.randint(10000, 95999)}",
                "remarques": rng.choice(FRENCH_COMMENTS),
            }
        elif loc == "de":
            path = rng.choice(["/warenkorb/kasse", "/bestellung/abschluss", "/kunden/anmeldung", "/suche"])
            params = {
                "benutzername": rng.choice(GERMAN_NAMES),
                "strasse": rng.choice(GERMAN_STREETS),
                "stadt": rng.choice(GERMAN_CITIES),
                "postleitzahl": f"{rng.randint(10000, 99999)}",
                "nachricht": rng.choice(GERMAN_COMMENTS),
            }
        else: # Indian English
            path = rng.choice(["/store/checkout", "/delivery/address", "/support/ticket", "/products/filter"])
            params = {
                "customer_name": rng.choice(INDIAN_NAMES),
                "city": rng.choice(INDIAN_CITIES),
                "landmark": rng.choice(INDIAN_LANDMARKS),
                "pincode": f"{rng.randint(110001, 700099)}",
                "delivery_notes": rng.choice(INDIAN_COMMENTS),
            }

        # Build raw HTTP
        headers = {
            "Host": "api.shop.com",
            "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/{rng.randint(110, 130)}.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": f"{loc},en;q=0.7",
        }

        if method == "GET":
            q_str = "&".join(f"{k}={v}" for k, v in params.items())
            full_path = f"{path}?{q_str}"
            lines = [f"GET {full_path} HTTP/1.1"]
            for hk, hv in headers.items():
                lines.append(f"{hk}: {hv}")
            lines.append("")
            raw = "\r\n".join(lines)
        else:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = "&".join(f"{k}={v}" for k, v in params.items())
            headers["Content-Length"] = str(len(body.encode("utf-8")))
            lines = [f"POST {path} HTTP/1.1"]
            for hk, hv in headers.items():
                lines.append(f"{hk}: {hv}")
            lines.append("")
            lines.append(body)
            raw = "\r\n".join(lines)

        param_keys = ",".join(sorted(params.keys()))
        group_id = f"intl_ecom::{path}?{param_keys}"

        samples.append({
            "category": "international_ecommerce",
            "method": method,
            "path": path,
            "raw_text": raw,
            "label": 0,
            "group_id": group_id,
        })

    return samples


CLASSIC_ENDPOINTS = [
    "/tienda/registro.jsp",
    "/portal/cliente.php",
    "/servicios/contacto.asp",
    "/usuarios/alta.aspx",
    "/catalogo/consulta.jsp",
    "/compras/pedido.php",
    "/clientes/formulario.asp",
    "/ventas/presupuesto.aspx",
    "/facturas/descarga.jsp",
    "/soporte/incidencia.php",
]


def generate_classic_web_forms(n: int, rng: random.Random) -> List[Dict[str, Any]]:
    """Generates classic server-rendered web forms (.jsp, .php, .asp, .aspx)
    with application/x-www-form-urlencoded payloads, standard form fields,
    multilingual names, dates, addresses, and numbers (~30% of benign hard negatives)."""
    import urllib.parse
    samples = []

    first_names = SPANISH_NAMES + FRENCH_NAMES + GERMAN_NAMES + INDIAN_NAMES
    cities = SPANISH_CITIES + FRENCH_CITIES + GERMAN_CITIES + INDIAN_CITIES
    streets = SPANISH_STREETS + FRENCH_STREETS + GERMAN_STREETS

    for i in range(n):
        ep = rng.choice(CLASSIC_ENDPOINTS)
        method = "POST" if rng.random() > 0.15 else "GET"

        name = rng.choice(first_names)
        city = rng.choice(cities)
        street = rng.choice(streets)
        phone = f"+{rng.randint(33, 91)} {rng.randint(600, 999)} {rng.randint(100, 999)} {rng.randint(100, 999)}"
        email = f"{name.lower().replace(' ', '.')}@correo.{rng.choice(['es', 'com', 'fr', 'de', 'org'])}"
        postal = f"{rng.randint(10000, 99999)}"
        comment = rng.choice(SPANISH_COMMENTS + FRENCH_COMMENTS + GERMAN_COMMENTS)

        form_type = rng.choice(["registration", "order", "search", "contact"])

        if form_type == "registration":
            params = {
                "nombre": name,
                "direccion": street,
                "ciudad": city,
                "codigo_postal": postal,
                "telefono": phone,
                "email": email,
                "comentarios": comment,
                "action": "enviar_formulario",
                "submit": "Guardar",
            }
        elif form_type == "order":
            params = {
                "id_cliente": str(rng.randint(1000, 99999)),
                "id_producto": str(rng.randint(100, 5000)),
                "cantidad": str(rng.randint(1, 10)),
                "fecha_entrega": f"2026-{rng.randint(11, 12):02d}-{rng.randint(1, 28):02d}",
                "direccion_envio": street,
                "ciudad": city,
                "codigo_postal": postal,
                "notas": comment,
                "modo_pago": rng.choice(["tarjeta", "transferencia", "contra_reembolso"]),
                "confirmar": "1",
            }
        elif form_type == "search":
            params = {
                "buscar": rng.choice(["portatil", "mesa", "silla", "pantalla", "teclado", "impresora", "raton"]),
                "categoria": rng.choice(["electronica", "oficina", "hogar", "informatica"]),
                "precio_min": str(rng.randint(10, 50)),
                "precio_max": str(rng.randint(100, 1500)),
                "orden": rng.choice(["precio_asc", "precio_desc", "relevancia"]),
                "pagina": str(rng.randint(1, 10)),
            }
        else:  # contact
            params = {
                "nombre_completo": name,
                "correo": email,
                "asunto": rng.choice(["Consulta sobre pedido", "Informacion de envio", "Solicitud de factura", "Estado de garantia"]),
                "mensaje": comment,
                "contacto_pref": rng.choice(["email", "telefono"]),
                "enviar": "Enviar",
            }

        encoded_body = urllib.parse.urlencode(params)

        headers = {
            "Host": "servicios.empresa.es",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
        }

        if method == "GET":
            full_path = f"{ep}?{encoded_body}"
            lines = [f"GET {full_path} HTTP/1.1"]
            for hk, hv in headers.items():
                lines.append(f"{hk}: {hv}")
            lines.append("")
            raw = "\r\n".join(lines)
        else:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Content-Length"] = str(len(encoded_body.encode("utf-8")))
            lines = [f"POST {ep} HTTP/1.1"]
            for hk, hv in headers.items():
                lines.append(f"{hk}: {hv}")
            lines.append("")
            lines.append(encoded_body)
            raw = "\r\n".join(lines)

        param_keys = ",".join(sorted(params.keys()))
        group_id = f"classic_form::{ep}?{param_keys}"

        samples.append({
            "category": "classic_form",
            "method": method,
            "path": ep,
            "raw_text": raw,
            "label": 0,
            "group_id": group_id,
        })

    return samples


def generate_prose_keywords(n: int, rng: random.Random) -> List[Dict[str, Any]]:
    """Generates benign natural prose containing SQL, JS, and HTML keywords."""
    samples = []
    combined_snippets = PROSE_SQL_SNIPPETS + PROSE_JS_HTML_SNIPPETS

    endpoints = [
        ("/search", "q"),
        ("/forum/topic", "title"),
        ("/library/books", "keyword"),
        ("/support/faq", "query"),
        ("/blog/comment", "comment_text"),
        ("/items/lookup", "description"),
        ("/feedback/submit", "feedback"),
    ]

    for i in range(n):
        ep, param_name = rng.choice(endpoints)
        method = "POST" if ep in ("/blog/comment", "/feedback/submit") else "GET"
        snippet = rng.choice(combined_snippets)
        user_name = rng.choice(SPANISH_NAMES + FRENCH_NAMES + INDIAN_NAMES)

        headers = {
            "Host": "knowledge.portal.org",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
            "Accept": "application/json, text/plain, */*",
        }

        if method == "GET":
            full_path = f"{ep}?{param_name}={snippet}&author={user_name}"
            lines = [f"GET {full_path} HTTP/1.1"]
            for hk, hv in headers.items():
                lines.append(f"{hk}: {hv}")
            lines.append("")
            raw = "\r\n".join(lines)
        else:
            headers["Content-Type"] = "application/json"
            body = json.dumps({
                param_name: snippet,
                "author": user_name,
                "rating": rng.randint(4, 5),
                "timestamp": f"2026-11-24T{rng.randint(10, 22)}:{rng.randint(10, 59)}:00Z"
            })
            headers["Content-Length"] = str(len(body.encode("utf-8")))
            lines = [f"POST {ep} HTTP/1.1"]
            for hk, hv in headers.items():
                lines.append(f"{hk}: {hv}")
            lines.append("")
            lines.append(body)
            raw = "\r\n".join(lines)

        group_id = f"prose_keywords::{ep}?{param_name}"
        samples.append({
            "category": "prose_keywords",
            "method": method,
            "path": ep,
            "raw_text": raw,
            "label": 0,
            "group_id": group_id,
        })

    return samples


def generate_rest_graphql(n: int, rng: random.Random) -> List[Dict[str, Any]]:
    """Generates complex modern REST and GraphQL API requests with nested JSON, UUIDs, JWTs."""
    samples = []

    graphql_queries = [
        "query GetAccountDetails($accId: UUID!) { account(id: $accId) { name balance transactions(limit: 5) { id amount currency date } } }",
        "query SearchInventory($category: String, $inStock: Boolean) { items(category: $category, inStock: $inStock) { id title price rating } }",
        "mutation UpdateProfile($input: UserProfileInput!) { updateUserProfile(input: $input) { success user { id email fullName } } }",
        "query GetFleetTelemetry($deviceId: ID!) { device(id: $deviceId) { status batteryLevel location { lat lng } } }",
    ]

    for i in range(n):
        is_graphql = (i % 3 == 0)

        if is_graphql:
            path = "/graphql"
            query_text = rng.choice(graphql_queries)
            body_dict = {
                "operationName": query_text.split()[1].split("(")[0],
                "query": query_text,
                "variables": {
                    "accId": str(uuid.UUID(int=rng.getrandbits(128))),
                    "category": rng.choice(["electronics", "clothing", "books", "home"]),
                    "inStock": True,
                    "timestamp": f"2026-11-24T{rng.randint(10, 23)}:{rng.randint(10, 59)}:{rng.randint(10, 59)}.000Z",
                }
            }
            body = json.dumps(body_dict)
            group_id = f"graphql::{path}::{body_dict['operationName']}"
        else:
            path = rng.choice(["/api/v2/events", "/api/v2/telemetry", "/api/v2/oauth/token", "/api/v2/users/sync"])
            body_dict = {
                "event_id": str(uuid.UUID(int=rng.getrandbits(128))),
                "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "".join(rng.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=64)) + ".signature",
                "client_redirect": f"https://client.service.io/callback?tenant={rng.choice(['prod', 'staging', 'corp'])}&code={rng.randint(100000, 999999)}",
                "nested_config": {
                    "retries": 3,
                    "timeout_ms": 5000,
                    "tags": ["cloud", "k8s", "waf-v2", rng.choice(["us-east-1", "eu-central-1", "ap-south-1"])],
                },
                "markdown_notes": "### Deployment Log\nAll checks passed with code `0`. Status: **OK**.",
            }
            body = json.dumps(body_dict)
            group_id = f"rest_api::{path}"

        headers = {
            "Host": "api.cloudservice.net",
            "Content-Type": "application/json",
            "Authorization": f"Bearer token_{rng.randint(10000, 99999)}",
            "Content-Length": str(len(body.encode("utf-8"))),
        }

        lines = [f"POST {path} HTTP/1.1"]
        for hk, hv in headers.items():
            lines.append(f"{hk}: {hv}")
        lines.append("")
        lines.append(body)
        raw = "\r\n".join(lines)

        samples.append({
            "category": "rest_graphql",
            "method": "POST",
            "path": path,
            "raw_text": raw,
            "label": 0,
            "group_id": group_id,
        })

    return samples


def generate_long_benign(n: int, rng: random.Random) -> List[Dict[str, Any]]:
    """Generates benign long-payload requests (>200 tokens) such as bios, reviews, and manuals."""
    samples = []
    endpoints = ["/users/profile/bio", "/reviews/submit", "/documentation/contribute", "/forum/post/create"]

    for i in range(n):
        ep = rng.choice(endpoints)
        essay = rng.choice(LONG_BIO_ESSAYS)
        author = rng.choice(SPANISH_NAMES + FRENCH_NAMES + GERMAN_NAMES + INDIAN_NAMES)

        # Extend text slightly with variable paragraphs to ensure > 200 tokens
        extra_paragraph = f" Additional notes recorded on 2026-11-24: Verified all guidelines and terms of service. Reference ID: {uuid.UUID(int=rng.getrandbits(128))}. Best regards, {author}."
        full_text = essay + extra_paragraph

        body_dict = {
            "author": author,
            "text": full_text,
            "category": "long_form_content",
            "word_count": len(full_text.split()),
            "status": "published",
        }
        body = json.dumps(body_dict)

        headers = {
            "Host": "community.publishing.org",
            "Content-Type": "application/json",
            "Content-Length": str(len(body.encode("utf-8"))),
        }

        lines = [f"POST {ep} HTTP/1.1"]
        for hk, hv in headers.items():
            lines.append(f"{hk}: {hv}")
        lines.append("")
        lines.append(body)
        raw = "\r\n".join(lines)

        group_id = f"long_benign::{ep}"
        samples.append({
            "category": "long_benign",
            "method": "POST",
            "path": ep,
            "raw_text": raw,
            "label": 0,
            "group_id": group_id,
        })

    return samples


def generate_modern_attacks(n: int, rng: random.Random) -> List[Dict[str, Any]]:
    """Generates ~400 modern API attack payloads (NoSQLi, SSTI, SSRF)."""
    samples = []
    endpoints = ["/api/v2/auth", "/api/v2/template/preview", "/api/v2/fetch-url", "/api/v2/query"]

    for i in range(n):
        payload, ctype, attack_type = rng.choice(MODERN_ATTACKS)
        ep = rng.choice(endpoints)
        method = "POST" if (ctype == "application/json" or i % 2 == 0) else "GET"

        headers = {
            "Host": "api.target.com",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
        }

        if method == "GET":
            # For GET, put attack in query parameter
            full_path = f"{ep}?target={payload}&type={attack_type}"
            lines = [f"GET {full_path} HTTP/1.1"]
            for hk, hv in headers.items():
                lines.append(f"{hk}: {hv}")
            lines.append("")
            raw = "\r\n".join(lines)
        else:
            headers["Content-Type"] = ctype
            if ctype == "application/json":
                body = payload
            else:
                body = f"input={payload}&category={attack_type}"
            headers["Content-Length"] = str(len(body.encode("utf-8")))

            lines = [f"POST {ep} HTTP/1.1"]
            for hk, hv in headers.items():
                lines.append(f"{hk}: {hv}")
            lines.append("")
            lines.append(body)
            raw = "\r\n".join(lines)

        group_id = f"modern_attack::{attack_type}::{ep}"
        samples.append({
            "category": f"attack_{attack_type}",
            "method": method,
            "path": ep,
            "raw_text": raw,
            "label": 1,
            "group_id": group_id,
        })

    return samples


# ============================================================================
# Main Generator & Split Logic
# ============================================================================

def generate_all_hard_negatives() -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Generates:
    - 5,000 hard-negative benign requests
    - 400 modern API attacks
    Splits into:
    - 500-sample pristine Hard-Negative Benign Validation Set (held out)
    - 4,900-sample Training Set
    - Combined Augmented Development Pool (18,000 baseline + ~4,900 hard-negative)
    """
    print("\n[Step 2] Generating Hard-Negative Benign & Modern Attack Dataset (seed=42)...")
    rng = random.Random(RANDOM_SEED)

    # 1. Generate 5,000 hard-negative benign requests across the 5 categories
    cat_classic = generate_classic_web_forms(1500, rng)
    cat1 = generate_international_ecommerce(1300, rng)
    cat2 = generate_prose_keywords(1000, rng)
    cat3 = generate_rest_graphql(700, rng)
    cat4 = generate_long_benign(500, rng)
    benign_samples = cat_classic + cat1 + cat2 + cat3 + cat4  # Exactly 5,000 benign
    print(f"  Generated {len(benign_samples):,} Hard-Negative Benign requests across 5 categories (including {len(cat_classic):,} classic web forms).")

    # 2. Generate 400 modern attack payloads
    attack_samples = generate_modern_attacks(400, rng)
    print(f"  Generated {len(attack_samples):,} Modern API attack payloads (NoSQLi, SSTI, SSRF).")

    all_samples = benign_samples + attack_samples
    rng.shuffle(all_samples)
    df_all = pd.DataFrame(all_samples)
    print(f"  Total generated pool: {len(df_all):,} samples (Benign: {(df_all['label']==0).sum():,}, Malicious: {(df_all['label']==1).sum():,})")

    # 3. Dedicated 500-sample Hard-Negative Benign Validation Set (Zero group overlap!)
    # We strictly select groups from benign samples to make exactly 500 validation benign samples
    df_benign = df_all[df_all["label"] == 0].copy()
    unique_benign_groups = list(df_benign["group_id"].unique())
    rng.shuffle(unique_benign_groups)

    val_benign_groups = set()
    val_benign_indices = []
    current_count = 0

    for grp in unique_benign_groups:
        grp_indices = df_benign[df_benign["group_id"] == grp].index.tolist()
        if current_count + len(grp_indices) <= 500:
            val_benign_groups.add(grp)
            val_benign_indices.extend(grp_indices)
            current_count += len(grp_indices)
        if current_count == 500:
            break

    # If count is slightly under 500 due to group sizes, fill remainder while maintaining group isolation
    if current_count < 500:
        for grp in unique_benign_groups:
            if grp not in val_benign_groups:
                grp_indices = df_benign[df_benign["group_id"] == grp].index.tolist()
                needed = 500 - current_count
                val_benign_groups.add(grp)
                val_benign_indices.extend(grp_indices[:needed])
                break

    df_val_500 = df_benign.loc[val_benign_indices[:500]].copy().reset_index(drop=True)
    val_groups_set = set(df_val_500["group_id"])

    # Training samples: everything in df_all EXCEPT the groups in val_benign_groups!
    df_train_pool = df_all[~df_all["group_id"].isin(val_groups_set)].copy().reset_index(drop=True)

    # Verify zero group leakage
    train_groups_set = set(df_train_pool["group_id"])
    overlap = val_groups_set.intersection(train_groups_set)
    assert len(overlap) == 0, f"FATAL: Group leakage detected in hard negatives! Overlap={len(overlap)}"
    assert len(df_val_500) == 500, f"Expected 500 val samples, got {len(df_val_500)}"

    print(f"  [Verification] Hard-Negative Benign Validation Set: {len(df_val_500):,} samples.")
    print(f"  [Verification] Hard-Negative Training Pool: {len(df_train_pool):,} samples.")
    print(f"  [Verification] Group Overlap: {len(overlap)} (Strict Zero Leakage Verified!).")

    # 4. Compute Representation D-v2 and D-v2-norm features
    print("  Computing Representation D-v2 and D-v2-norm features for all samples...")
    for df in [df_val_500, df_train_pool]:
        v2_feats = []
        v2_norm_feats = []
        for raw_t, lbl in zip(df["raw_text"], df["label"]):
            p = parse_raw_http(raw_t, label=lbl, source="hard_negative")
            v2_feats.append(build_features(p, representation="structured_v2"))
            v2_norm_feats.append(build_features(p, representation="structured_v2_norm"))
        df["feat_structured_v2"] = v2_feats
        df["feat_structured_v2_norm"] = v2_norm_feats

    # 5. Save Parquet Files
    df_val_500.to_parquet(HARD_NEG_VAL_PATH, index=False)
    df_train_pool.to_parquet(HARD_NEG_TRAIN_PATH, index=False)
    print(f"  Saved pristine val set -> {HARD_NEG_VAL_PATH}")
    print(f"  Saved training portion -> {HARD_NEG_TRAIN_PATH}")

    # 6. Build Combined Augmented Development Pool (v2.1)
    print("  Building combined Augmented Development Pool (Baseline 18k + Hard-Negatives)...")
    records = []

    # Load baseline AI WAF
    if AI_WAF_PATH.exists():
        ai_df = pd.read_parquet(AI_WAF_PATH)[["text", "label"]].dropna().copy()
        ai_df["text"] = ai_df["text"].astype(str).str.strip()
        ai_df["label"] = ai_df["label"].astype(str).str.strip().str.lower()
        ai_df = ai_df[ai_df["text"].ne("")].copy()
        ai_df["norm"] = ai_df["text"].str.split().str.join(" ").str.lower()
        ai_df = ai_df.drop_duplicates("norm").reset_index(drop=True)

        sample_ai_benign = ai_df[ai_df["label"] == "benign"].sample(
            min(len(ai_df[ai_df["label"] == "benign"]), 6000), random_state=RANDOM_SEED
        )
        sample_ai_mal = ai_df[ai_df["label"] == "malicious"].sample(
            min(len(ai_df[ai_df["label"] == "malicious"]), 3000), random_state=RANDOM_SEED
        )

        for t in sample_ai_benign["text"]:
            p = parse_raw_http(t, label=0, source="ai_waf")
            records.append({
                "source": "ai_waf",
                "raw_text": t,
                "feat_structured_v2": build_features(p, "structured_v2"),
                "feat_structured_v2_norm": build_features(p, "structured_v2_norm"),
                "label": 0,
                "group_id": f"ai_waf::{p.path}",
            })
        for t in sample_ai_mal["text"]:
            p = parse_raw_http(t, label=1, source="ai_waf")
            records.append({
                "source": "ai_waf",
                "raw_text": t,
                "feat_structured_v2": build_features(p, "structured_v2"),
                "feat_structured_v2_norm": build_features(p, "structured_v2_norm"),
                "label": 1,
                "group_id": f"ai_waf::{p.path}",
            })

    # Load baseline CSIC Dev
    if DEV_POOL_PATH.exists():
        csic_dev = pd.read_parquet(DEV_POOL_PATH)
        csic_benign = csic_dev[csic_dev["label"].str.lower() == "benign"]
        csic_mal = csic_dev[csic_dev["label"].str.lower().isin(["malicious", "anomalous"])]

        sample_csic_benign = csic_benign.sample(min(len(csic_benign), 4000), random_state=RANDOM_SEED)
        sample_csic_mal = csic_mal.sample(min(len(csic_mal), 3000), random_state=RANDOM_SEED)

        for t in sample_csic_benign["request_text"]:
            p = parse_raw_http(t, label=0, source="csic_dev")
            records.append({
                "source": "csic_dev",
                "raw_text": t,
                "feat_structured_v2": build_features(p, "structured_v2"),
                "feat_structured_v2_norm": build_features(p, "structured_v2_norm"),
                "label": 0,
                "group_id": f"csic_dev::{p.path}",
            })
        for t in sample_csic_mal["request_text"]:
            p = parse_raw_http(t, label=1, source="csic_dev")
            records.append({
                "source": "csic_dev",
                "raw_text": t,
                "feat_structured_v2": build_features(p, "structured_v2"),
                "feat_structured_v2_norm": build_features(p, "structured_v2_norm"),
                "label": 1,
                "group_id": f"csic_dev::{p.path}",
            })

    # Load baseline HTTP Params
    if HTTP_PARAMS_PATH.exists():
        hp_df = pd.read_csv(HTTP_PARAMS_PATH).dropna().copy()
        is_mal = hp_df["label"].astype(str).str.strip().str.lower().isin(["anom", "1", "malicious"])
        hp_mal = hp_df[is_mal].sample(min(len(hp_df[is_mal]), 2000), random_state=RANDOM_SEED)
        for pl in hp_mal["payload"]:
            feat = f"[METHOD] GET [PATH] /search [PARAM] q={pl} [PAYLOAD] {pl}"
            records.append({
                "source": "http_params",
                "raw_text": f"GET /search?q={pl} HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "feat_structured_v2": feat,
                "feat_structured_v2_norm": feat,
                "label": 1,
                "group_id": "http_params::search",
            })

    # Append Hard-Negative Training samples
    for _, r in df_train_pool.iterrows():
        records.append({
            "source": "hard_negative_aug",
            "raw_text": r["raw_text"],
            "feat_structured_v2": r["feat_structured_v2"],
            "feat_structured_v2_norm": r["feat_structured_v2_norm"],
            "label": r["label"],
            "group_id": r["group_id"],
        })

    df_dev_v2_1 = pd.DataFrame(records)
    df_dev_v2_1.to_parquet(DEV_V2_1_AUGMENTED_PATH, index=False)
    print(f"  Combined Augmented Development Pool v2.1 saved: {len(df_dev_v2_1):,} records -> {DEV_V2_1_AUGMENTED_PATH}")
    print(f"    - Benign: {(df_dev_v2_1['label']==0).sum():,}")
    print(f"    - Malicious: {(df_dev_v2_1['label']==1).sum():,}")

    return df_val_500, df_train_pool, df_dev_v2_1


if __name__ == "__main__":
    generate_all_hard_negatives()
