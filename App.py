import os
import json
import hashlib
import secrets
import re
from datetime import datetime, date
from typing import Any, Dict, List, Optional

import streamlit as st
from supabase import create_client

# OpenAI optional
try:
    from openai import OpenAI
except Exception:
    OpenAI = None


# =========================
# Config / Secrets
# =========================
SUPABASE_URL = st.secrets.get("SUPABASE_URL", os.getenv("SUPABASE_URL", ""))
SUPABASE_KEY = st.secrets.get("SUPABASE_SERVICE_ROLE_KEY", os.getenv("SUPABASE_SERVICE_ROLE_KEY", ""))
OPENAI_API_KEY = st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY", ""))
APP_TITLE = st.secrets.get("APP_BRAND_TITLE", os.getenv("APP_BRAND_TITLE", "Personal Potentials · Реализация"))

USERS_TABLE = "pp_users"
PROFILES_TABLE = "pp_profiles"

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in Streamlit secrets")

sb = create_client(SUPABASE_URL, SUPABASE_KEY)


# =========================
# Security helpers (stdlib PBKDF2)
# =========================
def _pbkdf2_hash(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return dk.hex()

def make_password(password: str) -> tuple[str, str]:
    salt = secrets.token_urlsafe(16)
    pw_hash = _pbkdf2_hash(password, salt)
    return salt, pw_hash

def verify_password(password: str, salt: str, pw_hash: str) -> bool:
    return secrets.compare_digest(_pbkdf2_hash(password, salt), pw_hash)


# =========================
# Potentials normalization (accept ANY input)
# =========================
DEFAULT_NAMES = [
    "Аметист","Гранат","Цитрин",
    "Сапфир","Гелиодор","Изумруд",
    "Янтарь","Шунгит","Рубин"
]

def _clean_tokens(s: str) -> List[str]:
    s = (s or "").strip()
    if not s:
        return []

    # Replace separators with commas
    s = s.replace("|", ",").replace("—", "-").replace("–", "-")
    # Remove common words
    s = re.sub(r"\b(ряд|row|процен(т|ты)|%|место|позиция|потенциал(ы)?)\b", " ", s, flags=re.I)
    # Remove numbering like "1." "2)" "3:" etc
    s = re.sub(r"(?<!\d)(\d{1,2})\s*[\.\)\:\-]", " ", s)
    s = re.sub(r"[\n\r]+", ",", s)
    # Split by comma or semicolon
    parts = re.split(r"[,\;]+", s)
    parts = [p.strip() for p in parts if p.strip()]
    return parts

def normalize_potentials_text(raw: str) -> str:
    """
    Accepts:
    - "1. Аметист 2. Гранат 3. Цитрин ..."
    - "Аметист, Гранат, Цитрин, ..."
    - "Аметист | Гранат | Цитрин ..."
    - Any messy text
    Returns 3x3 formatted string for AI.
    """
    tokens = _clean_tokens(raw)

    # If user pasted already 9 known names in any order — keep that order.
    # If less than 9, we fill with defaults at the end (for robustness).
    if len(tokens) >= 9:
        tokens = tokens[:9]
    else:
        # try to preserve what user wrote + fill remaining with defaults (no duplicates if possible)
        existing = set([t.lower() for t in tokens])
        for name in DEFAULT_NAMES:
            if name.lower() not in existing and len(tokens) < 9:
                tokens.append(name)

    # Build 3x3
    a = tokens[0:3]
    b = tokens[3:6]
    c = tokens[6:9]

    return (
        f"1 ряд: 1. {a[0]} | 2. {a[1]} | 3. {a[2]}\n"
        f"2 ряд: 4. {b[0]} | 5. {b[1]} | 6. {b[2]}\n"
        f"3 ряд: 7. {c[0]} | 8. {c[1]} | 9. {c[2]}"
    )


# =========================
# Default data (MVP)
# =========================
def default_profile() -> Dict[str, Any]:
    action_blocks = [
        {"key": "structure", "title": "Структура дня", "items": []},
        {"key": "focus", "title": "Фокус недели", "items": []},
        {"key": "growth", "title": "Рост и навыки", "items": []},
        {"key": "energy", "title": "Энергия и ресурс", "items": []},
    ]

    return {
        "meta": {
            "schema": "pp.realization.v1",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "updated_at": datetime.utcnow().isoformat() + "Z",
        },
        "foundation": {
            "name": "",
            "potentials_table": "",   # raw user input
            "notes": "",
        },
        "realization": {
            "point_a": "",
            "point_b": "",
            "weekly_focus": "",
            "focus_explainer": "",
            "action_blocks": action_blocks,
            "week_start": "",
        },
        "today": {
            "by_date": {},
        }
        "library": {
            "potentials_guide": "",
            "master_report": "",
            "master_report_updated_at": ""
        },
        "metrics": {
            "daily_target": 3,
            "weekly_target_days": 4
        },
    }


# =========================
# DB helpers
# =========================
def db_get_user_by_email(email: str) -> Optional[dict]:
    r = sb.table(USERS_TABLE).select("*").eq("email", email.lower().strip()).limit(1).execute()
    rows = r.data or []
    return rows[0] if rows else None

def db_create_user(email: str, password: str) -> dict:
    salt, pw_hash = make_password(password)
    r = sb.table(USERS_TABLE).insert({
        "email": email.lower().strip(),
        "salt": salt,
        "pw_hash": pw_hash,
    }).execute()
    return (r.data or [None])[0]

def db_get_profile(user_id: str) -> Optional[dict]:
    r = sb.table(PROFILES_TABLE).select("*").eq("user_id", user_id).limit(1).execute()
    rows = r.data or []
    return rows[0] if rows else None

def db_upsert_profile(user_id: str, data: dict) -> None:
    data["meta"]["updated_at"] = datetime.utcnow().isoformat() + "Z"
    sb.table(PROFILES_TABLE).upsert({
        "user_id": user_id,
        "data": data,
        "updated_at": datetime.utcnow().isoformat() + "Z"
    }).execute()


# =========================
# UI theme (LIGHT)
# =========================
def inject_css():
    st.markdown(
        """
<style>
@import url('https://fonts.googleapis.com/css2?family=Manrope:wght@300;400;600;700&family=Playfair+Display:wght@500;600;700&display=swap');

:root{
  --pp-bg: #ffffff;
  --pp-card: #ffffff;
  --pp-card2: #faf7fc;
  --pp-border: rgba(17, 24, 39, 0.10);
  --pp-text: #111827;
  --pp-muted: rgba(17, 24, 39, 0.62);
  --pp-violet: #3b1a5a;
  --pp-rose: #c18aa4;
  --pp-amber: #ff9f4a;
  --pp-shadow: 0 10px 24px rgba(17,24,39,0.08);
}

html, body, [class*="css"]  {
  font-family: Manrope, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif !important;
}

.main {
  background: radial-gradient(1200px 600px at 20% 0%, rgba(59,26,90,0.06), transparent 60%),
              radial-gradient(900px 500px at 85% 10%, rgba(255,159,74,0.05), transparent 60%),
              var(--pp-bg);
}

h1, h2, h3 {
  font-family: "Playfair Display", serif !important;
  letter-spacing: 0.2px;
  color: var(--pp-text);
}

.pp-card{
  background: var(--pp-card);
  border: 1px solid var(--pp-border);
  border-radius: 16px;
  padding: 16px 16px 14px 16px;
  margin: 10px 0;
  box-shadow: var(--pp-shadow);
}

.pp-chip{
  display:inline-block;
  padding: 6px 10px;
  border-radius: 999px;
  border: 1px solid var(--pp-border);
  background: rgba(59,26,90,0.05);
  color: var(--pp-violet);
  font-size: 12px;
  margin-right: 6px;
}

.pp-title{
  color: var(--pp-text);
  font-weight: 800;
  font-size: 16px;
  margin-bottom: 6px;
}

.pp-sub{
  color: var(--pp-muted);
  font-size: 13px;
  line-height: 1.35;
}

.pp-accent{
  color: var(--pp-violet);
  font-weight: 800;
}

hr { border-color: rgba(17,24,39,0.10) !important; }
</style>
        """,
        unsafe_allow_html=True,
    )


# =========================
# OpenAI helper (optional)
# =========================
def get_openai_client():
    if not OPENAI_API_KEY or not OpenAI:
        return None
    return OpenAI(api_key=OPENAI_API_KEY)

def _extract_json_from_text(txt: str) -> Optional[dict]:
    txt = (txt or "").strip()
    if not txt:
        return None
    # Try direct JSON
    try:
        return json.loads(txt)
    except Exception:
        pass
    # Try to find JSON object inside text
    m = re.search(r"\{[\s\S]*\}", txt)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None

def normalize_potentials_text(raw: str) -> str:
    if not raw:
        return ""
    s = raw.strip()

    # если человек просто перечислил через точки/пробелы — оставим как есть, но красиво
    # уберём двойные пробелы и приведём к строкам
    s = "\n".join([ln.strip() for ln in s.splitlines() if ln.strip()])
    if "\n" not in s:
        # одна строка — разобьём по точкам с номерами или по запятым
        s = s.replace("1.", "\n1.").replace("2.", "\n2.").replace("3.", "\n3.")
        s = s.replace("4.", "\n4.").replace("5.", "\n5.").replace("6.", "\n6.")
        s = s.replace("7.", "\n7.").replace("8.", "\n8.").replace("9.", "\n9.")
        s = s.replace(",", "\n")
        s = "\n".join([ln.strip() for ln in s.splitlines() if ln.strip()])
    return s

def ai_generate_focus(potentials_raw: str, point_a: str, point_b: str, model: str = "gpt-4o-mini") -> dict:
    client = get_openai_client()
    if not client:
        raise RuntimeError("OpenAI not configured")

    potentials_norm = normalize_potentials_text(potentials_raw)

    system = (
        "Ты — навигатор по реализации человека через Personal Potentials.\n"
        "Дай практичный план без давления. Не терапия. Не диагноз.\n"
        "Ответ СТРОГО в JSON.\n"
        "JSON schema:\n"
        "{"
        "  \"weekly_focus\": \"...\","
        "  \"focus_explainer\": \"...\","
        "  \"action_blocks\": ["
        "    {\"key\":\"structure\",\"items\":[{\"id\":\"...\",\"title\":\"...\",\"minutes\":15,\"freq\":\"daily\"}]},"
        "    {\"key\":\"focus\",\"items\":[...]},"
        "    {\"key\":\"growth\",\"items\":[...]},"
        "    {\"key\":\"energy\",\"items\":[...]}"
        "  ]"
        "}\n"
        "Требования: 3–5 задач на блок; задачи маленькие, измеримые; freq только daily/weekly; minutes 10–45."
    )
    user = f"""Потенциалы (нормализовано 3×3):
{potentials_norm}

Точка А (сейчас):
{point_a}

Точка Б (как хочу):
{point_b}

Сгенерируй фокус недели и план.
"""

    resp = client.chat.completions.create(
        model=model,
        messages=[{"role":"system","content":system},{"role":"user","content":user}],
        temperature=0.5,
    )

    txt = (resp.choices[0].message.content or "").strip()
    data = _extract_json_from_text(txt)
    if not data:
        # return a safe fallback so UI doesn't crash
        return {
            "weekly_focus": "Собрать фокус и ритм",
            "focus_explainer": "ИИ вернул не-JSON. Я сохранила безопасный фокус. Проверь ключ OpenAI или попробуй ещё раз.",
            "action_blocks": [
                {"key":"structure","items":[{"id":secrets.token_hex(6),"title":"15 минут план дня (1–3 приоритета)","minutes":15,"freq":"daily"}]},
                {"key":"focus","items":[{"id":secrets.token_hex(6),"title":"1 шаг к цели (самый маленький)","minutes":20,"freq":"daily"}]},
                {"key":"growth","items":[{"id":secrets.token_hex(6),"title":"10 минут обучение/чтение по теме","minutes":10,"freq":"daily"}]},
                {"key":"energy","items":[{"id":secrets.token_hex(6),"title":"Прогулка/вода/сон — 1 улучшение","minutes":15,"freq":"daily"}]},
            ]
        }
    return data

def ai_generate_master_report(potentials_raw: str, name: str, model: str="gpt-4o-mini") -> str:
    client = get_openai_client()
    if not client:
        raise RuntimeError("OpenAI not configured")

    potentials_norm = normalize_potentials_text(potentials_raw)

    system = (
        "Ты — эксперт по системе Personal Potentials. Пиши очень подробный мастер-отчёт.\n"
        "Стиль: глубоко, по-человечески, без эзотерического тумана, но с метафорами кристаллов.\n"
        "Нужно: 1) ядро 2) сильные стороны 3) ловушки 4) решения\n"
        "5) энергия 6) реализация/деньги 7) отношения/коммуникация 8) идеальная неделя\n"
        "9) план на 14 дней 10) чек-лист «что перестать/что начать».\n"
        "Формат: Markdown."
    )
    user = f"""Имя: {name or "Клиент"}
Потенциалы 3×3:
{potentials_norm}

Сгенерируй мастер-отчёт максимально подробно (как премиум отчёт).
"""

    resp = client.chat.completions.create(
        model=model,
        messages=[{"role":"system","content":system},{"role":"user","content":user}],
        temperature=0.6,
    )
    return (resp.choices[0].message.content or "").strip()

# =========================
# Session state
# =========================
def init_state():
    st.set_page_config(page_title=APP_TITLE, page_icon="💠", layout="wide")
    inject_css()
    if "authed" not in st.session_state:
        st.session_state.authed = False
    if "user" not in st.session_state:
        st.session_state.user = None
    if "profile" not in st.session_state:
        st.session_state.profile = None

def save_profile():
    if not st.session_state.user or not st.session_state.profile:
        return
    db_upsert_profile(st.session_state.user["id"], st.session_state.profile)

def monday_of_week(d: date) -> date:
    return d.fromordinal(d.toordinal() - d.weekday())


# =========================
# Auth screens
# =========================
def auth_screen():
    st.title(APP_TITLE)
    st.caption("Платформа навигации по реализации через потенциалы. Аккуратно, красиво, по делу.")
    me = st.secrets.get("MASTER_EMAIL", "")
    mp = st.secrets.get("MASTER_PASSWORD", "")
    if me and mp:
        if st.button("⚡ Войти как мастер (тест)", use_container_width=True):
        u = db_get_user_by_email(me)
            if not u:
                u = db_create_user(me, mp)
                data = default_profile()
                db_upsert_profile(u["id"], data)
            st.session_state.authed = True
            st.session_state.user = u
            prof = db_get_profile(u["id"])
            st.session_state.profile = (prof["data"] if prof else default_profile())
            st.rerun()
    st.markdown('<div class="pp-card">', unsafe_allow_html=True)
    tab_login, tab_signup = st.tabs(["Войти", "Создать доступ"])

    with tab_login:
        email = st.text_input("Email", key="login_email")
        pw = st.text_input("Пароль", type="password", key="login_pw")
        if st.button("Войти", use_container_width=True):
            u = db_get_user_by_email(email)
            if not u:
                st.error("Пользователь не найден.")
            else:
                if verify_password(pw, u["salt"], u["pw_hash"]):
                    st.session_state.authed = True
                    st.session_state.user = u
                    prof = db_get_profile(u["id"])
                    if not prof:
                        data = default_profile()
                        db_upsert_profile(u["id"], data)
                        st.session_state.profile = data
                    else:
                        st.session_state.profile = prof["data"]
                    st.rerun()
                else:
                    st.error("Неверный пароль.")

    with tab_signup:
        email2 = st.text_input("Email (для доступа)", key="su_email")
        pw2 = st.text_input("Пароль (минимум 8 символов)", type="password", key="su_pw")
        pw3 = st.text_input("Повтори пароль", type="password", key="su_pw2")
        if st.button("Создать доступ", use_container_width=True):
            if not email2 or "@" not in email2:
                st.error("Введи корректный email.")
            elif len(pw2) < 8:
                st.error("Пароль минимум 8 символов.")
            elif pw2 != pw3:
                st.error("Пароли не совпадают.")
            elif db_get_user_by_email(email2):
                st.error("Такой email уже зарегистрирован.")
            else:
                u = db_create_user(email2, pw2)
                data = default_profile()
                db_upsert_profile(u["id"], data)
                st.success("Готово ✅ Теперь зайди во вкладку «Войти».")
    st.markdown("</div>", unsafe_allow_html=True)


# =========================
# UI blocks
# =========================
def header_bar():
    st.markdown(f"# {APP_TITLE}")
    st.markdown(
        '<span class="pp-chip">💠 Personal Potentials</span>'
        '<span class="pp-chip">Навигация</span>'
        '<span class="pp-chip">Конструктор действий</span>',
        unsafe_allow_html=True,
    )
    st.write("")

def block_card(title: str, subtitle: str = ""):
    st.markdown('<div class="pp-card">', unsafe_allow_html=True)
    st.markdown(f'<div class="pp-title">{title}</div>', unsafe_allow_html=True)
    if subtitle:
        st.markdown(f'<div class="pp-sub">{subtitle}</div>', unsafe_allow_html=True)

def end_card():
    st.markdown("</div>", unsafe_allow_html=True)


def foundation_tab(profile: dict):
    f = profile["foundation"]

    block_card("0) Основа", "Можно просто перечислить потенциалы (через запятую). Я сама приведу к формату 3×3.")
    c1, c2 = st.columns([2, 1])
    with c1:
        f["name"] = st.text_input("Имя (как обращаться)", value=f.get("name",""))
    with c2:
        if st.button("💾 Сохранить основу", use_container_width=True):
            save_profile()
            st.success("Сохранено ✅")

    f["potentials_table"] = st.text_area(
        "Потенциалы (любой формат: «Аметист, Гранат…» или «1. Аметист 2. Гранат…»)",
        value=f.get("potentials_table",""),
        height=140
    )

    # preview normalized
    if f.get("potentials_table","").strip():
        st.caption("Как это будет читаться системой (авто-формат):")
        st.code(normalize_potentials_text(f["potentials_table"]), language="")

    f["notes"] = st.text_area(
        "Короткие заметки (необязательно)",
        value=f.get("notes",""),
        height=100
    )
    
    st.markdown("### Справочник по потенциалам (для чтения)")
    profile["library"]["potentials_guide"] = st.text_area(
        "Вставь сюда большой справочник (Markdown). Он будет доступен всегда.",
        value=profile["library"].get("potentials_guide",""),
        height=220
    )
    if st.button("💾 Сохранить справочник", use_container_width=True, key="save_guide"):
        save_profile()
        st.success("Сохранено ✅")

    st.markdown("### Мастер-отчёт (ИИ)")
    has_ai = bool(get_openai_client())
    model_r = st.selectbox("Модель отчёта", ["gpt-4o-mini","gpt-4.1-mini"], index=0, disabled=not has_ai, key="model_master")

    if st.button("🧠 Сгенерировать мастер-отчёт", use_container_width=True, disabled=not has_ai, key="btn_master_report"):
        if not f.get("potentials_table","").strip():
            st.error("Сначала вставь потенциалы.")
        else:
            txt = ai_generate_master_report(f["potentials_table"], f.get("name",""), model=model_r)
            profile["library"]["master_report"] = txt
            profile["library"]["master_report_updated_at"] = datetime.utcnow().isoformat()+"Z"
            save_profile()
            st.success("Готово ✅ Мастер-отчёт сохранён.")
            st.rerun()

    if profile["library"].get("master_report"):
        st.markdown(profile["library"]["master_report"])
    end_card()


def ensure_week_initialized(profile: dict):
    r = profile["realization"]
    today = date.today()
    week_start = monday_of_week(today).isoformat()
    if r.get("week_start") != week_start:
        r["week_start"] = week_start
        save_profile()


def realization_tab(profile: dict):
    ensure_week_initialized(profile)
    r = profile["realization"]
    f = profile["foundation"]

    block_card("1) Реализация", "Точка А → Точка Б → фокус недели → 4 блока действий.")
    c1, c2 = st.columns(2)
    with c1:
        r["point_a"] = st.text_area("Точка А (сейчас)", value=r.get("point_a",""), height=130)
    with c2:
        r["point_b"] = st.text_area("Точка Б (как хочу)", value=r.get("point_b",""), height=130)

    colA, colB, colC = st.columns([1,1,1.2])
    with colA:
        if st.button("💾 Сохранить", use_container_width=True):
            save_profile()
            st.success("Сохранено ✅")
    with colB:
        has_ai = bool(get_openai_client())
        model = st.selectbox("Модель ИИ", ["gpt-4o-mini","gpt-4.1-mini"], index=0, disabled=not has_ai)
    with colC:
        if st.button("✨ Сгенерировать фокус и план (ИИ)", use_container_width=True, disabled=not has_ai):
            try:
                if not f.get("potentials_table","").strip():
                    st.error("Сначала вставь потенциалы во вкладке «0) Основа».")
                elif not r.get("point_a","").strip() or not r.get("point_b","").strip():
                    st.error("Заполни Точку А и Точку Б.")
                else:
                    out = ai_generate_focus(
                        potentials_raw=f["potentials_table"],
                        point_a=r["point_a"],
                        point_b=r["point_b"],
                        model=model
                    )
                    r["weekly_focus"] = (out.get("weekly_focus","") or "").strip()
                    r["focus_explainer"] = (out.get("focus_explainer","") or "").strip()

                    blocks_by_key = {b["key"]: b for b in r["action_blocks"]}
                    for b in out.get("action_blocks", []):
                        k = b.get("key")
                        if k in blocks_by_key:
                            items = b.get("items", []) or []
                            norm = []
                            for it in items:
                                tid = it.get("id") or secrets.token_hex(6)
                                norm.append({
                                    "id": tid,
                                    "title": (it.get("title") or "").strip(),
                                    "minutes": int(it.get("minutes") or 15),
                                    "freq": (it.get("freq") or "daily").strip(),
                                })
                            blocks_by_key[k]["items"] = norm
                    save_profile()
                    st.success("Готово ✅ Фокус и задачи созданы.")
                    st.rerun()
            except Exception as e:
                st.error(f"Ошибка ИИ: {e}")

    st.write("")
    st.markdown(f"**Фокус недели:** <span class='pp-accent'>{r.get('weekly_focus','') or '—'}</span>", unsafe_allow_html=True)
    if r.get("focus_explainer"):
        st.caption(r["focus_explainer"])

    st.write("")
    st.markdown("### 4 блока действий (редактируемые)")
    for b in r["action_blocks"]:
        block_card(b["title"], "Добавь 3–7 маленьких действий. Частота: daily/weekly. 10–45 минут.")
        items = b.get("items", [])
        edited = st.data_editor(
            items,
            num_rows="dynamic",
            use_container_width=True,
            column_config={
                "id": st.column_config.TextColumn("id", disabled=True),
                "title": st.column_config.TextColumn("Действие"),
                "minutes": st.column_config.NumberColumn("мин", min_value=5, max_value=120, step=5),
                "freq": st.column_config.SelectboxColumn("частота", options=["daily","weekly"]),
            },
            key=f"ed_{b['key']}"
        )

        norm = []
        for it in edited:
            tid = it.get("id") or secrets.token_hex(6)
            norm.append({
                "id": tid,
                "title": (it.get("title") or "").strip(),
                "minutes": int(it.get("minutes") or 15),
                "freq": (it.get("freq") or "daily").strip(),
            })
        b["items"] = norm

        if st.button("💾 Сохранить блок", use_container_width=True, key=f"save_block_{b['key']}"):
            save_profile()
            st.success("Сохранено ✅")
        end_card()

def today_tab(profile: dict):
    ensure_week_initialized(profile)
    r = profile["realization"]
    t = profile["today"]

    block_card("2) Сегодня", "Галочки + заметки. Прогресс без давления.")
    chosen = st.date_input("Дата", value=date.today(), key="today_date")
    dkey = chosen.isoformat()
    day = t["by_date"].get(dkey) or {"done": {}, "notes": ""}

    tasks = []
    for b in r["action_blocks"]:
        for it in b.get("items", []):
            if it.get("title") and it.get("freq") == "daily":
                tasks.append((b["title"], it))

    if not tasks:
        st.info("Пока нет daily-действий. Зайди в «1) Реализация» и добавь задачи (частота daily).")
    else:
        st.markdown("### Мои действия на сегодня")
        done_map = day.get("done", {})
        done_count = 0

        for section, it in tasks:
            tid = it["id"]
            label = f"{it['title']} · {it.get('minutes',15)} мин"
            checked = bool(done_map.get(tid, False))
            c = st.checkbox(label, value=checked, key=f"chk_{dkey}_{tid}")
            done_map[tid] = bool(c)
            if c:
                done_count += 1

        total = len(tasks)
        st.progress(done_count / total if total else 0)
        st.caption(f"Сделано: {done_count} из {total}")

        day["done"] = done_map

    st.write("")
    day["notes"] = st.text_area("Инсайты / комментарии за день", value=day.get("notes",""), height=120)

    c1, c2 = st.columns([1,1])
    with c1:
        if st.button("💾 Сохранить день", use_container_width=True):
            t["by_date"][dkey] = day
            save_profile()
            st.success("Сохранено ✅")
    with c2:
        if st.button("🧹 Очистить отметки этого дня", use_container_width=True):
            t["by_date"][dkey] = {"done": {}, "notes": ""}
            save_profile()
            st.success("Очищено ✅")
            st.rerun()

    end_card()


def settings_tab():
    block_card("Настройки", "Профиль и выход.")
    st.code(f"Email: {st.session_state.user.get('email')}")
    if st.button("🚪 Выйти", use_container_width=True):
        st.session_state.authed = False
        st.session_state.user = None
        st.session_state.profile = None
        st.rerun()
    end_card()


# =========================
# Main
# =========================
init_state()

if not st.session_state.authed:
    auth_screen()
    st.stop()

profile = st.session_state.profile
if not profile:
    prof = db_get_profile(st.session_state.user["id"])
    if prof:
        st.session_state.profile = prof["data"]
        profile = st.session_state.profile
    else:
        data = default_profile()
        db_upsert_profile(st.session_state.user["id"], data)
        st.session_state.profile = data
        profile = data

header_bar()

tabs = st.tabs(["0) Основа", "1) Реализация", "2) Сегодня", "3) Прогресс", "Настройки"])

with tabs[0]:
    foundation_tab(profile)
    save_profile()

with tabs[1]:
    realization_tab(profile)
    save_profile()

with tabs[2]:
    today_tab(profile)
    save_profile()

with tabs[3]:
    settings_tab()
    
with tabs[4]:
    progress_tab(profile)
    save_profile()

with tabs[5]:
    settings_tab()