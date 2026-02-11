# App.py — Personal Potentials · Реализация
# One-file clean version (no duplicates, stable input, master report 1st-person)

import os
import json
import hashlib
import secrets
import re
from datetime import datetime, date
from typing import Any, Dict, List, Optional

import streamlit as st
from supabase import create_client

# Optional OpenAI
try:
    from openai import OpenAI
except Exception:
    OpenAI = None


# =========================================================
# CONFIG / SECRETS
# =========================================================
APP_TITLE = st.secrets.get("APP_BRAND_TITLE", os.getenv("APP_BRAND_TITLE", "Personal Potentials · Реализация"))

SUPABASE_URL = st.secrets.get("SUPABASE_URL", os.getenv("SUPABASE_URL", ""))
SUPABASE_KEY = st.secrets.get("SUPABASE_SERVICE_ROLE_KEY", os.getenv("SUPABASE_SERVICE_ROLE_KEY", ""))

OPENAI_API_KEY = st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY", ""))

USERS_TABLE = "pp_users"
PROFILES_TABLE = "pp_profiles"

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in Streamlit secrets")

sb = create_client(SUPABASE_URL, SUPABASE_KEY)


# =========================================================
# CANON IMPORT (optional) — if not available, keep empty
# =========================================================
# If Streamlit Cloud sometimes "doesn't see" separate files,
# you can paste canon dicts directly into this App.py (below).
try:
    from spch_canon import POT_CANON_1_3, POT_4_CANON, POT_5_CANON, POT_6_CANON
except Exception:
    POT_CANON_1_3, POT_4_CANON, POT_5_CANON, POT_6_CANON = {}, {}, {}, {}

# --- OPTIONAL: paste your canon dicts directly here if imports fail ---
# POT_CANON_1_3 = {...}
# POT_4_CANON = {...}
# POT_5_CANON = {...}
# POT_6_CANON = {...}


# =========================================================
# UI THEME (LIGHT)
# =========================================================
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


# =========================================================
# SECURITY (stdlib PBKDF2)
# =========================================================
def _pbkdf2_hash(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return dk.hex()

def make_password(password: str) -> tuple[str, str]:
    salt = secrets.token_urlsafe(16)
    pw_hash = _pbkdf2_hash(password, salt)
    return salt, pw_hash

def verify_password(password: str, salt: str, pw_hash: str) -> bool:
    return secrets.compare_digest(_pbkdf2_hash(password, salt), pw_hash)


# =========================================================
# DB HELPERS
# =========================================================
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
    data.setdefault("meta", {})
    data["meta"]["updated_at"] = datetime.utcnow().isoformat() + "Z"
    sb.table(PROFILES_TABLE).upsert({
        "user_id": user_id,
        "data": data,
        "updated_at": datetime.utcnow().isoformat() + "Z"
    }).execute()


# =========================================================
# PROFILE SCHEMA
# =========================================================
DEFAULT_NAMES = [
    "Аметист","Гранат","Цитрин",
    "Сапфир","Гелиодор","Изумруд",
    "Янтарь","Шунгит","Рубин"
]

def default_profile() -> Dict[str, Any]:
    return {
        "meta": {
            "schema": "pp.realization.v2",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "updated_at": datetime.utcnow().isoformat() + "Z",
        },
        "foundation": {
            "name": "",
            "potentials_table": "",
            "notes": "",
        },
        "realization": {
            "point_a": "",
            "point_b": "",
            "weekly_focus": "",
            "focus_explainer": "",
            "action_blocks": [
                {"key": "structure", "title": "Структура дня", "items": []},
                {"key": "focus", "title": "Фокус недели", "items": []},
                {"key": "growth", "title": "Рост и навыки", "items": []},
                {"key": "energy", "title": "Энергия и ресурс", "items": []},
            ],
            "week_start": "",
        },
        "today": {"by_date": {}},
        "library": {
            "extended_report_md": "",
            "extended_report_updated_at": "",
        },
        "metrics": {
            "daily_target": 3,
            "weekly_target_days": 4
        },
    }

def ensure_profile_schema(p: dict) -> dict:
    if not isinstance(p, dict):
        p = default_profile()

    p.setdefault("foundation", {})
    p["foundation"].setdefault("name", "")
    p["foundation"].setdefault("potentials_table", "")
    p["foundation"].setdefault("notes", "")

    p.setdefault("realization", {})
    p["realization"].setdefault("point_a", "")
    p["realization"].setdefault("point_b", "")
    p["realization"].setdefault("weekly_focus", "")
    p["realization"].setdefault("focus_explainer", "")
    p["realization"].setdefault("week_start", "")
    p["realization"].setdefault("action_blocks", [
        {"key": "structure", "title": "Структура дня", "items": []},
        {"key": "focus", "title": "Фокус недели", "items": []},
        {"key": "growth", "title": "Рост и навыки", "items": []},
        {"key": "energy", "title": "Энергия и ресурс", "items": []},
    ])

    p.setdefault("today", {})
    p["today"].setdefault("by_date", {})

    p.setdefault("library", {})
    p["library"].setdefault("extended_report_md", "")
    p["library"].setdefault("extended_report_updated_at", "")

    p.setdefault("metrics", {})
    p["metrics"].setdefault("daily_target", 3)
    p["metrics"].setdefault("weekly_target_days", 4)

    p.setdefault("meta", {})
    p["meta"].setdefault("schema", "pp.realization.v2")

    return p


# =========================================================
# POTENTIALS PARSING / NORMALIZATION (ONE VERSION)
# =========================================================
def _clean_tokens(raw: str) -> List[str]:
    s = (raw or "").strip()
    if not s:
        return []
    s = s.replace("|", ",").replace("—", "-").replace("–", "-")
    s = re.sub(r"\b(ряд|row|процен(т|ты)|%|место|позиция|потенциал(ы)?)\b", " ", s, flags=re.I)
    s = re.sub(r"(?<!\d)(\d{1,2})\s*[\.\)\:\-]", " ", s)
    s = re.sub(r"[\n\r]+", ",", s)
    parts = re.split(r"[,\;]+", s)
    parts = [p.strip() for p in parts if p.strip()]
    return parts

def parse_potentials_9(raw: str) -> List[str]:
    tokens = _clean_tokens(raw)

    # fill to 9 safely
    if len(tokens) >= 9:
        tokens = tokens[:9]
    else:
        existing = set([t.lower() for t in tokens])
        for name in DEFAULT_NAMES:
            if name.lower() not in existing and len(tokens) < 9:
                tokens.append(name)

    return tokens[:9]

def normalize_potentials_text(raw: str) -> str:
    p9 = parse_potentials_9(raw)
    a, b, c = p9[0:3], p9[3:6], p9[6:9]
    return (
        f"1 ряд (ядро): {a[0]} | {a[1]} | {a[2]}\n"
        f"2 ряд (наполнение/соц.слой): {b[0]} | {b[1]} | {b[2]}\n"
        f"3 ряд (риски/делегирование): {c[0]} | {c[1]} | {c[2]}"
    )

def build_matrix_table_md(p9: List[str]) -> str:
    if len(p9) < 9:
        return "—"
    pos1, pos2, pos3, pos4, pos5, pos6, pos7, pos8, pos9 = p9[:9]
    lines = [
        "| Ряд | Восприятие | Мотивация | Инструмент |",
        "|---|---|---|---|",
        f"| 1 (ядро / 60%) | {pos1} | {pos2} | {pos3} |",
        f"| 2 (наполнение / 30%) | {pos4} | {pos5} | {pos6} |",
        f"| 3 (риски / 10%) | {pos7} | {pos8} | {pos9} |",
    ]
    return "\n".join(lines)

def positions_dict(p9: List[str]) -> Dict[str, str]:
    p9 = (p9 + DEFAULT_NAMES)[:9]
    return {
        "pos1": p9[0], "pos2": p9[1], "pos3": p9[2],
        "pos4": p9[3], "pos5": p9[4], "pos6": p9[5],
        "pos7": p9[6], "pos8": p9[7], "pos9": p9[8],
    }


# =========================================================
# CANON EXCERPTS (safe, no hallucination)
# =========================================================
def _clean_pot_name(x: str) -> str:
    return (x or "").strip(" \t\r\n-–—•*,:;").strip()

def _canon_cell_1_3(pot: str, col: str) -> str:
    pot = _clean_pot_name(pot)
    d = (POT_CANON_1_3 or {}).get(pot, {}).get(col)
    if not d:
        return "—"
    if isinstance(d, str):
        return d.strip() or "—"
    if isinstance(d, dict):
        title = (d.get("title") or "").strip()
        lines = d.get("lines") or []
        intu = d.get("intuition") or []
        out = []
        if title:
            out.append(f"**{title}**")
        if lines:
            out.extend([f"- {str(x).strip()}" for x in lines if str(x).strip()])
        if intu:
            out.append("")
            out.append("**Интуиция / как мне лучше принимать решения:**")
            out.extend([f"- {str(x).strip()}" for x in intu if str(x).strip()])
        return "\n".join(out).strip() or "—"
    return "—"

def _canon_pos_4_5_6(pot: str, which: str) -> str:
    pot = _clean_pot_name(pot)
    canon = {"4": POT_4_CANON, "5": POT_5_CANON, "6": POT_6_CANON}.get(which, {}) or {}
    d = canon.get(pot)
    if not d:
        return "—"
    try:
        # canon for 4/5/6 may be structured — show as markdown-ish bullets if possible
        if isinstance(d, str):
            return d.strip() or "—"
        return json.dumps(d, ensure_ascii=False, indent=2)
    except Exception:
        return str(d)

def build_canon_bundle(pos: Dict[str, str]) -> Dict[str, Any]:
    # row1
    row1 = {
        "pos1": _canon_cell_1_3(pos["pos1"], "perception"),
        "pos2": _canon_cell_1_3(pos["pos2"], "motivation"),
        "pos3": _canon_cell_1_3(pos["pos3"], "instrument"),
    }
    # row2
    row2 = {
        "pos4": _canon_pos_4_5_6(pos["pos4"], "4"),
        "pos5": _canon_pos_4_5_6(pos["pos5"], "5"),
        "pos6": _canon_pos_4_5_6(pos["pos6"], "6"),
    }
    # row3 — use 1_3 canon by columns (as “описание потенциала”), interpretation is risk/delegation
    row3 = {
        "pos7": _canon_cell_1_3(pos["pos7"], "perception"),
        "pos8": _canon_cell_1_3(pos["pos8"], "motivation"),
        "pos9": _canon_cell_1_3(pos["pos9"], "instrument"),
    }
    return {"canon_row1": row1, "canon_row2": row2, "canon_row3": row3}


# =========================================================
# OPENAI HELPERS
# =========================================================
def get_openai_client():
    if not OPENAI_API_KEY or not OpenAI:
        return None
    return OpenAI(api_key=OPENAI_API_KEY)

def _extract_json_from_text(txt: str):
    txt = (txt or "").strip()
    if not txt:
        return None
    try:
        return json.loads(txt)
    except Exception:
        pass
    m = re.search(r"\{[\s\S]*\}", txt)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


# =========================================================
# AI: WEEKLY FOCUS (JSON)
# =========================================================
def ai_generate_focus(potentials_raw: str, point_a: str, point_b: str, model: str = "gpt-4o-mini") -> dict:
    client = get_openai_client()
    if not client:
        raise RuntimeError("OpenAI not configured")

    p9 = parse_potentials_9(potentials_raw)
    matrix_md = build_matrix_table_md(p9)

    system = (
        "Ты — навигатор по реализации через Personal Potentials (матрица 3×3).\n"
        "Дай практичный план без давления. Не терапия. Не диагноз.\n"
        "Ответ строго в JSON.\n"
        "Схема JSON:\n"
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
        "Ограничения: 3–5 задач на блок; задачи маленькие и измеримые; freq только daily/weekly; minutes 10–45."
    )

    user = f"""Матрица 3×3:
{matrix_md}

Точка А:
{point_a}

Точка Б:
{point_b}

Сгенерируй фокус недели и план.
"""

    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        temperature=0.5,
    )

    txt = (resp.choices[0].message.content or "").strip()
    data = _extract_json_from_text(txt)
    if not data:
        return {
            "weekly_focus": "Собрать фокус и ритм",
            "focus_explainer": "ИИ вернул не-JSON. Проверь ключ OpenAI или попробуй ещё раз.",
            "action_blocks": [
                {"key":"structure","items":[{"id":secrets.token_hex(6),"title":"План дня: 1–3 приоритета","minutes":15,"freq":"daily"}]},
                {"key":"focus","items":[{"id":secrets.token_hex(6),"title":"Один маленький шаг к цели","minutes":20,"freq":"daily"}]},
                {"key":"growth","items":[{"id":secrets.token_hex(6),"title":"10 минут обучения по теме","minutes":10,"freq":"daily"}]},
                {"key":"energy","items":[{"id":secrets.token_hex(6),"title":"Прогулка/вода/сон — 1 улучшение","minutes":15,"freq":"daily"}]},
            ]
        }
    return data


# =========================================================
# AI: MASTER REPORT (FIRST PERSON, NO QUESTIONS, CANON-BASED)
# =========================================================
def ai_generate_master_report_spch(
    potentials_raw: str,
    name: str,
    point_a: str,
    point_b: str,
    model: str = "gpt-4o-mini",
) -> str:
    client = get_openai_client()
    if not client:
        raise RuntimeError("OpenAI not configured")

    p9 = parse_potentials_9(potentials_raw)
    pos = positions_dict(p9)
    matrix_table = build_matrix_table_md(p9)

    canon_bundle = build_canon_bundle(pos)

    system = (
        "Ты — методист и мастер отчётов по СПЧ / Personal Potentials (матрица 3×3).\n"
        "Пиши по-русски.\n"
        "\n"
        "ЖЁСТКО:\n"
        "- НЕ используй слова: «кристалл», «камень», «магия», «эзотерика».\n"
        "- НЕ задавай вопросов.\n"
        "- НЕ выдумывай свойства потенциалов: опирайся ТОЛЬКО на CANON_EXCERPTS.\n"
        "- Если CANON_EXCERPTS для какой-то позиции пустой («—»), так и пиши: «в каноне данных нет, поэтому я не додумываю».\n"
        "\n"
        "СТИЛЬ ОТЧЁТА:\n"
        "- Пиши от ПЕРВОГО ЛИЦА (как будто это мой личный отчёт). Используй «я», «мне», «мой».\n"
        "- Тон: взросло, глубоко, структурно, без воды.\n"
        "- Это не терапия и не диагноз.\n"
        "\n"
        "ЛОГИКА МАТРИЦЫ:\n"
        "Столбцы:\n"
        "1) Восприятие = моя призма, как я вижу мир (позиции 1 и 4 усиливают эту призму)\n"
        "2) Мотивация = мой движок, кайф процесса\n"
        "3) Инструмент = моя ценность/самоценность, триумф результата (может быть не приятно, но даёт мощный эффект)\n"
        "Ряды:\n"
        "1 ряд = ядро/реализация/монетизация (≈60% энергии)\n"
        "2 ряд = наполнение/социальный слой/взаимодействие (≈30%)\n"
        "3 ряд = риски/делегирование (≈10%)\n"
        "\n"
        "ФОРМАТ: Markdown, с чёткими заголовками, таблицами и списками.\n"
    )

    payload = {
        "name": name or "Клиент",
        "point_a": point_a or "",
        "point_b": point_b or "",
        "matrix_table_md": matrix_table,
        "positions": pos,
        "CANON_EXCERPTS": canon_bundle,
    }

    user = (
        "Сделай мастерский расширенный отчёт диагностики.\n"
        "Структура СТРОГО такая:\n"
        "1) Матрица 3×3 (таблица)\n"
        "2) Как читать матрицу (очень кратко): 60/30/10 + 3 столбца (восприятие/мотивация/инструмент)\n"
        "3) 1 ряд — моё ядро и реализация (очень подробно):\n"
        "   3.1 Моя призма (позиция 1) — как я вижу мир и что для меня важно\n"
        "   3.2 Мой движок (позиция 2) — что меня реально заводит и где мой драйв\n"
        "   3.3 Мой инструмент (позиция 3) — где моя самоценность и триумф результата\n"
        "   3.4 Связка 1–2–3: какие роли/деятельности/форматы работы мне подходят, чтобы задействовать всё ядро\n"
        "   3.5 Деньги и монетизация: как доход растёт, когда я живу из 1 ряда\n"
        "4) 2 ряд — наполнение и взаимодействие (подробно):\n"
        "   4.1 Позиция 4 как усилитель призмы (как это меня подпитывает)\n"
        "   4.2 Позиция 5 как социальный/клиентский слой (как я взаимодействую и что меня наполняет)\n"
        "   4.3 Позиция 6 как результат/эмоциональная гармония (что меня возвращает в жизнь)\n"
        "   4.4 Как 2 ряд подзаряжает 1 ряд: простые принципы\n"
        "5) 3 ряд — риски и делегирование (подробно):\n"
        "   5.1 Где я теряю энергию\n"
        "   5.2 Что мне лучше ограничить\n"
        "   5.3 Что мне лучше делегировать\n"
        "6) Механика моей текущей ситуации (Точка А) — почему так могло сложиться:\n"
        "   - конфликт между рядами/столбцами\n"
        "   - уход в 2 ряд вместо 1\n"
        "   - блоки/страхи/подсознательные программы как заслон потенциалов\n"
        "7) Мост к Точке Б: 3–5 направлений/форматов деятельности, которые логично приведут меня туда\n"
        "8) Финальная сборка: «Кто я» — 10–15 строк\n"
        "\n"
        "Не задавай вопросов. Не добавляй новых свойств потенциалов. Опирайся только на CANON_EXCERPTS.\n"
        "\n"
        f"Входные данные (json):\n{json.dumps(payload, ensure_ascii=False)}"
    )

    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        temperature=0.45,
    )

    return (resp.choices[0].message.content or "").strip()


# =========================================================
# SESSION STATE INIT
# =========================================================
def init_state():
    st.set_page_config(page_title=APP_TITLE, page_icon="💠", layout="wide")
    inject_css()
    st.session_state.setdefault("authed", False)
    st.session_state.setdefault("user", None)
    st.session_state.setdefault("profile", None)

def save_profile_to_db(profile: dict):
    # save only when explicitly called
    if not st.session_state.get("user"):
        return
    db_upsert_profile(st.session_state["user"]["id"], profile)

def monday_of_week(d: date) -> date:
    return d.fromordinal(d.toordinal() - d.weekday())

def ensure_week_initialized(profile: dict):
    r = profile["realization"]
    week_start = monday_of_week(date.today()).isoformat()
    if r.get("week_start") != week_start:
        r["week_start"] = week_start


# =========================================================
# AUTH SCREEN
# =========================================================
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
            st.session_state.profile = ensure_profile_schema(prof["data"] if prof else default_profile())
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
                        st.session_state.profile = ensure_profile_schema(prof["data"])
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


# =========================================================
# TAB: FOUNDATION (stable form input)
# =========================================================
def foundation_tab(profile: dict):
    f = profile["foundation"]
    lib = profile["library"]

    block_card("0) Основа", "Заполни потенциалы. Сохранение — только по кнопке (чтобы не срывало набор текста).")

    # session keys
    name_key = "pp_name"
    pot_key = "pp_potentials_raw"
    show_key = "pp_show_preview"

    if name_key not in st.session_state:
        st.session_state[name_key] = f.get("name", "")
    if pot_key not in st.session_state:
        st.session_state[pot_key] = f.get("potentials_table", "")
    if show_key not in st.session_state:
        st.session_state[show_key] = False

    with st.form("foundation_form", clear_on_submit=False):
        c1, c2 = st.columns([2, 1])
        with c1:
            st.text_input("Имя (как обращаться)", key=name_key)
        with c2:
            save_clicked = st.form_submit_button("💾 Сохранить основу", use_container_width=True)

        st.text_area(
            "Потенциалы (любой формат: «Аметист, Гранат…» или «1. Аметист 2. Гранат…»)",
            key=pot_key,
            height=180
        )
        st.checkbox("Показать авто-формат 3×3", key=show_key)

    if save_clicked:
        f["name"] = (st.session_state.get(name_key) or "").strip()
        f["potentials_table"] = (st.session_state.get(pot_key) or "").strip()
        ensure_week_initialized(profile)
        save_profile_to_db(profile)
        st.success("Сохранено ✅")

    if st.session_state.get(show_key) and (st.session_state.get(pot_key) or "").strip():
        st.caption("Как это будет читаться системой (авто-формат 3×3):")
        st.code(normalize_potentials_text(st.session_state[pot_key]))

    st.divider()
    st.subheader("Расширенный отчёт (ИИ)")

    has_ai = bool(get_openai_client())
    model = st.selectbox(
        "Модель ИИ для отчёта",
        options=["gpt-4o-mini", "gpt-4.1-mini", "gpt-4.1"],
        index=0,
        disabled=not has_ai
    )
    if not has_ai:
        st.warning("OpenAI не настроен (нет ключа) — генерация отчёта недоступна.")
        end_card()
        return

    gen = st.button("🧠 Сгенерировать расширенный отчёт", use_container_width=True)
    if gen:
        try:
            potentials_raw = (f.get("potentials_table") or "").strip()
            if not potentials_raw:
                st.error("Сначала вставь потенциалы и нажми «Сохранить основу».")
            else:
                r = profile["realization"]
                text = ai_generate_master_report_spch(
                    potentials_raw=potentials_raw,
                    name=(f.get("name") or "Клиент").strip(),
                    point_a=(r.get("point_a") or "").strip(),
                    point_b=(r.get("point_b") or "").strip(),
                    model=model,
                )
                lib["extended_report_md"] = text
                lib["extended_report_updated_at"] = datetime.utcnow().isoformat() + "Z"
                save_profile_to_db(profile)
                st.success("Готово ✅")
        except Exception as e:
            st.error(f"Ошибка генерации: {e}")

    if (lib.get("extended_report_md") or "").strip():
        st.markdown("### Твой расширенный отчёт")
        st.markdown(lib["extended_report_md"])

    end_card()


# =========================================================
# TAB: REALIZATION (use form to prevent typing reruns)
# =========================================================
def realization_tab(profile: dict):
    ensure_week_initialized(profile)
    r = profile["realization"]
    f = profile["foundation"]

    block_card("1) Реализация", "Точка А → Точка Б → фокус недели → 4 блока действий. Сохранение — по кнопке.")

    # stable keys
    a_key = "pp_point_a"
    b_key = "pp_point_b"
    if a_key not in st.session_state:
        st.session_state[a_key] = r.get("point_a", "")
    if b_key not in st.session_state:
        st.session_state[b_key] = r.get("point_b", "")

    with st.form("realization_form", clear_on_submit=False):
        c1, c2 = st.columns(2)
        with c1:
            st.text_area("Точка А (сейчас)", key=a_key, height=140)
        with c2:
            st.text_area("Точка Б (как хочу)", key=b_key, height=140)

        save_r = st.form_submit_button("💾 Сохранить Реализацию", use_container_width=True)

    if save_r:
        r["point_a"] = (st.session_state.get(a_key) or "").strip()
        r["point_b"] = (st.session_state.get(b_key) or "").strip()
        save_profile_to_db(profile)
        st.success("Сохранено ✅")

    st.write("")
    colA, colB, colC = st.columns([1, 1, 1.2])
    with colA:
        pass
    with colB:
        has_ai = bool(get_openai_client())
        model = st.selectbox("Модель ИИ", ["gpt-4o-mini", "gpt-4.1-mini"], index=0, disabled=not has_ai)
    with colC:
        if st.button("✨ Сгенерировать фокус и план (ИИ)", use_container_width=True, disabled=not has_ai):
            try:
                if not (f.get("potentials_table") or "").strip():
                    st.error("Сначала вставь потенциалы во вкладке «0) Основа».")
                elif not (r.get("point_a") or "").strip() or not (r.get("point_b") or "").strip():
                    st.error("Заполни Точку А и Точку Б и нажми «Сохранить Реализацию».")
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

                    save_profile_to_db(profile)
                    st.success("Готово ✅ Фокус и задачи созданы.")
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

    editor_key = f"ed_{b['key']}"

    edited = st.data_editor(
        items,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "id": st.column_config.TextColumn("id", disabled=True),
            "title": st.column_config.TextColumn("Действие"),
            "minutes": st.column_config.NumberColumn("мин", min_value=10, max_value=45, step=5),
            "freq": st.column_config.SelectboxColumn("частота", options=["daily", "weekly"]),
        },
        key=editor_key
    )

    # ВАЖНО: НЕ пишем обратно в b["items"] на каждом run.
    # Готовим нормализованные данные только как "кандидата на сохранение".
    pending = []
    for it in edited or []:
        tid = it.get("id") or secrets.token_hex(6)
        pending.append({
            "id": tid,
            "title": (it.get("title") or "").strip(),
            "minutes": int(it.get("minutes") or 15),
            "freq": (it.get("freq") or "daily").strip(),
        })

    if st.button("💾 Сохранить блок", use_container_width=True, key=f"save_block_{b['key']}"):
        b["items"] = pending
        save_profile_to_db(profile)
        st.success("Сохранено ✅")

    end_card()

    end_card()


# =========================================================
# TAB: TODAY
# =========================================================
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

    c1, c2 = st.columns([1, 1])
    with c1:
        if st.button("💾 Сохранить день", use_container_width=True):
            t["by_date"][dkey] = day
            save_profile_to_db(profile)
            st.success("Сохранено ✅")
    with c2:
        if st.button("🧹 Очистить отметки этого дня", use_container_width=True):
            t["by_date"][dkey] = {"done": {}, "notes": ""}
            save_profile_to_db(profile)
            st.success("Очищено ✅")

    end_card()


# =========================================================
# TAB: PROGRESS (placeholder)
# =========================================================
def progress_tab(profile: dict):
    block_card("3) Прогресс", "Скоро: недельная/месячная статистика, метрики и AI-анализ.")
    st.info("В разработке. Следующий шаг — собрать статистику из today.by_date.")
    end_card()


# =========================================================
# TAB: SETTINGS
# =========================================================
def settings_tab():
    block_card("Настройки", "Профиль и выход.")
    u = st.session_state.get("user") or {}
    st.code(f"Email: {u.get('email')}")
    if st.button("🚪 Выйти", use_container_width=True):
        st.session_state.authed = False
        st.session_state.user = None
        st.session_state.profile = None
        st.rerun()
    end_card()


# =========================================================
# MAIN
# =========================================================
init_state()

if not st.session_state.authed:
    auth_screen()
    st.stop()

# load profile from session, if missing — from DB
if not st.session_state.profile:
    prof_row = db_get_profile(st.session_state.user["id"])
    if prof_row and prof_row.get("data"):
        st.session_state.profile = ensure_profile_schema(prof_row["data"])
    else:
        data = default_profile()
        db_upsert_profile(st.session_state.user["id"], data)
        st.session_state.profile = data

profile = ensure_profile_schema(st.session_state.profile)

header_bar()

tabs = st.tabs(["0) Основа", "1) Реализация", "2) Сегодня", "3) Прогресс", "Настройки"])

with tabs[0]:
    foundation_tab(profile)

with tabs[1]:
    realization_tab(profile)

with tabs[2]:
    today_tab(profile)

with tabs[3]:
    progress_tab(profile)

with tabs[4]:
    settings_tab()

# Keep session_state updated (no auto-save)
st.session_state.profile = profile