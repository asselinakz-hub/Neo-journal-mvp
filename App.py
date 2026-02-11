import os
import json
import time
import hashlib
import secrets
from datetime import datetime, date
from typing import Any, Dict, List

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
    # 200k iterations is fine for MVP
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return dk.hex()

def make_password(password: str) -> tuple[str, str]:
    salt = secrets.token_urlsafe(16)
    pw_hash = _pbkdf2_hash(password, salt)
    return salt, pw_hash

def verify_password(password: str, salt: str, pw_hash: str) -> bool:
    return secrets.compare_digest(_pbkdf2_hash(password, salt), pw_hash)


# =========================
# Default data (MVP)
# =========================
def default_profile() -> Dict[str, Any]:
    # 4 блока действий (вариант B)
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
            "potentials_table": "",   # сюда вставим матрицу
            "notes": "",
        },
        "realization": {
            "point_a": "",
            "point_b": "",
            "weekly_focus": "",       # выбранный фокус (строка)
            "focus_explainer": "",    # краткое объяснение фокуса (можно ИИ)
            "action_blocks": action_blocks,
            "week_start": "",         # дата понедельника текущей недели
        },
        "today": {
            # храним отметки по датам: {"YYYY-MM-DD": {"done": {task_id: true}, "notes": "..."}}
            "by_date": {}
        }
    }


# =========================
# DB helpers
# =========================
def db_get_user_by_email(email: str) -> dict | None:
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

def db_get_profile(user_id: str) -> dict | None:
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
# UI theme (Cyrillic fonts + brand look)
# =========================
def inject_css():
    st.markdown(
        """
<style>
@import url('https://fonts.googleapis.com/css2?family=Manrope:wght@300;400;600;700&family=Playfair+Display:wght@500;600;700&display=swap');

:root{
  --pp-bg: #0f0b14;
  --pp-card: rgba(255,255,255,0.06);
  --pp-card2: rgba(255,255,255,0.08);
  --pp-border: rgba(255,255,255,0.10);
  --pp-text: rgba(255,255,255,0.92);
  --pp-muted: rgba(255,255,255,0.65);
  --pp-violet: #3b1a5a;
  --pp-rose: #c18aa4;
  --pp-amber: #ff9f4a;
}

html, body, [class*="css"]  {
  font-family: Manrope, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif !important;
}

.main {
  background: radial-gradient(1200px 600px at 20% 0%, rgba(59,26,90,0.35), transparent 60%),
              radial-gradient(900px 500px at 85% 10%, rgba(255,159,74,0.12), transparent 60%),
              var(--pp-bg);
}

h1, h2, h3 {
  font-family: "Playfair Display", serif !important;
  letter-spacing: 0.2px;
}

.pp-card{
  background: var(--pp-card);
  border: 1px solid var(--pp-border);
  border-radius: 18px;
  padding: 16px 16px 14px 16px;
  margin: 8px 0;
  box-shadow: 0 10px 24px rgba(0,0,0,0.25);
}

.pp-chip{
  display:inline-block;
  padding: 6px 10px;
  border-radius: 999px;
  border: 1px solid var(--pp-border);
  background: rgba(255,255,255,0.05);
  color: var(--pp-muted);
  font-size: 12px;
  margin-right: 6px;
}

.pp-title{
  color: var(--pp-text);
  font-weight: 700;
  font-size: 16px;
  margin-bottom: 6px;
}

.pp-sub{
  color: var(--pp-muted);
  font-size: 13px;
  line-height: 1.35;
}

.pp-accent{
  color: var(--pp-amber);
  font-weight: 700;
}

hr { border-color: rgba(255,255,255,0.08) !important; }
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

def ai_generate_focus(potentials: str, point_a: str, point_b: str, model: str = "gpt-4o-mini") -> dict:
    client = get_openai_client()
    if not client:
        raise RuntimeError("OpenAI not configured")
    system = (
        "Ты — навигатор по реализации человека через Personal Potentials.\n"
        "Дай практичный план без давления. Не терапия. Не диагноз.\n"
        "Выводи только JSON.\n"
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
        "}"
    )
    user = f"""Потенциалы (матрица/таблица):
{potentials}

Точка А (сейчас):
{point_a}

Точка Б (как хочу):
{point_b}

Сгенерируй фокус недели и 3–5 задач на блок.
Задачи должны быть маленькие, измеримые, выполнимые. Частота: daily или weekly.
minutes 10–45.
"""
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role":"system","content":system},
            {"role":"user","content":user}
        ],
        temperature=0.5,
    )
    txt = resp.choices[0].message.content.strip()
    return json.loads(txt)


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

    with st.container():
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

    block_card("0) Основа", "Сюда попадают потенциалы. Это «линза», через которую ИИ и платформа дают навигацию.")
    c1, c2 = st.columns([2, 1])
    with c1:
        f["name"] = st.text_input("Имя (как обращаться)", value=f.get("name",""))
    with c2:
        if st.button("💾 Сохранить основу", use_container_width=True):
            save_profile()
            st.success("Сохранено ✅")

    f["potentials_table"] = st.text_area(
        "Матрица/таблица потенциалов (вставь сюда текст)",
        value=f.get("potentials_table",""),
        height=180
    )
    f["notes"] = st.text_area(
        "Короткие заметки (необязательно)",
        value=f.get("notes",""),
        height=120
    )
    end_card()

def ensure_week_initialized(profile: dict):
    r = profile["realization"]
    today = date.today()
    week_start = monday_of_week(today).isoformat()

    if r.get("week_start") != week_start:
        r["week_start"] = week_start
        # при смене недели не стираем блоки, но можно сбросить weekly_done, если появится позже
        save_profile()

def realization_tab(profile: dict):
    ensure_week_initialized(profile)
    r = profile["realization"]
    f = profile["foundation"]

    block_card("1) Реализация", "Точка А → Точка Б → выбираем фокус недели → собираем 4 блока действий.")
    c1, c2 = st.columns(2)
    with c1:
        r["point_a"] = st.text_area("Точка А (сейчас)", value=r.get("point_a",""), height=140)
    with c2:
        r["point_b"] = st.text_area("Точка Б (как хочу)", value=r.get("point_b",""), height=140)

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
                        potentials=f["potentials_table"],
                        point_a=r["point_a"],
                        point_b=r["point_b"],
                        model=model
                    )
                    r["weekly_focus"] = out.get("weekly_focus","").strip()
                    r["focus_explainer"] = out.get("focus_explainer","").strip()

                    # обновляем items в блоках по key
                    blocks_by_key = {b["key"]: b for b in r["action_blocks"]}
                    for b in out.get("action_blocks", []):
                        k = b.get("key")
                        if k in blocks_by_key:
                            items = b.get("items", []) or []
                            # нормализуем + проставим id если нет
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
        block_card(b["title"], "Добавь 3–7 маленьких действий. Частота daily/weekly. 10–45 минут.")
        items = b.get("items", [])
        # редактор списка задач
        # (пока упрощённый — следующим шагом сделаю «дорогие карточки» с кнопками)
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
        # ensure ids
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

    block_card("2) Сегодня", "Отмечай реальный прогресс: галочки, заметки, темп. Без давления.")
    chosen = st.date_input("Дата", value=date.today(), key="today_date")
    dkey = chosen.isoformat()
    day = t["by_date"].get(dkey) or {"done": {}, "notes": ""}

    # собрать список daily задач
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
    day["notes"] = st.text_area("Инсайты / комментарии за день", value=day.get("notes",""), height=140)

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
    block_card("Настройки", "Профиль, выход, техничка.")
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

tabs = st.tabs(["0) Основа", "1) Реализация", "2) Сегодня", "Настройки"])

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