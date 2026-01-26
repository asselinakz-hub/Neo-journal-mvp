import os, json, base64, hashlib
from datetime import datetime
import streamlit as st
from cryptography.fernet import Fernet, InvalidToken

# OpenAI (официальный клиент)
from openai import OpenAI

APP_TITLE = "NEO Навигационный дневник (MVP)"
VAULT_DIR = os.path.join("data", "vault")
os.makedirs(VAULT_DIR, exist_ok=True)

# -------------------------
# Crypto helpers (privacy)
# -------------------------
def _derive_fernet_key(password: str) -> bytes:
    # Делаем Fernet ключ из пароля (не идеально крипто-академично, но ок для MVP)
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)

def encrypt_json(data: dict, password: str) -> bytes:
    f = Fernet(_derive_fernet_key(password))
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    return f.encrypt(raw)

def decrypt_json(token: bytes, password: str) -> dict:
    f = Fernet(_derive_fernet_key(password))
    raw = f.decrypt(token)
    return json.loads(raw.decode("utf-8"))

def vault_path(user_id: str) -> str:
    safe = "".join(ch for ch in user_id if ch.isalnum() or ch in "-_").strip()
    return os.path.join(VAULT_DIR, f"{safe}.vault")

# -------------------------
# OpenAI client
# -------------------------
def get_client():
    key = st.secrets.get("OPENAI_API_KEY", None)
    if not key:
        return None
    return OpenAI(api_key=key)

def ai_chat(client: OpenAI, model: str, system: str, messages: list[dict]) -> str:
    # messages: [{"role":"user","content":"..."}, ...]
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role":"system","content":system}] + messages,
        temperature=0.6
    )
    return resp.choices[0].message.content

# -------------------------
# App state
# -------------------------
def init_state():
    if "authed" not in st.session_state:
        st.session_state.authed = False
    if "user_id" not in st.session_state:
        st.session_state.user_id = ""
    if "passphrase" not in st.session_state:
        st.session_state.passphrase = ""
    if "data" not in st.session_state:
        st.session_state.data = None
    if "chat0" not in st.session_state:
        st.session_state.chat0 = []  # вкладка 0 чат
    if "chat_money" not in st.session_state:
        st.session_state.chat_money = []
    if "chat_health" not in st.session_state:
        st.session_state.chat_health = []
    if "chat_rel" not in st.session_state:
        st.session_state.chat_rel = []

def default_payload():
    # 12 задач шаблон
    tasks = [{"task":"", "date":"", "metric":"", "done":False, "notes":""} for _ in range(12)]
    return {
        "meta": {
            "schema":"neo.journal.v1",
            "created_at": datetime.utcnow().isoformat()+"Z",
            "updated_at": datetime.utcnow().isoformat()+"Z",
        },
        "foundation": {
            "potentials_table": "",
            "about_me": "",
        },
        "money": {
            "goal": "",
            "tasks": tasks.copy(),
            "weekly_reflection": "",
        },
        "health": {
            "age": "",
            "height": "",
            "weight": "",
            "activity": "",
            "goal": "",
            "tasks": tasks.copy(),
            "weekly_reflection": "",
        },
        "relationships": {
            "with_whom": "",
            "goal": "",
            "tasks": tasks.copy(),
            "weekly_reflection": "",
        }
    }

def load_or_create(user_id: str, passphrase: str) -> dict:
    p = vault_path(user_id)
    if not os.path.exists(p):
        return default_payload()
    with open(p, "rb") as f:
        token = f.read()
    return decrypt_json(token, passphrase)

def save_vault(user_id: str, passphrase: str, data: dict):
    data["meta"]["updated_at"] = datetime.utcnow().isoformat()+"Z"
    token = encrypt_json(data, passphrase)
    with open(vault_path(user_id), "wb") as f:
        f.write(token)

# -------------------------
# UI blocks
# -------------------------
def login_screen():
    st.title(APP_TITLE)
    st.caption("Приватный дневник с ИИ. Данные сохраняются в зашифрованном виде. Доступа у создателя нет.")

    user_id = st.text_input("ID дневника (придумай и сохрани у себя)", value=st.session_state.user_id)
    passphrase = st.text_input("Пароль шифрования (не забудь!)", type="password", value=st.session_state.passphrase)

    c1, c2 = st.columns([1,1])
    with c1:
        if st.button("Войти / Создать", use_container_width=True):
            if not user_id or len(user_id) < 3:
                st.error("ID дневника слишком короткий.")
                return
            if not passphrase or len(passphrase) < 6:
                st.error("Пароль шифрования минимум 6 символов.")
                return

            try:
                data = load_or_create(user_id, passphrase)
            except InvalidToken:
                st.error("Неверный пароль для этого дневника (не могу расшифровать).")
                return
            except Exception as e:
                st.error(f"Ошибка загрузки: {e}")
                return

            st.session_state.user_id = user_id
            st.session_state.passphrase = passphrase
            st.session_state.data = data
            st.session_state.authed = True
            st.rerun()

    with c2:
        st.info("Совет: используй 1) короткий ID, 2) сильный пароль. Без пароля восстановить нельзя.")

def save_button(scope: str):
    if st.button(
        "💾 Сохранить",
        use_container_width=True,
        key=f"save_{scope}"
    ):
        try:
            save_vault(st.session_state.user_data)
            st.success("Сохранено ✅")
        except Exception as e:
            st.error(f"Не удалось сохранить: {e}")

def tasks_editor(path_key: str):
    # path_key: "money" | "health" | "relationships"
    block = st.session_state.data[path_key]
    st.markdown("### 12 задач (декомпозиция)")
    st.caption("Заполни сама или попроси ИИ внизу. ИИ не заполняет таблицу сам — ты контролируешь всё.")

    edited = st.data_editor(
        block["tasks"],
        num_rows="fixed",
        use_container_width=True,
        column_config={
            "task": st.column_config.TextColumn("Задача"),
            "date": st.column_config.TextColumn("Срок"),
            "metric": st.column_config.TextColumn("Метрика/как поймёшь, что сделано"),
            "done": st.column_config.CheckboxColumn("Готово"),
            "notes": st.column_config.TextColumn("Заметки/инсайты"),
        },
        key=f"tasks_{path_key}"
    )
    block["tasks"] = edited

    done_count = sum(1 for t in edited if t.get("done"))
    st.progress(done_count/12 if 12 else 0)
    st.caption(f"Готово задач: {done_count} из 12")

    st.markdown("### Еженедельная рефлексия")
    block["weekly_reflection"] = st.text_area(
        "Что получилось? Что мешало? Какие инсайты?",
        value=block.get("weekly_reflection",""),
        height=140,
        key=f"refl_{path_key}"
    )

def domain_chat(domain_key: str, title: str):
    client = get_client()
    model = st.selectbox("Модель", ["gpt-4.1-mini", "gpt-4o-mini"], index=0, key=f"model_{domain_key}")

    if not client:
        st.warning("Нет OPENAI_API_KEY в secrets. Чат не работает.")
        return

    base = st.session_state.data
    potentials = base["foundation"]["potentials_table"].strip()

    system = f"""
Ты — AI-навигатор в системе "NEO Потенциалы".
Всегда опирайся на потенциалы пользователя (если они указаны).
Не давай универсальных советов. Давай рекомендации через призму потенциалов.
Стиль: человеческий, тёплый, без давления. Не терапия. Не диагноз. Это навигация.
Если потенциалы пустые — попроси пользователя заполнить вкладку "Моя основа".
Потенциалы пользователя:
{potentials if potentials else "[ПУСТО]"}
Текущий раздел: {title}
"""

    chat_key = f"chat_{domain_key}"
    chat = st.session_state.get(chat_key, [])

    with st.expander("🤖 ИИ-помощник (чат)", expanded=True):
        for m in chat[-12:]:
            st.markdown(f"**{m['role']}**: {m['content']}")

        user_msg = st.text_input("Напиши вопрос / попроси разбить цель на 12 задач", key=f"msg_{domain_key}")
        if st.button("Отправить", key=f"send_{domain_key}", use_container_width=True):
            if not user_msg.strip():
                return
            chat.append({"role":"user","content":user_msg.strip()})
            try:
                answer = ai_chat(client, model, system, [{"role":m["role"],"content":m["content"]} for m in chat])
            except Exception as e:
                st.error(f"Ошибка OpenAI: {e}")
                return
            chat.append({"role":"assistant","content":answer})
            st.session_state[chat_key] = chat
            st.rerun()

# -------------------------
# Main app
# -------------------------
init_state()
st.set_page_config(page_title=APP_TITLE, page_icon="💠", layout="wide")

if not st.session_state.authed:
    login_screen()
    st.stop()

st.title("💠 NEO Навигационный дневник")
st.caption("Спутник для целей и жизни через призму потенциалов. Без давления. С приватностью.")

data = st.session_state.data

tabs = st.tabs(["0) Моя основа", "1) Деньги/реализация", "2) Здоровье", "3) Отношения", "Настройки"])

with tabs[0]:
    st.subheader("Вкладка 0 — Моя основа")
    data["foundation"]["potentials_table"] = st.text_area(
        "Твои потенциалы (вставь таблицу / текст после диагностики)",
        value=data["foundation"].get("potentials_table",""),
        height=200
    )
    data["foundation"]["about_me"] = st.text_area(
        "Коротко о тебе (по желанию)",
        value=data["foundation"].get("about_me",""),
        height=120
    )
    save_button()
    domain_chat("0", "Моя основа")

with tabs[1]:
    st.subheader("Деньги / Реализация")
    data["money"]["goal"] = st.text_input("Моя цель", value=data["money"].get("goal",""), key="goal_money")
    tasks_editor("money")
    save_button()
    domain_chat("money", "Деньги / Реализация")

with tabs[2]:
    st.subheader("Здоровье")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        data["health"]["age"] = st.text_input("Возраст", value=str(data["health"].get("age","")))
    with c2:
        data["health"]["height"] = st.text_input("Рост", value=str(data["health"].get("height","")))
    with c3:
        data["health"]["weight"] = st.text_input("Вес", value=str(data["health"].get("weight","")))
    with c4:
        data["health"]["activity"] = st.text_input("Активность", value=str(data["health"].get("activity","")))

    data["health"]["goal"] = st.text_input("Цель по здоровью", value=data["health"].get("goal",""), key="goal_health")
    tasks_editor("health")
    save_button()
    domain_chat("health", "Здоровье")

with tabs[3]:
    st.subheader("Отношения")
    data["relationships"]["with_whom"] = st.text_input("С кем отношения/про кого", value=data["relationships"].get("with_whom",""))
    data["relationships"]["goal"] = st.text_input("Цель в отношениях", value=data["relationships"].get("goal",""), key="goal_rel")
    tasks_editor("relationships")
    save_button()
    domain_chat("rel", "Отношения")

with tabs[4]:
    st.subheader("Настройки")
    st.code(f"ID дневника: {st.session_state.user_id}")
    if st.button("🚪 Выйти", use_container_width=True):
        st.session_state.authed = False
        st.session_state.data = None
        st.rerun()
    st.warning("Если забудешь пароль шифрования — восстановить дневник нельзя. Сохрани его где-то надёжно.")
