# spch_report.py
import json
import re
from datetime import datetime

from spch_canon import POT_CANON_1_3, POT_4_CANON, POT_5_CANON, POT_6_CANON


# ---------- helpers ----------
def _canon_dict_to_md(d: dict) -> str:
    if not d:
        return "—"
    lines = []
    for k, v in d.items():
        if v is None or v == "" or v == [] or v == {}:
            continue
        title = str(k).replace("_", " ").strip().capitalize()
        if isinstance(v, str):
            lines.append(f"**{title}:** {v}")
        elif isinstance(v, list):
            items = [str(x).strip() for x in v if str(x).strip()]
            if items:
                lines.append(f"**{title}:**")
                lines.extend([f"- {x}" for x in items])
        elif isinstance(v, dict):
            lines.append(f"**{title}:**")
            for kk, vv in v.items():
                if vv is None or vv == "" or vv == [] or vv == {}:
                    continue
                kk_t = str(kk).replace("_", " ").strip().capitalize()
                if isinstance(vv, list):
                    vv_items = [str(x).strip() for x in vv if str(x).strip()]
                    if vv_items:
                        lines.append(f"- **{kk_t}:**")
                        lines.extend([f"  - {x}" for x in vv_items])
                else:
                    lines.append(f"- **{kk_t}:** {str(vv).strip()}")
    return "\n".join(lines).strip() or "—"


def normalize_potentials_text(text: str) -> str:
    """
    Позволяем пользователю вставлять:
    - просто список "Аметист, Гранат, Цитрин..."
    - или нумерацию "1. Аметист 2. Гранат..."
    - или таблицу/матрицу
    Мы НЕ обязаны парсить идеально — ИИ сам прочитает,
    но для точности мы чистим мусор.
    """
    t = (text or "").strip()
    t = re.sub(r"[ \t]+", " ", t)
    return t


def build_spch_system_prompt() -> str:
    return "\n".join([
        "# ROLE",
        "Ты — эксперт по методике СПЧ (матрица потенциалов 3x3).",
        "",
        "# ЗАПРЕТЫ (ЖЕСТКО)",
        "- Пиши по-русски.",
        "- НЕ называй потенциалы «кристаллами» и не используй метафоры камней.",
        "- НЕ придумывай свойства потенциалов вне канона.",
        "- НЕ терапия и НЕ диагноз.",
        "",
        "# ТЕРМИНЫ",
        "- Говорим: «потенциал», «матрица 3x3», «1 ряд/2 ряд/3 ряд», «восприятие/мотивация/инструмент».",
        "",
        "# СТРУКТУРА МАТРИЦЫ",
        "Столбцы: 1) Восприятие 2) Мотивация 3) Инструмент",
        "Ряды: 1 ряд — ядро (природа и реализация); 2 ряд — социальный слой; 3 ряд — риски/делегирование",
        "",
        "# ВЫВОД",
        "Верни ТОЛЬКО один блок текста отчёта в Markdown, без JSON, без служебных меток.",
    ]).strip()


def build_spch_extended_report_user_prompt(
    name: str,
    matrix_text: str,
    canon_bundle_md: str,
    point_a: str = "",
    point_b: str = "",
) -> str:
    return "\n".join([
        f"Имя клиента: {name}",
        "",
        "Ниже данные по СПЧ.",
        "",
        "МАТРИЦА (как ввёл пользователь):",
        matrix_text,
        "",
        "КАНОН (выжимка по позициям 1–6):",
        canon_bundle_md,
        "",
        "Точка А (сейчас):",
        (point_a or "—"),
        "",
        "Точка Б (как хочу):",
        (point_b or "—"),
        "",
        "Сделай один РАСШИРЕННЫЙ ОТЧЁТ (очень подробно), который клиент читает сам для себя.",
        "Он должен быть глубже, чем «клиентский PDF», но НЕ должен быть «мастерский для специалиста».",
        "",
        "ОБЯЗАТЕЛЬНЫЕ РАЗДЕЛЫ:",
        "1) Вступление (2–5 абзацев) — что показывает матрица и как читать отчёт.",
        "2) Матрица 3x3 (вставь её текстом как есть, если он структурирован; если нет — аккуратно перечисли позиции).",
        "3) 1 ряд: общий портрет + разбор 1/2/3 потенциала (в языке узнавания, без воды).",
        "4) 2 ряд: общий портрет + разбор 4/5/6 потенциала (как человек влияет на людей/среду).",
        "5) 3 ряд (если в матрице нет — напиши «не указан» и объясни зачем он нужен; не выдумывай).",
        "6) Связки и внутренние конфликты (2–4 сценария застревания) — строго из логики рядов/столбцов.",
        "7) Реализация: какие форматы деятельности и среды подходят (3–7 пунктов, конкретно).",
        "8) Рекомендации по фокусу на ближайшие 2 недели (без чек-листов на 14 дней; только фокус и принципы).",
        "",
        "ВАЖНО:",
        "- Используй канон как основу формулировок. Не фантазируй.",
        "- Не используй слово «кристалл/камень».",
    ]).strip()


def build_canon_bundle_md(pos1, pos2, pos3, pos4, pos5, pos6) -> str:
    # 1-3 берём из POT_CANON_1_3[pot][perception/motivation/instrument]
    def canon_1_3(pot: str, col: str) -> str:
        d = (POT_CANON_1_3 or {}).get(pot) or {}
        cell = d.get(col)
        if isinstance(cell, str):
            return cell.strip() or "—"
        if isinstance(cell, dict):
            return _canon_dict_to_md(cell)
        return "—"

    # 4-6 берём из отдельных словарей
    def canon_pos(pot: str, canon_dict: dict) -> str:
        d = (canon_dict or {}).get(pot)
        if isinstance(d, str):
            return d.strip() or "—"
        if isinstance(d, dict):
            return _canon_dict_to_md(d)
        return "—"

    parts = [
        f"## Позиция 1 (Восприятие): {pos1}\n{canon_1_3(pos1, 'perception')}",
        f"## Позиция 2 (Мотивация): {pos2}\n{canon_1_3(pos2, 'motivation')}",
        f"## Позиция 3 (Инструмент): {pos3}\n{canon_1_3(pos3, 'instrument')}",
        f"## Позиция 4 (Проблематика/поле анализа): {pos4}\n{canon_pos(pos4, POT_4_CANON)}",
        f"## Позиция 5 (Запрос/миссия): {pos5}\n{canon_pos(pos5, POT_5_CANON)}",
        f"## Позиция 6 (Результат): {pos6}\n{canon_pos(pos6, POT_6_CANON)}",
    ]
    return "\n\n".join(parts).strip()


def generate_extended_report(openai_client, model: str, profile: dict) -> str:
    """
    profile: твой профиль из Supabase.
    Берём:
    - foundation.name
    - foundation.potentials_table (как ввели)
    - realization.point_a / point_b (если есть)
    - positions pos1..pos6 если ты их где-то хранишь
      (если нет — можно временно попросить пользователя вставить 1–6 строкой)
    """
    f = (profile or {}).get("foundation", {}) or {}
    r = (profile or {}).get("realization", {}) or {}

    name = (f.get("name") or "Клиент").strip()
    matrix_text = normalize_potentials_text(f.get("potentials_table", ""))

    # ВАЖНО: здесь нужны pos1..pos6.
    # В идеале ты хранишь их после диагностики в профиле.
    # Если пока нет — ты можешь попросить пользователя вставлять «позиции 1–6» отдельным блоком.
    lib = (profile or {}).get("library", {}) or {}
    positions = (lib.get("positions") or {}) if isinstance(lib.get("positions"), dict) else {}

    pos1 = (positions.get("pos1") or "").strip()
    pos2 = (positions.get("pos2") or "").strip()
    pos3 = (positions.get("pos3") or "").strip()
    pos4 = (positions.get("pos4") or "").strip()
    pos5 = (positions.get("pos5") or "").strip()
    pos6 = (positions.get("pos6") or "").strip()

    # Если позиций нет — не выдумываем: делаем отчёт по тому, что есть.
    # Но канон-бандл тогда будет пустоват — ты увидишь это и позже подключим автопередачу из диагностики.
    canon_bundle_md = ""
    if all([pos1, pos2, pos3, pos4, pos5, pos6]):
        canon_bundle_md = build_canon_bundle_md(pos1, pos2, pos3, pos4, pos5, pos6)
    else:
        canon_bundle_md = "Позиции 1–6 не зафиксированы в профиле. Отчёт опирается на текст матрицы, которую ввёл пользователь."

    sys = build_spch_system_prompt()
    user = build_spch_extended_report_user_prompt(
        name=name,
        matrix_text=matrix_text,
        canon_bundle_md=canon_bundle_md,
        point_a=r.get("point_a",""),
        point_b=r.get("point_b",""),
    )

    resp = openai_client.chat.completions.create(
        model=model,
        messages=[
            {"role":"system","content":sys},
            {"role":"user","content":user},
        ],
        temperature=0.45,
    )
    return (resp.choices[0].message.content or "").strip()