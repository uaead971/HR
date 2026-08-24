#!/usr/bin/env python3
"""Local, dependency-free HR application server.

The browser is intentionally a client of this module: business data and all
authorization decisions live in SQLite and are enforced by the HTTP API.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import mimetypes
import os
import re
import secrets
import smtplib
import sqlite3
import sys
import csv
import io
import struct
import zlib
import unicodedata
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from datetime import date, datetime, time, timedelta, timezone
from email.utils import formatdate
from email.message import EmailMessage
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qs, urlsplit
from zoneinfo import ZoneInfo


APP_DIR = Path(__file__).resolve().parent
APP_VERSION = "5.7.0"
DEFAULT_DB = APP_DIR / "data" / "hr.sqlite3"
SCHEMA_FILE = APP_DIR / "schema.sql"
UAE_TZ = ZoneInfo("Asia/Dubai")
SESSION_COOKIE = "hr_session"
SESSION_HOURS = 12
MAX_JSON_BYTES = 3_200_000
MAX_IMAGE_BYTES = 1_500_000
MAX_VISUAL_IDENTITY_IMAGE_BYTES = 1_350_000
PBKDF2_ROUNDS = 310_000
PASSWORD_RESET_MINUTES = 30


PERMISSION_CATALOG: dict[str, dict[str, str]] = {
    "dashboard": {
        "dashboard.view": "عرض لوحة القيادة التنفيذية",
        "report.view": "عرض التقارير الحية",
        "audit.view": "عرض سجل النشاط والتدقيق",
    },
    "people": {
        "employee.view": "عرض جميع ملفات الموظفين", "employee.manage": "إنشاء ملفات الموظفين وإدارة بياناتها التشغيلية",
        "employee.profile.edit": "تعديل البيانات الشخصية والوظيفية والصورة في ملف الموظف",
        "employee.emergency.manage": "إدارة جهات اتصال الطوارئ للموظفين",
        "employee.team": "عرض أسماء وأرقام موظفي الفريق فقط", "department.manage": "إدارة الأقسام",
        "employee_document.manage": "إدارة وثائق الموظفين", "employee_action.manage": "إدارة المخالفات والتعهدات",
        "employee_custody.view": "عرض سجل عُهد الموظفين", "employee_custody.manage": "إدارة عُهد الموظفين",
        "employee_custody.print": "طباعة سجلات استلام وتسليم العُهد",
        "employee_report.view": "عرض تقرير الموظف الشامل", "employee_report.export": "طباعة وحفظ تقرير الموظف الشامل PDF",
        "org.view": "عرض المؤسسة", "org.manage": "إدارة هوية المؤسسة",
        "branch.view": "عرض الفروع", "branch.manage": "إدارة الفروع والنطاقات",
        "reference.manage": "إدارة الدرجات والمسميات",
    },
    "time": {
        "attendance.view": "عرض الحضور", "attendance.team": "عرض أوقات دخول وخروج الفريق",
        "attendance.export": "تصدير كشف الحضور والانصراف CSV",
        "shift.view": "عرض المناوبات", "shift.manage": "إدارة المناوبات",
        "leave.view": "عرض طلبات الإجازة", "leave.team": "قرار المسؤول المباشر على طلبات الفريق", "leave.approve": "الاعتماد النهائي للإجازات لدى الموارد البشرية",
        "overtime.view": "عرض العمل الإضافي", "overtime.approve": "اعتماد العمل الإضافي",
    },
    "payroll": {
        "salary.view": "عرض الرواتب", "salary_certificate.issue": "إصدار شهادة راتب",
        "salary_certificate.print": "طباعة شهادة راتب", "salary_certificate.verify": "التحقق من صحة شهادة راتب",
        "payroll.manage": "إدارة المسيرات",
        "payroll.approve": "اعتماد المسيرات", "payroll.pay": "إثبات دفع المسيرات",
        "advance.view": "عرض السلف", "advance.approve": "اعتماد السلف",
    },
    "performance": {
        "evaluation.view": "عرض التقييمات", "evaluation.review": "مراجعة الموارد البشرية وحل التظلمات",
        "evaluation.override_manager": "استكمال تقييمات المسؤولين الغائبين",
        "evaluation.cycle.manage": "إنشاء دورات التقييم وإعلانها وإرسال تذكيراتها", "lifecycle.view": "عرض دورة الموظف",
        "lifecycle.manage": "إدارة دورة الموظف",
    },
    "communications": {
        "notification.send": "إرسال إشعارات داخلية", "notification.manage": "تعديل وإخفاء الإشعارات المرسلة لمسؤول النظام فقط", "communications.view": "عرض حملات البريد",
        "communications.send": "إنشاء وإرسال حملات البريد", "communications.retry": "إعادة محاولة البريد المتعثر",
    },
    "security": {
        "security.manage_users": "إدارة المستخدمين", "security.manage_permissions": "إدارة الصلاحيات",
        "security.reset_password": "تعيين كلمة مرور مؤقتة", "smtp.manage": "إدارة إعدادات SMTP",
        "smtp.test": "اختبار اتصال SMTP",
    },
}

ALL_PERMISSIONS = {permission for group in PERMISSION_CATALOG.values() for permission in group}


ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {"*"},
    "hr": {
        "org.view", "org.manage", "branch.view", "branch.manage", "employee.view", "employee.manage", "employee.profile.edit", "employee.emergency.manage",
        "salary.view", "attendance.view", "attendance.export", "shift.view", "shift.manage", "overtime.view",
        "overtime.approve", "leave.view", "leave.approve", "evaluation.view", "evaluation.review", "evaluation.cycle.manage",
        "notification.send", "salary_certificate.issue", "salary_certificate.print", "salary_certificate.verify", "department.manage",
        "evaluation.override_manager",
        "employee_document.manage", "employee_action.manage", "employee_custody.view", "employee_custody.manage", "employee_custody.print", "payroll.manage", "payroll.approve", "payroll.pay",
        "advance.view", "advance.approve", "reference.manage", "lifecycle.view", "lifecycle.manage", "report.view",
        "dashboard.view", "audit.view", "communications.view", "communications.send", "communications.retry",
        "employee_report.view", "employee_report.export",
    },
    "general_manager": {
        "org.view", "branch.view", "employee.view", "attendance.view", "shift.view",
        "overtime.view", "overtime.approve", "leave.view", "leave.approve", "evaluation.view", "notification.send",
        "salary.view", "salary_certificate.issue", "salary_certificate.print", "employee_custody.view", "employee_custody.manage", "employee_custody.print", "payroll.approve",
        "advance.view", "advance.approve", "lifecycle.view", "report.view",
    },
    "manager": {
        "org.view", "branch.view", "employee.team", "attendance.team", "shift.view",
        "overtime.view", "leave.team", "evaluation.view",
    },
    "employee": {"org.view", "branch.view", "shift.view"},
}

PEOPLE_ADMIN_ROLES = {"admin", "hr", "general_manager"}

DOCUMENT_TYPES = {
    "passport", "identity", "residency", "visa", "work_permit", "contract", "job_offer",
    "qualification", "professional_certificate", "marriage_certificate", "birth_certificate",
    "good_conduct", "medical_exam", "health_insurance", "driving_license", "personal_photo",
    "employee_file", "undertaking", "violation", "bank_document", "other", "general",
}

DOCUMENT_TYPE_LABELS_AR = {
    "passport": "جواز السفر", "identity": "الهوية الإماراتية", "residency": "الإقامة",
    "visa": "التأشيرة", "work_permit": "تصريح العمل", "contract": "عقد العمل",
    "job_offer": "عرض العمل", "qualification": "المؤهل العلمي", "professional_certificate": "الشهادة المهنية",
    "marriage_certificate": "عقد الزواج", "birth_certificate": "شهادة الميلاد", "good_conduct": "حسن السيرة",
    "medical_exam": "الفحص الطبي", "health_insurance": "التأمين الصحي", "driving_license": "رخصة القيادة",
    "employee_file": "ملف الموظف", "undertaking": "التعهد", "violation": "المخالفة", "bank_document": "وثيقة بنكية",
    "personal_photo": "الصورة الشخصية", "other": "وثيقة أخرى", "general": "وثيقة عامة",
}

CUSTODY_CONDITIONS = {"new", "used_clean", "used_average", "used_damaged"}

CARD_TEMPLATES = {"portrait_orbit", "executive_horizontal", "minimal_vertical"}

GENERIC_JOB_GOALS = (
    ("جودة ودقة الإنجاز", "إنجاز المسؤوليات الأساسية وفق الإجراءات المعتمدة وبأقل نسبة أخطاء.", "نسبة الأعمال المقبولة من المرة الأولى", 25),
    ("الإنتاجية والالتزام بالمواعيد", "تحقيق حجم العمل المستهدف وتسليم المهام في مواعيدها.", "نسبة المهام المنجزة ضمن الوقت المستهدف", 25),
    ("تحقيق مؤشرات الوظيفة", "تحقيق مؤشرات الأداء التشغيلية الخاصة بالمسمى الوظيفي.", "نسبة تحقق مؤشرات الأداء المعتمدة", 20),
    ("التعاون وخدمة المستفيدين", "التعاون مع الفريق وتقديم تجربة مهنية للمستفيدين الداخليين والخارجيين.", "رضا المستفيدين وتقييم التعاون", 15),
    ("التطوير والتحسين المستمر", "تطوير المهارات واقتراح تحسينات قابلة للتطبيق في نطاق العمل.", "إتمام خطة التطوير وعدد التحسينات المنفذة", 15),
)

SPECIALIZED_JOB_GOALS = {
    "أخصائي عمليات": (
        ("دقة تنفيذ العمليات والالتزام بالإجراءات", "تنفيذ المعاملات التشغيلية وفق الإجراءات ومستويات الخدمة المعتمدة.", "نسبة المعاملات المنجزة دون أخطاء", 30),
        ("الإنتاجية والالتزام بمواعيد الإنجاز", "إنجاز حجم العمل المستهدف ضمن الوقت المحدد لكل معاملة.", "نسبة المعاملات المنجزة ضمن الزمن المستهدف", 25),
        ("جودة خدمة المستفيدين", "معالجة الطلبات والملاحظات بمهنية وتحسين تجربة المستفيد.", "معدل رضا المستفيدين ونسبة إغلاق الملاحظات", 20),
        ("تحسين الإجراءات التشغيلية", "اقتراح وتنفيذ تحسينات تقلل الوقت أو الأخطاء أو التكلفة.", "عدد التحسينات المعتمدة وأثرها القابل للقياس", 15),
        ("التعاون والتطوير المهني", "مشاركة المعرفة وإكمال خطة التطوير المرتبطة بالوظيفة.", "تقييم التعاون ونسبة إكمال خطة التطوير", 10),
    ),
    "مديرة العمليات": (
        ("تحقيق الخطة التشغيلية", "قيادة تنفيذ خطة الإدارة وربطها بأولويات المؤسسة.", "نسبة إنجاز المبادرات والمؤشرات التشغيلية", 30),
        ("رفع الكفاءة والإنتاجية", "تحسين تدفق العمل والاستفادة من الموارد وخفض الهدر.", "تحسن زمن الدورة والإنتاجية والتكلفة", 25),
        ("قيادة الفريق وتطويره", "توزيع الأهداف والمتابعة والتوجيه وبناء قدرات الفريق.", "إنجاز أهداف الفريق وخطط التطوير", 20),
        ("جودة الخدمة ورضا المستفيدين", "ضمان جودة المخرجات والاستجابة للملاحظات.", "معدل الجودة والرضا وإغلاق الشكاوى", 15),
        ("إدارة المخاطر والامتثال", "متابعة المخاطر التشغيلية والالتزام بالسياسات والضوابط.", "نسبة إغلاق المخاطر وعدم تكرار المخالفات", 10),
    ),
    "مديرة الموارد البشرية": (
        ("تنفيذ استراتيجية الموارد البشرية", "تحويل أولويات المؤسسة إلى خطة قوى عاملة ومبادرات قابلة للقياس.", "نسبة إنجاز الخطة ومؤشرات القوى العاملة", 25),
        ("دقة العمليات والبيانات الوظيفية", "ضمان صحة ملفات الموظفين والحضور ومدخلات الرواتب وفي مواعيدها.", "نسبة الدقة والإنجاز ضمن دورة العمل", 25),
        ("الاستقطاب والاستبقاء", "شغل الاحتياجات الحرجة وتحسين تجربة الانضمام والاستبقاء.", "زمن شغل الوظيفة ونسبة الاستبقاء", 20),
        ("الامتثال والسياسات", "تحديث السياسات ومتابعة الامتثال لقانون العمل والضوابط الداخلية.", "نسبة المراجعات المكتملة والملاحظات المغلقة", 15),
        ("تجربة الموظف والتطوير", "رفع التفاعل وتنفيذ خطط التعلم والتطوير المؤسسية.", "رضا الموظفين ونسبة إكمال خطط التطوير", 15),
    ),
    "المدير العام": (
        ("تحقيق الأهداف الاستراتيجية للمؤسسة", "قيادة تنفيذ الخطة الاستراتيجية وتحقيق النتائج المؤسسية المعتمدة.", "نسبة تحقق المؤشرات والمبادرات الاستراتيجية", 35),
        ("الاستدامة المالية والتشغيلية", "تعزيز كفاءة الموارد واستدامة النتائج والنمو المنضبط.", "النتائج المالية والكفاءة التشغيلية", 25),
        ("الحوكمة وإدارة المخاطر", "تعزيز الرقابة والامتثال واتخاذ القرار المبني على البيانات.", "مستوى الامتثال وإغلاق المخاطر الجوهرية", 15),
        ("قيادة رأس المال البشري", "بناء القيادات ورفع التفاعل والأداء المؤسسي.", "مؤشرات الأداء والتعاقب والتفاعل", 15),
        ("الابتكار والتحول الرقمي", "رعاية مبادرات التحسين والتحول التي ترفع جودة وكفاءة المؤسسة.", "قيمة المبادرات المنفذة وأثرها", 10),
    ),
}


def seed_job_goal_templates(db: sqlite3.Connection, job_title_id: int, job_title_name: str, stamp: str) -> None:
    templates = SPECIALIZED_JOB_GOALS.get(job_title_name, GENERIC_JOB_GOALS)
    for sort_order, (title, description, measure, weight) in enumerate(templates, 1):
        db.execute(
            """INSERT OR IGNORE INTO evaluation_goal_templates
               (job_title_id,title,description,measure,default_weight,sort_order,active,created_at,updated_at)
               VALUES(?,?,?,?,?,?,1,?,?)""",
            (job_title_id, title, description, measure, weight, sort_order, stamp, stamp),
        )
DEFAULT_CARD_INSTRUCTIONS = "البطاقة شخصية ولا يجوز استخدامها من غير صاحبها. عند العثور عليها يرجى التواصل مع المؤسسة."
LANGUAGE_CATALOG: dict[str, dict[str, str]] = {
    "ar": {"name": "العربية", "flag": "🇦🇪", "flag_code": "AE"},
    "en": {"name": "الإنجليزية", "flag": "🇬🇧", "flag_code": "GB"},
    "ur": {"name": "الأوردو", "flag": "🇮🇳", "flag_code": "IN"},
    "hi": {"name": "الهندية", "flag": "🇮🇳", "flag_code": "IN"},
    "zh": {"name": "الصينية", "flag": "🇨🇳", "flag_code": "CN"},
    "fil": {"name": "الفلبينية", "flag": "🇵🇭", "flag_code": "PH"},
    "bn": {"name": "البنغالية", "flag": "🇧🇩", "flag_code": "BD"},
    "ne": {"name": "النيبالية", "flag": "🇳🇵", "flag_code": "NP"},
    "ru": {"name": "الروسية", "flag": "🇷🇺", "flag_code": "RU"},
    "fr": {"name": "الفرنسية", "flag": "🇫🇷", "flag_code": "FR"},
    "es": {"name": "الإسبانية", "flag": "🇪🇸", "flag_code": "ES"},
    "other": {"name": "أخرى", "flag": "🏳️", "flag_code": "OTHER"},
}
LANGUAGE_PROFICIENCIES = {
    "native": "اللغة الأم", "excellent": "ممتاز", "very_good": "جيد جداً", "good": "جيد", "basic": "أساسي",
}


class APIError(Exception):
    def __init__(self, status: int, message: str, code: str = "request_error", details: Any = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code
        self.details = details


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return utc_now().isoformat(timespec="seconds")


def local_now() -> datetime:
    return datetime.now(UAE_TZ)


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def parse_json_text(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def password_digest(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS).hex()


def password_record(password: str) -> tuple[str, str]:
    salt_hex = secrets.token_hex(16)
    return password_digest(password, salt_hex), salt_hex


def verify_password(password: str, expected: str, salt_hex: str) -> bool:
    try:
        return hmac.compare_digest(password_digest(password, salt_hex), expected)
    except (ValueError, TypeError):
        return False


def validate_password_strength(password: str) -> None:
    """Apply the same compact password policy to every password-setting flow."""
    failures = []
    if len(password) < 10: failures.append("١٠ أحرف على الأقل")
    if not re.search(r"[A-Z]", password): failures.append("حرف إنجليزي كبير")
    if not re.search(r"[a-z]", password): failures.append("حرف إنجليزي صغير")
    if not re.search(r"\d", password): failures.append("رقم")
    if not re.search(r"[^A-Za-z0-9]", password): failures.append("رمز خاص")
    if failures:
        raise APIError(422, "كلمة المرور لا تحقق المتطلبات: " + "، ".join(failures) + ".", "weak_password", {"requirements": failures})


def secret_key(db_path: Path) -> bytes:
    # Keep the deterministic fallback only for local development so an existing
    # single-user database remains readable when its folder is moved. A missing
    # key must never silently start a production instance: certificate HMACs and
    # encrypted SMTP credentials depend on this value.
    material = os.environ.get("HR_SECRET_KEY", "").strip()
    environment = os.environ.get("HR_ENV", "development").strip().lower()
    if environment in {"prod", "production"}:
        if not material:
            raise RuntimeError("HR_SECRET_KEY must be set when HR_ENV=production")
        if len(material) < 32:
            raise RuntimeError("HR_SECRET_KEY must contain at least 32 characters in production")
    if not material:
        material = "mawared-v46-local-development-key"
    return hashlib.sha256(material.encode("utf-8")).digest()


def seal_secret(value: str, db_path: Path) -> str:
    if not value:
        return ""
    nonce = secrets.token_bytes(16)
    key = secret_key(db_path)
    stream = hashlib.pbkdf2_hmac("sha256", key, nonce, 120_000, dklen=len(value.encode("utf-8")))
    raw = value.encode("utf-8")
    cipher = bytes(a ^ b for a, b in zip(raw, stream))
    tag = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(nonce + tag + cipher).decode("ascii")


def open_secret(value: str, db_path: Path) -> str:
    if not value:
        return ""
    try:
        packed = base64.urlsafe_b64decode(value.encode("ascii"))
        nonce, tag, cipher = packed[:16], packed[16:48], packed[48:]
        key = secret_key(db_path)
        if not hmac.compare_digest(tag, hmac.new(key, nonce + cipher, hashlib.sha256).digest()):
            return ""
        stream = hashlib.pbkdf2_hmac("sha256", key, nonce, 120_000, dklen=len(cipher))
        return bytes(a ^ b for a, b in zip(cipher, stream)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return ""


def certificate_integrity_hash(db_path: Path, values: dict[str, Any] | sqlite3.Row) -> str:
    """Seal the immutable salary-certificate snapshot with the application key."""
    immutable = {
        "certificate_no": str(values["certificate_no"]),
        "verification_code": str(values["verification_code"]),
        "employee_id": int(values["employee_id"]),
        "issued_by": int(values["issued_by"]),
        "purpose": str(values["purpose"]),
        "salary_snapshot": f"{float(values['salary_snapshot']):.2f}",
        "organization_snapshot": str(values["organization_snapshot"]),
        "employee_snapshot": str(values["employee_snapshot"]),
        "issued_at": str(values["issued_at"]),
    }
    payload = json.dumps(immutable, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(secret_key(db_path), payload, hashlib.sha256).hexdigest()


def new_certificate_verification_code(db: sqlite3.Connection, year: int) -> str:
    for _ in range(12):
        token = secrets.token_hex(6).upper()
        code = f"VRF-{year}-{token[:4]}-{token[4:8]}-{token[8:]}"
        if db.execute("SELECT 1 FROM salary_certificates WHERE verification_code=?", (code,)).fetchone() is None:
            return code
    raise RuntimeError("Could not allocate a unique salary-certificate verification code")


def _pdf_text(value: Any) -> str:
    """Keep the lightweight built-in PDF generator safe for arbitrary tenant data."""
    text = str(value or "").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return text.encode("ascii", "ignore").decode("ascii") or "-"


_PDF_FONT_CACHE: tuple[bytes, dict[int, int]] | None = None


def _ttf_cmap(font_data: bytes) -> dict[int, int]:
    """Read the Unicode cmap from a TrueType font without external packages."""
    if len(font_data) < 12:
        return {}
    table_count = struct.unpack_from(">H", font_data, 4)[0]
    cmap_offset = None
    for index in range(table_count):
        record_offset = 12 + index * 16
        if record_offset + 16 > len(font_data):
            break
        tag, _, offset, length = struct.unpack_from(">4sLLL", font_data, record_offset)
        if tag == b"cmap" and offset + length <= len(font_data):
            cmap_offset = offset
            break
    if cmap_offset is None or cmap_offset + 4 > len(font_data):
        return {}
    _, record_count = struct.unpack_from(">HH", font_data, cmap_offset)
    candidates: list[tuple[int, int, int]] = []
    for index in range(record_count):
        offset = cmap_offset + 4 + index * 8
        if offset + 8 > len(font_data):
            break
        platform, encoding, sub_offset = struct.unpack_from(">HHL", font_data, offset)
        subtable = cmap_offset + sub_offset
        if subtable + 2 > len(font_data):
            continue
        format_code = struct.unpack_from(">H", font_data, subtable)[0]
        preference = 0 if format_code == 12 and platform == 3 and encoding == 10 else 1 if format_code == 12 else 2 if format_code == 4 and platform in {0, 3} else 9
        candidates.append((preference, format_code, subtable))
    for _, format_code, subtable in sorted(candidates):
        mapping: dict[int, int] = {}
        if format_code == 12 and subtable + 16 <= len(font_data):
            groups = struct.unpack_from(">L", font_data, subtable + 12)[0]
            for index in range(groups):
                current = subtable + 16 + index * 12
                if current + 12 > len(font_data):
                    break
                start, end, glyph = struct.unpack_from(">LLL", font_data, current)
                # Contract text uses BMP Arabic/Latin characters; avoid
                # expanding supplementary-plane ranges into a huge mapping.
                for codepoint in range(start, min(end, 0xFFFF) + 1):
                    mapping[codepoint] = glyph + codepoint - start
            if mapping:
                return mapping
        elif format_code == 4 and subtable + 16 <= len(font_data):
            segment_count = struct.unpack_from(">H", font_data, subtable + 6)[0] // 2
            end_codes = subtable + 14
            start_codes = end_codes + segment_count * 2 + 2
            deltas = start_codes + segment_count * 2
            range_offsets = deltas + segment_count * 2
            for index in range(segment_count):
                end = struct.unpack_from(">H", font_data, end_codes + index * 2)[0]
                start = struct.unpack_from(">H", font_data, start_codes + index * 2)[0]
                delta = struct.unpack_from(">h", font_data, deltas + index * 2)[0]
                range_offset = struct.unpack_from(">H", font_data, range_offsets + index * 2)[0]
                if start > end or start == 0xFFFF:
                    continue
                for codepoint in range(start, end + 1):
                    if range_offset:
                        glyph_address = range_offsets + index * 2 + range_offset + (codepoint - start) * 2
                        glyph = struct.unpack_from(">H", font_data, glyph_address)[0] if glyph_address + 2 <= len(font_data) else 0
                        mapping[codepoint] = (glyph + delta) & 0xFFFF if glyph else 0
                    else:
                        mapping[codepoint] = (codepoint + delta) & 0xFFFF
            if mapping:
                return mapping
    return {}


def _pdf_unicode_font() -> tuple[bytes, dict[int, int]] | None:
    """Load a local Unicode font when available; fall back to Helvetica elsewhere."""
    global _PDF_FONT_CACHE
    if _PDF_FONT_CACHE is not None:
        return _PDF_FONT_CACHE
    paths = (
        Path("/System/Library/Fonts/Supplemental/Arial.ttf"),
        Path("/Library/Fonts/Arial Unicode.ttf"),
        Path("/System/Library/Fonts/Supplemental/Arial Unicode.ttf"),
        Path("/System/Library/Fonts/Supplemental/Tahoma.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    )
    for path in paths:
        try:
            data = path.read_bytes()
            cmap = _ttf_cmap(data)
            if cmap:
                _PDF_FONT_CACHE = (data, cmap)
                return _PDF_FONT_CACHE
        except (OSError, ValueError, struct.error):
            continue
    return None


def _ttf_glyph_widths(font_data: bytes) -> dict[int, int]:
    """Return glyph advance widths in PDF's 1000-unit coordinate system."""
    if len(font_data) < 12:
        return {}
    table_count = struct.unpack_from(">H", font_data, 4)[0]
    tables: dict[bytes, tuple[int, int]] = {}
    for index in range(table_count):
        record_offset = 12 + index * 16
        if record_offset + 16 > len(font_data):
            break
        tag, _, offset, length = struct.unpack_from(">4sLLL", font_data, record_offset)
        if offset + length <= len(font_data):
            tables[tag] = (offset, length)
    head = tables.get(b"head")
    hhea = tables.get(b"hhea")
    hmtx = tables.get(b"hmtx")
    maxp = tables.get(b"maxp")
    if not all((head, hhea, hmtx, maxp)):
        return {}
    head_offset, head_length = head
    hhea_offset, hhea_length = hhea
    hmtx_offset, hmtx_length = hmtx
    maxp_offset, maxp_length = maxp
    if head_length < 20 or hhea_length < 36 or maxp_length < 6:
        return {}
    units_per_em = struct.unpack_from(">H", font_data, head_offset + 18)[0]
    metric_count = struct.unpack_from(">H", font_data, hhea_offset + 34)[0]
    glyph_count = struct.unpack_from(">H", font_data, maxp_offset + 4)[0]
    if not units_per_em or not metric_count or not glyph_count:
        return {}
    widths: dict[int, int] = {}
    available_metrics = min(metric_count, glyph_count, hmtx_length // 4)
    last_advance = 0
    for glyph in range(available_metrics):
        advance = struct.unpack_from(">H", font_data, hmtx_offset + glyph * 4)[0]
        last_advance = advance
        widths[glyph] = max(1, round(advance * 1000 / units_per_em))
    for glyph in range(available_metrics, glyph_count):
        widths[glyph] = max(1, round(last_advance * 1000 / units_per_em))
    return widths


def _pdf_utf16_codepoint(codepoint: int) -> str:
    if codepoint <= 0xFFFF:
        return f"{codepoint:04X}"
    codepoint -= 0x10000
    high = 0xD800 + (codepoint >> 10)
    low = 0xDC00 + (codepoint & 0x3FF)
    return f"{high:04X}{low:04X}"


_ARABIC_PRESENTATION_FORMS: dict[int, dict[str, str]] | None = None


def _arabic_presentation_forms() -> dict[int, dict[str, str]]:
    global _ARABIC_PRESENTATION_FORMS
    if _ARABIC_PRESENTATION_FORMS is None:
        forms: dict[int, dict[str, str]] = {}
        for codepoint in range(0xFE70, 0xFEFF + 1):
            decomposition = unicodedata.decomposition(chr(codepoint)).split()
            if len(decomposition) >= 2 and decomposition[1] != "0020" and decomposition[0] in {"<isolated>", "<final>", "<initial>", "<medial>"}:
                forms.setdefault(int(decomposition[1], 16), {})[decomposition[0][1:-1]] = chr(codepoint)
        _ARABIC_PRESENTATION_FORMS = forms
    return _ARABIC_PRESENTATION_FORMS


def _shape_arabic_for_pdf(value: str) -> str:
    """Shape Arabic letters and apply a small bidi pass for the PDF writer.

    The PDF generator writes glyphs in the order supplied to ``Tj`` and does
    not have a paragraph bidi engine.  Reversing each word (the old behavior)
    left Arabic sentences with their words in the wrong order.  Shape in
    logical order first, then reverse complete RTL runs while keeping Latin
    and numeric runs readable.
    """
    forms = _arabic_presentation_forms()
    source = list(str(value or ""))

    def is_arabic(character: str) -> bool:
        if not character:
            return False
        codepoint = ord(character)
        return (
            codepoint in forms
            or 0x0600 <= codepoint <= 0x06FF
            or 0x0750 <= codepoint <= 0x077F
            or 0x08A0 <= codepoint <= 0x08FF
            or 0xFB50 <= codepoint <= 0xFDFF
            or 0xFE70 <= codepoint <= 0xFEFF
        )

    # Shape while the string is still in logical order. Joining decisions must
    # inspect logical neighbors, not the eventual visual order.
    shaped: list[str] = []
    for index, character in enumerate(source):
        available = forms.get(ord(character))
        if not available:
            shaped.append(character)
            continue
        previous = source[index - 1] if index else ""
        following = source[index + 1] if index + 1 < len(source) else ""
        previous_forms = forms.get(ord(previous), {}) if is_arabic(previous) else {}
        following_forms = forms.get(ord(following), {}) if is_arabic(following) else {}
        joins_previous = bool(previous_forms.get("initial") or previous_forms.get("medial")) and bool(available.get("final") or available.get("medial"))
        joins_following = bool(available.get("initial") or available.get("medial")) and bool(following_forms.get("final") or following_forms.get("medial"))
        form = "medial" if joins_previous and joins_following else "final" if joins_previous else "initial" if joins_following else "isolated"
        shaped.append(available.get(form, available.get("isolated", character)))

    def direction(character: str) -> str | None:
        if is_arabic(character):
            return "R"
        bidi = unicodedata.bidirectional(character)
        return "L" if bidi in {"L", "EN", "AN"} else None

    visual: list[str] = []
    segment: list[str] = []
    segment_direction: str | None = None

    def flush_segment() -> None:
        nonlocal segment, segment_direction
        if segment:
            visual.extend(reversed(segment) if segment_direction == "R" else segment)
        segment = []
        segment_direction = None

    for character in shaped:
        current_direction = direction(character)
        if current_direction and segment_direction and current_direction != segment_direction:
            flush_segment()
        if current_direction and segment_direction is None:
            segment_direction = current_direction
        segment.append(character)
    flush_segment()
    return "".join(visual)


def build_employment_contract_pdf(contract: dict[str, Any]) -> bytes:
    """Create the professional, framed Arabic employment-contract form."""
    employee = contract.get("employee") or {}
    organization = contract.get("organization") or {}
    start = contract.get("contract_start_on") or "-"
    end = contract.get("contract_end_on") or "-"
    name = employee.get("full_name") or employee.get("name") or "-"
    employer = organization.get("legal_name") or organization.get("display_name") or "خيشة - Khaisha"
    display_name = organization.get("display_name") or employer
    address = organization.get("address") or organization.get("emirate") or "-"
    license_no = organization.get("license_no") or "-"
    representative = organization.get("representative_name") or organization.get("manager_name") or "-"
    contract_number = contract.get("contract_number") or "-"
    issued_at = contract.get("issued_at") or "-"
    salary = employee.get("salary")
    salary_text = f"{float(salary):,.2f} درهم إماراتي" if salary not in (None, "") else "-"
    font_bundle = _pdf_unicode_font()
    use_unicode = bool(font_bundle)
    used_glyphs: dict[int, int] = {}
    page_streams: list[bytes] = []

    def color(hex_value: str) -> tuple[float, float, float]:
        value = hex_value.lstrip("#")
        return tuple(int(value[index:index + 2], 16) / 255 for index in (0, 2, 4))  # type: ignore[return-value]

    teal = color("#0d3d3b")
    teal_light = color("#eaf2ef")
    gold = color("#c49a52")
    ink = color("#23322f")
    muted = color("#64746e")
    line = color("#d2dbd5")
    white = (1.0, 1.0, 1.0)

    def add_fill(commands: list[str], x: float, y: float, width: float, height: float, fill: tuple[float, float, float]) -> None:
        r, g, b = fill
        commands.append(f"q {r:.4f} {g:.4f} {b:.4f} rg {x:.2f} {y:.2f} {width:.2f} {height:.2f} re f Q")

    def add_stroke(commands: list[str], x: float, y: float, width: float, height: float, stroke: tuple[float, float, float], weight: float = 0.7) -> None:
        r, g, b = stroke
        commands.append(f"q {r:.4f} {g:.4f} {b:.4f} RG {weight:.2f} w {x:.2f} {y:.2f} {width:.2f} {height:.2f} re S Q")

    def add_line(commands: list[str], x1: float, y1: float, x2: float, y2: float, stroke: tuple[float, float, float], weight: float = 0.7) -> None:
        r, g, b = stroke
        commands.append(f"q {r:.4f} {g:.4f} {b:.4f} RG {weight:.2f} w {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S Q")

    def add_text(commands: list[str], value: Any, x: float, y: float, size: float = 9.0, fill: tuple[float, float, float] = ink) -> None:
        text = str(value or "-")
        r, g, b = fill
        if use_unicode:
            assert font_bundle is not None
            _, cmap = font_bundle
            encoded = bytearray()
            for character in _shape_arabic_for_pdf(text):
                codepoint = ord(character)
                glyph = int(cmap.get(codepoint, 0))
                if not glyph:
                    decomposition = unicodedata.decomposition(character).split()
                    if len(decomposition) >= 2 and decomposition[0].startswith("<"):
                        codepoint = int(decomposition[1], 16)
                        glyph = int(cmap.get(codepoint, 0))
                encoded.extend(struct.pack(">H", glyph))
                if glyph:
                    used_glyphs[glyph] = codepoint
            commands.extend([
                "BT", f"{r:.4f} {g:.4f} {b:.4f} rg", f"/F2 {size:.2f} Tf",
                f"1 0 0 1 {x:.2f} {y:.2f} Tm", f"<{encoded.hex().upper()}> Tj", "ET",
            ])
        else:
            commands.extend([
                "BT", f"{r:.4f} {g:.4f} {b:.4f} rg", f"/F1 {size:.2f} Tf",
                f"1 0 0 1 {x:.2f} {y:.2f} Tm", f"({_pdf_text(text)}) Tj", "ET",
            ])

    def wrap(value: Any, limit: int = 88) -> list[str]:
        output: list[str] = []
        for raw in str(value or "-").splitlines() or ["-"]:
            remaining = raw.strip() or "-"
            while len(remaining) > limit:
                cut = remaining.rfind(" ", 0, limit)
                if cut < 24:
                    cut = limit
                output.append(remaining[:cut].rstrip())
                remaining = remaining[cut:].lstrip()
            output.append(remaining)
        return output

    def field(commands: list[str], label: str, value: Any, x: float, top: float, width: float, height: float = 30.0) -> None:
        add_fill(commands, x, top - height, width, height, white)
        add_stroke(commands, x, top - height, width, height, line)
        add_text(commands, label, x + 8, top - 10, 7.0, muted)
        add_text(commands, value, x + 8, top - 23, 8.5, ink)

    def heading(commands: list[str], title: str, top: float) -> float:
        add_fill(commands, 50, top - 21, 495, 21, teal)
        add_text(commands, title, 61, top - 14, 9.2, white)
        return top - 29

    def paragraph(commands: list[str], value: str, top: float, size: float = 8.5, limit: int = 92) -> float:
        current = top
        for line_text in wrap(value, limit):
            add_text(commands, line_text, 61, current - 10, size, ink)
            current -= 13
        return current - 3

    def clause(commands: list[str], title: str, value: str, top: float) -> float:
        current = heading(commands, title, top)
        return paragraph(commands, value, current, 8.25, 92)

    def page_shell(page_number: int, continuation: bool = False, total_pages: int = 6, language: str = "ar") -> list[str]:
        commands: list[str] = []
        add_fill(commands, 0, 0, 595, 842, color("#fbfcfa"))
        add_stroke(commands, 31, 28, 533, 786, gold, 1.1)
        add_stroke(commands, 37, 34, 521, 774, line, 0.45)
        add_fill(commands, 38, 774, 519, 40, teal)
        add_fill(commands, 38, 770, 519, 4, gold)
        if language == "en":
            add_text(commands, display_name, 53, 797, 10.5, white)
            add_text(commands, "Employment Contract", 400, 798, 12.0, white)
            add_text(commands, "HR-controlled institutional form", 53, 783, 7.0, color("#c5d9d2"))
            add_text(commands, "Employment form and acknowledgement", 365, 783, 7.0, color("#f1d69c"))
            add_text(commands, f"Page {page_number} of {total_pages}", 253, 45, 7.0, muted)
            add_text(commands, f"Contract reference: {contract_number}", 53, 45, 7.0, muted)
            add_text(commands, f"Issue date: {issued_at}", 395, 45, 7.0, muted)
        else:
            add_text(commands, display_name, 53, 797, 10.5, white)
            add_text(commands, "عقد عمل", 432, 798, 13.0, white)
            add_text(commands, "نموذج مؤسسي محفوظ لدى الموارد البشرية", 53, 783, 7.0, color("#c5d9d2"))
            add_text(commands, "استمارة تعاقد وإقرار", 415, 783, 7.0, color("#f1d69c"))
            add_text(commands, f"الصفحة {page_number} من {total_pages}" if not continuation else f"استكمال العقد · {page_number} من {total_pages}", 253, 45, 7.0, muted)
            add_text(commands, f"مرجع العقد: {contract_number}", 53, 45, 7.0, muted)
            add_text(commands, f"تاريخ الإصدار: {issued_at}", 395, 45, 7.0, muted)
        return commands

    # Page one: identity, employment data and the first two clauses.
    first = page_shell(1, total_pages=6)
    y = heading(first, "بيانات العقد والأطراف", 757)
    field(first, "صاحب العمل / الطرف الأول", employer, 55, y, 240)
    field(first, "الموظف / الطرف الثاني", name, 305, y, 235)
    y -= 38
    field(first, "الرخصة التجارية", license_no, 55, y, 240)
    field(first, "الجنسية", employee.get("nationality") or "-", 305, y, 235)
    y -= 38
    field(first, "يمثله", representative, 55, y, 240)
    field(first, "رقم الهوية / الجواز", employee.get("emirates_id_no") or employee.get("passport_no") or "-", 305, y, 235)
    y -= 38
    field(first, "العنوان ووسائل الاتصال", address, 55, y, 240)
    field(first, "الرقم الوظيفي", employee.get("employee_no") or "-", 305, y, 235)
    y -= 46
    y = heading(first, "بيانات الوظيفة ومدة العقد", y)
    field(first, "المسمى الوظيفي", employee.get("job_title") or "-", 55, y, 240)
    field(first, "القسم / الفرع", f"{employee.get('department_name') or '-'} / {employee.get('branch_name') or '-'}", 305, y, 235)
    y -= 38
    field(first, "تاريخ التعيين", employee.get("hire_date") or "-", 55, y, 240)
    field(first, "نوع العقد", "محدد المدة" if end != "-" else "غير محدد المدة", 305, y, 235)
    y -= 38
    field(first, "بداية العقد", start, 55, y, 240)
    field(first, "نهاية العقد", end, 305, y, 235)
    y -= 38
    field(first, "الأجر الإجمالي الشهري", salary_text, 55, y, 240)
    field(first, "مقر العمل الأساسي", address, 305, y, 235)
    y -= 46
    y = clause(first, "البند الأول: الإقرار بالاطلاع", f"يقر الطرف الثاني ({name}) بأنه اطلع اطلاعاً تاماً على أحكام قانون العمل الإماراتي (المرسوم بقانون اتحادي رقم 33 لسنة 2021) ولائحته التنفيذية، وعلى اللائحة الداخلية للشركة وسياساتها وقواعد السلوك الوظيفي المعمول بها، وفهم كافة بنودها، ويلتزم بالعمل بموجبها، على أن تطبق اللائحة الداخلية في كل ما لا يتعارض مع أحكام القانون الاتحادي، وفي حال التعارض تطبق أحكام القانون باعتبارها الحد الأدنى الملزم لحقوق الطرف الثاني.", y)
    clause(first, "البند الثاني: موضوع العقد", f"يعمل الطرف الثاني لدى الطرف الأول تحت المسمى الوظيفي: {employee.get('job_title') or '-'}، في قسم أو إدارة: {employee.get('department_name') or '-'}، ومقر العمل الأساسي: {address}، مع أحقية الطرف الأول في انتداب الطرف الثاني للعمل في أي مكان آخر داخل الدولة حسب مقتضيات العمل، وكذلك تكليفه بمهام إضافية تتصل بطبيعة وظيفته دون أن يشكل ذلك إخلالاً بشروط هذا العقد.", y - 5)
    page_streams.append("\n".join(first).encode("ascii", "ignore"))

    # Page two: the detailed working terms and employee obligations.
    second = page_shell(2, True, 6)
    y = heading(second, "الشروط والأحكام - الجزء الأول", 757)
    y = clause(second, "البند الثالث: مدة العقد وفترة التجربة", f"هذا العقد {('محدد المدة' if end != '-' else 'غير محدد المدة')}، ويبدأ نفاذه من تاريخ {start}. يخضع الطرف الثاني لفترة تجربة مدتها ______ يوماً لا تتجاوز 6 أشهر من تاريخ المباشرة الفعلية، ويحق خلالها لأي من الطرفين إنهاء العقد بإشعار كتابي مدته 14 يوماً على الأقل، دون استحقاق تعويض، وفقاً لأحكام قانون العمل.", y)
    y = clause(second, "البند الرابع: الأجر", f"يتقاضى الطرف الثاني أجراً إجمالياً شهرياً قدره ({salary_text})، يصرف نهاية كل شهر ميلادي عبر نظام حماية الأجور (WPS)، وتخصم منه أي مستحقات نظامية للجهات الحكومية، كالتأمينات الاجتماعية إن انطبقت، وفق القانون.", y - 4)
    y = clause(second, "البند الخامس: ساعات العمل وأيام العطلة الأسبوعية", "يحدد الطرف الأول ساعات وأيام العمل الرسمية بواقع 8 ساعات يومياً كحد أقصى أو ما يعادلها أسبوعياً وفق النظام المعمول به، ونظام العطلة الأسبوعية يوم أو أكثر بحسب طبيعة النشاط والقسم. ويحتفظ الطرف الأول بحقه في تعديل جدول الدوام أو نظام العطلة الأسبوعية أو أوقات المناوبات وفق مقتضيات العمل، شريطة عدم تجاوز الحد الأقصى لساعات العمل المقرر قانوناً، ويلتزم الطرف الثاني بهذه التعديلات بمجرد إبلاغه بها. وفي حال تكليفه بالعمل خلال أيام العطل الرسمية، يستحق بدلًا نقدياً أو إجازة تعويضية وفق اللائحة الداخلية، بما لا يقل عن الحدود الدنيا المقررة في قانون العمل.", y - 4)
    y = clause(second, "البند السادس: الإجازات", "يستحق الطرف الثاني إجازة سنوية مدفوعة الأجر بواقع 30 يوماً عن كل سنة خدمة كاملة، أو يومين عن كل شهر عن مدة خدمة تزيد على 6 أشهر وتقل عن سنة، إضافة إلى الإجازات المرضية والخاصة المنصوص عليها في قانون العمل، على أن يحدد موعد الإجازة بالتنسيق مع الطرف الأول وفق مقتضيات العمل.", y - 4)
    clause(second, "البند السابع: التزامات الطرف الثاني", "يلتزم الطرف الثاني: 1) بأداء العمل المكلف به بأمانة وإخلاص ووفق تعليمات الطرف الأول؛ 2) بالالتزام بأنظمة العمل الداخلية وسياسات الشركة وقواعد السلوك الوظيفي؛ 3) بالمحافظة على سرية معلومات وأسرار العمل أثناء سريان العقد ولمدة ______ سنة بعد انتهائه؛ 4) بعدم العمل لدى أي جهة أخرى منافسة أو غير منافسة دون إذن كتابي مسبق؛ 5) بالمحافظة على ممتلكات ومعدات الشركة وعدم التسبب بضرر أو إهمال جسيم؛ 6) بعدم إفشاء أو استغلال بيانات العملاء أو أعمال الشركة لأي غرض شخصي أو لمصلحة طرف ثالث.", y - 4)
    y = max(y - 12, 190)
    page_streams.append("\n".join(second).encode("ascii", "ignore"))

    # Page three: termination, disputes, general provisions and signatures.
    third = page_shell(3, True, 6)
    y = heading(third, "الشروط والأحكام - الجزء الثاني", 757)
    y = clause(third, "البند الثامن: حالات الفصل دون إشعار أو مكافأة", "يحق للطرف الأول إنهاء هذا العقد فوراً ودون إشعار أو مكافأة نهاية خدمة في الحالات المنصوص عليها حصراً في المادة (44) من قانون العمل الإماراتي، كالغش أو التزوير أو الإفشاء الجسيم للأسرار أو الاعتداء أو التغيب دون سبب مشروع لأكثر من المدد المقررة قانوناً، مع مراعاة الإجراءات والضمانات النظامية.", y)
    y = clause(third, "البند التاسع: إنهاء العقد ومكافأة نهاية الخدمة", "بعد انتهاء فترة التجربة، يخضع إنهاء العقد لإشعار كتابي مسبق مدته ______ يوماً، بين 30 و90 يوماً، وتُصرف مكافأة نهاية الخدمة والمستحقات وفق الحدود والنسب المقررة في قانون العمل الإماراتي، ولا تخل صياغة هذا العقد بأي حق إلزامي مقرر للطرف الثاني بموجب القانون.", y - 4)
    y = clause(third, "البند العاشر: تسوية النزاعات", "في حال نشوء أي نزاع، يسعى الطرفان إلى حله ودياً أولاً، وفي حال تعذر ذلك يحال إلى وزارة الموارد البشرية والتوطين، ثم إلى المحاكم المختصة في دولة الإمارات العربية المتحدة، التي تطبق أحكامها وقوانينها على هذا العقد.", y - 4)
    y = clause(third, "البند الحادي عشر: أحكام عامة", "أي بند يرد في هذا العقد ويخالف الحد الأدنى لحقوق الطرف الثاني المقررة بقانون العمل الإماراتي يعتبر لاغياً ويستبدل تلقائياً بالحكم القانوني المقابل دون أن يؤثر ذلك على باقي البنود. وتطبق أحكام قانون العمل الإماراتي ولائحته التنفيذية على كل ما لم يرد به نص. حرر هذا العقد من نسختين أصليتين متطابقتين، بيد كل طرف نسخة للعمل بموجبها، وأقر الطرفان بقراءته وفهم بنوده والموافقة عليه دون إكراه.", y - 4)
    y = max(y - 16, 300)
    add_fill(third, 50, y - 18, 495, 18, teal_light)
    add_text(third, "التوقيعات والإقرار", 61, y - 12, 9.0, teal)
    y -= 31
    add_stroke(third, 55, y - 82, 238, 72, line)
    add_stroke(third, 302, y - 82, 238, 72, line)
    add_text(third, "الطرف الأول - صاحب العمل", 68, y - 25, 8.3, muted)
    add_text(third, employer, 68, y - 40, 8.6, ink)
    add_text(third, "الاسم والتوقيع: __________________", 68, y - 61, 8.0, ink)
    add_text(third, "التاريخ: _________________________", 68, y - 75, 8.0, ink)
    add_text(third, "الطرف الثاني - الموظف", 315, y - 25, 8.3, muted)
    add_text(third, name, 315, y - 40, 8.6, ink)
    add_text(third, "الاسم والتوقيع: __________________", 315, y - 61, 8.0, ink)
    add_text(third, "التاريخ: _________________________", 315, y - 75, 8.0, ink)
    add_text(third, "يقر الطرفان بأن هذه الاستمارة تمثل عقد العمل والإقرار المتفق عليه، وبأن أي حق إلزامي مقرر بموجب القانون يبقى محفوظاً بالكامل.", 61, y - 105, 7.5, muted)
    page_streams.append("\n".join(third).encode("ascii", "ignore"))

    # Pages four to six repeat the form in English so the signed record is
    # usable by bilingual staff, banks and government-facing reviewers.
    salary_text_en = f"{float(salary):,.2f} AED" if salary not in (None, "") else "-"
    first_en = page_shell(4, total_pages=6, language="en")
    y = heading(first_en, "Contract parties and identity", 757)
    field(first_en, "Employer / First party", employer, 55, y, 240)
    field(first_en, "Employee / Second party", name, 305, y, 235)
    y -= 38
    field(first_en, "Trade licence number", license_no, 55, y, 240)
    field(first_en, "Nationality", employee.get("nationality") or "-", 305, y, 235)
    y -= 38
    field(first_en, "Represented by", representative, 55, y, 240)
    field(first_en, "Emirates ID / passport", employee.get("emirates_id_no") or employee.get("passport_no") or "-", 305, y, 235)
    y -= 38
    field(first_en, "Address and contact", address, 55, y, 240)
    field(first_en, "Employee number", employee.get("employee_no") or "-", 305, y, 235)
    y -= 46
    y = heading(first_en, "Employment details and contract term", y)
    field(first_en, "Job title", employee.get("job_title") or "-", 55, y, 240)
    field(first_en, "Department / branch", f"{employee.get('department_name') or '-'} / {employee.get('branch_name') or '-'}", 305, y, 235)
    y -= 38
    field(first_en, "Hire date", employee.get("hire_date") or "-", 55, y, 240)
    field(first_en, "Contract type", "Fixed term" if end != "-" else "Indefinite term", 305, y, 235)
    y -= 38
    field(first_en, "Contract start", start, 55, y, 240)
    field(first_en, "Contract end", end, 305, y, 235)
    y -= 38
    field(first_en, "Gross monthly salary", salary_text_en, 55, y, 240)
    field(first_en, "Primary work location", address, 305, y, 235)
    y -= 46
    y = clause(first_en, "Clause 1: acknowledgement", "The employee confirms that they have fully read and understood UAE Labour Law, Federal Decree-Law No. 33 of 2021 and its implementing regulations, as well as the employer's internal regulations, policies and code of conduct. The internal rules apply only to the extent that they do not conflict with federal law; where a conflict exists, the mandatory legal minimum applies.", y)
    clause(first_en, "Clause 2: scope of employment", "The employee is employed by the employer under the job title and department recorded in this form, with the primary work location recorded above. The employer may assign related duties or a work location within the UAE where reasonably required by the business, without reducing any statutory right.", y - 5)
    page_streams.append("\n".join(first_en).encode("ascii", "ignore"))

    second_en = page_shell(5, True, 6, "en")
    y = heading(second_en, "Terms and conditions - Part 1", 757)
    y = clause(second_en, "Clause 3: term and probation", f"This is a {'fixed-term' if end != '-' else 'indefinite-term'} contract effective from {start}. The employee may be subject to a probation period of ______ days, not exceeding six months from the actual commencement date. During probation either party may terminate with at least 14 days' written notice, in accordance with applicable law.", y)
    y = clause(second_en, "Clause 4: remuneration", f"The employee will receive a gross monthly salary of {salary_text_en}, paid at the end of each Gregorian month through the Wage Protection System (WPS), subject to lawful deductions and statutory contributions where applicable.", y - 4)
    y = clause(second_en, "Clause 5: working hours and weekly rest", "Normal working hours and weekly rest days are set by the employer according to the department and applicable UAE limits. The employer may adjust schedules and shifts for operational needs without exceeding statutory maximums. Work on public holidays is compensated by payment or a compensatory day in accordance with the internal policy and the legal minimum.", y - 4)
    y = clause(second_en, "Clause 6: leave", "The employee is entitled to annual leave of 30 paid days for each completed year, or two days for each month where service exceeds six months and is less than one year, in addition to statutory sick and special leave. Leave dates are coordinated with the employer and operational requirements.", y - 4)
    clause(second_en, "Clause 7: employee obligations", "The employee shall perform assigned duties faithfully, follow internal policies and conduct rules, protect confidential information during employment and for ______ years after termination, avoid outside work without prior written approval, safeguard company property, and never disclose or misuse customer or business data.", y - 4)
    page_streams.append("\n".join(second_en).encode("ascii", "ignore"))

    third_en = page_shell(6, True, 6, "en")
    y = heading(third_en, "Terms and conditions - Part 2", 757)
    y = clause(third_en, "Clause 8: termination for cause", "The employer may terminate without notice or end-of-service benefit only in the cases exhaustively provided by Article 44 of UAE Labour Law, including fraud, forgery, serious disclosure of confidential information, assault, or unjustified absence beyond the statutory periods, subject to the required procedures and safeguards.", y)
    y = clause(third_en, "Clause 9: termination and end-of-service benefit", "After probation, termination is subject to written notice of ______ days, between 30 and 90 days. End-of-service benefits and all final entitlements are paid in accordance with UAE Labour Law; no wording in this form waives a mandatory statutory right.", y - 4)
    y = clause(third_en, "Clause 10: dispute resolution", "The parties will first attempt to resolve any dispute amicably. If unresolved, the matter may be referred to the Ministry of Human Resources and Emiratisation and then to the competent courts of the UAE, whose laws govern this contract.", y - 4)
    y = clause(third_en, "Clause 11: general provisions", "Any provision that falls below the mandatory minimum rights under UAE Labour Law is void and automatically replaced by the applicable legal provision. UAE Labour Law and its implementing regulations apply to matters not expressly covered here. This form is prepared in two identical originals and both parties confirm that they have read, understood and accepted it without coercion.", y - 4)
    y = max(y - 16, 300)
    add_fill(third_en, 50, y - 18, 495, 18, teal_light)
    add_text(third_en, "Acknowledgement and signatures", 61, y - 12, 9.0, teal)
    y -= 31
    add_stroke(third_en, 55, y - 82, 238, 72, line)
    add_stroke(third_en, 302, y - 82, 238, 72, line)
    add_text(third_en, "First party - employer", 68, y - 25, 8.3, muted)
    add_text(third_en, employer, 68, y - 40, 8.6, ink)
    add_text(third_en, "Name and signature: __________________", 68, y - 61, 8.0, ink)
    add_text(third_en, "Date: ______________________________", 68, y - 75, 8.0, ink)
    add_text(third_en, "Second party - employee", 315, y - 25, 8.3, muted)
    add_text(third_en, name, 315, y - 40, 8.6, ink)
    add_text(third_en, "Name and signature: __________________", 315, y - 61, 8.0, ink)
    add_text(third_en, "Date: ______________________________", 315, y - 75, 8.0, ink)
    add_text(third_en, "Both parties acknowledge that this form records the agreed employment terms and preserves every mandatory legal right.", 61, y - 105, 7.5, muted)
    page_streams.append("\n".join(third_en).encode("ascii", "ignore"))

    page_count = len(page_streams)
    page_numbers = list(range(3, 3 + page_count))
    content_numbers = list(range(3 + page_count, 3 + page_count * 2))
    if use_unicode:
        assert font_bundle is not None
        font_data, _ = font_bundle
        font_descriptor_number = 3 + page_count * 2
        to_unicode_number = font_descriptor_number + 1
        compressed_number = to_unicode_number + 1
        cid_number = compressed_number + 1
        type0_number = cid_number + 1
        objects: list[bytes] = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            (f"<< /Type /Pages /Kids [{' '.join(f'{number} 0 R' for number in page_numbers)}] /Count {page_count} >>").encode("ascii"),
        ]
        for page_number, content_number in zip(page_numbers, content_numbers):
            objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F2 {type0_number} 0 R >> >> /Contents {content_number} 0 R >>".encode("ascii"))
        for stream in page_streams:
            objects.append(b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream")
        to_unicode_lines = ["/CIDInit /ProcSet findresource begin", "12 dict begin", "begincmap", "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def", "/CMapName /Adobe-Identity-UCS def", "/CMapType 2 def", "1 begincodespacerange", "<0000> <FFFF>", "endcodespacerange"]
        entries = [f"<{glyph:04X}> <{_pdf_utf16_codepoint(codepoint)}>" for glyph, codepoint in sorted(used_glyphs.items())]
        for start_index in range(0, len(entries), 100):
            chunk = entries[start_index:start_index + 100]
            to_unicode_lines.append(f"{len(chunk)} beginbfchar")
            to_unicode_lines.extend(chunk)
            to_unicode_lines.append("endbfchar")
        to_unicode_lines.extend(["endcmap", "CMapName currentdict /CMap defineresource pop", "end", "end"])
        to_unicode = "\n".join(to_unicode_lines).encode("ascii")
        compressed_font = zlib.compress(font_data, 9)
        font_widths = _ttf_glyph_widths(font_data)
        width_entries = " ".join(f"{glyph} [{font_widths.get(glyph, 600)}]" for glyph in sorted(used_glyphs))
        cid_widths = f"/W [{width_entries}]" if width_entries else ""
        objects.extend([
            b"<< /Type /FontDescriptor /FontName /Arial /Flags 4 /FontBBox [0 -250 2000 1000] /Ascent 900 /Descent -250 /CapHeight 700 /ItalicAngle 0 /StemV 80 /FontFile2 " + str(compressed_number).encode("ascii") + b" 0 R >>",
            b"<< /Length " + str(len(to_unicode)).encode("ascii") + b" >>\nstream\n" + to_unicode + b"\nendstream",
            b"<< /Length " + str(len(compressed_font)).encode("ascii") + b" /Filter /FlateDecode >>\nstream\n" + compressed_font + b"\nendstream",
            f"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Arial /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor {font_descriptor_number} 0 R /CIDToGIDMap /Identity /DW 600 {cid_widths} >>".encode("ascii"),
            f"<< /Type /Font /Subtype /Type0 /BaseFont /Arial /Encoding /Identity-H /DescendantFonts [{cid_number} 0 R] /ToUnicode {to_unicode_number} 0 R >>".encode("ascii"),
        ])
    else:
        font_number = 3 + page_count * 2 + 1
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            (f"<< /Type /Pages /Kids [{' '.join(f'{number} 0 R' for number in page_numbers)}] /Count {page_count} >>").encode("ascii"),
        ]
        for page_number, content_number in zip(page_numbers, content_numbers):
            objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 {font_number} 0 R >> >> /Contents {content_number} 0 R >>".encode("ascii"))
        for stream in page_streams:
            objects.append(b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream")
        objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode("ascii")); output.extend(obj); output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    output.extend("".join(f"{offset:010d} 00000 n \n" for offset in offsets[1:]).encode("ascii"))
    output.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    return bytes(output)


def build_salary_certificate_pdf(certificate: dict[str, Any]) -> bytes:
    """Create a dependency-free, printable PDF attachment for approved certificates.

    The browser renders the polished bilingual certificate; the email attachment is
    intentionally generated server-side so it is available even when the recipient
    never opens the web application.  ASCII-safe fallback text keeps this valid on
    installations without a PDF package or Arabic font files.
    """
    employee = certificate.get("employee") or {}
    organization = certificate.get("organization") or {}
    breakdown = certificate.get("salary_breakdown") or employee.get("salary_breakdown") or {}
    manual = breakdown.get("manual_allowances") or []
    lines = [
        organization.get("display_name") or "Khaisha - HR",
        "SALARY CERTIFICATE / شهادة راتب",
        f"Issue No: {certificate.get('certificate_no')}",
        f"Verification: {certificate.get('verification_code')}",
        f"Employee: {employee.get('name') or employee.get('full_name')}",
        f"Employee No: {employee.get('employee_no') or employee.get('employee_number')}",
        f"Job Title: {employee.get('job_title') or '-'}",
        f"Basic Salary (AED): {float(breakdown.get('basic_salary') or 0):,.2f}",
        f"Housing Allowance (AED): {float(breakdown.get('housing_allowance') or 0):,.2f}",
        f"Transport Allowance (AED): {float(breakdown.get('transport_allowance') or 0):,.2f}",
        f"Profession Allowance (AED): {float(breakdown.get('profession_allowance') or 0):,.2f}",
        f"Other Allowance (AED): {float(breakdown.get('other_allowance') or 0):,.2f}",
        *[f"{item.get('name')}: {float(item.get('amount') or 0):,.2f} AED" for item in manual if isinstance(item, dict)],
        f"Total Monthly Salary (AED): {float(certificate.get('salary') or breakdown.get('total') or 0):,.2f}",
        f"Purpose: {certificate.get('purpose') or 'To whom it may concern'}",
        f"Issued At: {certificate.get('issued_at') or '-'}",
        "This electronic document is verifiable in the HR system.",
    ]
    content_lines = ["BT", "/F1 12 Tf", "72 760 Td"]
    for index, line in enumerate(lines):
        if index:
            content_lines.append("0 -28 Td")
        content_lines.append(f"({_pdf_text(line)}) Tj")
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("ascii", "ignore")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode("ascii")); output.extend(obj); output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n".encode("ascii"))
    output.extend("".join(f"{offset:010d} 00000 n \n" for offset in offsets[1:]).encode("ascii"))
    output.extend(f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    return bytes(output)


def refresh_legacy_generated_contracts(db: sqlite3.Connection) -> int:
    """Regenerate legacy auto-created contract PDFs after a template revision."""
    rows = db.execute(
        """SELECT d.id,d.employee_id,d.document_number,d.issued_on,d.expires_on,d.updated_at,
                  e.*,jt.name AS job_title_name,dep.name AS department_name,b.name AS branch_name
           FROM employee_documents d
           JOIN employees e ON e.id=d.employee_id
           LEFT JOIN job_titles jt ON jt.id=e.job_title_id
           LEFT JOIN departments dep ON dep.id=e.department_id
           LEFT JOIN branches b ON b.id=e.branch_id
           WHERE d.document_type='contract' AND d.archived=0 AND d.notes LIKE ?""",
        ("عقد عمل منشأ آلياً%",),
    ).fetchall()
    if not rows:
        return 0
    organization = db.execute("SELECT * FROM organization WHERE id=1").fetchone()
    refreshed = 0
    for row in rows:
        if not row["issued_on"] or not row["expires_on"]:
            continue
        employee = dict(row)
        employee["job_title"] = employee.get("job_title_name") or employee.get("job_title") or ""
        contract_number = row["document_number"] or f"CTR-{employee.get('employee_no') or row['employee_id']}-{str(row['issued_on']).replace('-', '')}"
        payload = {
            "contract_number": contract_number,
            "contract_start_on": row["issued_on"],
            "contract_end_on": row["expires_on"],
            "issued_at": row["updated_at"] or now_iso(),
            "employee": employee,
            "organization": dict(organization or {}),
        }
        pdf_data_url = "data:application/pdf;base64," + base64.b64encode(build_employment_contract_pdf(payload)).decode("ascii")
        db.execute(
            "UPDATE employee_documents SET data_url=?,mime_type='application/pdf',file_name=?,notes=? WHERE id=?",
            (
                pdf_data_url,
                f"employment-contract-{employee.get('employee_no') or row['employee_id']}.pdf",
                "عقد عمل منشأ آلياً من بيانات الموظف وفق نموذج الإقرار الموجز؛ يمكن استبداله بنسخة موقعة من المؤسسة.",
                row["id"],
            ),
        )
        refreshed += 1
    return refreshed


def clean_email(value: Any) -> str:
    return str(value or "").strip().lower()


def require_text(data: dict[str, Any], key: str, max_len: int = 500) -> str:
    value = str(data.get(key, "")).strip()
    if not value:
        raise APIError(422, f"الحقل «{key}» مطلوب.", "validation_error", {"field": key})
    if len(value) > max_len:
        raise APIError(422, f"الحقل «{key}» أطول من الحد المسموح.", "validation_error", {"field": key})
    return value


def optional_text(data: dict[str, Any], key: str, max_len: int = 1000) -> str:
    value = str(data.get(key, "") or "").strip()
    if len(value) > max_len:
        raise APIError(422, f"الحقل «{key}» أطول من الحد المسموح.", "validation_error", {"field": key})
    return value


def as_int(value: Any, field: str, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise APIError(422, f"قيمة «{field}» غير صحيحة.", "validation_error", {"field": field})
    if minimum is not None and result < minimum or maximum is not None and result > maximum:
        raise APIError(422, f"قيمة «{field}» خارج النطاق المسموح.", "validation_error", {"field": field})
    return result


def as_float(value: Any, field: str, minimum: float | None = None, maximum: float | None = None) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise APIError(422, f"قيمة «{field}» غير صحيحة.", "validation_error", {"field": field})
    if not math.isfinite(result):
        raise APIError(422, f"قيمة «{field}» غير صحيحة.", "validation_error", {"field": field})
    if minimum is not None and result < minimum or maximum is not None and result > maximum:
        raise APIError(422, f"قيمة «{field}» خارج النطاق المسموح.", "validation_error", {"field": field})
    return result


def parse_date(value: Any, field: str = "date") -> date:
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        raise APIError(422, f"صيغة تاريخ «{field}» يجب أن تكون YYYY-MM-DD.", "validation_error", {"field": field})


def add_calendar_months(value: date, months: int) -> date:
    """Add calendar months while clamping dates such as 31 January."""
    index = value.year * 12 + (value.month - 1) + int(months)
    year, month_index = divmod(index, 12)
    month = month_index + 1
    # The first day of the following month minus one day is the last day of
    # the requested month and avoids another dependency just for this rule.
    next_year, next_month = (year + 1, 1) if month == 12 else (year, month + 1)
    last_day = (date(next_year, next_month, 1) - timedelta(days=1)).day
    return date(year, month, min(value.day, last_day))


def completed_service_months(hire_date: str | None, as_of: date | None = None) -> int:
    """Return completed calendar months of service for statutory leave accrual."""
    if not hire_date:
        return 0
    try:
        start = date.fromisoformat(str(hire_date)[:10])
    except (TypeError, ValueError):
        return 0
    end = as_of or local_now().date()
    if start > end:
        return 0
    months = (end.year - start.year) * 12 + end.month - start.month
    if end.day < start.day:
        months -= 1
    return max(0, months)


def annual_leave_accrued_to(hire_date: str | None, as_of: date) -> float:
    """Calculate UAE annual leave accrual at a service point.

    No annual paid leave is earned before six completed months.  From six
    months through the first year the balance is two days per completed month;
    each completed service year thereafter contributes thirty days.
    """
    months = completed_service_months(hire_date, as_of)
    if months < 6:
        return 0.0
    if months < 12:
        return float(months * 2)
    return float((months // 12) * 30)


def annual_leave_entitlement_for_year(hire_date: str | None, year: int, as_of: date | None = None) -> float:
    """Return the earned annual entitlement attributable to one calendar year."""
    today = as_of or local_now().date()
    if year > today.year:
        return 0.0
    end = min(date(year, 12, 31), today)
    previous_end = date(year - 1, 12, 31)
    return max(0.0, annual_leave_accrued_to(hire_date, end) - annual_leave_accrued_to(hire_date, previous_end))


def leave_days_excluding_public_holidays(db: sqlite3.Connection, start: date, end: date) -> float:
    """Count requested leave days while excluding configured public holidays.

    Weekly rest days remain part of the requested calendar range.  Only dates
    explicitly confirmed by HR in ``public_holidays`` are excluded, which is
    important for the UAE's Hijri-based holidays whose Gregorian dates change
    each year.
    """
    holiday_rows = db.execute(
        "SELECT holiday_date FROM public_holidays WHERE active=1 AND holiday_date>=? AND holiday_date<=?",
        (start.isoformat(), end.isoformat()),
    ).fetchall()
    holidays = {str(row["holiday_date"])[:10] for row in holiday_rows}
    current = start
    days = 0
    while current <= end:
        if current.isoformat() not in holidays:
            days += 1
        current += timedelta(days=1)
    return float(days)


def parse_clock(value: Any, field: str) -> time:
    text = str(value or "")
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", text):
        raise APIError(422, f"صيغة وقت «{field}» يجب أن تكون HH:MM.", "validation_error", {"field": field})
    return time.fromisoformat(text)


def money_cents(value: Any, field: str = "amount", minimum: Decimal = Decimal("0")) -> int:
    try:
        amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError):
        raise APIError(422, f"قيمة «{field}» غير صحيحة.", "validation_error", {"field": field})
    if amount < minimum:
        raise APIError(422, f"قيمة «{field}» أقل من الحد المسموح.", "validation_error", {"field": field})
    return int(amount * 100)


def cents_value(cents: int | None) -> float:
    return float((Decimal(int(cents or 0)) / Decimal(100)).quantize(Decimal("0.01")))


def validate_data_url(value: Any, label: str, allowed: Iterable[str] = ("image/png", "image/jpeg", "image/webp"), max_bytes: int = MAX_IMAGE_BYTES) -> str | None:
    if value in (None, ""):
        return None
    text = str(value)
    match = re.fullmatch(r"data:([^;,]+);base64,([A-Za-z0-9+/=\r\n]+)", text)
    if not match or match.group(1).lower() not in set(allowed):
        raise APIError(422, f"صيغة {label} غير مدعومة.", "invalid_upload")
    try:
        raw = base64.b64decode(match.group(2), validate=True)
    except ValueError:
        raise APIError(422, f"ملف {label} غير صالح.", "invalid_upload")
    if len(raw) > max_bytes:
        raise APIError(413, f"حجم {label} يتجاوز الحد المسموح.", "upload_too_large", {"max_bytes": max_bytes})
    mime = match.group(1).lower()
    signatures = {
        "image/png": raw.startswith(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg": raw.startswith(b"\xff\xd8\xff"),
        "image/webp": len(raw) >= 12 and raw.startswith(b"RIFF") and raw[8:12] == b"WEBP",
        "application/pdf": raw.startswith(b"%PDF-"),
    }
    if mime in signatures and not signatures[mime]:
        raise APIError(422, f"محتوى ملف {label} لا يطابق صيغته.", "invalid_upload")
    return text


def color_contrast(first: str, second: str) -> float:
    def luminance(value: str) -> float:
        channels = [int(value[index:index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4 for channel in channels]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]
    light, dark = sorted((luminance(first), luminance(second)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


def haversine_m(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    radius = 6_371_000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lng2 - lng1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return radius * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def row_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def open_db(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=15, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def seed_user(db: sqlite3.Connection, email: str, password: str, name: str, role: str, employee_id: int | None) -> int:
    existing = db.execute("SELECT id FROM users WHERE email = ? COLLATE NOCASE", (email,)).fetchone()
    if existing:
        return int(existing["id"])
    digest, salt = password_record(password)
    stamp = now_iso()
    cursor = db.execute(
        "INSERT INTO users(email,display_name,role,password_hash,password_salt,employee_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
        (email, name, role, digest, salt, employee_id, stamp, stamp),
    )
    return int(cursor.lastrowid)


def migrate_nonterminal_legacy_evaluations(db: sqlite3.Connection) -> None:
    """Move actionable V1 evaluations onto the employee -> manager -> HR flow.

    Terminal V1 decisions remain immutable history.  A non-terminal row is only
    changed when its employee still has a real direct manager; otherwise it is
    left untouched and an idempotent audit flag records the configuration gap.
    """
    legacy_rows = db.execute(
        """SELECT e.id,e.employee_id,e.status
             FROM evaluations e
            WHERE COALESCE(e.workflow_version,1)=1
              AND e.status IN ('draft','returned','submitted','in_review')
            ORDER BY e.id"""
    ).fetchall()
    stamp = now_iso()
    for evaluation in legacy_rows:
        manager = db.execute(
            """SELECT COALESCE(e.manager_id,d.manager_employee_id) AS manager_id
                 FROM employees e LEFT JOIN departments d ON d.id=e.department_id
                WHERE e.id=?""",
            (evaluation["employee_id"],),
        ).fetchone()
        manager_id = int(manager["manager_id"]) if manager and manager["manager_id"] else None
        manager_exists = bool(
            manager_id
            and manager_id != int(evaluation["employee_id"])
            and db.execute("SELECT 1 FROM employees WHERE id=?", (manager_id,)).fetchone()
        )
        if not manager_exists:
            already_flagged = db.execute(
                """SELECT 1 FROM audit_log
                    WHERE action='evaluation.workflow_migration_skipped'
                      AND entity_type='evaluation' AND entity_id=? LIMIT 1""",
                (str(evaluation["id"]),),
            ).fetchone()
            if not already_flagged:
                db.execute(
                    """INSERT INTO audit_log(actor_user_id,action,entity_type,entity_id,details,created_at)
                       VALUES(NULL,'evaluation.workflow_migration_skipped','evaluation',?,?,?)""",
                    (str(evaluation["id"]), json_text({"reason": "direct_manager_missing", "from_status": evaluation["status"]}), stamp),
                )
            continue

        evaluation_id = int(evaluation["id"])
        waiting_for_manager = evaluation["status"] in {"submitted", "in_review"}
        migrated_status = "submitted" if waiting_for_manager else "draft"
        current_step = 1 if waiting_for_manager else 0
        db.execute("DELETE FROM evaluation_approvals WHERE evaluation_id=?", (evaluation_id,))
        if waiting_for_manager:
            db.execute(
                """INSERT INTO evaluation_approvals
                   (evaluation_id,step_no,approver_employee_id,status,comment,decided_at,created_at)
                   VALUES(?,1,?,'pending','',NULL,?)""",
                (evaluation_id, manager_id, stamp),
            )
        db.execute(
            "UPDATE evaluation_goals SET awarded_points=NULL,updated_at=? WHERE evaluation_id=?",
            (stamp, evaluation_id),
        )
        db.execute(
            """UPDATE evaluations
                  SET workflow_version=2,status=?,manager_employee_id=?,current_step=?,
                      weighted_score=NULL,rating=NULL,finalized_at=NULL,
                      manager_report='',manager_submitted_at=NULL,hr_reviewed_by=NULL,
                      hr_comment='',disclosure_date=NULL,updated_at=?
                WHERE id=?""",
            (migrated_status, manager_id, current_step, stamp, evaluation_id),
        )
        db.execute(
            """INSERT INTO audit_log(actor_user_id,action,entity_type,entity_id,details,created_at)
               VALUES(NULL,'evaluation.workflow_migrate_v2','evaluation',?,?,?)""",
            (
                str(evaluation_id),
                json_text({
                    "from_status": evaluation["status"],
                    "to_status": migrated_status,
                    "manager_employee_id": manager_id,
                }),
                stamp,
            ),
        )


def database_direct_manager_id(db: sqlite3.Connection, employee_id: int) -> int | None:
    row = db.execute(
        """SELECT COALESCE(e.manager_id,d.manager_employee_id) AS manager_id
             FROM employees e LEFT JOIN departments d ON d.id=e.department_id
            WHERE e.id=?""",
        (employee_id,),
    ).fetchone()
    if row is None or not row["manager_id"] or int(row["manager_id"]) == employee_id:
        return None
    manager_id = int(row["manager_id"])
    return manager_id if db.execute("SELECT 1 FROM employees WHERE id=? AND active=1", (manager_id,)).fetchone() else None


def default_evaluation_cycle_dates(year: int) -> dict[str, str]:
    """Return an open UAE-calendar window that safely contains legacy work."""
    period_start = date(year, 1, 1)
    period_end = date(year, 12, 31)
    today = local_now().date()
    in_year = min(period_end, max(period_start, today))
    self_due = min(period_end, max(date(year, 10, 31), in_year + timedelta(days=30)))
    manager_due = min(period_end, self_due + timedelta(days=15))
    hr_due = min(period_end, manager_due + timedelta(days=15))
    return {
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "self_opens_on": period_start.isoformat(),
        "self_due_on": self_due.isoformat(),
        "manager_due_on": manager_due.isoformat(),
        "hr_due_on": hr_due.isoformat(),
    }


def evaluation_cycle_announcement_body(cycle: sqlite3.Row | dict[str, Any]) -> str:
    return (
        f"تم إعلان {cycle['name']}. فترة الأداء من {cycle['period_start']} إلى {cycle['period_end']}. "
        f"يفتح التقييم الذاتي في {cycle['self_opens_on']} وآخر موعد للإرسال {cycle['self_due_on']}. "
        "افتح صفحة التقييم السنوي لإكمال أهدافك وتقييمك الذاتي."
    )


def evaluation_cycle_notification_body(cycle: sqlite3.Row | dict[str, Any]) -> str:
    """Keep HR's message while guaranteeing the operational dates in every delivery."""
    body = str(cycle["announcement_body"] or "").strip()
    required_dates = (str(cycle["period_start"]), str(cycle["self_opens_on"]), str(cycle["self_due_on"]))
    if body and all(value in body for value in required_dates):
        return body
    dated_context = evaluation_cycle_announcement_body(cycle)
    return f"{body}\n\n{dated_context}" if body else dated_context


def enroll_evaluation_cycle(
    db: sqlite3.Connection,
    cycle_id: int,
    actor_user_id: int | None,
    *,
    notify: bool,
) -> dict[str, int | None]:
    cycle = db.execute("SELECT * FROM evaluation_cycles WHERE id=?", (cycle_id,)).fetchone()
    if cycle is None:
        raise ValueError("evaluation cycle not found")
    stamp = now_iso()
    created = 0
    missing_manager = 0
    recipients: list[tuple[int, int]] = []
    for employee in db.execute("SELECT id FROM employees WHERE active=1 ORDER BY id").fetchall():
        employee_id = int(employee["id"])
        manager_id = database_direct_manager_id(db, employee_id)
        if manager_id is None:
            missing_manager += 1
        cursor = db.execute(
            """INSERT OR IGNORE INTO evaluations
               (cycle_id,employee_id,workflow_version,manager_employee_id,created_at,updated_at)
               VALUES(?,?,2,?,?,?)""",
            (cycle_id, employee_id, manager_id, stamp, stamp),
        )
        created += int(cursor.rowcount > 0)
        db.execute(
            """UPDATE evaluations SET manager_employee_id=?,updated_at=?
                WHERE cycle_id=? AND employee_id=? AND status='draft'""",
            (manager_id, stamp, cycle_id, employee_id),
        )
        account = db.execute("SELECT id FROM users WHERE employee_id=? AND active=1", (employee_id,)).fetchone()
        if account:
            recipients.append((employee_id, int(account["id"])))

    notification_id = int(cycle["announcement_notification_id"]) if cycle["announcement_notification_id"] else None
    if notify and recipients:
        sender_id = actor_user_id or db.execute(
            "SELECT id FROM users WHERE active=1 ORDER BY is_super_admin DESC,id LIMIT 1"
        ).fetchone()["id"]
        for employee_id, recipient_user_id in recipients:
            already_sent = db.execute(
                "SELECT notification_id FROM evaluation_cycle_notifications WHERE cycle_id=? AND employee_id=?",
                (cycle_id, employee_id),
            ).fetchone()
            if already_sent:
                notification_id = notification_id or int(already_sent["notification_id"])
                continue
            employee_notification_id = create_internal_notification(
                db,
                int(sender_id),
                [recipient_user_id],
                str(cycle["announcement_title"] or f"إعلان {cycle['name']}"),
                evaluation_cycle_notification_body(cycle),
            )
            db.execute(
                "INSERT INTO evaluation_cycle_notifications(cycle_id,employee_id,notification_id,created_at) VALUES(?,?,?,?)",
                (cycle_id, employee_id, employee_notification_id, stamp),
            )
            notification_id = notification_id or employee_notification_id
        if cycle["announcement_notification_id"] is None and notification_id is not None:
            db.execute(
                "UPDATE evaluation_cycles SET announcement_notification_id=?,updated_at=? WHERE id=?",
                (notification_id, stamp, cycle_id),
            )
    return {
        "eligible": int(db.execute("SELECT COUNT(*) FROM employees WHERE active=1").fetchone()[0]),
        "created": created,
        "missing_manager": missing_manager,
        "notification_id": notification_id,
    }


def migrate_evaluation_cycles_v51(db: sqlite3.Connection, backfill_goals: bool) -> None:
    """Upgrade V5.0 cycles and their current goals without replacing records."""
    actor = db.execute("SELECT id FROM users WHERE active=1 ORDER BY is_super_admin DESC,id LIMIT 1").fetchone()
    actor_id = int(actor["id"]) if actor else None
    stamp = now_iso()
    legacy_cycles = db.execute(
        "SELECT * FROM evaluation_cycles WHERE period_start IS NULL OR period_start='' ORDER BY year,id"
    ).fetchall()
    for cycle in legacy_cycles:
        dates = default_evaluation_cycle_dates(int(cycle["year"]))
        status = "announced" if bool(cycle["active"]) else "closed"
        title = f"إعلان {cycle['name']}"
        values = dict(cycle) | dates | {"announcement_title": title}
        body = evaluation_cycle_announcement_body(values)
        db.execute(
            """UPDATE evaluation_cycles
                  SET period_start=?,period_end=?,self_opens_on=?,self_due_on=?,manager_due_on=?,hr_due_on=?,
                      status=?,announcement_title=?,announcement_body=?,created_by=COALESCE(created_by,?),
                      announced_by=CASE WHEN ?='announced' THEN COALESCE(announced_by,?) ELSE announced_by END,
                      announced_at=CASE WHEN ?='announced' THEN COALESCE(announced_at,?) ELSE announced_at END,
                      created_at=COALESCE(created_at,?),updated_at=?
                WHERE id=?""",
            (
                dates["period_start"], dates["period_end"], dates["self_opens_on"], dates["self_due_on"],
                dates["manager_due_on"], dates["hr_due_on"], status, title, body, actor_id,
                status, actor_id, status, stamp, stamp, stamp, cycle["id"],
            ),
        )
        if status == "announced":
            enroll_evaluation_cycle(db, int(cycle["id"]), actor_id, notify=True)
        db.execute(
            """INSERT INTO audit_log(actor_user_id,action,entity_type,entity_id,details,created_at)
               VALUES(?,'evaluation.cycle_migrate_v51','evaluation_cycle',?,?,?)""",
            (actor_id, str(cycle["id"]), json_text({"status": status, **dates}), stamp),
        )

    if backfill_goals:
        goals = db.execute(
            """SELECT g.id,g.achievement,g.employee_comment,c.period_start,c.period_end
                 FROM evaluation_goals g JOIN evaluations e ON e.id=g.evaluation_id
                 JOIN evaluation_cycles c ON c.id=e.cycle_id"""
        ).fetchall()
        for goal in goals:
            achievement = float(goal["achievement"] or 0)
            progress = "completed" if achievement >= 100 else "not_completed" if achievement <= 0 else "in_progress"
            evidence = str(goal["employee_comment"] or "").strip() or "تم ترحيل هذا الهدف من دورة سابقة."
            db.execute(
                """UPDATE evaluation_goals SET goal_type='result',start_date=?,end_date=?,
                       progress_status=?,evidence_note=?,updated_at=? WHERE id=?""",
                (goal["period_start"], goal["period_end"], progress, evidence, stamp, goal["id"]),
            )


def process_evaluation_reminders(db: sqlite3.Connection, today: date | None = None) -> int:
    """Persist and deliver due reminders once per cycle, employee and type."""
    current = today or local_now().date()
    sent = 0
    cycles = db.execute("SELECT * FROM evaluation_cycles WHERE status='announced'").fetchall()
    for cycle in cycles:
        due = date.fromisoformat(cycle["self_due_on"])
        days = (due - current).days
        reminder_type = "due_today" if days == 0 else "due_soon" if 0 < days <= 3 else "overdue" if days < 0 else None
        if reminder_type is None:
            continue
        title = {
            "due_soon": "اقترب موعد التقييم الذاتي",
            "due_today": "موعد التقييم الذاتي اليوم",
            "overdue": "تأخر إرسال التقييم الذاتي",
        }[reminder_type]
        for evaluation in db.execute(
            "SELECT id,employee_id FROM evaluations WHERE cycle_id=? AND status='draft'",
            (cycle["id"],),
        ).fetchall():
            account = db.execute("SELECT id FROM users WHERE employee_id=? AND active=1", (evaluation["employee_id"],)).fetchone()
            if account is None:
                continue
            cursor = db.execute(
                """INSERT OR IGNORE INTO evaluation_reminders
                   (cycle_id,employee_id,reminder_type,notification_id,created_by,sent_at)
                   VALUES(?,?,?,NULL,?,?)""",
                (cycle["id"], evaluation["employee_id"], reminder_type, cycle["announced_by"], now_iso()),
            )
            if cursor.rowcount == 0:
                continue
            sender_id = cycle["announced_by"] or cycle["created_by"]
            if not sender_id:
                sender = db.execute("SELECT id FROM users WHERE active=1 ORDER BY is_super_admin DESC,id LIMIT 1").fetchone()
                sender_id = sender["id"] if sender else None
            if not sender_id:
                continue
            body = (
                f"الدورة: {cycle['name']}. آخر موعد للإرسال {cycle['self_due_on']}. "
                "انتقل إلى صفحة التقييم السنوي (#evaluations) لإكمال أهدافك وتقييمك الذاتي."
            )
            notification_id = create_internal_notification(db, int(sender_id), [int(account["id"])], title, body)
            db.execute("UPDATE evaluation_reminders SET notification_id=? WHERE cycle_id=? AND employee_id=? AND reminder_type=?", (notification_id, cycle["id"], evaluation["employee_id"], reminder_type))
            sent += 1
    return sent


def initialize_database(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    schema = SCHEMA_FILE.read_text(encoding="utf-8")
    db = open_db(db_path)
    production = os.environ.get("HR_ENV", "development").strip().lower() in {"prod", "production"}
    try:
        with db:
            db.executescript(schema)
            goal_columns_before_v51 = {row["name"] for row in db.execute("PRAGMA table_info(evaluation_goals)")}
            backfill_v50_goals = "progress_status" not in goal_columns_before_v51
            migrations = {
                "organization": {
                    "general_manager_employee_id": "INTEGER",
                    "visual_identity_enabled": "INTEGER NOT NULL DEFAULT 0",
                    "visual_identity_mode": "TEXT NOT NULL DEFAULT 'static'",
                    "visual_identity_surface": "TEXT NOT NULL DEFAULT 'both'",
                    "visual_identity_interval_seconds": "INTEGER NOT NULL DEFAULT 20",
                    "visual_identity_overlay": "INTEGER NOT NULL DEFAULT 58",
                    "card_template": "TEXT NOT NULL DEFAULT 'portrait_orbit'",
                    "card_primary_color": "TEXT NOT NULL DEFAULT '#123d34'",
                    "card_accent_color": "TEXT NOT NULL DEFAULT '#c6a15b'",
                    "card_back_instructions": "TEXT NOT NULL DEFAULT 'البطاقة شخصية ولا يجوز استخدامها من غير صاحبها. عند العثور عليها يرجى التواصل مع المؤسسة.'",
                    "card_contact_phone": "TEXT NOT NULL DEFAULT ''",
                    "card_contact_email": "TEXT NOT NULL DEFAULT ''",
                    "smtp_host": "TEXT NOT NULL DEFAULT ''",
                    "smtp_port": "INTEGER NOT NULL DEFAULT 587",
                    "smtp_tls": "INTEGER NOT NULL DEFAULT 1",
                    "smtp_ssl": "INTEGER NOT NULL DEFAULT 0",
                    "smtp_username": "TEXT NOT NULL DEFAULT ''",
                    "smtp_password_encrypted": "TEXT NOT NULL DEFAULT ''",
                    "smtp_from_name": "TEXT NOT NULL DEFAULT ''",
                    "smtp_from_email": "TEXT NOT NULL DEFAULT ''",
                },
                "departments": {"branch_id": "INTEGER", "updated_at": "TEXT"},
                "employees": {
                    "job_title_id": "INTEGER", "job_grade_id": "INTEGER",
                    "gender": "TEXT NOT NULL DEFAULT 'unspecified'",
                    "qualification": "TEXT NOT NULL DEFAULT ''", "nationality": "TEXT NOT NULL DEFAULT ''",
                    "birth_date": "TEXT", "place_of_birth": "TEXT NOT NULL DEFAULT ''",
                    "passport_no": "TEXT NOT NULL DEFAULT ''", "passport_expires_on": "TEXT",
                    "emirates_id_no": "TEXT NOT NULL DEFAULT ''", "emirates_id_expires_on": "TEXT",
                    "marital_status": "TEXT NOT NULL DEFAULT 'unspecified'",
                    "address_country": "TEXT NOT NULL DEFAULT ''", "address_city": "TEXT NOT NULL DEFAULT ''",
                    "address_area": "TEXT NOT NULL DEFAULT ''", "address_street": "TEXT NOT NULL DEFAULT ''",
                    "address_building": "TEXT NOT NULL DEFAULT ''", "address_po_box": "TEXT NOT NULL DEFAULT ''",
                    "address_notes": "TEXT NOT NULL DEFAULT ''",
                    "basic_salary": "REAL NOT NULL DEFAULT 0", "housing_allowance": "REAL NOT NULL DEFAULT 0",
                    "transport_allowance": "REAL NOT NULL DEFAULT 0", "profession_allowance": "REAL NOT NULL DEFAULT 0",
                    "other_allowance": "REAL NOT NULL DEFAULT 0", "manual_allowances_json": "TEXT NOT NULL DEFAULT '[]'",
                },
                "users": {
                    "must_change_password": "INTEGER NOT NULL DEFAULT 0",
                    "is_super_admin": "INTEGER NOT NULL DEFAULT 0",
                    "last_password_change_at": "TEXT",
                },
                "sessions": {"csrf_token": "TEXT NOT NULL DEFAULT ''"},
                "salary_certificates": {
                    "verification_code": "TEXT NOT NULL DEFAULT ''",
                    "integrity_hash": "TEXT NOT NULL DEFAULT ''",
                    "verification_status": "TEXT NOT NULL DEFAULT 'valid'",
                    "verification_count": "INTEGER NOT NULL DEFAULT 0",
                    "last_verified_at": "TEXT",
                    "request_status": "TEXT NOT NULL DEFAULT 'issued'",
                    "requester_id": "INTEGER",
                    "requested_at": "TEXT",
                    "approved_by": "INTEGER",
                    "approved_at": "TEXT",
                    "decision_note": "TEXT NOT NULL DEFAULT ''",
                    "email_outbox_id": "INTEGER",
                },
                "leave_requests": {
                    "manager_employee_id": "INTEGER",
                    "manager_decision": "TEXT NOT NULL DEFAULT 'pending'",
                    "manager_comment": "TEXT NOT NULL DEFAULT ''",
                    "manager_decided_by": "INTEGER",
                    "manager_decided_at": "TEXT",
                    "start_time": "TEXT",
                    "end_time": "TEXT",
                    "hours": "REAL NOT NULL DEFAULT 0",
                },
                "leave_types": {
                    "max_hours": "REAL NOT NULL DEFAULT 0",
                },
                "evaluation_cycles": {
                    "period_start": "TEXT",
                    "period_end": "TEXT",
                    "self_opens_on": "TEXT",
                    "self_due_on": "TEXT",
                    "manager_due_on": "TEXT",
                    "hr_due_on": "TEXT",
                    "status": "TEXT NOT NULL DEFAULT 'draft'",
                    "announcement_title": "TEXT NOT NULL DEFAULT ''",
                    "announcement_body": "TEXT NOT NULL DEFAULT ''",
                    "created_by": "INTEGER",
                    "announced_by": "INTEGER",
                    "announced_at": "TEXT",
                    "announcement_notification_id": "INTEGER",
                    "extension_reason": "TEXT NOT NULL DEFAULT ''",
                    "created_at": "TEXT",
                    "updated_at": "TEXT",
                },
                "evaluations": {
                    "workflow_version": "INTEGER NOT NULL DEFAULT 1",
                    "manager_employee_id": "INTEGER",
                    "manager_report": "TEXT NOT NULL DEFAULT ''",
                    "manager_submitted_at": "TEXT",
                    "hr_reviewed_by": "INTEGER",
                    "hr_comment": "TEXT NOT NULL DEFAULT ''",
                    "disclosure_date": "TEXT",
                    "submitted_late": "INTEGER NOT NULL DEFAULT 0",
                },
                "evaluation_goals": {
                    "source_template_id": "INTEGER",
                    "awarded_points": "REAL",
                    "goal_type": "TEXT NOT NULL DEFAULT 'result'",
                    "start_date": "TEXT",
                    "end_date": "TEXT",
                    "progress_status": "TEXT NOT NULL DEFAULT 'not_completed'",
                    "evidence_note": "TEXT NOT NULL DEFAULT ''",
                },
                "notifications": {"available_at": "TEXT", "hidden_at": "TEXT", "hidden_by": "INTEGER", "edited_at": "TEXT"},
            }
            for table, columns in migrations.items():
                existing_columns = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
                for column, definition in columns.items():
                    if column not in existing_columns:
                        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            db.execute(
                """CREATE TABLE IF NOT EXISTS visual_identity_slides (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       organization_id INTEGER NOT NULL DEFAULT 1 CHECK (organization_id=1),
                       image_data TEXT,image_mime TEXT,title_ar TEXT NOT NULL DEFAULT '',title_en TEXT NOT NULL DEFAULT '',
                       alt_ar TEXT NOT NULL DEFAULT '',alt_en TEXT NOT NULL DEFAULT '',
                       focus_position TEXT NOT NULL DEFAULT 'center' CHECK (focus_position IN ('center','top','bottom','right','left')),
                       active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
                       sort_order INTEGER NOT NULL,
                       created_by INTEGER,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
                       FOREIGN KEY (organization_id) REFERENCES organization(id) ON DELETE CASCADE,
                       FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
                       UNIQUE (organization_id,sort_order))"""
            )
            # Defensive normalization for hand-edited legacy files before the
            # stricter V5.4 settings are exposed by the API.
            db.execute("UPDATE organization SET visual_identity_mode='static' WHERE visual_identity_mode NOT IN ('static','rotation')")
            db.execute("UPDATE organization SET visual_identity_surface='both' WHERE visual_identity_surface NOT IN ('login','dashboard','both')")
            db.execute("UPDATE organization SET visual_identity_interval_seconds=20 WHERE visual_identity_interval_seconds NOT BETWEEN 5 AND 300")
            db.execute("UPDATE organization SET visual_identity_overlay=58 WHERE visual_identity_overlay NOT BETWEEN 20 AND 90")
            db.execute("UPDATE employees SET marital_status='unspecified' WHERE marital_status NOT IN ('unspecified','single','married','divorced','widowed','separated')")
            # Older profiles stored one gross salary value only. Preserve that
            # value as the basic salary so the new detailed breakdown remains
            # backward-compatible and the gross total does not change.
            db.execute(
                "UPDATE employees SET basic_salary=salary WHERE COALESCE(basic_salary,0)=0 AND COALESCE(salary,0)>0 "
                "AND COALESCE(housing_allowance,0)=0 AND COALESCE(transport_allowance,0)=0 "
                "AND COALESCE(profession_allowance,0)=0 AND COALESCE(other_allowance,0)=0"
            )
            db.execute("UPDATE employees SET manual_allowances_json='[]' WHERE manual_allowances_json IS NULL OR TRIM(manual_allowances_json)=''")
            db.execute("UPDATE salary_certificates SET request_status='issued' WHERE request_status IS NULL OR request_status NOT IN ('requested','approved','rejected','issued')")
            db.execute(
                """UPDATE leave_requests
                   SET manager_employee_id=COALESCE(
                       manager_employee_id,
                       (SELECT COALESCE(e.manager_id,d.manager_employee_id)
                          FROM employees e LEFT JOIN departments d ON d.id=e.department_id
                         WHERE e.id=leave_requests.employee_id)
                   )"""
            )
            db.execute("UPDATE leave_requests SET manager_decision='approved' WHERE status='approved' AND manager_decision='pending'")
            db.execute("UPDATE leave_requests SET manager_decision='rejected' WHERE status='rejected' AND manager_decision='pending'")
            db.execute(
                """UPDATE evaluations SET manager_employee_id=COALESCE(
                       manager_employee_id,
                       (SELECT COALESCE(e.manager_id,d.manager_employee_id)
                          FROM employees e LEFT JOIN departments d ON d.id=e.department_id
                         WHERE e.id=evaluations.employee_id)
                   )"""
            )
            legacy_certificates = db.execute(
                "SELECT * FROM salary_certificates WHERE verification_code='' OR integrity_hash='' ORDER BY id"
            ).fetchall()
            for certificate in legacy_certificates:
                try:
                    issue_year = datetime.fromisoformat(certificate["issued_at"]).year
                except ValueError:
                    issue_year = local_now().year
                code = certificate["verification_code"] or new_certificate_verification_code(db, issue_year)
                values = dict(certificate)
                values["verification_code"] = code
                digest = certificate_integrity_hash(db_path, values)
                db.execute(
                    "UPDATE salary_certificates SET verification_code=?,integrity_hash=? WHERE id=?",
                    (code, digest, certificate["id"]),
                )
            db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_salary_certificates_verification_code ON salary_certificates(verification_code)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_salary_certificates_request_status ON salary_certificates(request_status, requested_at)"
            )
            # V5.8 adds a dedicated outbox kind and optional PDF attachment fields.
            # Older databases used a restrictive CHECK constraint, so rebuild that
            # small append-only table once rather than silently storing certificates
            # as campaign messages.
            outbox_schema = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='email_outbox'").fetchone()
            if outbox_schema and "salary_certificate" not in str(outbox_schema["sql"]):
                db.execute("""CREATE TABLE email_outbox_v58 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL CHECK (kind IN ('password_reset','campaign','smtp_test','salary_certificate')),
                    to_email TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','sent','failed')),
                    attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '',
                    campaign_id INTEGER, delivery_id INTEGER, user_id INTEGER,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, sent_at TEXT,
                    attachment_name TEXT, attachment_content_type TEXT, attachment_data TEXT,
                    FOREIGN KEY (campaign_id) REFERENCES email_campaigns(id) ON DELETE CASCADE,
                    FOREIGN KEY (delivery_id) REFERENCES email_deliveries(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
                )""")
                db.execute("""INSERT INTO email_outbox_v58(id,kind,to_email,subject,body,status,attempts,last_error,campaign_id,delivery_id,user_id,created_at,updated_at,sent_at)
                              SELECT id,kind,to_email,subject,body,status,attempts,last_error,campaign_id,delivery_id,user_id,created_at,updated_at,sent_at FROM email_outbox""")
                db.execute("DROP TABLE email_outbox")
                db.execute("ALTER TABLE email_outbox_v58 RENAME TO email_outbox")
                db.execute("CREATE INDEX IF NOT EXISTS idx_outbox_status ON email_outbox(status, created_at)")
            db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_evaluation_goal_template_once ON evaluation_goals(evaluation_id,source_template_id) WHERE source_template_id IS NOT NULL"
            )
            document_schema = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='employee_documents'").fetchone()
            if document_schema and "'residency'" not in str(document_schema["sql"]):
                db.execute("""CREATE TABLE employee_documents_v44 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id INTEGER NOT NULL,
                    document_type TEXT NOT NULL CHECK (document_type IN ('passport','identity','residency','visa','work_permit','contract','job_offer','qualification','professional_certificate','marriage_certificate','birth_certificate','good_conduct','medical_exam','health_insurance','driving_license','personal_photo','employee_file','undertaking','violation','bank_document','other','general')),
                    title TEXT NOT NULL, document_number TEXT NOT NULL DEFAULT '', issuer TEXT NOT NULL DEFAULT '',
                    issued_on TEXT, expires_on TEXT, no_expiry INTEGER NOT NULL DEFAULT 0 CHECK (no_expiry IN (0,1)),
                    file_name TEXT NOT NULL, mime_type TEXT NOT NULL, data_url TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '',
                    archived INTEGER NOT NULL DEFAULT 0 CHECK (archived IN (0,1)), visible_to_employee INTEGER NOT NULL DEFAULT 1 CHECK (visible_to_employee IN (0,1)),
                    uploaded_by INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT,
                    FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
                    FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE RESTRICT)""")
                db.execute("""INSERT INTO employee_documents_v44(id,employee_id,document_type,title,file_name,mime_type,data_url,visible_to_employee,uploaded_by,created_at,updated_at)
                              SELECT id,employee_id,document_type,title,file_name,mime_type,data_url,visible_to_employee,uploaded_by,created_at,created_at FROM employee_documents""")
                db.execute("DROP TABLE employee_documents")
                db.execute("ALTER TABLE employee_documents_v44 RENAME TO employee_documents")
            stamp = now_iso()
            db.execute(
                "INSERT OR IGNORE INTO organization(id,display_name,legal_name,sector,emirate,address,phone,email,website,updated_at) VALUES(1,?,?,?,?,?,?,?,?,?)",
                ("خيشة - Khaisha", "خيشة - Khaisha", "الخدمات المهنية", "دبي", "دبي، الإمارات العربية المتحدة", "+971 4 000 0000", "people@demo.ae", "https://example.ae", stamp),
            )
            # V5.2: migrate only identities shipped by older demo builds.  A tenant
            # name entered by the customer is deliberately outside this allowlist.
            db.execute(
                """UPDATE organization SET display_name='خيشة - Khaisha',updated_at=?
                     WHERE id=1 AND display_name IN ('مجموعة أفق المؤسسية','منصة موارد','موارد')""",
                (stamp,),
            )
            db.execute(
                """UPDATE organization SET legal_name='خيشة - Khaisha',updated_at=?
                     WHERE id=1 AND legal_name IN ('مجموعة أفق المؤسسية ذ.م.م','مجموعة أفق المؤسسية','منصة موارد','موارد')""",
                (stamp,),
            )
            for name in ("الإدارة العامة", "الموارد البشرية", "العمليات", "المالية"):
                db.execute("INSERT OR IGNORE INTO departments(name,created_at) VALUES(?,?)", (name, stamp))
            grade_seed = (("G-07", "الدرجة السابعة"), ("G-12", "الدرجة الثانية عشرة"), ("G-15", "الدرجة الخامسة عشرة"))
            for code, name in grade_seed:
                db.execute("INSERT OR IGNORE INTO job_grades(code,name,created_at,updated_at) VALUES(?,?,?,?)", (code, name, stamp, stamp))
            hr_dept = db.execute("SELECT id FROM departments WHERE name='الموارد البشرية'").fetchone()[0]
            ops_dept = db.execute("SELECT id FROM departments WHERE name='العمليات'").fetchone()[0]
            gm_dept = db.execute("SELECT id FROM departments WHERE name='الإدارة العامة'").fetchone()[0]
            db.execute(
                "INSERT OR IGNORE INTO branches(name,address,latitude,longitude,radius_m,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                ("المقر الرئيسي", "دبي، الإمارات العربية المتحدة", 25.204849, 55.270783, 250, 1, stamp, stamp),
            )
            branch_id = db.execute("SELECT id FROM branches WHERE name='المقر الرئيسي'").fetchone()[0]
            db.execute(
                "INSERT OR IGNORE INTO shifts(name,start_time,end_time,break_minutes,working_days,rest_days,grace_minutes,daily_limit_minutes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("الدوام الإداري", "08:00", "17:00", 60, "[0,1,2,3,4]", "[5,6]", 10, 480, stamp, stamp),
            )
            # Demo identities are local fixtures only. Never create them in a
            # production database; the first administrator is bootstrapped
            # explicitly from secret environment variables below.
            employee_seed = [] if production else [
                ("EMP-1001", "خالد المنصوري", "gm@demo.ae", "المدير العام", "G-15", gm_dept, None, 45000),
                ("EMP-1002", "مريم الهاشمي", "manager@demo.ae", "مديرة العمليات", "G-12", ops_dept, None, 28000),
                ("EMP-1003", "ليلى الحمادي", "hr@demo.ae", "مديرة الموارد البشرية", "G-12", hr_dept, None, 26000),
                ("EMP-1024", "أحمد الراشدي", "employee@demo.ae", "أخصائي عمليات", "G-07", ops_dept, None, 12000),
            ]
            employee_ids: dict[str, int] = {}
            for employee_no, name, email, title, grade, dept, manager, salary in employee_seed:
                db.execute("INSERT OR IGNORE INTO job_titles(name,department_id,created_at,updated_at) VALUES(?,?,?,?)", (title, dept, stamp, stamp))
                db.execute(
                    "INSERT OR IGNORE INTO employees(employee_no,full_name,email,job_title,job_grade,department_id,branch_id,manager_id,hire_date,salary,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (employee_no, name, email, title, grade, dept, branch_id, manager, "2023-01-01", salary, stamp, stamp),
                )
                employee_ids[employee_no] = int(db.execute("SELECT id FROM employees WHERE employee_no=?", (employee_no,)).fetchone()[0])
                title_id = db.execute("SELECT id FROM job_titles WHERE name=?", (title,)).fetchone()[0]
                grade_id = db.execute("SELECT id FROM job_grades WHERE code=?", (grade,)).fetchone()[0]
                db.execute("UPDATE employees SET job_title_id=COALESCE(job_title_id,?),job_grade_id=COALESCE(job_grade_id,?) WHERE employee_no=?", (title_id, grade_id, employee_no))
            for title_row in db.execute("SELECT id,name FROM job_titles").fetchall():
                seed_job_goal_templates(db, int(title_row["id"]), str(title_row["name"]), stamp)
            if employee_ids:
                gm_emp = employee_ids["EMP-1001"]
                manager_emp = employee_ids["EMP-1002"]
                hr_emp = employee_ids["EMP-1003"]
                regular_emp = employee_ids["EMP-1024"]
                db.execute("UPDATE employees SET manager_id=? WHERE id IN (?,?)", (gm_emp, manager_emp, hr_emp))
                db.execute("UPDATE employees SET manager_id=? WHERE id=?", (manager_emp, regular_emp))
                db.execute("UPDATE departments SET manager_employee_id=? WHERE id=?", (gm_emp, gm_dept))
                db.execute("UPDATE departments SET manager_employee_id=? WHERE id=?", (manager_emp, ops_dept))
                db.execute("UPDATE departments SET manager_employee_id=? WHERE id=?", (hr_emp, hr_dept))
                db.execute("UPDATE branches SET manager_employee_id=? WHERE id=?", (manager_emp, branch_id))
                admin_user = seed_user(db, "admin@demo.ae", "Admin@123", "مدير النظام", "admin", None)
                db.execute("UPDATE users SET is_super_admin=1 WHERE id=?", (admin_user,))
                seed_user(db, "hr@demo.ae", "HR@12345", "ليلى الحمادي", "hr", hr_emp)
                seed_user(db, "employee@demo.ae", "Emp@12345", "أحمد الراشدي", "employee", regular_emp)
                seed_user(db, "manager@demo.ae", "Manager@12345", "مريم الهاشمي", "manager", manager_emp)
                seed_user(db, "gm@demo.ae", "GM@12345", "خالد المنصوري", "general_manager", gm_emp)
                shift_id = db.execute("SELECT id FROM shifts WHERE name='الدوام الإداري'").fetchone()[0]
                for emp_id in employee_ids.values():
                    exists = db.execute("SELECT 1 FROM employee_shift_assignments WHERE employee_id=?", (emp_id,)).fetchone()
                    if not exists:
                        db.execute(
                            "INSERT INTO employee_shift_assignments(employee_id,shift_id,effective_from,created_by,created_at) VALUES(?,?,?,?,?)",
                            (emp_id, shift_id, "2023-01-01", admin_user, stamp),
                        )
            leave_seed = [
                ("annual", "إجازة سنوية", 30, 0, 0, 1, 0),
                ("sick", "إجازة مرضية", 90, 0, 1, 1, 0),
                ("maternity", "إجازة أمومة", 60, 0, 1, 1, 0),
                ("parental", "إجازة والدية", 5, 0, 1, 1, 0),
                ("bereavement", "إجازة حداد", 5, 0, 1, 1, 0),
                ("study", "إجازة دراسية", 10, 7, 1, 1, 0),
                ("unpaid", "إجازة بدون راتب", 0, 7, 0, 0, 0),
                ("work_permission", "ترخيص خلال ساعات العمل (حتى ساعتين)", 0, 0, 0, 1, 2),
            ]
            for values in leave_seed:
                db.execute("INSERT OR IGNORE INTO leave_types(code,name,annual_entitlement,min_notice_days,requires_attachment,paid,max_hours) VALUES(?,?,?,?,?,?,?)", values)
            current_year = local_now().year
            for emp_id in employee_ids.values():
                for leave in db.execute("SELECT id,annual_entitlement FROM leave_types WHERE active=1").fetchall():
                    db.execute(
                        "INSERT OR IGNORE INTO leave_balances(employee_id,leave_type_id,year,entitlement) VALUES(?,?,?,?)",
                        (emp_id, leave["id"], current_year, leave["annual_entitlement"]),
                    )
            if production and db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
                bootstrap_email = os.environ.get("HR_BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
                bootstrap_password = os.environ.get("HR_BOOTSTRAP_ADMIN_PASSWORD", "")
                bootstrap_name = os.environ.get("HR_BOOTSTRAP_ADMIN_NAME", "مدير النظام").strip() or "مدير النظام"
                if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", bootstrap_email):
                    raise RuntimeError("Production database has no users. Set HR_BOOTSTRAP_ADMIN_EMAIL to a valid email address for the first start.")
                if not bootstrap_password:
                    raise RuntimeError("Production database has no users. Set HR_BOOTSTRAP_ADMIN_PASSWORD for the first start.")
                try:
                    validate_password_strength(bootstrap_password)
                except APIError as exc:
                    raise RuntimeError(f"HR_BOOTSTRAP_ADMIN_PASSWORD is too weak: {exc.message}") from exc
                bootstrap_id = seed_user(db, bootstrap_email, bootstrap_password, bootstrap_name, "admin", None)
                db.execute("UPDATE users SET is_super_admin=1 WHERE id=?", (bootstrap_id,))
            db.execute(
                "INSERT OR IGNORE INTO evaluation_cycles(year,name,starts_on,ends_on,active) VALUES(?,?,?,?,1)",
                (current_year, f"تقييم الأداء {current_year}", f"{current_year}-01-01", f"{current_year}-12-31"),
            )
            migrate_evaluation_cycles_v51(db, backfill_v50_goals)
            migrate_nonterminal_legacy_evaluations(db)
            refresh_legacy_generated_contracts(db)
            process_evaluation_reminders(db)
    finally:
        db.close()


def is_configured_general_manager(db: sqlite3.Connection, user: dict[str, Any]) -> bool:
    keys = user.keys() if hasattr(user, "keys") else user
    active = user["active"] if "active" in keys else True
    employee_id = user["employee_id"] if "employee_id" in keys else None
    if not bool(active) or employee_id is None:
        return False
    row = db.execute("SELECT general_manager_employee_id FROM organization WHERE id=1").fetchone()
    return bool(row and row["general_manager_employee_id"] and int(row["general_manager_employee_id"]) == int(employee_id))


def has_permission(db: sqlite3.Connection, user: dict[str, Any], permission: str) -> bool:
    if bool(user.get("is_super_admin")) and user.get("role") == "admin" and bool(user.get("active", True)):
        return True
    if is_configured_general_manager(db, user):
        return True
    override = db.execute("SELECT granted FROM user_permissions WHERE user_id=? AND permission=?", (user["id"], permission)).fetchone()
    if override is not None:
        return bool(override["granted"])
    base = ROLE_PERMISSIONS.get(str(user["role"]), set())
    return "*" in base or permission in base


def effective_permissions(db: sqlite3.Connection, user: dict[str, Any]) -> tuple[list[str], dict[str, str]]:
    if bool(user.get("is_super_admin")) and user.get("role") == "admin" and bool(user.get("active", True)):
        values = sorted(ALL_PERMISSIONS | {"*"})
        return values, {permission: "protected_super_admin" for permission in values}
    if is_configured_general_manager(db, user):
        values = sorted(ALL_PERMISSIONS | {"*"})
        return values, {permission: "configured_general_manager" for permission in values}
    base = ROLE_PERMISSIONS.get(str(user.get("role")), set())
    granted = set(ALL_PERMISSIONS if "*" in base else base)
    reasons = {permission: f"role:{user.get('role')}" for permission in granted}
    for item in db.execute("SELECT permission,granted FROM user_permissions WHERE user_id=?", (user["id"],)):
        if bool(item["granted"]):
            granted.add(item["permission"]); reasons[item["permission"]] = "explicit_grant"
        else:
            granted.discard(item["permission"]); reasons[item["permission"]] = "explicit_deny"
    return sorted(granted), reasons


def audit(db: sqlite3.Connection, actor_id: int | None, action: str, entity_type: str, entity_id: Any, details: Any = None) -> None:
    db.execute(
        "INSERT INTO audit_log(actor_user_id,action,entity_type,entity_id,details,created_at) VALUES(?,?,?,?,?,?)",
        (actor_id, action, entity_type, str(entity_id) if entity_id is not None else None, json_text(details or {}), now_iso()),
    )


def create_internal_notification(
    db: sqlite3.Connection,
    sender_user_id: int,
    recipient_user_ids: list[int] | set[int],
    title: str,
    body: str,
    available_at: str | None = None,
) -> int | None:
    recipients = sorted({int(value) for value in recipient_user_ids if int(value) > 0})
    if not recipients:
        return None
    stamp = now_iso()
    cursor = db.execute(
        "INSERT INTO notifications(sender_user_id,title,body,message_type,audience_type,audience_ref,available_at,created_at) VALUES(?,?,?,'notice','employees',?,?,?)",
        (sender_user_id, title, body, json_text(recipients), available_at, stamp),
    )
    notification_id = int(cursor.lastrowid)
    db.executemany(
        "INSERT INTO notification_recipients(notification_id,user_id) VALUES(?,?)",
        [(notification_id, recipient_id) for recipient_id in recipients],
    )
    return notification_id


def ensure_document_expiry_notifications(db: sqlite3.Connection) -> int:
    """Create one HR inbox alert per document expiry date within the next 90 days."""
    hr_users = db.execute(
        "SELECT id,display_name FROM users WHERE role='hr' AND active=1 ORDER BY id"
    ).fetchall()
    if not hr_users:
        return 0
    sender_id = int(hr_users[0]["id"])
    recipients = [int(row["id"]) for row in hr_users]
    today = local_now().date()
    expiry_limit = today + timedelta(days=90)
    documents = db.execute(
        """SELECT d.id,d.document_type,d.title,d.expires_on,e.full_name,e.employee_no
             FROM employee_documents d
             JOIN employees e ON e.id=d.employee_id
            WHERE e.active=1 AND d.archived=0 AND d.no_expiry=0
              AND d.expires_on BETWEEN ? AND ?
            ORDER BY d.expires_on ASC,d.id ASC""",
        (today.isoformat(), expiry_limit.isoformat()),
    ).fetchall()
    created = 0
    for document in documents:
        with db:
            marker = db.execute(
                "INSERT OR IGNORE INTO document_expiry_alerts(document_id,expires_on,created_at) VALUES(?,?,?)",
                (document["id"], document["expires_on"], now_iso()),
            )
            if marker.rowcount != 1:
                continue
            days_remaining = (date.fromisoformat(document["expires_on"]) - today).days
            document_label = DOCUMENT_TYPE_LABELS_AR.get(document["document_type"], document["title"] or "وثيقة")
            title = "تنبيه: وثيقة تقترب من الانتهاء"
            if document["document_type"] == "contract":
                title = "تنبيه: عقد العمل يقترب من الانتهاء"
            body = (
                f"الموظف: {document['full_name']} ({document['employee_no']}). "
                f"الوثيقة: {document_label}. تاريخ الانتهاء: {document['expires_on']} "
                f"(متبقٍ {days_remaining} يوماً). يرجى اتخاذ الإجراء قبل انتهاء الصلاحية."
            )
            notification_id = create_internal_notification(db, sender_id, recipients, title, body)
            db.execute(
                "UPDATE document_expiry_alerts SET notification_id=? WHERE document_id=? AND expires_on=?",
                (notification_id, document["id"], document["expires_on"]),
            )
            audit(db, sender_id, "notification.document_expiry", "employee_document", document["id"], {"expires_on": document["expires_on"], "days_remaining": days_remaining, "notification_id": notification_id})
            created += 1
    return created


def public_user(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    data = {
        "id": row["id"], "email": row["email"], "name": row["display_name"],
        "role": row["role"], "employee_id": row["employee_id"], "active": bool(row["active"]),
    }
    keys = row.keys() if hasattr(row, "keys") else row
    data["must_change_password"] = bool(row["must_change_password"]) if "must_change_password" in keys else False
    data["is_super_admin"] = bool(row["is_super_admin"]) if "is_super_admin" in keys else False
    return data


def serialize_org(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data.pop("id", None)
    for key in ("smtp_host", "smtp_port", "smtp_tls", "smtp_ssl", "smtp_username", "smtp_password_encrypted", "smtp_from_name", "smtp_from_email"):
        data.pop(key, None)
    return data


def visual_identity_slide_payload(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["active"] = bool(data.get("active"))
    data.pop("organization_id", None)
    data.pop("created_by", None)
    image_data = str(data.get("image_data") or "")
    if image_data and "," in image_data:
        try:
            data["image_bytes"] = len(base64.b64decode(image_data.split(",", 1)[1], validate=True))
        except ValueError:
            data["image_bytes"] = 0
    else:
        data["image_bytes"] = 0
    return data


def visual_identity_payload(db: sqlite3.Connection, organization: sqlite3.Row, admin: bool = False) -> dict[str, Any]:
    enabled = bool(organization["visual_identity_enabled"])
    mode = str(organization["visual_identity_mode"] or "static")
    payload = {
        "enabled": enabled,
        "mode": mode,
        "surface": str(organization["visual_identity_surface"] or "both"),
        "interval_seconds": int(organization["visual_identity_interval_seconds"] or 20),
        "overlay": int(organization["visual_identity_overlay"] or 58),
        "slides": [],
    }
    if admin:
        rows = db.execute("SELECT * FROM visual_identity_slides WHERE organization_id=1 ORDER BY sort_order,id").fetchall()
    elif enabled:
        limit = " LIMIT 1" if mode == "static" else ""
        rows = db.execute(
            "SELECT * FROM visual_identity_slides WHERE organization_id=1 AND active=1 ORDER BY sort_order,id" + limit
        ).fetchall()
    else:
        rows = []
    payload["slides"] = [visual_identity_slide_payload(row) for row in rows]
    return payload


EMPLOYEE_SENSITIVE_FIELDS = (
    "birth_date", "place_of_birth", "passport_no", "passport_expires_on",
    "emirates_id_no", "emirates_id_expires_on", "marital_status",
    "address_country", "address_city", "address_area", "address_street",
    "address_building", "address_po_box", "address_notes",
)

SALARY_COMPONENT_FIELDS = (
    "basic_salary", "housing_allowance", "transport_allowance",
    "profession_allowance", "other_allowance",
)


def normalize_manual_allowances(value: Any) -> list[dict[str, Any]]:
    """Return safe, printable custom salary allowance rows."""
    raw = value
    if isinstance(raw, str):
        raw = parse_json_text(raw, [])
    if not isinstance(raw, list):
        return []
    result: list[dict[str, Any]] = []
    for item in raw[:20]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("label") or "").strip()[:120]
        if not name:
            continue
        try:
            amount = float(item.get("amount") or 0)
        except (TypeError, ValueError):
            continue
        if amount < 0 or amount > 100_000_000:
            continue
        result.append({"name": name, "amount": round(amount, 2)})
    return result


def salary_breakdown_from_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """Build a consistent salary breakdown and gross total from an employee row."""
    data = dict(row) if isinstance(row, sqlite3.Row) else row
    components = {
        "basic_salary": round(float(data.get("basic_salary") or 0), 2),
        "housing_allowance": round(float(data.get("housing_allowance") or 0), 2),
        "transport_allowance": round(float(data.get("transport_allowance") or 0), 2),
        "profession_allowance": round(float(data.get("profession_allowance") or 0), 2),
        "other_allowance": round(float(data.get("other_allowance") or 0), 2),
    }
    manual = normalize_manual_allowances(data.get("manual_allowances_json", data.get("manual_allowances", [])))
    custom_total = round(sum(item["amount"] for item in manual), 2)
    total = round(sum(components.values()) + custom_total, 2)
    lines = [
        {"code": "basic_salary", "name": "الراتب الأساسي", "name_en": "Basic salary", "amount": components["basic_salary"]},
        {"code": "housing_allowance", "name": "بدل السكن", "name_en": "Housing allowance", "amount": components["housing_allowance"]},
        {"code": "transport_allowance", "name": "بدل المواصلات", "name_en": "Transport allowance", "amount": components["transport_allowance"]},
        {"code": "profession_allowance", "name": "بدل طبيعة مهنة", "name_en": "Profession allowance", "amount": components["profession_allowance"]},
        {"code": "other_allowance", "name": "بدل آخر", "name_en": "Other allowance", "amount": components["other_allowance"]},
    ]
    lines.extend({"code": "manual", "name": item["name"], "name_en": item["name"], "amount": item["amount"]} for item in manual)
    return {
        **components,
        "manual_allowances": manual,
        "custom_allowances_total": custom_total,
        "allowances_total": round(sum(components[key] for key in SALARY_COMPONENT_FIELDS if key != "basic_salary") + custom_total, 2),
        "total": total,
        "lines": lines,
    }


def employee_query(include_salary: bool = True, include_sensitive: bool = False) -> str:
    salary = "e.salary" if include_salary else "NULL AS salary"
    salary_components = ",e.basic_salary,e.housing_allowance,e.transport_allowance,e.profession_allowance,e.other_allowance,e.manual_allowances_json" if include_salary else ",NULL AS basic_salary,NULL AS housing_allowance,NULL AS transport_allowance,NULL AS profession_allowance,NULL AS other_allowance,NULL AS manual_allowances_json"
    sensitive = "," + ",".join(f"e.{field}" for field in EMPLOYEE_SENSITIVE_FIELDS) if include_sensitive else ""
    emergency_count = "," + "(SELECT COUNT(*) FROM employee_emergency_contacts ec WHERE ec.employee_id=e.id AND ec.archived=0) AS emergency_contact_count" if include_sensitive else ""
    return f"""
        SELECT e.id,e.employee_no,e.full_name,e.email,e.phone,e.gender,
               COALESCE(jt.name,e.job_title) AS job_title,COALESCE(jg.code,e.job_grade) AS job_grade,
               e.job_title_id,e.job_grade_id,jg.name AS job_grade_name,
               e.department_id,d.name AS department_name,e.branch_id,b.name AS branch_name,
               e.manager_id,m.full_name AS manager_name,e.hire_date,e.qualification,e.nationality,{salary}{salary_components},e.photo_data,e.active{sensitive}{emergency_count},
               (SELECT ed.issued_on FROM employee_documents ed WHERE ed.employee_id=e.id AND ed.document_type='contract' AND ed.archived=0 ORDER BY ed.expires_on DESC,ed.id DESC LIMIT 1) AS contract_start_on,
               (SELECT ed.expires_on FROM employee_documents ed WHERE ed.employee_id=e.id AND ed.document_type='contract' AND ed.archived=0 ORDER BY ed.expires_on DESC,ed.id DESC LIMIT 1) AS contract_end_on,
               e.created_at,e.updated_at,
               (SELECT COUNT(*) FROM employee_documents ed WHERE ed.employee_id=e.id) AS document_count,
               (SELECT COUNT(*) FROM employee_actions ea WHERE ea.employee_id=e.id AND ea.action_type='violation') AS violation_count,
               (SELECT COUNT(*) FROM employee_actions ea WHERE ea.employee_id=e.id AND ea.action_type='undertaking') AS undertaking_count
        FROM employees e
        LEFT JOIN departments d ON d.id=e.department_id
        LEFT JOIN branches b ON b.id=e.branch_id
        LEFT JOIN employees m ON m.id=e.manager_id
        LEFT JOIN job_titles jt ON jt.id=e.job_title_id
        LEFT JOIN job_grades jg ON jg.id=e.job_grade_id
    """


def organization_employee_query() -> str:
    """Return the small, non-sensitive employee projection used by org views.

    The organization chart can contain every employee in the tenant. Reusing
    ``employee_query`` here used to include salary fields and the full
    ``photo_data`` data URL for every person, which made a large chart consume
    excessive browser memory while parsing JSON. The chart only needs
    identity, placement and reporting fields, so keep this projection narrow.
    """
    return """
        SELECT e.id,e.employee_no,e.full_name,e.gender,
               COALESCE(jt.name,e.job_title) AS job_title,
               COALESCE(jg.code,e.job_grade) AS job_grade,
               e.job_title_id,e.job_grade_id,jg.name AS job_grade_name,
               e.department_id,d.name AS department_name,
               e.branch_id,b.name AS branch_name,
               e.manager_id,m.full_name AS manager_name,
               e.hire_date,e.active,e.updated_at
        FROM employees e
        LEFT JOIN departments d ON d.id=e.department_id
        LEFT JOIN branches b ON b.id=e.branch_id
        LEFT JOIN employees m ON m.id=e.manager_id
        LEFT JOIN job_titles jt ON jt.id=e.job_title_id
        LEFT JOIN job_grades jg ON jg.id=e.job_grade_id
    """


def normalize_employee(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    data = dict(row)
    data["active"] = bool(data["active"])
    if "basic_salary" in data and data.get("basic_salary") is not None:
        breakdown = salary_breakdown_from_row(data)
        data["salary_breakdown"] = breakdown
        data["salary_total"] = breakdown["total"]
        # Keep the legacy field as the canonical gross salary for existing
        # payroll/certificate consumers while making the detailed lines public.
        if data.get("salary") is not None:
            data["salary"] = breakdown["total"]
    if "birth_date" in data:
        data["age_years"] = None
        if data.get("birth_date"):
            try:
                born = date.fromisoformat(str(data["birth_date"]))
                today = local_now().date()
                data["age_years"] = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
            except ValueError:
                data["age_years"] = None
        completeness_fields = (
            "full_name", "photo_data", "employee_no", "email", "phone", "birth_date", "nationality",
            "passport_no", "emirates_id_no", "qualification", "job_title", "job_grade",
            "department_id", "branch_id", "manager_id", "hire_date", "address_country", "address_city",
            "emergency_contact_count",
        )
        filled = sum(bool(data.get(field)) for field in completeness_fields)
        data["profile_completeness"] = {
            "percent": round((filled / len(completeness_fields)) * 100),
            "filled": filled,
            "total": len(completeness_fields),
            "missing": [field for field in completeness_fields if not data.get(field)],
        }
    if data.get("hire_date"):
        try:
            service_days=max(0,(local_now().date()-date.fromisoformat(data["hire_date"])).days)
            data["service_days"]=service_days; data["service_years"]=round(service_days/365.2425,1)
        except ValueError:
            data["service_days"]=None; data["service_years"]=None
    return data


def make_handler(db_path: Path, static_root: Path = APP_DIR) -> type[BaseHTTPRequestHandler]:
    class HRHandler(BaseHTTPRequestHandler):
        server_version = f"KhaishaHR/{APP_VERSION}"
        protocol_version = "HTTP/1.1"

        def setup(self) -> None:
            super().setup()
            self.db = open_db(db_path)
            self._user: dict[str, Any] | None | bool = False

        def finish(self) -> None:
            try:
                self.db.close()
            finally:
                super().finish()

        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

        def end_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header("Permissions-Policy", "geolocation=(self)")
            self.send_header("Cache-Control", "no-store" if self.path.startswith("/api/") else "no-cache")
            super().end_headers()

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self.send_header("Allow", "GET, HEAD, POST, PATCH, DELETE, OPTIONS")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_HEAD(self) -> None:
            self._dispatch("HEAD")

        def do_GET(self) -> None:
            self._dispatch("GET")

        def do_POST(self) -> None:
            self._dispatch("POST")

        def do_PATCH(self) -> None:
            self._dispatch("PATCH")

        def do_DELETE(self) -> None:
            self._dispatch("DELETE")

        def _dispatch(self, method: str) -> None:
            # A BaseHTTPRequestHandler instance serves every request carried by
            # one HTTP/1.1 keep-alive connection. Authentication must therefore
            # be resolved anew from the cookie for each request, not cached for
            # the lifetime of the TCP connection.
            self._user = False
            try:
                parsed = urlsplit(self.path)
                path = parsed.path.rstrip("/") or "/"
                self.query = {k: v[-1] for k, v in parse_qs(parsed.query).items() if v}
                if not path.startswith("/api/") and path != "/api":
                    if method not in ("GET", "HEAD"):
                        raise APIError(405, "الطريقة غير مسموحة.", "method_not_allowed")
                    return self.serve_static(path, head=(method == "HEAD"))

                if method in {"POST", "PATCH", "DELETE"} and path not in {
                    "/api/auth/login", "/api/auth/forgot-password", "/api/auth/reset-password",
                    "/api/auth/reset-password/validate",
                }:
                    session_user = self.current_user(False)
                    if session_user is not None:
                        expected_csrf = str(session_user.get("csrf_token") or "")
                        supplied_csrf = self.headers.get("X-CSRF-Token", "")
                        if not expected_csrf or not hmac.compare_digest(expected_csrf, supplied_csrf):
                            raise APIError(403, "رمز حماية الطلب غير صالح. حدّث الصفحة وحاول مجدداً.", "csrf_failed")
                request_user = self.current_user(False)
                password_gate_paths = {
                    "/api/health", "/api/org", "/api/auth/login", "/api/auth/logout", "/api/auth/me",
                    "/api/auth/change-password", "/api/auth/forgot-password", "/api/auth/reset-password",
                    "/api/auth/reset-password/validate",
                }
                if request_user and bool(request_user.get("must_change_password")) and path not in password_gate_paths:
                    raise APIError(428, "يجب تغيير كلمة المرور المؤقتة قبل متابعة العمل.", "password_change_required")
                if request_user:
                    with self.db:
                        process_evaluation_reminders(self.db)

                routes: list[tuple[str, str, Callable[..., Any]]] = [
                    ("GET", r"/api/health", self.api_health),
                    ("POST", r"/api/auth/login", self.api_login),
                    ("POST", r"/api/auth/logout", self.api_logout),
                    ("GET", r"/api/auth/me", self.api_auth_me),
                    ("POST", r"/api/auth/change-password", self.api_change_password),
                    ("POST", r"/api/auth/forgot-password", self.api_forgot_password),
                    ("POST", r"/api/auth/reset-password/validate", self.api_reset_password_validate),
                    ("POST", r"/api/auth/reset-password", self.api_reset_password),
                    ("GET", r"/api/dashboard", self.api_executive_dashboard),
                    ("GET", r"/api/org/grid", self.api_org_grid),
                    ("GET", r"/api/admin/permissions/catalog", self.api_permission_catalog),
                    ("GET", r"/api/admin/users", self.api_admin_users),
                    ("PATCH", r"/api/admin/users/(\d+)", self.api_admin_user_patch),
                    ("GET", r"/api/admin/users/(\d+)/permissions", self.api_user_permissions_get),
                    ("PATCH", r"/api/admin/users/(\d+)/permissions", self.api_user_permissions_patch),
                    ("POST", r"/api/admin/users/(\d+)/reset-password", self.api_admin_password_reset),
                    ("GET", r"/api/admin/smtp", self.api_smtp_get),
                    ("PATCH", r"/api/admin/smtp", self.api_smtp_patch),
                    ("POST", r"/api/admin/smtp/test", self.api_smtp_test),
                    ("GET", r"/api/admin/outbox", self.api_outbox_get),
                    ("GET", r"/api/communications/campaigns", self.api_campaigns_get),
                    ("POST", r"/api/communications/campaigns", self.api_campaign_post),
                    ("GET", r"/api/communications/campaigns/(\d+)", self.api_campaign_get),
                    ("POST", r"/api/communications/campaigns/(\d+)/retry", self.api_campaign_retry),
                    ("GET", r"/api/org/visual-identity", self.api_visual_identity_admin_get),
                    ("PATCH", r"/api/org/visual-identity", self.api_visual_identity_settings_patch),
                    ("POST", r"/api/org/visual-identity/slides", self.api_visual_identity_slide_post),
                    ("PATCH", r"/api/org/visual-identity/slides/order", self.api_visual_identity_order_patch),
                    ("PATCH", r"/api/org/visual-identity/slides/(\d+)", self.api_visual_identity_slide_patch),
                    ("DELETE", r"/api/org/visual-identity/slides/(\d+)", self.api_visual_identity_slide_delete),
                    ("GET", r"/api/org", self.api_org_get),
                    ("PATCH", r"/api/org", self.api_org_patch),
                    ("GET", r"/api/departments", self.api_departments),
                    ("POST", r"/api/departments", self.api_department_post),
                    ("PATCH", r"/api/departments/(\d+)", self.api_department_patch),
                    ("DELETE", r"/api/departments/(\d+)", self.api_department_delete),
                    ("POST", r"/api/departments/(\d+)/assign", self.api_department_assign),
                    ("GET", r"/api/org/hierarchy", self.api_org_hierarchy),
                    ("GET", r"/api/job-grades", self.api_job_grades_get),
                    ("POST", r"/api/job-grades", self.api_job_grades_post),
                    ("PATCH", r"/api/job-grades/(\d+)", self.api_job_grade_patch),
                    ("DELETE", r"/api/job-grades/(\d+)", self.api_job_grade_delete),
                    ("GET", r"/api/job-titles", self.api_job_titles_get),
                    ("POST", r"/api/job-titles", self.api_job_titles_post),
                    ("PATCH", r"/api/job-titles/(\d+)", self.api_job_title_patch),
                    ("DELETE", r"/api/job-titles/(\d+)", self.api_job_title_delete),
                    ("GET", r"/api/branches", self.api_branches_get),
                    ("POST", r"/api/branches", self.api_branches_post),
                    ("GET", r"/api/branches/(\d+)", self.api_branch_get),
                    ("PATCH", r"/api/branches/(\d+)", self.api_branch_patch),
                    ("DELETE", r"/api/branches/(\d+)", self.api_branch_delete),
                    ("POST", r"/api/branches/(\d+)/assign", self.api_branch_assign),
                    ("POST", r"/api/branches/(\d+)/location-test", self.api_branch_location_test),
                    ("GET", r"/api/employees", self.api_employees_get),
                    ("POST", r"/api/employees", self.api_employees_post),
                    ("GET", r"/api/employee-reports/search", self.api_employee_report_search),
                    ("POST", r"/api/employees/(\d+)/comprehensive-report", self.api_employee_report_generate),
                    ("POST", r"/api/employees/(\d+)/comprehensive-report/export", self.api_employee_report_export),
                    ("GET", r"/api/employees/(\d+)", self.api_employee_get),
                    ("PATCH", r"/api/employees/(\d+)", self.api_employee_patch),
                    ("GET", r"/api/employees/(\d+)/emergency-contacts", self.api_employee_emergency_contacts_get),
                    ("POST", r"/api/employees/(\d+)/emergency-contacts", self.api_employee_emergency_contact_post),
                    ("PATCH", r"/api/emergency-contacts/(\d+)", self.api_employee_emergency_contact_patch),
                    ("DELETE", r"/api/emergency-contacts/(\d+)", self.api_employee_emergency_contact_delete),
                    ("GET", r"/api/languages/catalog", self.api_language_catalog),
                    ("GET", r"/api/employees/(\d+)/languages", self.api_employee_languages_get),
                    ("PATCH", r"/api/employees/(\d+)/languages", self.api_employee_languages_patch),
                    ("GET", r"/api/employees/(\d+)/documents", self.api_employee_documents_get),
                    ("POST", r"/api/employees/(\d+)/documents", self.api_employee_documents_post),
                    ("GET", r"/api/documents/(\d+)", self.api_document_get),
                    ("PATCH", r"/api/documents/(\d+)", self.api_document_patch),
                    ("DELETE", r"/api/documents/(\d+)", self.api_document_delete),
                    ("GET", r"/api/employees/(\d+)/actions", self.api_employee_actions_get),
                    ("POST", r"/api/employees/(\d+)/actions", self.api_employee_actions_post),
                    ("GET", r"/api/employees/(\d+)/custody", self.api_employee_custody_get),
                    ("POST", r"/api/employees/(\d+)/custody", self.api_employee_custody_post),
                    ("PATCH", r"/api/employee-actions/(\d+)", self.api_employee_action_patch),
                    ("PATCH", r"/api/employee-custody/(\d+)", self.api_employee_custody_patch),
                    ("POST", r"/api/employee-custody/(\d+)/print", self.api_employee_custody_print),
                    ("GET", r"/api/employees/(\d+)/card", self.api_employee_card),
                    ("POST", r"/api/employees/(\d+)/card/print", self.api_employee_card_print),
                    ("GET", r"/api/cards/verify/([A-Za-z0-9-]+)", self.api_card_verify),
                    ("GET", r"/api/me/card", self.api_my_card),
                    ("GET", r"/api/me/dashboard", self.api_my_dashboard),
                    ("POST", r"/api/attendance/punch", self.api_attendance_punch),
                    ("GET", r"/api/attendance/daily", self.api_attendance_daily),
                    ("GET", r"/api/attendance/range", self.api_attendance_range),
                    ("GET", r"/api/attendance/range\.csv", self.api_attendance_range_csv),
                    ("GET", r"/api/shifts", self.api_shifts_get),
                    ("POST", r"/api/shifts", self.api_shifts_post),
                    ("PATCH", r"/api/shifts/(\d+)", self.api_shift_patch),
                    ("DELETE", r"/api/shifts/(\d+)", self.api_shift_delete),
                    ("POST", r"/api/shifts/(\d+)/assign", self.api_shift_assign),
                    ("GET", r"/api/overtime", self.api_overtime_get),
                    ("POST", r"/api/overtime", self.api_overtime_post),
                    ("POST", r"/api/overtime/(\d+)/decision", self.api_overtime_decision),
                    ("GET", r"/api/leaves/types", self.api_leave_types),
                    ("GET", r"/api/leaves/holidays", self.api_leave_holidays_get),
                    ("POST", r"/api/leaves/holidays", self.api_leave_holiday_post),
                    ("PATCH", r"/api/leaves/holidays/(\d+)", self.api_leave_holiday_patch),
                    ("DELETE", r"/api/leaves/holidays/(\d+)", self.api_leave_holiday_delete),
                    ("GET", r"/api/leaves/balances", self.api_leave_balances),
                    ("GET", r"/api/leaves/requests", self.api_leave_requests_get),
                    ("POST", r"/api/leaves/requests", self.api_leave_requests_post),
                    ("POST", r"/api/leaves/requests/(\d+)/decision", self.api_leave_request_decision),
                    ("GET", r"/api/leaves/sales", self.api_leave_sales_get),
                    ("POST", r"/api/leaves/sales", self.api_leave_sales_post),
                    ("POST", r"/api/leaves/sales/(\d+)/decision", self.api_leave_sale_decision),
                    ("GET", r"/api/evaluation-cycles", self.api_evaluation_cycles_get),
                    ("POST", r"/api/evaluation-cycles", self.api_evaluation_cycle_post),
                    ("GET", r"/api/evaluation-cycles/(\d+)", self.api_evaluation_cycle_get),
                    ("PATCH", r"/api/evaluation-cycles/(\d+)", self.api_evaluation_cycle_patch),
                    ("POST", r"/api/evaluation-cycles/(\d+)/announce", self.api_evaluation_cycle_announce),
                    ("POST", r"/api/evaluation-cycles/(\d+)/reminders", self.api_evaluation_cycle_reminders),
                    ("GET", r"/api/evaluations", self.api_evaluations_get),
                    ("POST", r"/api/evaluations", self.api_evaluations_post),
                    ("GET", r"/api/evaluations/history", self.api_evaluation_history),
                    ("GET", r"/api/employees/(\d+)/evaluations/history", self.api_employee_evaluation_history),
                    ("GET", r"/api/evaluation-goal-templates", self.api_evaluation_goal_templates_get),
                    ("POST", r"/api/evaluation-goal-templates", self.api_evaluation_goal_template_post),
                    ("PATCH", r"/api/evaluation-goal-templates/(\d+)", self.api_evaluation_goal_template_patch),
                    ("GET", r"/api/evaluations/(\d+)", self.api_evaluation_get),
                    ("POST", r"/api/evaluations/(\d+)/goals", self.api_evaluation_goal_post),
                    ("POST", r"/api/evaluations/(\d+)/goals/from-templates", self.api_evaluation_goals_from_templates),
                    ("PATCH", r"/api/evaluation-goals/(\d+)", self.api_evaluation_goal_patch),
                    ("DELETE", r"/api/evaluation-goals/(\d+)", self.api_evaluation_goal_delete),
                    ("POST", r"/api/evaluations/(\d+)/submit", self.api_evaluation_submit),
                    ("POST", r"/api/evaluations/(\d+)/decision", self.api_evaluation_decision),
                    ("POST", r"/api/evaluations/(\d+)/manager-review", self.api_evaluation_manager_review),
                    ("POST", r"/api/evaluations/(\d+)/hr-review", self.api_evaluation_hr_review),
                    ("POST", r"/api/evaluations/(\d+)/grievance", self.api_evaluation_grievance_post),
                    ("POST", r"/api/evaluation-grievances/(\d+)/resolve", self.api_evaluation_grievance_resolve),
                    ("GET", r"/api/notifications/manage", self.api_notification_manage_get),
                    ("GET", r"/api/notifications/inbox", self.api_notification_inbox),
                    ("GET", r"/api/notifications/unread-count", self.api_notification_unread_count),
                    ("POST", r"/api/notifications", self.api_notification_send),
                    ("GET", r"/api/notifications/(\d+)", self.api_notification_get),
                    ("PATCH", r"/api/notifications/(\d+)", self.api_notification_patch),
                    ("POST", r"/api/notifications/(\d+)/read", self.api_notification_read),
                    ("POST", r"/api/notifications/read-all", self.api_notification_read_all),
                    ("POST", r"/api/salary-certificates", self.api_certificate_post),
                    ("POST", r"/api/salary-certificates/request", self.api_certificate_request_post),
                    ("GET", r"/api/salary-certificates/requests", self.api_certificate_requests_get),
                    ("GET", r"/api/salary-certificates/history", self.api_certificate_history_get),
                    ("POST", r"/api/salary-certificates/verify", self.api_certificate_verify),
                    ("GET", r"/api/salary-certificates/(\d+)", self.api_certificate_get),
                    ("POST", r"/api/salary-certificates/(\d+)/print", self.api_certificate_print),
                    ("POST", r"/api/salary-certificates/(\d+)/decision", self.api_certificate_request_decision),
                    ("GET", r"/api/payroll/runs", self.api_payroll_runs_get),
                    ("POST", r"/api/payroll/runs", self.api_payroll_runs_post),
                    ("GET", r"/api/payroll/runs/(\d+)", self.api_payroll_run_get),
                    ("POST", r"/api/payroll/runs/(\d+)/transition", self.api_payroll_transition),
                    ("GET", r"/api/payroll/runs/(\d+)/export\.csv", self.api_payroll_csv),
                    ("GET", r"/api/me/payslips", self.api_my_payslips),
                    ("GET", r"/api/payslips/(\d+)", self.api_payslip_get),
                    ("GET", r"/api/advances", self.api_advances_get),
                    ("POST", r"/api/advances", self.api_advances_post),
                    ("POST", r"/api/advances/(\d+)/decision", self.api_advance_decision),
                    ("GET", r"/api/lifecycle/cases", self.api_lifecycle_get),
                    ("POST", r"/api/lifecycle/cases", self.api_lifecycle_post),
                    ("PATCH", r"/api/lifecycle/cases/(\d+)", self.api_lifecycle_patch),
                    ("DELETE", r"/api/lifecycle/cases/(\d+)", self.api_lifecycle_delete),
                    ("GET", r"/api/reports/summary", self.api_report_summary),
                    ("GET", r"/api/reports/summary\.csv", self.api_report_summary_csv),
                ]
                for route_method, pattern, handler in routes:
                    match = re.fullmatch(pattern, path)
                    if match and route_method == method:
                        return handler(*[int(x) if x.isdigit() else x for x in match.groups()])
                if any(re.fullmatch(pattern, path) for _, pattern, _ in routes):
                    raise APIError(405, "الطريقة غير مسموحة.", "method_not_allowed")
                raise APIError(404, "واجهة الخدمة المطلوبة غير موجودة.", "not_found")
            except APIError as exc:
                self.send_api_error(exc)
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception as exc:
                self.log_error("Unhandled API error: %r", exc)
                self.send_api_error(APIError(500, "حدث خطأ داخلي غير متوقع.", "internal_error"))

        def read_json(self) -> dict[str, Any]:
            content_type = self.headers.get_content_type()
            if content_type != "application/json":
                raise APIError(415, "أرسل البيانات بصيغة application/json.", "unsupported_media_type")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise APIError(400, "طول الطلب غير صالح.", "invalid_request")
            if length <= 0 or length > MAX_JSON_BYTES:
                raise APIError(413 if length > MAX_JSON_BYTES else 400, "حجم الطلب غير صالح.", "payload_too_large" if length > MAX_JSON_BYTES else "invalid_request")
            try:
                data = json.loads(self.rfile.read(length))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise APIError(400, "تعذر قراءة JSON.", "invalid_json")
            if not isinstance(data, dict):
                raise APIError(422, "يجب أن يكون الطلب كائناً JSON.", "validation_error")
            return data

        def send_json(self, status: int, payload: Any, cookie: str | None = None) -> None:
            raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(raw)

        def send_csv(self, filename: str, rows: list[list[Any]]) -> None:
            buffer = io.StringIO(newline="")
            writer = csv.writer(buffer)
            writer.writerows(rows)
            raw = ("\ufeff" + buffer.getvalue()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(raw)

        def send_api_error(self, exc: APIError) -> None:
            payload: dict[str, Any] = {"error": exc.message, "code": exc.code}
            if exc.details is not None:
                payload["details"] = exc.details
            self.send_json(exc.status, payload)

        def client_ip(self) -> str:
            return str(self.client_address[0] if self.client_address else "local")[:80]

        def rate_limit(self, action: str, key: str, maximum: int, window_minutes: int) -> bool:
            """Return True when the request is within its rolling persistence-backed window."""
            digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
            now = utc_now(); row = self.db.execute(
                "SELECT window_started,attempts FROM auth_rate_limits WHERE rate_key=? AND action=?", (digest, action)
            ).fetchone()
            fresh = True
            if row:
                try: fresh = datetime.fromisoformat(row["window_started"]) + timedelta(minutes=window_minutes) <= now
                except ValueError: fresh = True
            with self.db:
                if not row or fresh:
                    self.db.execute("INSERT OR REPLACE INTO auth_rate_limits(rate_key,action,window_started,attempts) VALUES(?,?,?,1)", (digest, action, now.isoformat(timespec="seconds")))
                    return True
                attempts = int(row["attempts"]) + 1
                self.db.execute("UPDATE auth_rate_limits SET attempts=? WHERE rate_key=? AND action=?", (attempts, digest, action))
            return attempts <= maximum

        def serve_static(self, path: str, head: bool = False) -> None:
            from urllib.parse import unquote
            clean = unquote(path).lstrip("/") or "index.html"
            candidate = (static_root / clean).resolve()
            try:
                candidate.relative_to(static_root.resolve())
            except ValueError:
                raise APIError(403, "المسار غير مسموح.", "forbidden")
            if candidate.is_dir():
                candidate = candidate / "index.html"
            if not candidate.is_file() or candidate.suffix.lower() in {".py", ".sql", ".sqlite", ".sqlite3", ".command"} or "data" in candidate.parts:
                raise APIError(404, "الملف غير موجود.", "not_found")
            raw = candidate.read_bytes()
            mime = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", f"{mime}; charset=utf-8" if mime.startswith("text/") else mime)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Last-Modified", formatdate(candidate.stat().st_mtime, usegmt=True))
            self.end_headers()
            if not head:
                self.wfile.write(raw)

        def current_user(self, required: bool = True) -> dict[str, Any] | None:
            if self._user is not False:
                if required and self._user is None:
                    raise APIError(401, "يرجى تسجيل الدخول أولاً.", "authentication_required")
                return self._user  # type: ignore[return-value]
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            morsel = cookie.get(SESSION_COOKIE)
            user = None
            if morsel:
                token_hash = hashlib.sha256(morsel.value.encode("ascii", "ignore")).hexdigest()
                row = self.db.execute(
                    """SELECT u.id,u.email,u.display_name,u.role,u.employee_id,u.active,u.must_change_password,u.is_super_admin,
                              s.expires_at,s.csrf_token
                       FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?""",
                    (token_hash,),
                ).fetchone()
                if row and bool(row["active"]):
                    try:
                        expires = datetime.fromisoformat(row["expires_at"])
                    except ValueError:
                        expires = utc_now() - timedelta(seconds=1)
                    if expires > utc_now():
                        user = dict(row)
                        user.pop("expires_at", None)
                        self.db.execute("UPDATE sessions SET last_seen_at=? WHERE token_hash=?", (now_iso(), token_hash))
                        self.db.commit()
                    else:
                        self.db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
                        self.db.commit()
            self._user = user
            if required and user is None:
                raise APIError(401, "يرجى تسجيل الدخول أولاً.", "authentication_required")
            return user

        def require_permission(self, permission: str) -> dict[str, Any]:
            user = self.current_user(True)
            assert user is not None
            if bool(user.get("must_change_password")):
                raise APIError(428, "يجب تغيير كلمة المرور المؤقتة قبل متابعة العمل.", "password_change_required")
            if not has_permission(self.db, user, permission):
                raise APIError(403, "لا تملك الصلاحية اللازمة لهذا الإجراء.", "forbidden", {"permission": permission})
            return user

        def own_employee_id(self) -> int:
            user = self.current_user(True)
            assert user is not None
            if user.get("employee_id") is None:
                raise APIError(409, "حساب المستخدم غير مرتبط بملف موظف.", "employee_not_linked")
            return int(user["employee_id"])

        def has_privileged_people_access(self, user: dict[str, Any], permission: str) -> bool:
            return str(user.get("role")) in PEOPLE_ADMIN_ROLES and has_permission(self.db, user, permission)

        def team_member_row(self, manager_employee_id: int, employee_id: int) -> sqlite3.Row | None:
            return self.db.execute(
                """SELECT e.id,e.employee_no,e.full_name
                     FROM employees e
                     LEFT JOIN departments d ON d.id=e.department_id
                    WHERE e.id=? AND e.active=1 AND e.id<>?
                      AND (e.manager_id=? OR d.manager_employee_id=?)""",
                (employee_id, manager_employee_id, manager_employee_id, manager_employee_id),
            ).fetchone()

        def direct_manager_employee_id(self, employee_id: int) -> int | None:
            row = self.db.execute(
                """SELECT e.manager_id,d.manager_employee_id,o.general_manager_employee_id
                     FROM employees e LEFT JOIN departments d ON d.id=e.department_id
                     CROSS JOIN organization o
                     WHERE e.id=?""",
                (employee_id,),
            ).fetchone()
            if row is None:
                return None
            manager_id = row["manager_id"] or row["manager_employee_id"]
            if manager_id and int(manager_id) != employee_id:
                return int(manager_id)
            configured = row["general_manager_employee_id"]
            return int(configured) if configured and int(configured) != employee_id else None

        def is_department_head(self, employee_id: int) -> bool:
            return bool(self.db.execute(
                "SELECT 1 FROM departments WHERE manager_employee_id=? AND active=1 LIMIT 1",
                (employee_id,),
            ).fetchone())

        def sync_manager_assignment_workflows(
            self,
            employee_id: int,
            previous_manager_id: int | None,
            new_manager_id: int | None,
            actor_user_id: int,
        ) -> None:
            """Move pending workflow ownership when an employee's manager changes.

            The employee row is the source of truth for the reporting line, but
            submitted evaluations and leave requests keep a snapshot of the
            approver.  Keep those snapshots aligned while they are still
            actionable; completed manager reviews remain immutable history.
            """
            old_id = int(previous_manager_id) if previous_manager_id else None
            next_id = int(new_manager_id) if new_manager_id else None
            if old_id == next_id:
                return
            stamp = now_iso()
            next_user = self.db.execute(
                "SELECT id FROM users WHERE employee_id=? AND active=1",
                (next_id,),
            ).fetchone() if next_id else None
            pending_evaluations = self.db.execute(
                """SELECT id,status,manager_employee_id FROM evaluations
                     WHERE employee_id=? AND workflow_version>=2
                       AND status IN ('submitted','returned')""",
                (employee_id,),
            ).fetchall()
            for evaluation in pending_evaluations:
                evaluation_id = int(evaluation["id"])
                self.db.execute("DELETE FROM evaluation_approvals WHERE evaluation_id=? AND step_no=1", (evaluation_id,))
                if next_id:
                    self.db.execute(
                        """INSERT INTO evaluation_approvals
                           (evaluation_id,step_no,approver_employee_id,status,comment,decided_at,created_at)
                           VALUES(?,1,?,'pending','',NULL,?)""",
                        (evaluation_id, next_id, stamp),
                    )
                self.db.execute(
                    """UPDATE evaluations SET manager_employee_id=?,status='submitted',current_step=1,
                              weighted_score=NULL,rating=NULL,manager_report='',manager_submitted_at=NULL,
                              hr_comment='',updated_at=? WHERE id=?""",
                    (next_id, stamp, evaluation_id),
                )
                audit(
                    self.db,
                    actor_user_id,
                    "evaluation.manager_reassigned",
                    "evaluation",
                    evaluation_id,
                    {"from_manager_employee_id": old_id, "to_manager_employee_id": next_id, "reason": "employee_manager_changed"},
                )
            # Draft evaluations have no approval decision to preserve, but must
            # still carry the new manager so the next submission routes there.
            self.db.execute(
                """UPDATE evaluations SET manager_employee_id=?,updated_at=?
                     WHERE employee_id=? AND workflow_version>=2 AND status='draft'""",
                (next_id, stamp, employee_id),
            )
            pending_leaves = self.db.execute(
                """SELECT id FROM leave_requests
                     WHERE employee_id=? AND status='submitted' AND manager_decision='pending'""",
                (employee_id,),
            ).fetchall()
            if pending_leaves:
                self.db.execute(
                    """UPDATE leave_requests SET manager_employee_id=?,updated_at=?
                         WHERE employee_id=? AND status='submitted' AND manager_decision='pending'""",
                    (next_id, stamp, employee_id),
                )
            if next_user:
                evaluation_count = len(pending_evaluations)
                leave_count = len(pending_leaves)
                if evaluation_count or leave_count:
                    create_internal_notification(
                        self.db,
                        actor_user_id,
                        [int(next_user["id"])],
                        "تم تحديث نطاق مسؤوليتك",
                        f"تم إسناد {evaluation_count} تقييم و{leave_count} طلب إجازة معلّق إلى نطاقك بعد تحديث المسؤول المباشر.",
                    )
            audit(
                self.db,
                actor_user_id,
                "employee.manager_assignment_sync",
                "employee",
                employee_id,
                {
                    "from_manager_employee_id": old_id,
                    "to_manager_employee_id": next_id,
                    "pending_evaluations": len(pending_evaluations),
                    "pending_leaves": len(pending_leaves),
                },
            )

        def sync_department_manager_workflows(
            self,
            department_id: int,
            previous_manager_id: int | None,
            new_manager_id: int | None,
            actor_user_id: int,
        ) -> None:
            """Re-route employees who inherit their manager from a department.

            An explicit employee.manager_id always wins over the department
            manager, so only employees without an explicit manager are moved.
            """
            old_id = int(previous_manager_id) if previous_manager_id else None
            next_id = int(new_manager_id) if new_manager_id else None
            if old_id == next_id:
                return
            employee_ids = [
                int(row["id"])
                for row in self.db.execute(
                    "SELECT id FROM employees WHERE department_id=? AND active=1 AND manager_id IS NULL",
                    (department_id,),
                ).fetchall()
            ]
            for employee_id in employee_ids:
                self.sync_manager_assignment_workflows(employee_id, old_id, next_id, actor_user_id)

        def may_access_employee(self, employee_id: int, broad_permission: str = "employee.view") -> bool:
            user = self.current_user(True)
            assert user is not None
            if user.get("employee_id") == employee_id:
                return True
            return self.has_privileged_people_access(user, broad_permission) or has_permission(self.db, user, "employee.profile.edit")

        # Authentication and basic reference data
        def api_health(self) -> None:
            self.send_json(200, {"ok": True, "service": "Khaisha HR", "version": APP_VERSION})

        def api_login(self) -> None:
            data = self.read_json()
            email = clean_email(data.get("email"))
            password = str(data.get("password", ""))
            if not email or not password:
                raise APIError(422, "البريد وكلمة المرور مطلوبان.", "validation_error")
            row = self.db.execute("SELECT * FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
            if row is None or not bool(row["active"]) or not verify_password(password, row["password_hash"], row["password_salt"]):
                allowed = self.rate_limit("login", f"{self.client_ip()}|{email}", 12, 15)
                with self.db: audit(self.db, row["id"] if row else None, "auth.login_failed", "security", row["id"] if row else None, {"email_hash": hashlib.sha256(email.encode()).hexdigest()[:16]})
                if not allowed:
                    with self.db: audit(self.db, None, "auth.login_rate_limited", "security", None, {"email_hash": hashlib.sha256(email.encode()).hexdigest()[:16]})
                    raise APIError(429, "محاولات كثيرة. انتظر قليلاً ثم أعد المحاولة.", "rate_limited")
                raise APIError(401, "بيانات الدخول غير صحيحة.", "invalid_credentials")
            with self.db:
                self.db.execute("DELETE FROM auth_rate_limits WHERE rate_key=? AND action='login'", (hashlib.sha256(f"{self.client_ip()}|{email}".encode("utf-8")).hexdigest(),))
            raw_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
            csrf_token = secrets.token_urlsafe(24)
            stamp = now_iso()
            expires = (utc_now() + timedelta(hours=SESSION_HOURS)).isoformat(timespec="seconds")
            with self.db:
                self.db.execute("DELETE FROM sessions WHERE expires_at <= ?", (stamp,))
                self.db.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at,last_seen_at,csrf_token) VALUES(?,?,?,?,?,?)", (token_hash, row["id"], expires, stamp, stamp, csrf_token))
                audit(self.db, row["id"], "auth.login", "user", row["id"])
            cookie = f"{SESSION_COOKIE}={raw_token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_HOURS * 3600}"
            self.send_json(200, {"user": public_user(row), "csrf_token": csrf_token}, cookie=cookie)

        def api_logout(self) -> None:
            user = self.current_user(False)
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            morsel = cookie.get(SESSION_COOKIE)
            if morsel:
                token_hash = hashlib.sha256(morsel.value.encode("ascii", "ignore")).hexdigest()
                with self.db:
                    self.db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
                    if user:
                        audit(self.db, user["id"], "auth.logout", "user", user["id"])
            self.send_json(200, {"ok": True}, cookie=f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")

        def api_auth_me(self) -> None:
            user = self.current_user(True)
            assert user is not None
            if not user.get("csrf_token"):
                csrf_token = secrets.token_urlsafe(24); cookie = SimpleCookie(self.headers.get("Cookie", "")); morsel = cookie.get(SESSION_COOKIE)
                if morsel:
                    token_hash = hashlib.sha256(morsel.value.encode("ascii", "ignore")).hexdigest()
                    with self.db: self.db.execute("UPDATE sessions SET csrf_token=? WHERE token_hash=?", (csrf_token, token_hash))
                    user["csrf_token"] = csrf_token
            permissions, reasons = effective_permissions(self.db, user)
            self.send_json(200, {"user": public_user(user), "permissions": permissions, "permission_reasons": reasons, "csrf_token": user.get("csrf_token", "")})

        def api_change_password(self) -> None:
            user = self.current_user(True); assert user is not None
            data = self.read_json(); current = str(data.get("current_password", "")); password = str(data.get("password", ""))
            if password != str(data.get("confirm_password", "")):
                raise APIError(422, "تأكيد كلمة المرور غير مطابق.", "password_mismatch")
            row = self.db.execute("SELECT password_hash,password_salt FROM users WHERE id=?", (user["id"],)).fetchone()
            if not row or not verify_password(current, row["password_hash"], row["password_salt"]):
                raise APIError(403, "كلمة المرور الحالية غير صحيحة.", "current_password_invalid")
            validate_password_strength(password); digest, salt = password_record(password); stamp = now_iso()
            with self.db:
                self.db.execute("UPDATE users SET password_hash=?,password_salt=?,must_change_password=0,last_password_change_at=?,updated_at=? WHERE id=?", (digest, salt, stamp, stamp, user["id"]))
                self.db.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
                audit(self.db, user["id"], "auth.password_changed", "user", user["id"])
            self.send_json(200, {"ok": True, "reauthenticate": True}, cookie=f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")

        def reset_token_row(self, raw_token: str) -> sqlite3.Row | None:
            if not raw_token or len(raw_token) > 180: return None
            token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
            return self.db.execute("SELECT * FROM password_reset_tokens WHERE token_hash=?", (token_hash,)).fetchone()

        def api_forgot_password(self) -> None:
            data = self.read_json(); email = clean_email(data.get("email"))
            generic = {"ok": True, "message": "إذا كان البريد مسجلاً ونشطاً فستصل تعليمات الاسترجاع خلال دقائق."}
            if not email or len(email) > 254:
                self.send_json(200, generic); return
            allowed = self.rate_limit("forgot_password", f"{self.client_ip()}|{email}", 5, 60)
            row = self.db.execute("SELECT id,email,active FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
            if allowed and row and bool(row["active"]):
                raw_token = secrets.token_urlsafe(40); token_hash = hashlib.sha256(raw_token.encode("ascii")).hexdigest(); stamp = now_iso()
                expires = (utc_now() + timedelta(minutes=PASSWORD_RESET_MINUTES)).isoformat(timespec="seconds")
                port = int(self.server.server_address[1]); link = f"http://localhost:{port}/?reset_token={raw_token}#reset-password"
                subject = "استرجاع كلمة المرور — منصة موارد"
                body = f"تم طلب إعادة تعيين كلمة المرور. استخدم الرابط خلال {PASSWORD_RESET_MINUTES} دقيقة:\n{link}\nإذا لم تطلب ذلك فتجاهل الرسالة."
                with self.db:
                    self.db.execute("UPDATE password_reset_tokens SET used_at=? WHERE user_id=? AND used_at IS NULL", (stamp, row["id"]))
                    self.db.execute("INSERT INTO password_reset_tokens(user_id,token_hash,expires_at,requested_ip,created_at) VALUES(?,?,?,?,?)", (row["id"], token_hash, expires, self.client_ip(), stamp))
                    self.queue_email("password_reset", row["email"], subject, body, user_id=row["id"])
                    audit(self.db, None, "auth.password_reset_requested", "user", row["id"], {"delivery": "queued_or_sent"})
            elif not allowed:
                with self.db: audit(self.db, None, "auth.password_reset_rate_limited", "security", None, {"email_hash": hashlib.sha256(email.encode()).hexdigest()[:16]})
            self.send_json(200, generic)

        def api_reset_password_validate(self) -> None:
            token = str(self.read_json().get("token", "")); row = self.reset_token_row(token); valid = False
            if row and row["used_at"] is None:
                try: valid = datetime.fromisoformat(row["expires_at"]) > utc_now()
                except ValueError: valid = False
            self.send_json(200, {"valid": valid, "expires_in_minutes": PASSWORD_RESET_MINUTES if valid else 0})

        def api_reset_password(self) -> None:
            data = self.read_json(); token = str(data.get("token", "")); password = str(data.get("password", ""))
            if password != str(data.get("confirm_password", "")):
                raise APIError(422, "تأكيد كلمة المرور غير مطابق.", "password_mismatch")
            validate_password_strength(password); row = self.reset_token_row(token)
            if not row or row["used_at"] is not None:
                raise APIError(410, "رابط الاسترجاع غير صالح أو سبق استخدامه.", "reset_token_invalid")
            try: expired = datetime.fromisoformat(row["expires_at"]) <= utc_now()
            except ValueError: expired = True
            if expired: raise APIError(410, "انتهت صلاحية رابط الاسترجاع.", "reset_token_expired")
            digest, salt = password_record(password); stamp = now_iso()
            with self.db:
                self.db.execute("UPDATE users SET password_hash=?,password_salt=?,must_change_password=0,last_password_change_at=?,updated_at=? WHERE id=?", (digest, salt, stamp, stamp, row["user_id"]))
                self.db.execute("UPDATE password_reset_tokens SET used_at=? WHERE id=?", (stamp, row["id"]))
                self.db.execute("DELETE FROM sessions WHERE user_id=?", (row["user_id"],))
                audit(self.db, row["user_id"], "auth.password_reset_completed", "user", row["user_id"])
            self.send_json(200, {"ok": True, "message": "تم تحديث كلمة المرور. يمكنك تسجيل الدخول الآن."})

        def permission_catalog_payload(self) -> list[dict[str, Any]]:
            group_labels = {"dashboard":"القيادة والتقارير","people":"الأشخاص والهيكل","time":"الوقت والإجازات","payroll":"الرواتب والمزايا","performance":"الأداء والتطوير","communications":"التواصل","security":"الإدارة والأمان"}
            return [{"key": key, "label": group_labels[key], "permissions": [{"key": p, "label": label} for p, label in values.items()]} for key, values in PERMISSION_CATALOG.items()]

        def api_permission_catalog(self) -> None:
            self.require_permission("security.manage_permissions"); self.send_json(200, {"groups": self.permission_catalog_payload()})

        def admin_user_payload(self, row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
            user = dict(row); effective, reasons = effective_permissions(self.db, user)
            overrides = [{"permission": x["permission"], "granted": bool(x["granted"])} for x in self.db.execute("SELECT permission,granted FROM user_permissions WHERE user_id=? ORDER BY permission", (user["id"],))]
            return public_user(user) | {"permissions": effective, "permission_reasons": reasons, "overrides": overrides, "last_password_change_at": user.get("last_password_change_at")}

        def api_admin_users(self) -> None:
            user = self.current_user(True); assert user is not None
            if not (has_permission(self.db, user, "security.manage_users") or has_permission(self.db, user, "security.manage_permissions")):
                raise APIError(403, "لا تملك صلاحية إدارة المستخدمين.", "forbidden")
            rows = self.db.execute("SELECT id,email,display_name,role,employee_id,active,must_change_password,is_super_admin,last_password_change_at FROM users ORDER BY display_name").fetchall()
            self.send_json(200, {"items": [self.admin_user_payload(row) for row in rows]})

        def admin_target(self, user_id: int) -> sqlite3.Row:
            row = self.db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            if not row: raise APIError(404, "المستخدم غير موجود.", "not_found")
            return row

        def guard_admin_continuity(self, actor: dict[str, Any], target: sqlite3.Row, updates: dict[str, Any]) -> None:
            if bool(target["is_super_admin"]) and (updates.get("active") == 0 or updates.get("role", target["role"]) != "admin"):
                raise APIError(409, "لا يمكن تعطيل أو خفض دور المدير الأعلى المحمي.", "protected_super_admin")
            removes_admin = target["role"] == "admin" and bool(target["active"]) and (updates.get("active") == 0 or updates.get("role", "admin") != "admin")
            if removes_admin:
                others = self.db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1 AND id<>?", (target["id"],)).fetchone()[0]
                if not others: raise APIError(409, "يجب الإبقاء على مدير نظام نشط واحد على الأقل.", "last_admin_protected")

        def api_admin_user_patch(self, user_id: int) -> None:
            actor = self.require_permission("security.manage_users"); target = self.admin_target(user_id); data = self.read_json(); updates: dict[str, Any] = {}
            if "active" in data: updates["active"] = 1 if bool(data["active"]) else 0
            if "role" in data:
                if data["role"] not in ROLE_PERMISSIONS: raise APIError(422, "الدور غير صالح.", "validation_error")
                updates["role"] = data["role"]
            if not updates: raise APIError(422, "لا توجد تغييرات.", "validation_error")
            self.guard_admin_continuity(actor, target, updates); before = {k: target[k] for k in updates}; updates["updated_at"] = now_iso()
            with self.db:
                self.db.execute("UPDATE users SET "+",".join(f"{k}=?" for k in updates)+" WHERE id=?", (*updates.values(), user_id))
                if updates.get("active") == 0: self.db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
                audit(self.db, actor["id"], "security.user_update", "user", user_id, {"before": before, "after": updates})
            self.send_json(200, {"user": self.admin_user_payload(self.admin_target(user_id))})

        def api_user_permissions_get(self, user_id: int) -> None:
            self.require_permission("security.manage_permissions"); target = self.admin_target(user_id)
            self.send_json(200, {"user": self.admin_user_payload(target), "groups": self.permission_catalog_payload()})

        def api_user_permissions_patch(self, user_id: int) -> None:
            actor = self.require_permission("security.manage_permissions"); target = self.admin_target(user_id); data = self.read_json()
            if bool(target["is_super_admin"]): raise APIError(409, "صلاحيات المدير الأعلى المحمي ثابتة وكاملة.", "protected_super_admin")
            if is_configured_general_manager(self.db, target): raise APIError(409, "صلاحيات المدير العام المعين ثابتة وكاملة.", "protected_general_manager")
            raw = data.get("overrides")
            if not isinstance(raw, list) or len(raw) > len(ALL_PERMISSIONS): raise APIError(422, "قائمة الصلاحيات غير صالحة.", "validation_error")
            normalized: dict[str, bool] = {}
            for item in raw:
                if not isinstance(item, dict) or item.get("permission") not in ALL_PERMISSIONS or not isinstance(item.get("granted"), bool):
                    raise APIError(422, "تحتوي القائمة على صلاحية غير صالحة.", "validation_error")
                normalized[item["permission"]] = item["granted"]
            critical = {"security.manage_permissions", "security.manage_users"}
            if actor["id"] == user_id and any(permission in critical and not granted for permission, granted in normalized.items()):
                raise APIError(409, "لا يمكنك منع صلاحيات الإدارة الحرجة عن حسابك الحالي.", "critical_self_deny")
            before = [{"permission": r["permission"], "granted": bool(r["granted"])} for r in self.db.execute("SELECT permission,granted FROM user_permissions WHERE user_id=? ORDER BY permission", (user_id,))]
            with self.db:
                self.db.execute("DELETE FROM user_permissions WHERE user_id=?", (user_id,))
                self.db.executemany("INSERT INTO user_permissions(user_id,permission,granted) VALUES(?,?,?)", [(user_id, p, 1 if g else 0) for p, g in normalized.items()])
                audit(self.db, actor["id"], "security.permissions_update", "user", user_id, {"before": before, "after": [{"permission": p, "granted": g} for p, g in normalized.items()]})
            self.send_json(200, {"user": self.admin_user_payload(self.admin_target(user_id))})

        def api_admin_password_reset(self, user_id: int) -> None:
            actor = self.require_permission("security.reset_password"); target = self.admin_target(user_id); data = self.read_json()
            if data.get("confirm") is not True: raise APIError(422, "يلزم تأكيد تعيين كلمة المرور المؤقتة.", "confirmation_required")
            password = str(data.get("password", ""))
            if password != str(data.get("confirm_password", "")): raise APIError(422, "تأكيد كلمة المرور غير مطابق.", "password_mismatch")
            validate_password_strength(password); digest, salt = password_record(password); stamp = now_iso()
            with self.db:
                self.db.execute("UPDATE users SET password_hash=?,password_salt=?,must_change_password=1,last_password_change_at=?,updated_at=? WHERE id=?", (digest, salt, stamp, stamp, user_id))
                self.db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
                audit(self.db, actor["id"], "security.temporary_password_set", "user", user_id, {"must_change_password": True})
            self.send_json(200, {"ok": True, "must_change_password": True})

        def smtp_settings(self) -> dict[str, Any]:
            row = self.db.execute("SELECT smtp_host,smtp_port,smtp_tls,smtp_ssl,smtp_username,smtp_password_encrypted,smtp_from_name,smtp_from_email,display_name,email FROM organization WHERE id=1").fetchone()
            return dict(row) if row else {}

        def smtp_deliver(self, to_email: str, subject: str, body: str, attachment: dict[str, Any] | None = None) -> tuple[str, str]:
            settings = self.smtp_settings()
            if not settings.get("smtp_host"):
                return "queued", ""
            message = EmailMessage(); message["Subject"] = subject; message["To"] = to_email
            message["From"] = f'{settings.get("smtp_from_name") or settings.get("display_name") or "موارد"} <{settings.get("smtp_from_email") or settings.get("email") or settings.get("smtp_username")}>'
            message.set_content(body, subtype="plain", charset="utf-8")
            if attachment and attachment.get("data"):
                raw = attachment["data"] if isinstance(attachment["data"], bytes) else base64.b64decode(str(attachment["data"]))
                message.add_attachment(raw, maintype="application", subtype="pdf", filename=str(attachment.get("name") or "salary-certificate.pdf"))
            password = open_secret(str(settings.get("smtp_password_encrypted") or ""), db_path)
            try:
                smtp_class = smtplib.SMTP_SSL if bool(settings.get("smtp_ssl")) else smtplib.SMTP
                with smtp_class(str(settings["smtp_host"]), int(settings.get("smtp_port") or 587), timeout=12) as client:
                    if bool(settings.get("smtp_tls")) and not bool(settings.get("smtp_ssl")): client.starttls()
                    if settings.get("smtp_username"): client.login(str(settings["smtp_username"]), password)
                    client.send_message(message)
                return "sent", ""
            except (OSError, smtplib.SMTPException) as exc:
                return "failed", type(exc).__name__

        def queue_email(self, kind: str, to_email: str, subject: str, body: str, *, campaign_id: int | None = None, delivery_id: int | None = None, user_id: int | None = None, attachment: dict[str, Any] | None = None) -> tuple[int, str]:
            stamp = now_iso(); status, error = self.smtp_deliver(to_email, subject, body, attachment)
            cursor = self.db.execute(
                "INSERT INTO email_outbox(kind,to_email,subject,body,status,attempts,last_error,campaign_id,delivery_id,user_id,created_at,updated_at,sent_at,attachment_name,attachment_content_type,attachment_data) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (kind, to_email, subject, body, status, 1 if status != "queued" else 0, error, campaign_id, delivery_id, user_id, stamp, stamp, stamp if status == "sent" else None,
                 (attachment or {}).get("name"), (attachment or {}).get("content_type"),
                 base64.b64encode(attachment["data"]).decode("ascii") if attachment and isinstance(attachment.get("data"), bytes) else ((attachment or {}).get("data") if attachment else None)),
            )
            return int(cursor.lastrowid), status

        def api_smtp_get(self) -> None:
            self.require_permission("smtp.manage"); settings = self.smtp_settings()
            payload = {key: settings.get(key) for key in ("smtp_host","smtp_port","smtp_tls","smtp_ssl","smtp_username","smtp_from_name","smtp_from_email")}
            payload["smtp_tls"] = bool(payload["smtp_tls"]); payload["smtp_ssl"] = bool(payload["smtp_ssl"])
            payload["password_configured"] = bool(settings.get("smtp_password_encrypted")); payload["smtp_password"] = "••••••••" if payload["password_configured"] else ""
            self.send_json(200, {"smtp": payload})

        def api_smtp_patch(self) -> None:
            user = self.require_permission("smtp.manage"); data = self.read_json(); values: dict[str, Any] = {}
            for key in ("smtp_host","smtp_username","smtp_from_name","smtp_from_email"):
                if key in data: values[key] = optional_text(data, key, 254)
            if "smtp_port" in data: values["smtp_port"] = as_int(data["smtp_port"], "smtp_port", 1, 65535)
            for key in ("smtp_tls","smtp_ssl"):
                if key in data: values[key] = 1 if bool(data[key]) else 0
            if values.get("smtp_tls") and values.get("smtp_ssl"): raise APIError(422, "اختر TLS أو SSL وليس كليهما.", "validation_error")
            if "smtp_from_email" in values and values["smtp_from_email"] and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", values["smtp_from_email"]): raise APIError(422, "بريد المرسل غير صالح.", "validation_error")
            if "smtp_password" in data and str(data["smtp_password"]) and "•" not in str(data["smtp_password"]):
                values["smtp_password_encrypted"] = seal_secret(str(data["smtp_password"]), db_path)
            if data.get("clear_password") is True: values["smtp_password_encrypted"] = ""
            if not values: raise APIError(422, "لا توجد تغييرات للحفظ.", "validation_error")
            with self.db:
                self.db.execute("UPDATE organization SET "+",".join(f"{k}=?" for k in values)+",updated_at=? WHERE id=1", (*values.values(), now_iso()))
                audit(self.db, user["id"], "smtp.settings_update", "organization", 1, {"fields": [k for k in values if k != "smtp_password_encrypted"], "password_changed": "smtp_password_encrypted" in values})
            self.api_smtp_get()

        def api_smtp_test(self) -> None:
            user = self.require_permission("smtp.test"); data = self.read_json(); to_email = clean_email(data.get("to_email") or user["email"])
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", to_email): raise APIError(422, "بريد الاختبار غير صالح.", "validation_error")
            with self.db:
                outbox_id, status = self.queue_email("smtp_test", to_email, "اختبار اتصال البريد — منصة موارد", "هذه رسالة اختبار لإعدادات البريد المؤسسي.", user_id=user["id"])
                audit(self.db, user["id"], "smtp.test", "email_outbox", outbox_id, {"status": status})
            self.send_json(200 if status == "sent" else 202, {"status": status, "message": "تم إرسال رسالة الاختبار." if status == "sent" else "لم يتم الإرسال عبر SMTP؛ حُفظت الرسالة في صندوق التطوير الآمن."})

        def api_outbox_get(self) -> None:
            self.require_permission("smtp.manage"); rows = self.db.execute("SELECT id,kind,to_email,subject,body,status,attempts,last_error,campaign_id,created_at,updated_at,sent_at FROM email_outbox ORDER BY id DESC LIMIT 100").fetchall()
            items = []
            for row in rows:
                item = dict(row)
                if item["kind"] == "password_reset": item["body"] = "[محتوى رابط الاسترجاع محجوب أمنياً]"
                items.append(item)
            self.send_json(200, {"items": items})

        def campaign_recipients(self, audience_type: str, audience_ref: Any) -> list[sqlite3.Row]:
            query = "SELECT id,full_name,email,department_id,branch_id FROM employees WHERE active=1 AND email IS NOT NULL AND TRIM(email)<>''"; params: list[Any] = []
            if audience_type == "employee": query += " AND id=?"; params.append(as_int(audience_ref, "audience_ref", 1))
            elif audience_type == "department": query += " AND department_id=?"; params.append(as_int(audience_ref, "audience_ref", 1))
            elif audience_type == "branch": query += " AND branch_id=?"; params.append(as_int(audience_ref, "audience_ref", 1))
            elif audience_type != "all": raise APIError(422, "نطاق المستلمين غير صالح.", "validation_error")
            return self.db.execute(query+" ORDER BY full_name", params).fetchall()

        def campaign_payload(self, campaign_id: int, include_deliveries: bool = True) -> dict[str, Any]:
            row = self.db.execute("SELECT c.*,u.display_name AS sender_name FROM email_campaigns c JOIN users u ON u.id=c.sender_user_id WHERE c.id=?", (campaign_id,)).fetchone()
            if not row: raise APIError(404, "الحملة البريدية غير موجودة.", "not_found")
            data = dict(row)
            if include_deliveries:
                data["deliveries"] = [dict(x) for x in self.db.execute("SELECT d.*,e.full_name AS employee_name FROM email_deliveries d JOIN employees e ON e.id=d.employee_id WHERE d.campaign_id=? ORDER BY d.id", (campaign_id,))]
            return data

        def refresh_campaign_status(self, campaign_id: int) -> None:
            counts = self.db.execute("SELECT COUNT(*) total,SUM(status='sent') sent,SUM(status='failed') failed,SUM(status='queued') queued FROM email_deliveries WHERE campaign_id=?", (campaign_id,)).fetchone()
            total, sent, failed, queued = (int(counts[k] or 0) for k in ("total","sent","failed","queued"))
            status = "sent" if total and sent == total else "failed" if total and failed == total else "partial" if sent or failed else "queued"
            self.db.execute("UPDATE email_campaigns SET status=?,recipient_count=?,sent_count=?,failed_count=?,updated_at=? WHERE id=?", (status,total,sent,failed,now_iso(),campaign_id))

        def api_campaigns_get(self) -> None:
            self.require_permission("communications.view"); rows = self.db.execute("SELECT id FROM email_campaigns ORDER BY id DESC LIMIT 100").fetchall()
            self.send_json(200, {"items": [self.campaign_payload(row["id"], False) for row in rows]})

        def api_campaign_get(self, campaign_id: int) -> None:
            self.require_permission("communications.view"); self.send_json(200, {"campaign": self.campaign_payload(campaign_id)})

        def api_campaign_post(self) -> None:
            user = self.require_permission("communications.send"); data = self.read_json(); audience_type = str(data.get("audience_type", "")); audience_ref = data.get("audience_ref")
            subject = require_text(data, "subject", 200); body = require_text(data, "body", 5000); template = optional_text(data, "template", 40) or "plain"
            if template not in {"plain","announcement","policy","congratulation"}: raise APIError(422, "قالب الرسالة غير صالح.", "validation_error")
            recipients = self.campaign_recipients(audience_type, audience_ref)
            if not recipients: raise APIError(422, "لا يوجد مستلمون نشطون لديهم بريد ضمن النطاق المحدد.", "no_recipients")
            if len(recipients) > 5000: raise APIError(422, "يتجاوز عدد المستلمين الحد المسموح للحملة.", "recipient_limit")
            stamp = now_iso()
            with self.db:
                cursor = self.db.execute("INSERT INTO email_campaigns(sender_user_id,audience_type,audience_ref,subject,body,template,recipient_count,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", (user["id"],audience_type,str(audience_ref) if audience_ref not in (None,"") else None,subject,body,template,len(recipients),stamp,stamp)); campaign_id = int(cursor.lastrowid)
                for recipient in recipients:
                    delivery = self.db.execute("INSERT INTO email_deliveries(campaign_id,employee_id,to_email,created_at,updated_at) VALUES(?,?,?,?,?)", (campaign_id,recipient["id"],recipient["email"],stamp,stamp)); delivery_id = int(delivery.lastrowid)
                    _, status = self.queue_email("campaign", recipient["email"], subject, body, campaign_id=campaign_id, delivery_id=delivery_id, user_id=user["id"])
                    self.db.execute("UPDATE email_deliveries SET status=?,attempts=?,updated_at=?,sent_at=? WHERE id=?", (status,0 if status=="queued" else 1,now_iso(),now_iso() if status=="sent" else None,delivery_id))
                self.refresh_campaign_status(campaign_id); audit(self.db,user["id"],"communications.campaign_create","email_campaign",campaign_id,{"audience_type":audience_type,"audience_ref":audience_ref,"recipient_count":len(recipients)})
            self.send_json(201, {"campaign": self.campaign_payload(campaign_id)})

        def api_campaign_retry(self, campaign_id: int) -> None:
            user = self.require_permission("communications.retry"); campaign = self.campaign_payload(campaign_id, False); deliveries = self.db.execute("SELECT * FROM email_deliveries WHERE campaign_id=? AND status IN ('queued','failed')", (campaign_id,)).fetchall()
            with self.db:
                for delivery in deliveries:
                    _, status = self.queue_email("campaign", delivery["to_email"], campaign["subject"], campaign["body"], campaign_id=campaign_id, delivery_id=delivery["id"], user_id=user["id"])
                    self.db.execute("UPDATE email_deliveries SET status=?,attempts=attempts+1,last_error='',updated_at=?,sent_at=? WHERE id=?", (status,now_iso(),now_iso() if status=="sent" else None,delivery["id"]))
                self.refresh_campaign_status(campaign_id); audit(self.db,user["id"],"communications.campaign_retry","email_campaign",campaign_id,{"delivery_count":len(deliveries)})
            self.send_json(200, {"campaign": self.campaign_payload(campaign_id)})

        def executive_scope(self, user: dict[str, Any]) -> tuple[list[str], list[Any]]:
            conditions: list[str] = []; params: list[Any] = []
            branch_id = self.query.get("branch_id"); department_id = self.query.get("department_id")
            if not has_permission(self.db, user, "employee.view"):
                employee = self.db.execute("SELECT branch_id,department_id FROM employees WHERE id=?", (user.get("employee_id"),)).fetchone()
                if not employee: return ["1=0"], []
                if employee["branch_id"]: conditions.append("e.branch_id=?"); params.append(employee["branch_id"])
                if employee["department_id"]: conditions.append("e.department_id=?"); params.append(employee["department_id"])
            if branch_id: conditions.append("e.branch_id=?"); params.append(as_int(branch_id,"branch_id",1))
            if department_id: conditions.append("e.department_id=?"); params.append(as_int(department_id,"department_id",1))
            return conditions, params

        def executive_attendance_context(
            self,
            employees: list[sqlite3.Row],
            work_date: date,
            present_employee_ids: set[int],
        ) -> dict[str, int]:
            """Classify who is actually due to attend before deriving absence.

            A person is excluded when they had not joined yet, have approved leave,
            have no effective shift, are on the shift's weekly rest day, or when
            today's shift has not reached its start plus grace period.  An early
            check-in remains attendance and makes that employee eligible.
            """
            employee_ids = {int(employee["id"]) for employee in employees}
            approved_leave_ids: set[int] = set()
            if employee_ids:
                placeholders = ",".join("?" for _ in employee_ids)
                approved_leave_ids = {
                    int(row["employee_id"])
                    for row in self.db.execute(
                        f"SELECT DISTINCT employee_id FROM leave_requests "
                        f"WHERE status='approved' AND employee_id IN ({placeholders}) "
                        "AND start_date<=? AND end_date>=?",
                        (*sorted(employee_ids), work_date.isoformat(), work_date.isoformat()),
                    )
                }
            context = {
                "eligible_to_attend": 0,
                "eligible_present": 0,
                "absent": 0,
                "approved_leave": 0,
                "weekly_rest": 0,
                "no_shift": 0,
                "not_due_yet": 0,
                "not_employed_yet": 0,
            }
            current = local_now()
            for employee in employees:
                employee_id = int(employee["id"])
                hire_date = parse_date(employee["hire_date"], "hire_date") if employee["hire_date"] else None
                if hire_date and hire_date > work_date:
                    context["not_employed_yet"] += 1
                    continue
                if employee_id in approved_leave_ids:
                    context["approved_leave"] += 1
                    continue
                shift = self.shift_for_employee(employee_id, work_date)
                if shift is None:
                    context["no_shift"] += 1
                    continue
                rest_days = set(shift.get("rest_days") or [])
                working_days = set(shift.get("working_days") or [])
                if work_date.weekday() in rest_days or (working_days and work_date.weekday() not in working_days):
                    context["weekly_rest"] += 1
                    continue
                already_present = employee_id in present_employee_ids
                if work_date > current.date():
                    context["not_due_yet"] += 1
                    continue
                if work_date == current.date() and not already_present:
                    expected_start = datetime.combine(work_date, parse_clock(shift["start_time"], "start_time"), UAE_TZ)
                    due_at = expected_start + timedelta(minutes=int(shift.get("grace_minutes") or 0))
                    if current < due_at:
                        context["not_due_yet"] += 1
                        continue
                context["eligible_to_attend"] += 1
                if already_present:
                    context["eligible_present"] += 1
                else:
                    context["absent"] += 1
            return context

        def api_executive_dashboard(self) -> None:
            user = self.require_permission("dashboard.view")
            ensure_document_expiry_notifications(self.db)
            today = local_now().date(); date_to = parse_date(self.query.get("date_to", today.isoformat()), "date_to"); date_from = parse_date(self.query.get("date_from", (date_to-timedelta(days=29)).isoformat()), "date_from")
            if date_from > date_to or (date_to-date_from).days > 366: raise APIError(422,"نطاق التاريخ غير صالح أو يتجاوز سنة.","validation_error")
            conditions, params = self.executive_scope(user); where = " WHERE "+" AND ".join(conditions) if conditions else ""
            def count(extra: str = "", extra_params: tuple[Any,...] = ()) -> int:
                clauses = conditions + ([extra] if extra else []); sql_where = " WHERE "+" AND ".join(clauses) if clauses else ""
                return int(self.db.execute("SELECT COUNT(*) FROM employees e"+sql_where, (*params,*extra_params)).fetchone()[0])
            total = count(); active = count("e.active=1"); inactive = total-active
            active_rows = self.db.execute("SELECT e.id,e.hire_date FROM employees e"+(" WHERE "+" AND ".join(conditions+["e.active=1"])), params).fetchall()
            attendance = int(self.db.execute("SELECT COUNT(DISTINCT a.employee_id) FROM attendance a JOIN employees e ON e.id=a.employee_id"+(" WHERE "+" AND ".join(conditions+["e.active=1","a.work_date=?","a.check_in_at IS NOT NULL"])), (*params,date_to.isoformat())).fetchone()[0])
            late = 0
            attendance_rows = self.db.execute("SELECT a.* FROM attendance a JOIN employees e ON e.id=a.employee_id"+(" WHERE "+" AND ".join(conditions+["e.active=1","a.work_date=?","a.check_in_at IS NOT NULL"])), (*params,date_to.isoformat())).fetchall()
            for row in attendance_rows:
                shift = self.shift_for_employee(int(row["employee_id"]), date_to)
                if shift and self.attendance_metrics(row, shift).get("late_minutes",0)>0: late += 1
            attendance_context = self.executive_attendance_context(active_rows, date_to, {int(row["employee_id"]) for row in attendance_rows})
            absent = attendance_context["absent"]
            scope_join = (" AND "+" AND ".join(c.replace("e.","e.") for c in conditions)) if conditions else ""
            leave_pending = int(self.db.execute("SELECT COUNT(*) FROM leave_requests r JOIN employees e ON e.id=r.employee_id WHERE r.status='submitted'"+scope_join, params).fetchone()[0])
            overtime_pending = int(self.db.execute("SELECT COUNT(*) FROM overtime_requests r JOIN employees e ON e.id=r.employee_id WHERE r.status='submitted'"+scope_join, params).fetchone()[0])
            expiry_limit = (today+timedelta(days=90)).isoformat()
            expiring_docs = int(self.db.execute("SELECT COUNT(*) FROM employee_documents d JOIN employees e ON e.id=d.employee_id WHERE d.archived=0 AND d.no_expiry=0 AND d.expires_on BETWEEN ? AND ?"+scope_join, (today.isoformat(),expiry_limit,*params)).fetchone()[0])
            new_employees = count("e.hire_date BETWEEN ? AND ?", (date_from.isoformat(),date_to.isoformat()))
            advance_active = int(self.db.execute("SELECT COUNT(*) FROM advances a JOIN employees e ON e.id=a.employee_id WHERE a.status IN ('submitted','approved')"+scope_join, params).fetchone()[0])
            payroll = self.db.execute("SELECT COUNT(DISTINCT r.id) runs,COALESCE(SUM(i.net_cents),0) net FROM payroll_runs r JOIN payroll_items i ON i.run_id=r.id JOIN employees e ON e.id=i.employee_id WHERE r.payroll_month BETWEEN ? AND ?"+scope_join, (date_from.strftime('%Y-%m'),date_to.strftime('%Y-%m'),*params)).fetchone()
            departments = [dict(r) for r in self.db.execute("SELECT COALESCE(d.name,'دون قسم') label,COUNT(*) value FROM employees e LEFT JOIN departments d ON d.id=e.department_id"+where+(" AND " if where else " WHERE ")+"e.active=1 GROUP BY e.department_id,d.name ORDER BY value DESC", params)]
            branches = [dict(r) for r in self.db.execute("SELECT COALESCE(b.name,'دون فرع') label,COUNT(*) value FROM employees e LEFT JOIN branches b ON b.id=e.branch_id"+where+(" AND " if where else " WHERE ")+"e.active=1 GROUP BY e.branch_id,b.name ORDER BY value DESC", params)]
            activity = [dict(r) for r in self.db.execute("SELECT a.action,a.entity_type,a.entity_id,a.created_at,COALESCE(u.display_name,'النظام') actor_name FROM audit_log a LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.id DESC LIMIT 12")]
            eligible_to_attend = attendance_context["eligible_to_attend"]
            absence_penalty = round((absent/eligible_to_attend)*35) if eligible_to_attend else 0
            health_score = max(0, min(100, 100-absence_penalty-min(expiring_docs*3,25)-min((leave_pending+overtime_pending)*2,20)))
            action_map = [("employee.manage","إضافة موظف","employees"),("leave.approve","اعتماد الإجازات","leaves"),("payroll.manage","إنشاء مسير","payroll"),("communications.send","إرسال تعميم","communications")]
            quick_actions = [{"label":label,"route":route} for permission,label,route in action_map if has_permission(self.db,user,permission)]
            selected_label = "اليوم" if date_to == today else date_to.isoformat()
            self.send_json(200,{"filters":{"date_from":date_from.isoformat(),"date_to":date_to.isoformat(),"branch_id":self.query.get("branch_id"),"department_id":self.query.get("department_id")},"metrics":{"employees_total":total,"employees_active":active,"employees_inactive":inactive,"attendance_today":attendance,"absent_today":absent,"eligible_to_attend":eligible_to_attend,"late_today":late,"leave_pending":leave_pending,"overtime_pending":overtime_pending,"documents_expiring":expiring_docs,"new_employees":new_employees,"advance_active":advance_active,"payroll_runs":int(payroll["runs"] or 0),"payroll_net":cents_value(payroll["net"])},"attendance_context":attendance_context|{"date":date_to.isoformat(),"label":selected_label},"health":{"score":health_score,"status":"جيد" if health_score>=80 else "يحتاج متابعة" if health_score>=60 else "حرج","absence_denominator":eligible_to_attend},"pulse":[{"label":"القوة النشطة","value":active},{"label":"حضور "+selected_label,"value":attendance},{"label":"طلبات معلقة","value":leave_pending+overtime_pending},{"label":"وثائق قريبة","value":expiring_docs}],"distributions":{"departments":departments,"branches":branches},"activity":activity,"quick_actions":quick_actions,"as_of":now_iso()})

        def api_org_grid(self) -> None:
            user = self.current_user(True); assert user is not None
            if not self.has_privileged_people_access(user, "employee.view"):
                raise APIError(403, "المخطط الكامل متاح للإدارة المخولة فقط.", "forbidden")
            branch = self.query.get("branch_id"); department = self.query.get("department_id"); search = self.query.get("q","").strip()
            conditions = ["e.active=1"]; params: list[Any] = []
            if branch: conditions.append("e.branch_id=?"); params.append(as_int(branch,"branch_id",1))
            if department: conditions.append("e.department_id=?"); params.append(as_int(department,"department_id",1))
            if search: conditions.append("(e.full_name LIKE ? OR e.employee_no LIKE ? OR e.job_title LIKE ?)"); term=f"%{search}%"; params.extend((term,term,term))
            employees = [dict(row) for row in self.db.execute(organization_employee_query()+" WHERE "+" AND ".join(conditions)+" ORDER BY e.full_name", params)]
            configured_gm = self.db.execute("SELECT general_manager_employee_id FROM organization WHERE id=1").fetchone()
            gm_row = None
            if configured_gm and configured_gm["general_manager_employee_id"]:
                gm_row = self.db.execute(
                    organization_employee_query()+" WHERE e.id=? AND e.active=1",
                    (configured_gm["general_manager_employee_id"],),
                ).fetchone()
            if gm_row is None:
                gm_row = self.db.execute(organization_employee_query()+" JOIN users gu ON gu.employee_id=e.id WHERE gu.role='general_manager' AND gu.active=1 ORDER BY gu.is_super_admin DESC,e.id LIMIT 1").fetchone()
            gm = dict(gm_row) if gm_row else next((e for e in employees if e and not e.get("manager_id")), None)
            departments = []
            dept_rows = self.db.execute("SELECT d.id,d.name,d.branch_id,b.name AS branch_name,d.manager_employee_id,m.full_name AS manager_name FROM departments d LEFT JOIN branches b ON b.id=d.branch_id LEFT JOIN employees m ON m.id=d.manager_employee_id WHERE d.active=1 ORDER BY d.name").fetchall()
            for row in dept_rows:
                members=[e for e in employees if e and e.get("department_id")==row["id"]]
                if members or (not branch and not department and not search): departments.append(dict(row)|{"employees":members})
            self.send_json(200,{"view":"grid","label":"المخطط الشبكي","general_manager":gm,"departments":departments,"employee_count":len([e for e in employees if e]),"filters":{"branch_id":branch,"department_id":department,"q":search},"source":"employees+departments+users"})

        def api_departments(self) -> None:
            user = self.current_user(True); assert user is not None
            rows = self.db.execute("SELECT d.*,e.full_name AS manager_name,b.name AS branch_name,(SELECT COUNT(*) FROM employees x WHERE x.department_id=d.id AND x.active=1) AS employee_count FROM departments d LEFT JOIN employees e ON e.id=d.manager_employee_id LEFT JOIN branches b ON b.id=d.branch_id ORDER BY d.name").fetchall()
            privileged = self.has_privileged_people_access(user, "employee.view")
            items = []
            for row in rows:
                data = dict(row) | {"active": bool(row["active"])}
                if not privileged:
                    data = {key: data.get(key) for key in ("id", "name", "branch_id", "branch_name", "active")}
                items.append(data)
            self.send_json(200, {"items": items})

        def parse_department(self, data: dict[str, Any], partial: bool = False) -> dict[str, Any]:
            result: dict[str, Any] = {}
            if not partial or "name" in data:
                result["name"] = require_text(data, "name", 150)
            for key in ("branch_id", "manager_employee_id"):
                if key in data:
                    result[key] = as_int(data[key], key, 1) if data[key] not in (None, "") else None
            if "active" in data:
                result["active"] = 1 if bool(data["active"]) else 0
            elif not partial:
                result["active"] = 1
            return result

        def api_department_post(self) -> None:
            user = self.require_permission("department.manage")
            values = self.parse_department(self.read_json())
            stamp = now_iso()
            try:
                with self.db:
                    cur = self.db.execute("INSERT INTO departments(name,branch_id,manager_employee_id,active,created_at,updated_at) VALUES(?,?,?,?,?,?)", (values["name"], values.get("branch_id"), values.get("manager_employee_id"), values["active"], stamp, stamp))
                    audit(self.db, user["id"], "department.create", "department", cur.lastrowid, values)
            except sqlite3.IntegrityError as exc:
                raise APIError(409, "يوجد قسم بالاسم نفسه أو مرجع غير صالح.", "department_conflict") from exc
            row = self.db.execute("SELECT * FROM departments WHERE id=?", (cur.lastrowid,)).fetchone()
            self.send_json(201, {"department": dict(row)})

        def api_department_patch(self, department_id: int) -> None:
            user = self.require_permission("department.manage")
            existing = self.db.execute("SELECT * FROM departments WHERE id=?", (department_id,)).fetchone()
            if not existing:
                raise APIError(404, "القسم غير موجود.", "not_found")
            values = self.parse_department(self.read_json(), True)
            if not values:
                raise APIError(422, "لا توجد تغييرات للحفظ.", "validation_error")
            previous_manager_id = int(existing["manager_employee_id"]) if existing["manager_employee_id"] else None
            values["updated_at"] = now_iso()
            try:
                with self.db:
                    self.db.execute("UPDATE departments SET " + ",".join(f"{k}=?" for k in values) + " WHERE id=?", (*values.values(), department_id))
                    if "manager_employee_id" in values:
                        self.sync_department_manager_workflows(
                            department_id,
                            previous_manager_id,
                            int(values["manager_employee_id"]) if values["manager_employee_id"] else None,
                            int(user["id"]),
                        )
                    audit(self.db, user["id"], "department.update", "department", department_id, values)
            except sqlite3.IntegrityError as exc:
                raise APIError(409, "تعذر تحديث القسم بسبب تعارض البيانات.", "department_conflict") from exc
            self.send_json(200, {"department": dict(self.db.execute("SELECT * FROM departments WHERE id=?", (department_id,)).fetchone())})

        def api_department_delete(self, department_id: int) -> None:
            user = self.require_permission("department.manage")
            count = int(self.db.execute("SELECT COUNT(*) FROM employees WHERE department_id=?", (department_id,)).fetchone()[0])
            if count:
                raise APIError(409, "لا يمكن حذف قسم مرتبط بموظفين. انقل الموظفين أولاً.", "department_has_employees", {"employee_count": count})
            with self.db:
                result = self.db.execute("DELETE FROM departments WHERE id=?", (department_id,))
                if not result.rowcount:
                    raise APIError(404, "القسم غير موجود.", "not_found")
                audit(self.db, user["id"], "department.delete", "department", department_id)
            self.send_json(200, {"ok": True})

        def api_department_assign(self, department_id: int) -> None:
            user = self.require_permission("department.manage")
            if not self.db.execute("SELECT 1 FROM departments WHERE id=? AND active=1", (department_id,)).fetchone():
                raise APIError(404, "القسم غير موجود أو غير نشط.", "not_found")
            employee_id = as_int(self.read_json().get("employee_id"), "employee_id", 1)
            previous_manager_id = self.direct_manager_employee_id(employee_id)
            with self.db:
                result = self.db.execute("UPDATE employees SET department_id=?,updated_at=? WHERE id=?", (department_id, now_iso(), employee_id))
                if not result.rowcount:
                    raise APIError(404, "الموظف غير موجود.", "not_found")
                self.sync_manager_assignment_workflows(
                    employee_id,
                    previous_manager_id,
                    self.direct_manager_employee_id(employee_id),
                    int(user["id"]),
                )
                audit(self.db, user["id"], "department.assign_employee", "employee", employee_id, {"department_id": department_id})
            self.send_json(200, {"employee": normalize_employee(self.db.execute(employee_query(True) + " WHERE e.id=?", (employee_id,)).fetchone())})

        def api_org_hierarchy(self) -> None:
            user = self.current_user(True); assert user is not None
            if not self.has_privileged_people_access(user, "employee.view"):
                raise APIError(403, "الهيكل الكامل متاح للإدارة المخولة فقط.", "forbidden")
            view=self.query.get("view","hierarchical")
            if view not in {"hierarchical","grid","sequential"}: raise APIError(422,"عرض الهيكل غير صالح.","validation_error")
            departments = [dict(r) for r in self.db.execute("SELECT d.*,b.name AS branch_name,m.full_name AS manager_name FROM departments d LEFT JOIN branches b ON b.id=d.branch_id LEFT JOIN employees m ON m.id=d.manager_employee_id ORDER BY d.name")]
            employees = [dict(r) for r in self.db.execute(organization_employee_query() + " ORDER BY e.full_name")]
            by_id = {e["id"]: e for e in employees if e}
            department_managers = {int(d["id"]): int(d["manager_employee_id"]) for d in departments if d.get("manager_employee_id")}
            flat = []
            for employee in employees:
                if not employee:
                    continue
                # A department head is the effective direct manager when an
                # employee has no explicit manager_id. This keeps the
                # hierarchy useful even when only the department assignment
                # was maintained by HR.
                effective_manager_id = employee.get("manager_id") or department_managers.get(int(employee.get("department_id") or 0))
                if effective_manager_id and int(effective_manager_id) == int(employee["id"]):
                    effective_manager_id = None
                employee = employee | {"manager_id": effective_manager_id}
                chain, seen, manager_id = [], set(), effective_manager_id
                while manager_id and manager_id not in seen and manager_id in by_id:
                    seen.add(manager_id); manager = by_id[manager_id]
                    chain.append({"id": manager["id"], "full_name": manager["full_name"], "job_title": manager["job_title"]})
                    next_manager = manager.get("manager_id") or department_managers.get(int(manager.get("department_id") or 0))
                    manager_id = None if next_manager and int(next_manager) == int(manager["id"]) else next_manager
                flat.append(employee | {"manager_chain": chain})
            branch_filter=self.query.get("branch_id"); department_filter=self.query.get("department_id"); search=self.query.get("q","").strip().casefold()
            if branch_filter: flat=[e for e in flat if str(e.get("branch_id") or "")==branch_filter]
            if department_filter: flat=[e for e in flat if str(e.get("department_id") or "")==department_filter]
            if search: flat=[e for e in flat if search in " ".join(str(e.get(k) or "") for k in ("full_name","employee_no","job_title","department_name","branch_name")).casefold()]
            relevant_departments={e.get("department_id") for e in flat}; departments=[d for d in departments if d["id"] in relevant_departments or (not branch_filter and not department_filter and not search)]
            self.send_json(200, {"view":view,"filters":{"branch_id":branch_filter,"department_id":department_filter,"q":self.query.get("q","")},"departments": departments, "employees": flat,"source":"employees.manager_id+departments"})

        def api_job_grades_get(self) -> None:
            self.current_user(True)
            rows = self.db.execute("SELECT *,min_salary_cents/100.0 AS min_salary,max_salary_cents/100.0 AS max_salary FROM job_grades ORDER BY code").fetchall()
            self.send_json(200, {"items": [dict(r) | {"active": bool(r["active"])} for r in rows]})

        def api_job_grades_post(self) -> None:
            user = self.require_permission("reference.manage"); data = self.read_json(); stamp = now_iso()
            code, name = require_text(data, "code", 40), require_text(data, "name", 120)
            minimum, maximum = money_cents(data.get("min_salary", 0), "min_salary"), money_cents(data.get("max_salary", 0), "max_salary")
            if maximum and maximum < minimum: raise APIError(422, "الحد الأعلى أقل من الحد الأدنى.", "validation_error")
            try:
                with self.db:
                    cur = self.db.execute("INSERT INTO job_grades(code,name,min_salary_cents,max_salary_cents,created_at,updated_at) VALUES(?,?,?,?,?,?)", (code,name,minimum,maximum,stamp,stamp)); audit(self.db,user["id"],"job_grade.create","job_grade",cur.lastrowid)
            except sqlite3.IntegrityError as exc: raise APIError(409,"رمز الدرجة مستخدم.","duplicate_reference") from exc
            self.send_json(201,{"job_grade":dict(self.db.execute("SELECT * FROM job_grades WHERE id=?",(cur.lastrowid,)).fetchone())})

        def api_job_grade_patch(self, grade_id: int) -> None:
            user=self.require_permission("reference.manage"); data=self.read_json(); existing=self.db.execute("SELECT * FROM job_grades WHERE id=?",(grade_id,)).fetchone()
            if existing is None: raise APIError(404,"الدرجة غير موجودة.","not_found")
            allowed={}
            if "code" in data: allowed["code"]=require_text(data,"code",40)
            if "name" in data: allowed["name"]=require_text(data,"name",120)
            if "min_salary" in data: allowed["min_salary_cents"]=money_cents(data["min_salary"],"min_salary")
            if "max_salary" in data: allowed["max_salary_cents"]=money_cents(data["max_salary"],"max_salary")
            if "active" in data: allowed["active"]=1 if bool(data["active"]) else 0
            if not allowed: raise APIError(422,"لا توجد تغييرات.","validation_error")
            minimum=allowed.get("min_salary_cents",existing["min_salary_cents"]); maximum=allowed.get("max_salary_cents",existing["max_salary_cents"])
            if maximum and maximum < minimum: raise APIError(422,"الحد الأعلى أقل من الحد الأدنى.","validation_error")
            allowed["updated_at"]=now_iso()
            try:
                with self.db:
                    self.db.execute("UPDATE job_grades SET "+",".join(f"{k}=?" for k in allowed)+" WHERE id=?",(*allowed.values(),grade_id))
                    audit(self.db,user["id"],"job_grade.update","job_grade",grade_id,allowed)
            except sqlite3.IntegrityError as exc: raise APIError(409,"رمز الدرجة مستخدم.","duplicate_reference") from exc
            self.send_json(200,{"job_grade":dict(self.db.execute("SELECT * FROM job_grades WHERE id=?",(grade_id,)).fetchone())})

        def api_job_grade_delete(self, grade_id: int) -> None:
            user=self.require_permission("reference.manage")
            if self.db.execute("SELECT 1 FROM employees WHERE job_grade_id=?",(grade_id,)).fetchone(): raise APIError(409,"الدرجة مرتبطة بموظفين.","reference_in_use")
            with self.db:
                result=self.db.execute("DELETE FROM job_grades WHERE id=?",(grade_id,)); audit(self.db,user["id"],"job_grade.delete","job_grade",grade_id)
            if not result.rowcount: raise APIError(404,"الدرجة غير موجودة.","not_found")
            self.send_json(200,{"ok":True})

        def api_job_titles_get(self) -> None:
            self.current_user(True); rows=self.db.execute("SELECT jt.*,d.name AS department_name FROM job_titles jt LEFT JOIN departments d ON d.id=jt.department_id ORDER BY jt.name").fetchall(); self.send_json(200,{"items":[dict(r)|{"active":bool(r["active"])} for r in rows]})

        def api_job_titles_post(self) -> None:
            user=self.require_permission("reference.manage"); data=self.read_json(); stamp=now_iso(); name=require_text(data,"name",180); department_id=as_int(data["department_id"],"department_id",1) if data.get("department_id") else None
            try:
                with self.db:
                    cur=self.db.execute("INSERT INTO job_titles(name,department_id,created_at,updated_at) VALUES(?,?,?,?)",(name,department_id,stamp,stamp))
                    seed_job_goal_templates(self.db, int(cur.lastrowid), name, stamp)
                    audit(self.db,user["id"],"job_title.create","job_title",cur.lastrowid)
            except sqlite3.IntegrityError as exc: raise APIError(409,"المسمى مستخدم.","duplicate_reference") from exc
            self.send_json(201,{"job_title":dict(self.db.execute("SELECT * FROM job_titles WHERE id=?",(cur.lastrowid,)).fetchone())})

        def api_job_title_patch(self, title_id: int) -> None:
            user=self.require_permission("reference.manage"); data=self.read_json(); existing=self.db.execute("SELECT id FROM job_titles WHERE id=?",(title_id,)).fetchone()
            if existing is None: raise APIError(404,"المسمى غير موجود.","not_found")
            values={}
            if "name" in data: values["name"]=require_text(data,"name",180)
            if "active" in data: values["active"]=1 if bool(data["active"]) else 0
            if "department_id" in data: values["department_id"]=as_int(data["department_id"],"department_id",1) if data["department_id"] else None
            if not values: raise APIError(422,"لا توجد تغييرات.","validation_error")
            values["updated_at"]=now_iso()
            try:
                with self.db:
                    self.db.execute("UPDATE job_titles SET "+",".join(f"{k}=?" for k in values)+" WHERE id=?",(*values.values(),title_id))
                    audit(self.db,user["id"],"job_title.update","job_title",title_id,values)
            except sqlite3.IntegrityError as exc: raise APIError(409,"المسمى مستخدم.","duplicate_reference") from exc
            self.send_json(200,{"job_title":dict(self.db.execute("SELECT * FROM job_titles WHERE id=?",(title_id,)).fetchone())})

        def api_job_title_delete(self, title_id: int) -> None:
            user=self.require_permission("reference.manage")
            if self.db.execute("SELECT 1 FROM employees WHERE job_title_id=?",(title_id,)).fetchone(): raise APIError(409,"المسمى مرتبط بموظفين.","reference_in_use")
            with self.db:
                result=self.db.execute("DELETE FROM job_titles WHERE id=?",(title_id,)); audit(self.db,user["id"],"job_title.delete","job_title",title_id)
            if not result.rowcount: raise APIError(404,"المسمى غير موجود.","not_found")
            self.send_json(200,{"ok":True})

        # Organization, branches and employees
        def api_org_get(self) -> None:
            user = self.current_user(False)
            row = self.db.execute("SELECT * FROM organization WHERE id=1").fetchone()
            organization = serialize_org(row)
            organization["visual_identity"] = visual_identity_payload(self.db, row, admin=False)
            if user is None:
                organization["stamp_data"] = None
            self.send_json(200, {"organization": organization})

        def api_visual_identity_admin_get(self) -> None:
            self.require_permission("org.manage")
            row = self.db.execute("SELECT * FROM organization WHERE id=1").fetchone()
            self.send_json(200, {"visual_identity": visual_identity_payload(self.db, row, admin=True)})

        def api_visual_identity_settings_patch(self) -> None:
            user = self.require_permission("org.manage")
            data = self.read_json()
            updates: dict[str, Any] = {}
            if "enabled" in data:
                if not isinstance(data["enabled"], bool):
                    raise APIError(422, "حالة تفعيل الهوية يجب أن تكون قيمة منطقية.", "validation_error", {"field": "enabled"})
                updates["visual_identity_enabled"] = 1 if data["enabled"] else 0
            if "mode" in data:
                mode = str(data["mode"])
                if mode not in {"static", "rotation"}:
                    raise APIError(422, "نمط الهوية البصرية غير صالح.", "validation_error", {"field": "mode"})
                updates["visual_identity_mode"] = mode
            if "surface" in data:
                surface = str(data["surface"])
                if surface not in {"login", "dashboard", "both"}:
                    raise APIError(422, "سطح ظهور الهوية غير صالح.", "validation_error", {"field": "surface"})
                updates["visual_identity_surface"] = surface
            if "interval_seconds" in data:
                updates["visual_identity_interval_seconds"] = as_int(data["interval_seconds"], "interval_seconds", 5, 300)
            if "overlay" in data:
                updates["visual_identity_overlay"] = as_int(data["overlay"], "overlay", 20, 90)
            if not updates:
                raise APIError(422, "لا توجد تغييرات للحفظ.", "validation_error")
            updates["updated_at"] = now_iso()
            with self.db:
                self.db.execute(
                    "UPDATE organization SET " + ",".join(f"{key}=?" for key in updates) + " WHERE id=1",
                    tuple(updates.values()),
                )
                audit(self.db, user["id"], "visual_identity.settings_update", "organization", 1, {"fields": list(updates)})
            row = self.db.execute("SELECT * FROM organization WHERE id=1").fetchone()
            self.send_json(200, {"visual_identity": visual_identity_payload(self.db, row, admin=True)})

        def parse_visual_identity_slide(self, data: dict[str, Any], current: sqlite3.Row | None = None) -> dict[str, Any]:
            values: dict[str, Any] = {}
            for key, limit in (("title_ar", 240), ("title_en", 240), ("alt_ar", 300), ("alt_en", 300)):
                if current is None or key in data:
                    values[key] = optional_text(data, key, limit)
            if current is None or "focus_position" in data:
                focus = str(data.get("focus_position") or "center")
                if focus not in {"center", "top", "bottom", "right", "left"}:
                    raise APIError(422, "نقطة تركيز الصورة غير صالحة.", "validation_error", {"field": "focus_position"})
                values["focus_position"] = focus
            if current is None or "active" in data:
                active = data.get("active", True)
                if not isinstance(active, bool):
                    raise APIError(422, "حالة الشريحة يجب أن تكون قيمة منطقية.", "validation_error", {"field": "active"})
                values["active"] = 1 if active else 0
            if "image_data" in data:
                image_data = validate_data_url(
                    data.get("image_data"), "خلفية الهوية",
                    ("image/png", "image/jpeg", "image/webp"), MAX_VISUAL_IDENTITY_IMAGE_BYTES,
                )
                values["image_data"] = image_data
                values["image_mime"] = image_data.split(";", 1)[0][5:] if image_data else None
            elif current is None:
                values["image_data"] = None
                values["image_mime"] = None
            effective = dict(current) if current is not None else {}
            effective.update(values)
            if not str(effective.get("image_data") or "") and not str(effective.get("title_ar") or "") and not str(effective.get("title_en") or ""):
                raise APIError(422, "أضف صورة أو رسالة واحدة على الأقل للشريحة.", "validation_error")
            if effective.get("image_data") and not str(effective.get("alt_ar") or effective.get("alt_en") or ""):
                raise APIError(422, "النص البديل مطلوب عند إضافة صورة.", "validation_error", {"field": "alt_ar"})
            return values

        def api_visual_identity_slide_post(self) -> None:
            user = self.require_permission("org.manage")
            data = self.read_json()
            count = int(self.db.execute("SELECT COUNT(*) FROM visual_identity_slides WHERE organization_id=1").fetchone()[0])
            if count >= 5:
                raise APIError(409, "وصلت مكتبة الهوية إلى الحد الأقصى: خمس شرائح.", "slide_limit_reached", {"max_slides": 5})
            values = self.parse_visual_identity_slide(data)
            stamp = now_iso()
            with self.db:
                cursor = self.db.execute(
                    """INSERT INTO visual_identity_slides
                       (organization_id,image_data,image_mime,title_ar,title_en,alt_ar,alt_en,focus_position,active,sort_order,created_by,created_at,updated_at)
                       VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (values["image_data"], values["image_mime"], values["title_ar"], values["title_en"],
                     values["alt_ar"], values["alt_en"], values["focus_position"], values["active"], count + 1,
                     user["id"], stamp, stamp),
                )
                audit(self.db, user["id"], "visual_identity.slide_create", "visual_identity_slide", cursor.lastrowid,
                      {"sort_order": count + 1, "has_image": bool(values["image_data"])})
            row = self.db.execute("SELECT * FROM visual_identity_slides WHERE id=?", (cursor.lastrowid,)).fetchone()
            self.send_json(201, {"slide": visual_identity_slide_payload(row)})

        def visual_identity_slide_row(self, slide_id: int) -> sqlite3.Row:
            row = self.db.execute("SELECT * FROM visual_identity_slides WHERE id=? AND organization_id=1", (slide_id,)).fetchone()
            if row is None:
                raise APIError(404, "شريحة الهوية غير موجودة.", "not_found")
            return row

        def api_visual_identity_slide_patch(self, slide_id: int) -> None:
            user = self.require_permission("org.manage")
            current = self.visual_identity_slide_row(slide_id)
            values = self.parse_visual_identity_slide(self.read_json(), current)
            if not values:
                raise APIError(422, "لا توجد تغييرات للحفظ.", "validation_error")
            values["updated_at"] = now_iso()
            with self.db:
                self.db.execute(
                    "UPDATE visual_identity_slides SET " + ",".join(f"{key}=?" for key in values) + " WHERE id=?",
                    (*values.values(), slide_id),
                )
                audit(self.db, user["id"], "visual_identity.slide_update", "visual_identity_slide", slide_id,
                      {"fields": list(values), "has_image": bool(values.get("image_data", current["image_data"]))})
            self.send_json(200, {"slide": visual_identity_slide_payload(self.visual_identity_slide_row(slide_id))})

        def api_visual_identity_order_patch(self) -> None:
            user = self.require_permission("org.manage")
            data = self.read_json()
            raw_ids = data.get("slide_ids")
            if not isinstance(raw_ids, list) or not raw_ids or len(raw_ids) > 5:
                raise APIError(422, "أرسل ترتيب الشرائح كاملاً.", "validation_error", {"field": "slide_ids"})
            try:
                slide_ids = [int(value) for value in raw_ids]
            except (TypeError, ValueError):
                raise APIError(422, "معرّفات الشرائح غير صالحة.", "validation_error", {"field": "slide_ids"})
            existing = [int(row["id"]) for row in self.db.execute("SELECT id FROM visual_identity_slides WHERE organization_id=1 ORDER BY sort_order,id")]
            if len(set(slide_ids)) != len(slide_ids) or set(slide_ids) != set(existing):
                raise APIError(409, "يجب أن يحتوي الترتيب على جميع الشرائح الحالية مرة واحدة.", "order_conflict")
            stamp = now_iso()
            with self.db:
                self.db.execute("UPDATE visual_identity_slides SET sort_order=sort_order+10 WHERE organization_id=1")
                for order, slide_id in enumerate(slide_ids, 1):
                    self.db.execute("UPDATE visual_identity_slides SET sort_order=?,updated_at=? WHERE id=?", (order, stamp, slide_id))
                audit(self.db, user["id"], "visual_identity.slides_reorder", "organization", 1, {"slide_ids": slide_ids})
            row = self.db.execute("SELECT * FROM organization WHERE id=1").fetchone()
            self.send_json(200, {"visual_identity": visual_identity_payload(self.db, row, admin=True)})

        def api_visual_identity_slide_delete(self, slide_id: int) -> None:
            user = self.require_permission("org.manage")
            current = self.visual_identity_slide_row(slide_id)
            with self.db:
                self.db.execute("DELETE FROM visual_identity_slides WHERE id=?", (slide_id,))
                self.db.execute("UPDATE visual_identity_slides SET sort_order=sort_order+10 WHERE organization_id=1")
                remaining = self.db.execute("SELECT id FROM visual_identity_slides WHERE organization_id=1 ORDER BY sort_order,id").fetchall()
                for order, row in enumerate(remaining, 1):
                    self.db.execute("UPDATE visual_identity_slides SET sort_order=? WHERE id=?", (order, row["id"]))
                audit(self.db, user["id"], "visual_identity.slide_delete", "visual_identity_slide", slide_id,
                      {"sort_order": current["sort_order"], "had_image": bool(current["image_data"])})
            self.send_json(200, {"ok": True})

        def api_org_patch(self) -> None:
            user = self.require_permission("org.manage")
            data = self.read_json()
            allowed = {
                "display_name", "legal_name", "license_no", "tax_no", "sector", "emirate",
                "address", "phone", "email", "website", "timezone", "currency",
                "general_manager_employee_id",
                "primary_color", "accent_color", "document_template", "logo_data", "stamp_data",
                "card_template", "card_primary_color", "card_accent_color", "card_back_instructions",
                "card_contact_phone", "card_contact_email",
            }
            updates: dict[str, Any] = {}
            for key in allowed:
                if key not in data:
                    continue
                if key in {"logo_data", "stamp_data"}:
                    updates[key] = validate_data_url(data[key], "الشعار" if key == "logo_data" else "الختم")
                else:
                    updates[key] = optional_text(data, key, 1200 if key == "card_back_instructions" else 500)
            if "general_manager_employee_id" in data:
                raw_gm = data.get("general_manager_employee_id")
                if raw_gm in (None, ""):
                    updates["general_manager_employee_id"] = None
                else:
                    gm_id = as_int(raw_gm, "general_manager_employee_id", 1)
                    if self.db.execute("SELECT 1 FROM employees WHERE id=? AND active=1", (gm_id,)).fetchone() is None:
                        raise APIError(422, "يجب اختيار موظف نشط ليكون المدير العام.", "invalid_general_manager")
                    updates["general_manager_employee_id"] = gm_id
            if "display_name" in updates and not updates["display_name"] or "legal_name" in updates and not updates["legal_name"]:
                raise APIError(422, "اسم العرض والاسم القانوني لا يمكن أن يكونا فارغين.", "validation_error")
            for color_key in ("primary_color", "accent_color", "card_primary_color", "card_accent_color"):
                if color_key in updates and not re.fullmatch(r"#[0-9a-fA-F]{6}", updates[color_key]):
                    raise APIError(422, "رمز اللون غير صالح.", "validation_error", {"field": color_key})
            if "document_template" in updates and updates["document_template"] not in {"corporate", "modern", "compact"}:
                raise APIError(422, "قالب الوثائق غير صالح.", "validation_error")
            if "card_template" in updates and updates["card_template"] not in CARD_TEMPLATES:
                raise APIError(422, "قالب البطاقة غير صالح.", "validation_error", {"field": "card_template"})
            if "card_contact_email" in updates and updates["card_contact_email"] and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", updates["card_contact_email"]):
                raise APIError(422, "بريد التواصل الخاص بالبطاقة غير صالح.", "validation_error", {"field": "card_contact_email"})
            current_org = self.db.execute("SELECT card_primary_color,card_accent_color,general_manager_employee_id FROM organization WHERE id=1").fetchone()
            effective_primary = updates.get("card_primary_color", current_org["card_primary_color"])
            effective_accent = updates.get("card_accent_color", current_org["card_accent_color"])
            if color_contrast(effective_primary, "#ffffff") < 4.5:
                raise APIError(422, "لون البطاقة الأساسي لا يحقق تبايناً كافياً مع النص الأبيض.", "invalid_contrast", {"field": "card_primary_color"})
            if color_contrast(effective_primary, effective_accent) < 1.35:
                raise APIError(422, "اللونان الأساسي والمساند متقاربان أكثر من اللازم.", "invalid_contrast", {"field": "card_accent_color"})
            if not updates:
                raise APIError(422, "لا توجد تغييرات للحفظ.", "validation_error")
            updates["updated_at"] = now_iso()
            previous_gm = int(current_org["general_manager_employee_id"]) if current_org and current_org["general_manager_employee_id"] else None
            with self.db:
                self.db.execute("UPDATE organization SET " + ",".join(f"{key}=?" for key in updates) + " WHERE id=1", tuple(updates.values()))
                audit(self.db, user["id"], "organization.update", "organization", 1, {"fields": list(updates)})
            if "general_manager_employee_id" in updates and previous_gm != updates["general_manager_employee_id"]:
                next_gm = int(updates["general_manager_employee_id"]) if updates["general_manager_employee_id"] else None
                fallback_rows = self.db.execute(
                    """SELECT e.id FROM employees e
                       LEFT JOIN departments d ON d.id=e.department_id
                       WHERE e.active=1 AND e.manager_id IS NULL
                         AND (d.manager_employee_id IS NULL OR d.manager_employee_id=e.id)"""
                ).fetchall()
                for fallback in fallback_rows:
                    employee_id = int(fallback["id"])
                    self.sync_manager_assignment_workflows(employee_id, previous_gm, self.direct_manager_employee_id(employee_id), int(user["id"]))
            row = self.db.execute("SELECT * FROM organization WHERE id=1").fetchone()
            organization = serialize_org(row)
            organization["visual_identity"] = visual_identity_payload(self.db, row, admin=False)
            self.send_json(200, {"organization": organization})

        def branch_row(self, branch_id: int) -> sqlite3.Row:
            row = self.db.execute(
                """SELECT b.*,e.full_name AS manager_name,
                          (SELECT COUNT(*) FROM employees x WHERE x.branch_id=b.id AND x.active=1) AS employee_count
                   FROM branches b LEFT JOIN employees e ON e.id=b.manager_employee_id WHERE b.id=?""",
                (branch_id,),
            ).fetchone()
            if row is None:
                raise APIError(404, "الفرع غير موجود.", "not_found")
            return row

        def serialize_branch(self, row: sqlite3.Row) -> dict[str, Any]:
            data = dict(row)
            data["active"] = bool(data["active"])
            return data

        def parse_branch(self, data: dict[str, Any], partial: bool = False) -> dict[str, Any]:
            result: dict[str, Any] = {}
            if not partial or "name" in data:
                result["name"] = require_text(data, "name", 150)
            if not partial or "address" in data:
                result["address"] = optional_text(data, "address", 500)
            if not partial or "latitude" in data:
                result["latitude"] = as_float(data.get("latitude"), "latitude", -90, 90)
            if not partial or "longitude" in data:
                result["longitude"] = as_float(data.get("longitude"), "longitude", -180, 180)
            if not partial or "radius_m" in data:
                result["radius_m"] = as_int(data.get("radius_m"), "radius_m", 50, 5000)
            if "manager_employee_id" in data:
                result["manager_employee_id"] = as_int(data["manager_employee_id"], "manager_employee_id", 1) if data["manager_employee_id"] not in (None, "") else None
                if result["manager_employee_id"] and not self.db.execute("SELECT 1 FROM employees WHERE id=? AND active=1", (result["manager_employee_id"],)).fetchone():
                    raise APIError(422, "مدير الفرع المحدد غير موجود.", "validation_error")
            if "active" in data:
                result["active"] = 1 if bool(data["active"]) else 0
            elif not partial:
                result["active"] = 1
            return result

        def api_branches_get(self) -> None:
            user = self.current_user(True); assert user is not None
            rows = self.db.execute(
                """SELECT b.*,e.full_name AS manager_name,
                          (SELECT COUNT(*) FROM employees x WHERE x.branch_id=b.id AND x.active=1) AS employee_count
                   FROM branches b LEFT JOIN employees e ON e.id=b.manager_employee_id ORDER BY b.active DESC,b.name"""
            ).fetchall()
            privileged = self.has_privileged_people_access(user, "employee.view")
            items = []
            for row in rows:
                data = self.serialize_branch(row)
                if not privileged:
                    data = {key: data.get(key) for key in ("id", "name", "address", "latitude", "longitude", "radius_m", "active")}
                items.append(data)
            self.send_json(200, {"items": items})

        def api_branch_get(self, branch_id: int) -> None:
            user = self.current_user(True); assert user is not None
            data = self.serialize_branch(self.branch_row(branch_id))
            if not self.has_privileged_people_access(user, "employee.view"):
                data = {key: data.get(key) for key in ("id", "name", "address", "latitude", "longitude", "radius_m", "active")}
            self.send_json(200, {"branch": data})

        def api_branches_post(self) -> None:
            user = self.require_permission("branch.manage")
            values = self.parse_branch(self.read_json())
            stamp = now_iso()
            try:
                with self.db:
                    cursor = self.db.execute(
                        "INSERT INTO branches(name,address,manager_employee_id,latitude,longitude,radius_m,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                        (values["name"], values["address"], values.get("manager_employee_id"), values["latitude"], values["longitude"], values["radius_m"], values["active"], stamp, stamp),
                    )
                    branch_id = int(cursor.lastrowid)
                    audit(self.db, user["id"], "branch.create", "branch", branch_id, values)
            except sqlite3.IntegrityError as exc:
                raise APIError(409, "يوجد فرع بالاسم نفسه.", "duplicate_branch") from exc
            self.send_json(201, {"branch": self.serialize_branch(self.branch_row(branch_id))})

        def api_branch_patch(self, branch_id: int) -> None:
            user = self.require_permission("branch.manage")
            self.branch_row(branch_id)
            values = self.parse_branch(self.read_json(), partial=True)
            if not values:
                raise APIError(422, "لا توجد تغييرات للحفظ.", "validation_error")
            values["updated_at"] = now_iso()
            try:
                with self.db:
                    self.db.execute("UPDATE branches SET " + ",".join(f"{key}=?" for key in values) + " WHERE id=?", (*values.values(), branch_id))
                    audit(self.db, user["id"], "branch.update", "branch", branch_id, values)
            except sqlite3.IntegrityError as exc:
                raise APIError(409, "يوجد فرع بالاسم نفسه أو أن البيانات غير صحيحة.", "conflict") from exc
            self.send_json(200, {"branch": self.serialize_branch(self.branch_row(branch_id))})

        def api_branch_delete(self, branch_id: int) -> None:
            user = self.require_permission("branch.manage")
            self.branch_row(branch_id)
            count = self.db.execute("SELECT COUNT(*) FROM employees WHERE branch_id=?", (branch_id,)).fetchone()[0]
            if count:
                raise APIError(409, "لا يمكن حذف الفرع لوجود موظفين مرتبطين به. انقل الموظفين أولاً.", "branch_has_employees", {"employee_count": count})
            with self.db:
                self.db.execute("DELETE FROM branches WHERE id=?", (branch_id,))
                audit(self.db, user["id"], "branch.delete", "branch", branch_id)
            self.send_json(200, {"ok": True})

        def api_branch_assign(self, branch_id: int) -> None:
            user = self.require_permission("branch.manage")
            branch = self.branch_row(branch_id)
            if not bool(branch["active"]):
                raise APIError(409, "لا يمكن تعيين موظف لفرع غير نشط.", "inactive_branch")
            data = self.read_json()
            employee_id = as_int(data.get("employee_id"), "employee_id", 1)
            if not self.db.execute("SELECT 1 FROM employees WHERE id=? AND active=1", (employee_id,)).fetchone():
                raise APIError(404, "الموظف غير موجود.", "not_found")
            with self.db:
                self.db.execute("UPDATE employees SET branch_id=?,updated_at=? WHERE id=?", (branch_id, now_iso(), employee_id))
                audit(self.db, user["id"], "branch.assign_employee", "employee", employee_id, {"branch_id": branch_id})
            employee = self.db.execute(employee_query(True) + " WHERE e.id=?", (employee_id,)).fetchone()
            self.send_json(200, {"employee": normalize_employee(employee)})

        def api_branch_location_test(self, branch_id: int) -> None:
            self.require_permission("branch.manage")
            branch = self.branch_row(branch_id)
            data = self.read_json()
            latitude = as_float(data.get("latitude"), "latitude", -90, 90)
            longitude = as_float(data.get("longitude"), "longitude", -180, 180)
            distance = haversine_m(latitude, longitude, branch["latitude"], branch["longitude"])
            self.send_json(200, {"inside": distance <= branch["radius_m"], "distance_m": round(distance, 1), "radius_m": branch["radius_m"], "branch_id": branch_id})

        # Comprehensive employee report (HR/admin only unless explicitly granted)
        def api_employee_report_search(self) -> None:
            self.require_permission("employee_report.view")
            query = str(self.query.get("q", "")).strip()
            if not query:
                self.send_json(200, {"items": []})
                return
            if len(query) > 120:
                raise APIError(422, "نص البحث أطول من الحد المسموح.", "validation_error", {"field": "q"})
            token = f"%{query}%"
            rows = self.db.execute(
                """SELECT e.id,e.employee_no,e.full_name,e.hire_date,e.active,
                          COALESCE(jt.name,e.job_title) AS job_title,d.name AS department_name
                     FROM employees e
                     LEFT JOIN job_titles jt ON jt.id=e.job_title_id
                     LEFT JOIN departments d ON d.id=e.department_id
                    WHERE e.full_name LIKE ? COLLATE NOCASE OR e.employee_no LIKE ? COLLATE NOCASE
                    ORDER BY CASE WHEN e.employee_no=? COLLATE NOCASE THEN 0 ELSE 1 END,e.active DESC,e.full_name
                    LIMIT 12""",
                (token, token, query),
            ).fetchall()
            self.send_json(200, {"items": [{**dict(row), "active": bool(row["active"])} for row in rows]})

        def employee_report_period(self, employee: sqlite3.Row, data: dict[str, Any]) -> dict[str, Any]:
            today = local_now().date()
            hire_date = parse_date(employee["hire_date"], "hire_date") if employee["hire_date"] else parse_date(str(employee["created_at"])[:10], "created_at")
            requested_from = parse_date(data.get("date_from", hire_date.isoformat()), "date_from")
            requested_to = parse_date(data.get("date_to", today.isoformat()), "date_to")
            if requested_from > requested_to:
                raise APIError(422, "تاريخ البداية يجب ألا يكون بعد تاريخ النهاية.", "invalid_report_range", {"field": "date_from"})
            if requested_from > today or requested_to > today:
                raise APIError(422, "لا يمكن إنشاء تقرير عن فترة مستقبلية.", "future_report_range", {"today": today.isoformat()})
            if (requested_to - requested_from).days > 60 * 366:
                raise APIError(422, "الفترة المطلوبة تتجاوز حد الأمان البالغ 60 عاماً.", "report_range_too_large")

            service_end = today
            service_end_source = "active_employee_today"
            if not bool(employee["active"]):
                offboarding = self.db.execute(
                    """SELECT COALESCE(closed_at,updated_at) AS ended_at
                         FROM lifecycle_cases
                        WHERE employee_id=? AND module='offboarding' AND status='closed'
                        ORDER BY COALESCE(closed_at,updated_at) DESC,id DESC LIMIT 1""",
                    (employee["id"],),
                ).fetchone()
                if offboarding and offboarding["ended_at"]:
                    service_end = parse_date(str(offboarding["ended_at"])[:10], "offboarding_end")
                    service_end_source = "closed_offboarding"
                else:
                    service_end = parse_date(str(employee["updated_at"])[:10], "employee_updated_at")
                    service_end_source = "inactive_profile_updated_at_fallback"
                service_end = min(service_end, today)

            effective_from = max(requested_from, hire_date)
            effective_to = min(requested_to, service_end)
            if effective_to < effective_from:
                raise APIError(
                    422,
                    "الفترة المطلوبة لا تتقاطع مع مدة خدمة الموظف.",
                    "report_range_outside_service",
                    {"hire_date": hire_date.isoformat(), "service_end": service_end.isoformat()},
                )
            return {
                "requested_from": requested_from,
                "requested_to": requested_to,
                "effective_from": effective_from,
                "effective_to": effective_to,
                "hire_date": hire_date,
                "service_end": service_end,
                "service_end_source": service_end_source,
                "adjusted": requested_from != effective_from or requested_to != effective_to,
            }

        def build_employee_comprehensive_report(self, employee_id: int, data: dict[str, Any], actor: dict[str, Any]) -> dict[str, Any]:
            employee = self.db.execute(
                """SELECT e.id,e.employee_no,e.full_name,e.hire_date,e.photo_data,e.active,e.gender,e.created_at,e.updated_at,
                          COALESCE(jt.name,e.job_title) AS job_title,COALESCE(jg.code,e.job_grade) AS job_grade,
                          jg.name AS job_grade_name,d.name AS department_name,b.name AS branch_name
                     FROM employees e
                     LEFT JOIN job_titles jt ON jt.id=e.job_title_id
                     LEFT JOIN job_grades jg ON jg.id=e.job_grade_id
                     LEFT JOIN departments d ON d.id=e.department_id
                     LEFT JOIN branches b ON b.id=e.branch_id
                    WHERE e.id=?""",
                (employee_id,),
            ).fetchone()
            if employee is None:
                raise APIError(404, "الموظف غير موجود.", "not_found")
            period = self.employee_report_period(employee, data)
            start: date = period["effective_from"]
            end: date = period["effective_to"]

            assignment_rows = self.db.execute(
                """SELECT a.id,a.effective_from,a.effective_to,s.*
                     FROM employee_shift_assignments a JOIN shifts s ON s.id=a.shift_id
                    WHERE a.employee_id=? AND a.effective_from<=?
                      AND (a.effective_to IS NULL OR a.effective_to>=?) AND s.active=1
                    ORDER BY a.effective_from DESC,a.id DESC""",
                (employee_id, end.isoformat(), start.isoformat()),
            ).fetchall()
            assignments: list[dict[str, Any]] = []
            for row in assignment_rows:
                item = dict(row)
                item["working_days"] = parse_json_text(item["working_days"], [])
                item["rest_days"] = parse_json_text(item["rest_days"], [])
                assignments.append(item)

            def shift_on(day: date) -> dict[str, Any] | None:
                iso = day.isoformat()
                return next((item for item in assignments if item["effective_from"] <= iso and (not item["effective_to"] or item["effective_to"] >= iso)), None)

            attendance_rows = self.db.execute(
                "SELECT * FROM attendance WHERE employee_id=? AND work_date BETWEEN ? AND ? ORDER BY work_date",
                (employee_id, start.isoformat(), end.isoformat()),
            ).fetchall()
            attendance_by_day = {row["work_date"]: row for row in attendance_rows}
            approved_leaves = self.db.execute(
                """SELECT lr.id,lr.start_date,lr.end_date,lr.days,lr.reason,lr.status,
                          lt.code AS leave_type_code,lt.name AS leave_type_name
                     FROM leave_requests lr JOIN leave_types lt ON lt.id=lr.leave_type_id
                    WHERE lr.employee_id=? AND lr.status='approved' AND lr.start_date<=? AND lr.end_date>=?
                    ORDER BY lr.start_date,lr.id""",
                (employee_id, end.isoformat(), start.isoformat()),
            ).fetchall()

            leave_dates: set[str] = set()
            leave_items: list[dict[str, Any]] = []
            for row in approved_leaves:
                overlap_start = max(start, parse_date(row["start_date"]))
                overlap_end = min(end, parse_date(row["end_date"]))
                overlap_days = (overlap_end - overlap_start).days + 1
                cursor = overlap_start
                while cursor <= overlap_end:
                    leave_dates.add(cursor.isoformat())
                    cursor += timedelta(days=1)
                leave_items.append({
                    "id": row["id"], "leave_type_code": row["leave_type_code"], "leave_type_name": row["leave_type_name"],
                    "start_date": row["start_date"], "end_date": row["end_date"], "days_in_period": overlap_days,
                    "reason": row["reason"], "status": row["status"],
                })

            attendance_items: list[dict[str, Any]] = []
            absence_dates: list[str] = []
            weekly_rest_dates: list[str] = []
            no_shift_days = 0
            net_minutes = 0
            late_minutes = 0
            completed_days = 0
            open_days = 0
            cursor = start
            while cursor <= end:
                iso = cursor.isoformat()
                shift = shift_on(cursor)
                attendance = attendance_by_day.get(iso)
                if shift is None:
                    no_shift_days += 1
                elif cursor.weekday() in shift["rest_days"]:
                    weekly_rest_dates.append(iso)
                elif (
                    cursor.weekday() in shift["working_days"]
                    and iso not in leave_dates
                    and (attendance is None or not attendance["check_in_at"])
                ):
                    absence_dates.append(iso)
                if attendance is not None:
                    metrics = self.attendance_metrics(attendance, shift)
                    is_completed = bool(attendance["check_in_at"] and attendance["check_out_at"])
                    is_open = bool(attendance["check_in_at"] and not attendance["check_out_at"])
                    if is_completed:
                        completed_days += 1
                        net_minutes += int(metrics["net_minutes"])
                        late_minutes += int(metrics["late_minutes"])
                    elif is_open:
                        open_days += 1
                    attendance_items.append({
                        "id": attendance["id"], "work_date": iso, "check_in_at": attendance["check_in_at"],
                        "check_out_at": attendance["check_out_at"], "net_minutes": int(metrics["net_minutes"]),
                        "late_minutes": int(metrics["late_minutes"]), "day_status": metrics["day_status"],
                        "shift_name": shift["name"] if shift else None,
                    })
                cursor += timedelta(days=1)

            actions = [dict(row) for row in self.db.execute(
                """SELECT id,action_type,action_date,description,penalty,status
                     FROM employee_actions
                    WHERE employee_id=? AND action_date BETWEEN ? AND ? AND status<>'cancelled'
                    ORDER BY action_date,id""",
                (employee_id, start.isoformat(), end.isoformat()),
            ).fetchall()]
            overtime = [dict(row) for row in self.db.execute(
                """SELECT id,work_date,start_time,end_time,duration_minutes,reason,status
                     FROM overtime_requests
                    WHERE employee_id=? AND status='approved' AND work_date BETWEEN ? AND ?
                    ORDER BY work_date,id""",
                (employee_id, start.isoformat(), end.isoformat()),
            ).fetchall()]

            balance_year = end.year
            balances = []
            for row in self.db.execute(
                """SELECT lt.code AS leave_type_code,lt.name AS leave_type_name,
                          COALESCE(lb.entitlement,lt.annual_entitlement) AS entitlement,
                          COALESCE(lb.carried,0) AS carried,COALESCE(lb.used,0) AS used
                     FROM leave_types lt
                     LEFT JOIN leave_balances lb ON lb.leave_type_id=lt.id AND lb.employee_id=? AND lb.year=?
                    WHERE lt.active=1 AND lt.code <> 'sick' ORDER BY lt.id""",
                (employee_id, balance_year),
            ).fetchall():
                item = dict(row)
                if item["leave_type_code"] == "maternity" and str(employee["gender"] if "gender" in employee.keys() else "unspecified").lower() != "female":
                    continue
                item["remaining"] = max(0, float(item["entitlement"] or 0) + float(item["carried"] or 0) - float(item["used"] or 0))
                balances.append(item)

            advances = []
            advance_rows = self.db.execute("SELECT * FROM advances WHERE employee_id=? ORDER BY created_at,id", (employee_id,)).fetchall()
            for advance in advance_rows:
                created_date = parse_date(str(advance["created_at"])[:10], "advance_created_at")
                active = advance["status"] in {"submitted", "approved"}
                if not active and not (start <= created_date <= end):
                    continue
                installments = self.db.execute(
                    "SELECT installment_no,due_month,amount_cents,status FROM advance_installments WHERE advance_id=? ORDER BY installment_no",
                    (advance["id"],),
                ).fetchall()
                paid_cents = sum(int(item["amount_cents"]) for item in installments if item["status"] == "paid")
                remaining_cents = sum(int(item["amount_cents"]) for item in installments if item["status"] == "scheduled")
                due_months = [str(item["due_month"]) for item in installments if item["status"] != "cancelled"]
                advances.append({
                    "id": advance["id"], "amount_cents": int(advance["amount_cents"]), "months": int(advance["months"]),
                    "reason": advance["reason"], "status": advance["status"], "created_at": advance["created_at"],
                    "paid_cents": paid_cents, "remaining_cents": remaining_cents,
                    "last_due_month": max(due_months) if due_months else None,
                    "installments": [dict(item) for item in installments],
                })

            absence_months: dict[str, int] = {}
            for value in absence_dates:
                month = value[:7]
                absence_months[month] = absence_months.get(month, 0) + 1
            issued_at = now_iso()
            reference_seed = f"{employee_id}|{start.isoformat()}|{end.isoformat()}|{actor['id']}|{issued_at}"
            reference_hash = hashlib.sha256(reference_seed.encode("utf-8")).hexdigest()[:10].upper()
            employee_token = re.sub(r"[^A-Za-z0-9]", "", str(employee["employee_no"]).upper())[-12:] or str(employee_id)
            report_reference = f"ER-{local_now().year}-{employee_token}-{reference_hash}"
            organization = self.db.execute("SELECT * FROM organization WHERE id=1").fetchone()
            total_overtime = sum(int(item["duration_minutes"]) for item in overtime)
            active_advances = [item for item in advances if item["status"] in {"submitted", "approved"}]
            return {
                "report_reference": report_reference,
                "issued_at": issued_at,
                "issued_by": {"id": actor["id"], "name": actor.get("display_name") or actor.get("name") or actor.get("email")},
                "confidentiality": "internal_confidential",
                "organization": {
                    "display_name": organization["display_name"], "legal_name": organization["legal_name"],
                    "logo_data": organization["logo_data"], "primary_color": organization["primary_color"],
                    "accent_color": organization["accent_color"], "currency": organization["currency"],
                },
                "employee": {
                    "id": employee["id"], "employee_no": employee["employee_no"], "full_name": employee["full_name"],
                    "job_title": employee["job_title"], "job_grade": employee["job_grade"],
                    "job_grade_name": employee["job_grade_name"], "department_name": employee["department_name"],
                    "branch_name": employee["branch_name"], "hire_date": period["hire_date"].isoformat(),
                    "photo_data": employee["photo_data"], "active": bool(employee["active"]),
                },
                "period": {
                    "requested_from": period["requested_from"].isoformat(), "requested_to": period["requested_to"].isoformat(),
                    "effective_from": start.isoformat(), "effective_to": end.isoformat(), "adjusted_to_service": period["adjusted"],
                    "service_end": period["service_end"].isoformat(), "service_end_source": period["service_end_source"],
                    "calendar_days": (end - start).days + 1,
                },
                "summary": {
                    "net_work_minutes": net_minutes, "attendance_completed_days": completed_days,
                    "attendance_open_days": open_days, "late_minutes": late_minutes,
                    "absence_days": len(absence_dates), "weekly_rest_days": len(weekly_rest_dates),
                    "approved_leave_days": sum(int(item["days_in_period"]) for item in leave_items),
                    "approved_overtime_minutes": total_overtime,
                    "violation_count": sum(item["action_type"] == "violation" for item in actions),
                    "undertaking_count": sum(item["action_type"] == "undertaking" for item in actions),
                    "advance_count": len(advances), "active_advance_count": len(active_advances),
                    "active_advance_remaining_cents": sum(int(item["remaining_cents"]) for item in active_advances),
                },
                "attendance": attendance_items, "leaves": leave_items,
                "leave_balances": {"year": balance_year, "items": balances},
                "actions": actions, "overtime": overtime, "advances": advances,
                "absence": {"dates": absence_dates, "by_month": [{"month": key, "days": value} for key, value in sorted(absence_months.items())]},
                "weekly_rest": {"dates": weekly_rest_dates},
                "calculation_notes": [
                    {"code": "live_sqlite_snapshot", "ar": "جميع القيم مشتقة من SQLite لحظة الإصدار.", "en": "All values are derived from SQLite at issue time."},
                    {"code": "net_completed_only", "ar": "صافي العمل يخص سجلات الدخول والخروج المكتملة بعد خصم الاستراحة.", "en": "Net work includes completed check-in/out records after the scheduled break."},
                    {"code": "absence_rule", "ar": "الغياب يحتسب في يوم عمل ذي مناوبة فقط عند غياب الحضور والإجازة المعتمدة.", "en": "Absence is counted only on a scheduled workday without attendance or approved leave."},
                    {"code": "annual_balance", "ar": f"أرصدة الإجازات سنوية لسنة {balance_year}.", "en": f"Leave balances are annual for {balance_year}."},
                ],
                "calculation_sources": {
                    "net_work_minutes": {"table": "attendance + employee_shift_assignments + shifts", "rule": "attendance_metrics.net_minutes"},
                    "absence_days": {"table": "shifts + attendance + leave_requests", "rule": "scheduled working day without attendance or approved leave"},
                    "weekly_rest_days": {"table": "employee_shift_assignments + shifts", "rule": "effective shift rest_days"},
                    "approved_leave_days": {"table": "leave_requests", "rule": "approved overlap with effective period"},
                    "actions": {"table": "employee_actions", "rule": "action_date in range and status is not cancelled"},
                    "overtime": {"table": "overtime_requests", "rule": "approved duration_minutes in range"},
                    "advances": {"table": "advances + advance_installments", "rule": "created in range or active; paid/scheduled exact cents"},
                    "no_shift_days": {"table": "employee_shift_assignments", "value": no_shift_days},
                },
            }

        def api_employee_report_generate(self, employee_id: int) -> None:
            user = self.require_permission("employee_report.view")
            report = self.build_employee_comprehensive_report(employee_id, self.read_json(), user)
            with self.db:
                audit(self.db, user["id"], "employee_report.generate", "employee", employee_id, {
                    "date_from": report["period"]["effective_from"], "date_to": report["period"]["effective_to"],
                    "report_reference": report["report_reference"],
                })
            self.send_json(200, {"report": report})

        def api_employee_report_export(self, employee_id: int) -> None:
            user = self.require_permission("employee_report.view")
            if not has_permission(self.db, user, "employee_report.export"):
                raise APIError(403, "لا تملك صلاحية طباعة أو حفظ تقرير الموظف.", "forbidden")
            data = self.read_json()
            if data.get("format") != "print_pdf":
                raise APIError(422, "صيغة التصدير المتاحة هي print_pdf فقط.", "validation_error", {"field": "format"})
            report = self.build_employee_comprehensive_report(employee_id, data, user)
            supplied_reference = str(data.get("report_reference") or report["report_reference"])
            if not re.fullmatch(r"ER-[A-Za-z0-9-]{8,80}", supplied_reference):
                raise APIError(422, "مرجع التقرير غير صالح.", "validation_error", {"field": "report_reference"})
            with self.db:
                audit(self.db, user["id"], "employee_report.export", "employee", employee_id, {
                    "date_from": report["period"]["effective_from"], "date_to": report["period"]["effective_to"],
                    "format": "print_pdf", "report_reference": supplied_reference,
                })
            self.send_json(200, {"print_authorized": True, "format": "print_pdf", "report_reference": supplied_reference})

        def api_employees_get(self) -> None:
            user = self.current_user(True)
            assert user is not None
            scope = "self"
            if self.has_privileged_people_access(user, "employee.view") or has_permission(self.db, user, "employee.profile.edit"):
                rows = self.db.execute(employee_query(has_permission(self.db, user, "salary.view")) + " ORDER BY e.full_name").fetchall()
                payload = [normalize_employee(row) for row in rows]
                scope = "all"
            elif has_permission(self.db, user, "employee.team") and user.get("employee_id"):
                rows = self.db.execute(
                    """SELECT DISTINCT e.id,e.employee_no,e.full_name
                         FROM employees e LEFT JOIN departments d ON d.id=e.department_id
                        WHERE e.active=1 AND e.id<>? AND (e.manager_id=? OR d.manager_employee_id=?)
                        ORDER BY e.full_name""",
                    (user["employee_id"], user["employee_id"], user["employee_id"]),
                ).fetchall()
                payload = [dict(row) for row in rows]
                scope = "team_identity_only"
            elif user.get("employee_id"):
                rows = self.db.execute(employee_query(True) + " WHERE e.id=?", (user["employee_id"],)).fetchall()
                payload = [normalize_employee(row) for row in rows]
            else:
                raise APIError(403, "لا تملك صلاحية عرض الموظفين.", "forbidden")
            self.send_json(200, {"items": payload, "scope": scope})

        def parse_employee(self, data: dict[str, Any], partial: bool = False) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, max_len in (("employee_no", 40), ("full_name", 180)):
                if not partial or key in data:
                    result[key] = require_text(data, key, max_len)
            for key, max_len in (
                ("email", 254), ("phone", 60), ("job_title", 180), ("job_grade", 80),
                ("qualification", 300), ("nationality", 100), ("place_of_birth", 180),
                ("passport_no", 80), ("emirates_id_no", 40), ("address_country", 100),
                ("address_city", 120), ("address_area", 120), ("address_street", 180),
                ("address_building", 120), ("address_po_box", 40), ("address_notes", 800),
            ):
                if key in data or not partial:
                    result[key] = optional_text(data, key, max_len)
            if "gender" in data or not partial:
                gender = str(data.get("gender") or "unspecified").strip().lower()
                if gender not in {"unspecified", "male", "female"}:
                    raise APIError(422, "الجنس غير صالح.", "validation_error", {"field": "gender"})
                result["gender"] = gender
            if "email" in result:
                result["email"] = clean_email(result["email"]) or None
                if result["email"] and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", result["email"]):
                    raise APIError(422, "البريد الإلكتروني غير صالح.", "validation_error", {"field": "email"})
            if result.get("passport_no") and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ./-]{3,79}", result["passport_no"]):
                raise APIError(422, "رقم جواز السفر غير صالح.", "validation_error", {"field": "passport_no"})
            if result.get("emirates_id_no") and not re.fullmatch(r"[0-9][0-9 -]{6,39}", result["emirates_id_no"]):
                raise APIError(422, "رقم الهوية الإماراتية غير صالح.", "validation_error", {"field": "emirates_id_no"})
            for key in ("department_id", "branch_id", "manager_id"):
                if key in data:
                    result[key] = as_int(data[key], key, 1) if data[key] not in (None, "") else None
            if "job_title_id" in data:
                result["job_title_id"] = as_int(data["job_title_id"], "job_title_id", 1) if data["job_title_id"] not in (None, "") else None
                if result["job_title_id"]:
                    title = self.db.execute("SELECT name FROM job_titles WHERE id=? AND active=1", (result["job_title_id"],)).fetchone()
                    if not title: raise APIError(422, "المسمى الوظيفي غير موجود أو غير نشط.", "validation_error")
                    result["job_title"] = title["name"]
            if "job_grade_id" in data:
                result["job_grade_id"] = as_int(data["job_grade_id"], "job_grade_id", 1) if data["job_grade_id"] not in (None, "") else None
                if result["job_grade_id"]:
                    grade = self.db.execute("SELECT code FROM job_grades WHERE id=? AND active=1", (result["job_grade_id"],)).fetchone()
                    if not grade: raise APIError(422, "الدرجة الوظيفية غير موجودة أو غير نشطة.", "validation_error")
                    result["job_grade"] = grade["code"]
            if "hire_date" in data:
                result["hire_date"] = parse_date(data["hire_date"], "hire_date").isoformat() if data["hire_date"] else None
            if "birth_date" in data or not partial:
                if data.get("birth_date"):
                    birth_date = parse_date(data["birth_date"], "birth_date")
                    if birth_date < date(1900, 1, 1) or birth_date > local_now().date():
                        raise APIError(422, "تاريخ الميلاد خارج النطاق المنطقي.", "validation_error", {"field": "birth_date"})
                    result["birth_date"] = birth_date.isoformat()
                else:
                    result["birth_date"] = None
            for field in ("passport_expires_on", "emirates_id_expires_on"):
                if field in data or not partial:
                    result[field] = parse_date(data[field], field).isoformat() if data.get(field) else None
                    if result[field] and result.get("birth_date") and result[field] <= result["birth_date"]:
                        raise APIError(422, "تاريخ الانتهاء يجب أن يكون بعد تاريخ الميلاد.", "validation_error", {"field": field})
            if "marital_status" in data or not partial:
                marital_status = str(data.get("marital_status") or "unspecified").strip().lower()
                if marital_status not in {"unspecified", "single", "married", "divorced", "widowed", "separated"}:
                    raise APIError(422, "الحالة الاجتماعية غير صالحة.", "validation_error", {"field": "marital_status"})
                result["marital_status"] = marital_status
            salary_component_input = any(key in data for key in (*SALARY_COMPONENT_FIELDS, "manual_allowances", "manual_allowances_json"))
            if salary_component_input or not partial:
                for key in SALARY_COMPONENT_FIELDS:
                    if key in data or not partial:
                        result[key] = as_float(data.get(key, 0), key, 0, 100_000_000)
                if "manual_allowances" in data or "manual_allowances_json" in data or not partial:
                    manual_value = data.get("manual_allowances", data.get("manual_allowances_json", []))
                    manual = normalize_manual_allowances(manual_value)
                    if isinstance(manual_value, list) and len(manual) != len(manual_value):
                        raise APIError(422, "يوجد بدل يدوي غير صالح.", "validation_error", {"field": "manual_allowances"})
                    result["manual_allowances_json"] = json_text(manual)
            if "salary" in data:
                result["salary"] = as_float(data["salary"], "salary", 0, 100_000_000)
            elif not partial:
                result["salary"] = 0
            if salary_component_input or not partial:
                manual = normalize_manual_allowances(result.get("manual_allowances_json", []))
                total = sum(float(result.get(key) or 0) for key in SALARY_COMPONENT_FIELDS) + sum(item["amount"] for item in manual)
                result["salary"] = round(total, 2)
            elif "salary" in data and not any(key in data for key in SALARY_COMPONENT_FIELDS):
                # Legacy callers can still set one gross value; it is treated
                # as the basic salary so the new breakdown remains coherent.
                result["basic_salary"] = result["salary"]
                result["housing_allowance"] = 0.0
                result["transport_allowance"] = 0.0
                result["profession_allowance"] = 0.0
                result["other_allowance"] = 0.0
                result["manual_allowances_json"] = "[]"
            if "photo_data" in data:
                result["photo_data"] = validate_data_url(data["photo_data"], "صورة الموظف")
            if "active" in data:
                result["active"] = 1 if bool(data["active"]) else 0
            elif not partial:
                result["active"] = 1
            return result

        def parse_contract_dates(self, data: dict[str, Any], current: sqlite3.Row | None = None) -> tuple[str, str] | None:
            """Validate the contract window supplied by the employee form.

            Contract dates live on the contract document so the card, document
            expiry alerts, and audit trail all use one source of truth.  The
            employee profile still exposes the dates as convenient form fields.
            """
            if not any(key in data for key in ("contract_start_on", "contract_end_on")):
                return None
            start_value = data.get("contract_start_on") if "contract_start_on" in data else (current["issued_on"] if current else None)
            end_value = data.get("contract_end_on") if "contract_end_on" in data else (current["expires_on"] if current else None)
            if not start_value or not end_value:
                raise APIError(422, "تاريخ بداية ونهاية عقد العمل مطلوبان معاً.", "contract_dates_required")
            start = parse_date(start_value, "contract_start_on").isoformat()
            end = parse_date(end_value, "contract_end_on").isoformat()
            if end < start:
                raise APIError(422, "تاريخ انتهاء العقد لا يمكن أن يسبق تاريخ بدايته.", "validation_error", {"field": "contract_end_on"})
            return start, end

        def sync_employee_contract(self, employee_id: int, dates: tuple[str, str], user_id: int, stamp: str) -> int:
            """Create or update the active contract record used by card validity.

            Profile entry is enough to create a printable PDF contract.  If HR
            later uploads a signed contract, the signed file is preserved while
            the validity dates continue to be synchronized from the profile.
            """
            start, end = dates
            row = self.db.execute(
                "SELECT * FROM employee_documents WHERE employee_id=? AND document_type='contract' AND archived=0 ORDER BY expires_on DESC,id DESC LIMIT 1",
                (employee_id,),
            ).fetchone()
            employee = self.db.execute(
                """SELECT e.*,jt.name AS job_title_name,d.name AS department_name,b.name AS branch_name
                   FROM employees e LEFT JOIN job_titles jt ON jt.id=e.job_title_id
                   LEFT JOIN departments d ON d.id=e.department_id LEFT JOIN branches b ON b.id=e.branch_id
                   WHERE e.id=?""",
                (employee_id,),
            ).fetchone()
            organization = self.db.execute("SELECT * FROM organization WHERE id=1").fetchone()
            employee_data = dict(employee or {})
            employee_data["job_title"] = employee_data.get("job_title_name") or employee_data.get("job_title") or ""
            contract_number = f"CTR-{employee_data.get('employee_no') or employee_id}-{start.replace('-', '')}"
            contract_payload = {
                "contract_number": contract_number,
                "contract_start_on": start,
                "contract_end_on": end,
                "issued_at": stamp,
                "employee": employee_data,
                "organization": dict(organization or {}),
            }
            pdf = build_employment_contract_pdf(contract_payload)
            pdf_data_url = "data:application/pdf;base64," + base64.b64encode(pdf).decode("ascii")
            generated_note = "عقد عمل منشأ آلياً من بيانات الموظف وفق نموذج الإقرار الموجز؛ يمكن استبداله بنسخة موقعة من المؤسسة."
            keep_uploaded_file = bool(row and row["data_url"] and row["mime_type"] == "application/pdf" and not str(row["notes"] or "").startswith(("سجل عقد العمل أُنشئ", "عقد عمل منشأ آلياً")))
            if row:
                if keep_uploaded_file:
                    self.db.execute("UPDATE employee_documents SET issued_on=?,expires_on=?,no_expiry=0,updated_at=? WHERE id=?", (start, end, stamp, row["id"]))
                else:
                    self.db.execute(
                        """UPDATE employee_documents SET title=?,document_number=?,issuer=?,issued_on=?,expires_on=?,no_expiry=0,
                           file_name=?,mime_type=?,data_url=?,notes=?,updated_at=? WHERE id=?""",
                        (f"عقد العمل - {employee_data.get('full_name') or ''}".strip(" -"), contract_number,
                         organization["legal_name"] if organization else "", start, end, f"employment-contract-{employee_data.get('employee_no') or employee_id}.pdf",
                         "application/pdf", pdf_data_url, generated_note, stamp, row["id"]),
                    )
                document_id = int(row["id"])
            else:
                self.db.execute(
                    """INSERT INTO employee_documents(
                           employee_id,document_type,title,document_number,issuer,issued_on,expires_on,no_expiry,
                           file_name,mime_type,data_url,notes,archived,visible_to_employee,uploaded_by,created_at,updated_at
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        employee_id, "contract", f"عقد العمل - {employee_data.get('full_name') or ''}".strip(" -"), contract_number,
                        organization["legal_name"] if organization else "", start, end, 0,
                        f"employment-contract-{employee_data.get('employee_no') or employee_id}.pdf", "application/pdf", pdf_data_url,
                        generated_note, 0, 1, user_id, stamp, stamp,
                    ),
                )
                document_id = int(self.db.execute("SELECT last_insert_rowid()").fetchone()[0])
            audit(self.db, user_id, "employee_contract.sync", "employee", employee_id, {"document_id": document_id, "issued_on": start, "expires_on": end})
            return document_id

        def api_employees_post(self) -> None:
            user = self.require_permission("employee.manage")
            data = self.read_json()
            values = self.parse_employee(data)
            contract_dates = self.parse_contract_dates(data)
            languages = self.parse_languages(data["languages"]) if "languages" in data else []
            stamp = now_iso()
            account_info: dict[str, Any] | None = None
            columns = list(values) + ["created_at", "updated_at"]
            try:
                with self.db:
                    cursor = self.db.execute(
                        f"INSERT INTO employees({','.join(columns)}) VALUES({','.join('?' for _ in columns)})",
                        (*values.values(), stamp, stamp),
                    )
                    employee_id = int(cursor.lastrowid)
                    if contract_dates:
                        self.sync_employee_contract(employee_id, contract_dates, user["id"], stamp)
                    if data.get("create_user"):
                        email = values.get("email")
                        if not email:
                            raise APIError(422, "البريد مطلوب لإنشاء حساب المستخدم.", "validation_error")
                        password = str(data.get("password", ""))
                        if len(password) < 8:
                            raise APIError(422, "كلمة المرور يجب أن تكون 8 أحرف على الأقل.", "weak_password")
                        role = str(data.get("role", "employee"))
                        if role not in ROLE_PERMISSIONS:
                            raise APIError(422, "الدور غير صالح.", "validation_error")
                        digest, salt = password_record(password)
                        account_cursor = self.db.execute(
                            "INSERT INTO users(email,display_name,role,password_hash,password_salt,employee_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                            (email, values["full_name"], role, digest, salt, employee_id, stamp, stamp),
                        )
                        account_info = {"id": int(account_cursor.lastrowid), "email": email, "role": role}
                        if role == "general_manager":
                            self.db.execute("UPDATE organization SET general_manager_employee_id=?,updated_at=? WHERE id=1", (employee_id, stamp))
                            audit(self.db, user["id"], "organization.general_manager_assign", "employee", employee_id, {"source": "employee_create"})
                    for leave in self.db.execute("SELECT id,code,annual_entitlement FROM leave_types WHERE active=1"):
                        # Annual paid leave is earned from service, never granted
                        # as an opening balance when a profile is created.
                        opening_entitlement = 0 if leave["code"] == "annual" else leave["annual_entitlement"]
                        self.db.execute("INSERT INTO leave_balances(employee_id,leave_type_id,year,entitlement) VALUES(?,?,?,?)", (employee_id, leave["id"], local_now().year, opening_entitlement))
                    self.replace_employee_languages(employee_id, languages, stamp)
                    for cycle in self.db.execute("SELECT id,announced_by FROM evaluation_cycles WHERE status='announced'").fetchall():
                        enroll_evaluation_cycle(self.db, int(cycle["id"]), cycle["announced_by"] or user["id"], notify=True)
                    audit(self.db, user["id"], "employee.create", "employee", employee_id, {"language_codes": [row["code"] for row in languages]})
            except sqlite3.IntegrityError as exc:
                raise APIError(409, "رقم الموظف أو البريد مستخدم بالفعل.", "duplicate_employee") from exc
            include_salary = user.get("employee_id") == employee_id or has_permission(self.db, user, "salary.view")
            row = self.db.execute(employee_query(include_salary, True) + " WHERE e.id=?", (employee_id,)).fetchone()
            employee = normalize_employee(row)
            assert employee is not None
            employee["languages"] = self.employee_languages(employee_id)
            self.send_json(201, {"employee": employee, "account": account_info})

        def api_employee_get(self, employee_id: int) -> None:
            user = self.current_user(True)
            assert user is not None
            is_own = user.get("employee_id") == employee_id
            can_edit_profile = has_permission(self.db, user, "employee.profile.edit")
            if not is_own and not self.has_privileged_people_access(user, "employee.view") and not can_edit_profile:
                if has_permission(self.db, user, "employee.team") and user.get("employee_id"):
                    team_member = self.team_member_row(int(user["employee_id"]), employee_id)
                    if team_member is not None:
                        self.send_json(200, {"employee": dict(team_member), "scope": "team_identity_only"})
                        return
                raise APIError(403, "لا يمكنك عرض ملف هذا الموظف.", "forbidden")
            include_salary = user.get("employee_id") == employee_id or has_permission(self.db, user, "salary.view")
            row = self.db.execute(employee_query(include_salary, True) + " WHERE e.id=?", (employee_id,)).fetchone()
            if row is None:
                raise APIError(404, "الموظف غير موجود.", "not_found")
            employee = normalize_employee(row)
            assert employee is not None
            employee["languages"] = self.employee_languages(employee_id)
            self.send_json(200, {"employee": employee, "scope": "self" if is_own else "full"})

        def employee_languages(self, employee_id: int) -> list[dict[str, Any]]:
            rows = self.db.execute(
                "SELECT code,name,flag,flag_code,proficiency,display_order FROM employee_languages WHERE employee_id=? ORDER BY display_order,id",
                (employee_id,),
            ).fetchall()
            return [dict(row) | {"proficiency_label": LANGUAGE_PROFICIENCIES[row["proficiency"]]} for row in rows]

        def parse_languages(self, value: Any) -> list[dict[str, Any]]:
            if not isinstance(value, list):
                raise APIError(422, "يجب إرسال اللغات في قائمة.", "validation_error", {"field": "languages"})
            if len(value) > len(LANGUAGE_CATALOG):
                raise APIError(422, "عدد اللغات يتجاوز القائمة المتاحة.", "validation_error", {"field": "languages"})
            parsed: list[dict[str, Any]] = []
            seen: set[str] = set()
            for index, item in enumerate(value):
                if not isinstance(item, dict):
                    raise APIError(422, "بيانات اللغة غير صالحة.", "validation_error", {"index": index})
                code = str(item.get("code", "")).strip().lower()
                proficiency = str(item.get("proficiency", "")).strip().lower()
                if code not in LANGUAGE_CATALOG:
                    raise APIError(422, "رمز اللغة غير معروف.", "unknown_language", {"code": code, "index": index})
                if proficiency not in LANGUAGE_PROFICIENCIES:
                    raise APIError(422, "مستوى إجادة اللغة غير معروف.", "unknown_proficiency", {"proficiency": proficiency, "index": index})
                if code in seen:
                    raise APIError(422, "لا يمكن تكرار اللغة نفسها.", "duplicate_language", {"code": code})
                seen.add(code)
                definition = LANGUAGE_CATALOG[code]
                parsed.append({"code": code, **definition, "proficiency": proficiency, "display_order": index})
            return parsed

        def replace_employee_languages(self, employee_id: int, languages: list[dict[str, Any]], stamp: str) -> None:
            self.db.execute("DELETE FROM employee_languages WHERE employee_id=?", (employee_id,))
            self.db.executemany(
                """INSERT INTO employee_languages(employee_id,code,name,flag,flag_code,proficiency,display_order,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                [(employee_id, row["code"], row["name"], row["flag"], row["flag_code"], row["proficiency"], row["display_order"], stamp, stamp) for row in languages],
            )

        def api_language_catalog(self) -> None:
            self.current_user(True)
            self.send_json(200, {"items": [dict(code=code, **definition) for code, definition in LANGUAGE_CATALOG.items()], "proficiencies": [{"code": code, "name": name} for code, name in LANGUAGE_PROFICIENCIES.items()]})

        def api_employee_languages_get(self, employee_id: int) -> None:
            if not self.may_access_employee(employee_id):
                raise APIError(403, "لا يمكنك عرض لغات هذا الموظف.", "forbidden")
            if not self.db.execute("SELECT 1 FROM employees WHERE id=?", (employee_id,)).fetchone():
                raise APIError(404, "الموظف غير موجود.", "not_found")
            self.send_json(200, {"items": self.employee_languages(employee_id)})

        def api_employee_languages_patch(self, employee_id: int) -> None:
            user = self.require_permission("employee.profile.edit")
            if not self.db.execute("SELECT 1 FROM employees WHERE id=?", (employee_id,)).fetchone():
                raise APIError(404, "الموظف غير موجود.", "not_found")
            languages = self.parse_languages(self.read_json().get("languages"))
            stamp = now_iso()
            with self.db:
                self.replace_employee_languages(employee_id, languages, stamp)
                audit(self.db, user["id"], "employee.languages_update", "employee", employee_id, {"codes": [row["code"] for row in languages]})
            self.send_json(200, {"items": self.employee_languages(employee_id)})

        def api_employee_patch(self, employee_id: int) -> None:
            user = self.current_user(True)
            assert user is not None
            existing_employee = self.db.execute("SELECT * FROM employees WHERE id=?", (employee_id,)).fetchone()
            if not existing_employee:
                raise APIError(404, "الموظف غير موجود.", "not_found")
            data = self.read_json()
            institution_role = data.get("institution_role")
            if institution_role is not None:
                institution_role = str(institution_role or "employee").strip().lower()
                if institution_role not in {"employee", "general_manager"}:
                    raise APIError(422, "منصب المؤسسة غير صالح.", "validation_error", {"field": "institution_role"})
                if not has_permission(self.db, user, "org.manage"):
                    raise APIError(403, "لا تملك صلاحية تعيين المدير العام.", "forbidden", {"permission": "org.manage"})
            values = self.parse_employee(data, partial=True)
            salary_touched = "salary" in data or any(key in data for key in (*SALARY_COMPONENT_FIELDS, "manual_allowances", "manual_allowances_json"))
            if salary_touched:
                merged_salary = {key: float(existing_employee[key] or 0) for key in SALARY_COMPONENT_FIELDS}
                for key in SALARY_COMPONENT_FIELDS:
                    if key in values:
                        merged_salary[key] = float(values[key] or 0)
                manual_value = values.get("manual_allowances_json", existing_employee["manual_allowances_json"])
                manual = normalize_manual_allowances(manual_value)
                for key, value in merged_salary.items():
                    values[key] = round(value, 2)
                values["manual_allowances_json"] = json_text(manual)
                values["salary"] = round(sum(merged_salary.values()) + sum(item["amount"] for item in manual), 2)
            current_contract = None
            if any(key in data for key in ("contract_start_on", "contract_end_on")):
                current_contract = self.db.execute(
                    "SELECT issued_on,expires_on FROM employee_documents WHERE employee_id=? AND document_type='contract' AND archived=0 ORDER BY expires_on DESC,id DESC LIMIT 1",
                    (employee_id,),
                ).fetchone()
            contract_dates = self.parse_contract_dates(data, current_contract)
            languages = self.parse_languages(data["languages"]) if "languages" in data else None
            profile_editor = has_permission(self.db, user, "employee.profile.edit")
            reference_only = set(values).issubset({"job_title_id", "job_title", "job_grade_id", "job_grade"}) and has_permission(self.db, user, "reference.manage")
            if contract_dates and not profile_editor:
                raise APIError(403, "لا تملك صلاحية تعديل عقد الموظف.", "forbidden", {"permission": "employee.profile.edit"})
            if not profile_editor and not reference_only:
                raise APIError(403, "لا تملك صلاحية تعديل ملف الموظف.", "forbidden", {"permission": "employee.profile.edit"})
            if "salary" in values and not has_permission(self.db, user, "salary.view"):
                raise APIError(403, "لا تملك صلاحية تعديل الراتب.", "forbidden", {"permission": "salary.view"})
            if values.get("manager_id") == employee_id:
                raise APIError(422, "لا يمكن أن يكون الموظف مديراً مباشراً لنفسه.", "validation_error")
            if not values and languages is None and contract_dates is None and institution_role is None:
                raise APIError(422, "لا توجد تغييرات للحفظ.", "validation_error")
            reporting_line_changed = "manager_id" in data or "department_id" in data
            previous_manager_id = self.direct_manager_employee_id(employee_id) if reporting_line_changed else None
            previous_general_manager = self.db.execute("SELECT general_manager_employee_id FROM organization WHERE id=1").fetchone()["general_manager_employee_id"]
            leadership_changed = institution_role is not None and (int(previous_general_manager) if previous_general_manager else None) != (employee_id if institution_role == "general_manager" else None)
            stamp = now_iso()
            if values:
                values["updated_at"] = stamp
            previous_grade = str(existing_employee["job_grade"] or "").strip()
            next_grade = str(values.get("job_grade") or previous_grade).strip()
            grade_changed = bool(next_grade and previous_grade and next_grade != previous_grade)
            try:
                with self.db:
                    if values:
                        self.db.execute("UPDATE employees SET " + ",".join(f"{k}=?" for k in values) + " WHERE id=?", (*values.values(), employee_id))
                    if languages is not None:
                        self.replace_employee_languages(employee_id, languages, stamp)
                    if contract_dates:
                        self.sync_employee_contract(employee_id, contract_dates, user["id"], stamp)
                    if institution_role is not None:
                        next_general_manager = employee_id if institution_role == "general_manager" else None
                        self.db.execute("UPDATE organization SET general_manager_employee_id=?,updated_at=? WHERE id=1", (next_general_manager, stamp))
                        if institution_role == "general_manager":
                            # A designated general manager receives the wildcard
                            # role and any old explicit overrides are cleared so
                            # the authority is genuinely complete.
                            self.db.execute("UPDATE users SET role='employee',updated_at=? WHERE employee_id=? AND role='general_manager'", (stamp, employee_id))
                            self.db.execute("UPDATE users SET role='general_manager',updated_at=? WHERE employee_id=? AND active=1", (stamp, employee_id))
                            self.db.execute("DELETE FROM user_permissions WHERE user_id IN (SELECT id FROM users WHERE employee_id=? AND role='general_manager')", (employee_id,))
                        else:
                            self.db.execute("UPDATE users SET role='employee',updated_at=? WHERE employee_id=? AND role='general_manager'", (stamp, employee_id))
                        audit(self.db, user["id"], "organization.general_manager_assign" if institution_role == "general_manager" else "organization.general_manager_clear", "employee", employee_id, {"previous_employee_id": previous_general_manager, "next_employee_id": next_general_manager})
                    if reporting_line_changed:
                        self.sync_manager_assignment_workflows(
                            employee_id,
                            previous_manager_id,
                            self.direct_manager_employee_id(employee_id),
                            int(user["id"]),
                        )
                    if grade_changed:
                        employee_account = self.db.execute("SELECT id FROM users WHERE employee_id=? AND active=1", (employee_id,)).fetchone()
                        if employee_account:
                            create_internal_notification(
                                self.db, user["id"], [int(employee_account["id"])],
                                "تهانينا بالترقية",
                                f"نبارك لك ترقيتك من الدرجة {previous_grade} إلى الدرجة {next_grade}. نتمنى لك المزيد من التقدم والنجاح في مهام عملك، وأن تكون هذه الترقية حافزاً لك لمزيد من العطاء والتميز.",
                            )
                        audit(self.db, user["id"], "employee.promotion", "employee", employee_id, {"from_grade": previous_grade, "to_grade": next_grade})
                    audit(self.db, user["id"], "employee.update", "employee", employee_id, {"fields": [key for key in values if key != "updated_at"] + (["languages"] if languages is not None else []) + (["contract_dates"] if contract_dates else []) + (["institution_role"] if institution_role is not None else []), "language_codes": [row["code"] for row in languages] if languages is not None else None})
            except sqlite3.IntegrityError as exc:
                raise APIError(409, "رقم الموظف أو البريد مستخدم بالفعل.", "duplicate_employee") from exc
            if leadership_changed:
                next_general_manager = employee_id if institution_role == "general_manager" else None
                fallback_rows = self.db.execute("SELECT e.id FROM employees e LEFT JOIN departments d ON d.id=e.department_id WHERE e.active=1 AND e.manager_id IS NULL AND (d.manager_employee_id IS NULL OR d.manager_employee_id=e.id)").fetchall()
                for fallback in fallback_rows:
                    self.sync_manager_assignment_workflows(int(fallback["id"]), int(previous_general_manager) if previous_general_manager else None, self.direct_manager_employee_id(int(fallback["id"])), int(user["id"]))
            include_salary = user.get("employee_id") == employee_id or has_permission(self.db, user, "salary.view")
            row = self.db.execute(employee_query(include_salary, True) + " WHERE e.id=?", (employee_id,)).fetchone()
            employee = normalize_employee(row)
            assert employee is not None
            employee["languages"] = self.employee_languages(employee_id)
            self.send_json(200, {"employee": employee})

        def may_view_emergency_contacts(self, employee_id: int) -> bool:
            user = self.current_user(True)
            assert user is not None
            return user.get("employee_id") == employee_id or has_permission(self.db, user, "employee.emergency.manage")

        def serialize_emergency_contact(self, row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
            result = dict(row)
            result["is_primary"] = bool(result["is_primary"])
            result["archived"] = bool(result["archived"])
            for field in ("created_by", "archived_by", "archived_at"):
                result.pop(field, None)
            return result

        def parse_emergency_contact(self, data: dict[str, Any], partial: bool = False) -> dict[str, Any]:
            values: dict[str, Any] = {}
            for key, max_len in (("full_name", 180), ("relationship", 100), ("phone", 60)):
                if key in data or not partial:
                    values[key] = require_text(data, key, max_len)
            for key, max_len in (("alternate_phone", 60), ("email", 254), ("notes", 800)):
                if key in data or not partial:
                    values[key] = optional_text(data, key, max_len)
            if "email" in values:
                values["email"] = clean_email(values["email"]) or None
                if values["email"] and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", values["email"]):
                    raise APIError(422, "البريد الإلكتروني لجهة الطوارئ غير صالح.", "validation_error", {"field": "email"})
            for field in ("phone", "alternate_phone"):
                if values.get(field) and not re.fullmatch(r"[+0-9() ./-]{5,60}", values[field]):
                    raise APIError(422, "رقم هاتف جهة الطوارئ غير صالح.", "validation_error", {"field": field})
            if "is_primary" in data:
                values["is_primary"] = 1 if bool(data["is_primary"]) else 0
            elif not partial:
                values["is_primary"] = 0
            return values

        def api_employee_emergency_contacts_get(self, employee_id: int) -> None:
            if not self.db.execute("SELECT 1 FROM employees WHERE id=?", (employee_id,)).fetchone():
                raise APIError(404, "الموظف غير موجود.", "not_found")
            if not self.may_view_emergency_contacts(employee_id):
                raise APIError(403, "لا يمكنك عرض جهات اتصال الطوارئ لهذا الموظف.", "forbidden")
            rows = self.db.execute(
                "SELECT * FROM employee_emergency_contacts WHERE employee_id=? AND archived=0 ORDER BY is_primary DESC,id",
                (employee_id,),
            ).fetchall()
            self.send_json(200, {"items": [self.serialize_emergency_contact(row) for row in rows]})

        def api_employee_emergency_contact_post(self, employee_id: int) -> None:
            user = self.require_permission("employee.emergency.manage")
            if not self.db.execute("SELECT 1 FROM employees WHERE id=?", (employee_id,)).fetchone():
                raise APIError(404, "الموظف غير موجود.", "not_found")
            values = self.parse_emergency_contact(self.read_json())
            stamp = now_iso()
            with self.db:
                active_count = int(self.db.execute(
                    "SELECT COUNT(*) FROM employee_emergency_contacts WHERE employee_id=? AND archived=0", (employee_id,)
                ).fetchone()[0])
                if active_count == 0:
                    values["is_primary"] = 1
                elif values["is_primary"]:
                    self.db.execute("UPDATE employee_emergency_contacts SET is_primary=0,updated_at=? WHERE employee_id=? AND archived=0", (stamp, employee_id))
                columns = ["employee_id", *values, "created_by", "created_at", "updated_at"]
                cursor = self.db.execute(
                    f"INSERT INTO employee_emergency_contacts({','.join(columns)}) VALUES({','.join('?' for _ in columns)})",
                    (employee_id, *values.values(), user["id"], stamp, stamp),
                )
                contact_id = int(cursor.lastrowid)
                audit(self.db, user["id"], "employee.emergency_contact.create", "employee", employee_id, {"contact_id": contact_id, "fields": sorted(values)})
            row = self.db.execute("SELECT * FROM employee_emergency_contacts WHERE id=?", (contact_id,)).fetchone()
            self.send_json(201, {"contact": self.serialize_emergency_contact(row)})

        def api_employee_emergency_contact_patch(self, contact_id: int) -> None:
            user = self.require_permission("employee.emergency.manage")
            current = self.db.execute("SELECT * FROM employee_emergency_contacts WHERE id=? AND archived=0", (contact_id,)).fetchone()
            if current is None:
                raise APIError(404, "جهة اتصال الطوارئ غير موجودة.", "not_found")
            values = self.parse_emergency_contact(self.read_json(), partial=True)
            if not values:
                raise APIError(422, "لا توجد تغييرات للحفظ.", "validation_error")
            employee_id = int(current["employee_id"])
            stamp = now_iso()
            with self.db:
                if values.get("is_primary"):
                    self.db.execute("UPDATE employee_emergency_contacts SET is_primary=0,updated_at=? WHERE employee_id=? AND id<>? AND archived=0", (stamp, employee_id, contact_id))
                values["updated_at"] = stamp
                self.db.execute("UPDATE employee_emergency_contacts SET " + ",".join(f"{key}=?" for key in values) + " WHERE id=?", (*values.values(), contact_id))
                if current["is_primary"] and values.get("is_primary") == 0:
                    replacement = self.db.execute("SELECT id FROM employee_emergency_contacts WHERE employee_id=? AND archived=0 AND id<>? ORDER BY id LIMIT 1", (employee_id, contact_id)).fetchone()
                    if replacement:
                        self.db.execute("UPDATE employee_emergency_contacts SET is_primary=1,updated_at=? WHERE id=?", (stamp, replacement["id"]))
                audit(self.db, user["id"], "employee.emergency_contact.update", "employee", employee_id, {"contact_id": contact_id, "fields": sorted(key for key in values if key != "updated_at")})
            row = self.db.execute("SELECT * FROM employee_emergency_contacts WHERE id=?", (contact_id,)).fetchone()
            self.send_json(200, {"contact": self.serialize_emergency_contact(row)})

        def api_employee_emergency_contact_delete(self, contact_id: int) -> None:
            self.require_permission("employee.emergency.manage")
            raise APIError(405, "لا يمكن حذف أو أرشفة جهة اتصال الطوارئ. استخدم التعديل فقط.", "emergency_contact_edit_only")

        def api_employee_documents_get(self, employee_id: int) -> None:
            if not self.may_access_employee(employee_id): raise APIError(403,"لا يمكنك عرض مستندات هذا الموظف.","forbidden")
            user=self.current_user(True); assert user is not None
            can_manage_documents = has_permission(self.db, user, "employee_document.manage")
            visible_only=user.get("employee_id")==employee_id and not can_manage_documents
            conditions=["employee_id=?"]; params:[Any]=[employee_id]
            # Contract PDFs are restricted records.  Employees may see the
            # contract dates in the employment panel, but never the document
            # contents or its direct download endpoint.
            if not can_manage_documents:
                conditions.append("document_type<>'contract'")
            if visible_only: conditions.append("visible_to_employee=1")
            if self.query.get("type"): conditions.append("document_type=?"); params.append(self.query["type"])
            if self.query.get("archived") in {"0","1"}: conditions.append("archived=?"); params.append(int(self.query["archived"]))
            rows=self.db.execute("SELECT * FROM employee_documents WHERE "+" AND ".join(conditions)+" ORDER BY archived,COALESCE(expires_on,'9999-12-31'),created_at DESC",params).fetchall()
            documents=[self.serialize_document(r) for r in rows]
            if self.query.get("status"): documents=[d for d in documents if d["status"]==self.query["status"]]
            alerts=[d for d in documents if d["status"] in {"expiring_soon","expired"}]
            self.send_json(200,{"items":documents,"alerts":alerts,"counts":{"total":len(documents),"expired":sum(d["status"]=="expired" for d in documents),"expiring_soon":sum(d["status"]=="expiring_soon" for d in documents)}})

        def serialize_document(self, row: sqlite3.Row | dict[str, Any], include_data: bool=False) -> dict[str, Any]:
            result=dict(row); result["visible_to_employee"]=bool(result["visible_to_employee"]); result["no_expiry"]=bool(result.get("no_expiry")); result["archived"]=bool(result.get("archived"))
            if result["archived"]: status="archived"; days_remaining=None; alert_window=None
            elif result["no_expiry"] or not result.get("expires_on"): status="no_expiry"; days_remaining=None; alert_window=None
            else:
                days_remaining=(date.fromisoformat(result["expires_on"])-local_now().date()).days
                status="expired" if days_remaining<0 else "expiring_soon" if days_remaining<=90 else "valid"
                alert_window=30 if 0<=days_remaining<=30 else 60 if 0<=days_remaining<=60 else 90 if 0<=days_remaining<=90 else None
            result.update({"status":status,"days_remaining":days_remaining,"alert_window":alert_window})
            if not include_data: result.pop("data_url",None)
            return result

        def api_employee_documents_post(self, employee_id: int) -> None:
            user=self.require_permission("employee_document.manage")
            if not self.db.execute("SELECT 1 FROM employees WHERE id=?",(employee_id,)).fetchone(): raise APIError(404,"الموظف غير موجود.","not_found")
            data=self.read_json(); document_type=str(data.get("document_type",""))
            if document_type not in DOCUMENT_TYPES: raise APIError(422,"نوع المستند غير صالح.","validation_error")
            data_url=validate_data_url(data.get("data_url"),"مستند الموظف",("image/png","image/jpeg","image/webp","application/pdf"),2_000_000)
            assert data_url is not None
            mime_type=data_url[5:data_url.index(";")]
            file_name=require_text(data,"file_name",240)
            allowed_extensions={"image/png":{".png"},"image/jpeg":{".jpg",".jpeg"},"image/webp":{".webp"},"application/pdf":{".pdf"}}
            if Path(file_name).suffix.lower() not in allowed_extensions[mime_type]:
                raise APIError(422,"امتداد الملف لا يطابق نوع محتواه.","invalid_upload")
            issued_on=parse_date(data["issued_on"],"issued_on").isoformat() if data.get("issued_on") else None
            no_expiry=bool(data.get("no_expiry")); expires_on=parse_date(data["expires_on"],"expires_on").isoformat() if data.get("expires_on") and not no_expiry else None
            if issued_on and expires_on and expires_on<issued_on: raise APIError(422,"تاريخ الانتهاء يسبق تاريخ الإصدار.","validation_error")
            if document_type=="contract" and (not issued_on or no_expiry or not expires_on): raise APIError(422,"تاريخ بداية وانتهاء عقد العمل مطلوبان لإصدار البطاقة.","contract_dates_required")
            stamp=now_iso()
            with self.db:
                title=require_text(data,"title",180)
                document_number=optional_text(data,"document_number",120)
                issuer=optional_text(data,"issuer",180)
                notes=optional_text(data,"notes",2000)
                visible=1 if data.get("visible_to_employee",True) else 0
                generated_contract = self.db.execute(
                    "SELECT id FROM employee_documents WHERE employee_id=? AND document_type='contract' AND archived=0 AND notes LIKE 'عقد عمل منشأ آلياً%' ORDER BY id DESC LIMIT 1",
                    (employee_id,),
                ).fetchone() if document_type == "contract" else None
                if generated_contract:
                    self.db.execute(
                        """UPDATE employee_documents SET title=?,document_number=?,issuer=?,issued_on=?,expires_on=?,no_expiry=?,
                           file_name=?,mime_type=?,data_url=?,notes=?,visible_to_employee=?,uploaded_by=?,updated_at=? WHERE id=?""",
                        (title, document_number, issuer, issued_on, expires_on, 1 if no_expiry else 0, file_name, mime_type, data_url,
                         notes, visible, user["id"], stamp, generated_contract["id"]),
                    )
                    document_id = int(generated_contract["id"])
                    audit(self.db,user["id"],"employee_document.replace_generated_contract","employee_document",document_id,{"employee_id":employee_id,"document_type":document_type})
                else:
                    cur=self.db.execute("""INSERT INTO employee_documents(employee_id,document_type,title,document_number,issuer,issued_on,expires_on,no_expiry,file_name,mime_type,data_url,notes,archived,visible_to_employee,uploaded_by,created_at,updated_at)
                                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(employee_id,document_type,title,document_number,issuer,issued_on,expires_on,1 if no_expiry else 0,file_name,mime_type,data_url,notes,0,visible,user["id"],stamp,stamp))
                    document_id = int(cur.lastrowid)
                    audit(self.db,user["id"],"employee_document.upload","employee_document",document_id,{"employee_id":employee_id,"document_type":document_type})
            self.send_json(201,{"document":self.serialize_document(self.db.execute("SELECT * FROM employee_documents WHERE id=?",(document_id,)).fetchone())})

        def api_document_get(self, document_id: int) -> None:
            row=self.db.execute("SELECT * FROM employee_documents WHERE id=?",(document_id,)).fetchone()
            if not row: raise APIError(404,"المستند غير موجود.","not_found")
            user=self.current_user(True); assert user is not None
            if not self.may_access_employee(row["employee_id"]): raise APIError(403,"لا يمكنك عرض هذا المستند.","forbidden")
            if row["document_type"] == "contract" and not has_permission(self.db,user,"employee_document.manage"):
                raise APIError(403,"محتوى عقد العمل متاح للموارد البشرية أو من يملك صلاحية مستندات الموظفين فقط.","contract_document_restricted")
            if user.get("employee_id")==row["employee_id"] and not row["visible_to_employee"] and not has_permission(self.db,user,"employee_document.manage"):
                raise APIError(403,"لا يمكنك عرض هذا المستند.","forbidden")
            audit(self.db,user["id"],"employee_document.view","employee_document",document_id)
            self.db.commit()
            self.send_json(200,{"document":self.serialize_document(row,True)})

        def api_document_patch(self, document_id: int) -> None:
            user=self.require_permission("employee_document.manage"); row=self.db.execute("SELECT * FROM employee_documents WHERE id=?",(document_id,)).fetchone()
            if not row: raise APIError(404,"المستند غير موجود.","not_found")
            data=self.read_json(); values={}
            for key,limit in (("title",180),("document_number",120),("issuer",180),("notes",2000)):
                if key in data: values[key]=require_text(data,key,limit) if key=="title" else optional_text(data,key,limit)
            if "document_type" in data:
                if data["document_type"] not in DOCUMENT_TYPES: raise APIError(422,"نوع المستند غير صالح.","validation_error")
                values["document_type"]=data["document_type"]
            for key in ("issued_on","expires_on"):
                if key in data: values[key]=parse_date(data[key],key).isoformat() if data[key] else None
            for key in ("no_expiry","archived","visible_to_employee"):
                if key in data: values[key]=1 if bool(data[key]) else 0
            effective_type=values.get("document_type",row["document_type"]); effective_no_expiry=bool(values.get("no_expiry",row["no_expiry"])); effective_issued=values.get("issued_on",row["issued_on"]); effective_expiry=values.get("expires_on",row["expires_on"])
            if effective_no_expiry: values["expires_on"]=None; effective_expiry=None
            if effective_issued and effective_expiry and effective_expiry < effective_issued: raise APIError(422,"تاريخ انتهاء العقد يسبق تاريخ بدايته.","validation_error")
            if effective_type=="contract" and (not effective_issued or effective_no_expiry or not effective_expiry): raise APIError(422,"تاريخ بداية وانتهاء عقد العمل مطلوبان لإصدار البطاقة.","contract_dates_required")
            if not values: raise APIError(422,"لا توجد تغييرات.","validation_error")
            values["updated_at"]=now_iso()
            with self.db:
                self.db.execute("UPDATE employee_documents SET "+",".join(f"{k}=?" for k in values)+" WHERE id=?",(*values.values(),document_id)); audit(self.db,user["id"],"employee_document.update","employee_document",document_id,values)
            self.send_json(200,{"document":self.serialize_document(self.db.execute("SELECT * FROM employee_documents WHERE id=?",(document_id,)).fetchone())})

        def api_document_delete(self, document_id: int) -> None:
            user=self.require_permission("employee_document.manage")
            with self.db:
                result=self.db.execute("DELETE FROM employee_documents WHERE id=?",(document_id,))
                if not result.rowcount: raise APIError(404,"المستند غير موجود.","not_found")
                audit(self.db,user["id"],"employee_document.delete","employee_document",document_id)
            self.send_json(200,{"ok":True})

        def api_employee_actions_get(self, employee_id: int) -> None:
            if not self.may_access_employee(employee_id): raise APIError(403,"لا يمكنك عرض سجل هذا الموظف.","forbidden")
            rows=self.db.execute("SELECT a.*,u.display_name AS created_by_name FROM employee_actions a LEFT JOIN users u ON u.id=a.created_by WHERE a.employee_id=? ORDER BY a.action_date DESC,a.id DESC",(employee_id,)).fetchall()
            self.send_json(200,{"items":[dict(r) for r in rows],"counts":{"violations":sum(r["action_type"]=="violation" for r in rows),"undertakings":sum(r["action_type"]=="undertaking" for r in rows),"open":sum(r["status"]=="open" for r in rows)}})

        def custody_employee_access(self, employee_id: int) -> dict[str, Any]:
            user = self.current_user(True)
            assert user is not None
            if user.get("employee_id") == employee_id:
                return user
            if has_permission(self.db, user, "employee_custody.view") and self.has_privileged_people_access(user, "employee.view"):
                return user
            raise APIError(403, "لا يمكنك عرض عُهد هذا الموظف.", "forbidden")

        def serialize_custody(self, row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
            result = dict(row)
            result["status"] = "returned" if result.get("returned_on") else "assigned"
            result["status_label"] = "مُسلّمة" if result["status"] == "returned" else "على عهدة الموظف"
            result["received_condition_label"] = {
                "new": "جديد", "used_clean": "مستعمل نظيف", "used_average": "مستعمل بحالة متوسطة", "used_damaged": "مستعمل تالف",
            }.get(result.get("received_condition"), result.get("received_condition", "—"))
            photos = self.db.execute(
                "SELECT id,stage,file_name,mime_type,data_url,caption,uploaded_by,created_at FROM employee_custody_photos WHERE custody_id=? ORDER BY id",
                (result["id"],),
            ).fetchall()
            result["received_photos"] = [dict(photo) for photo in photos if photo["stage"] == "received"]
            result["return_photos"] = [dict(photo) for photo in photos if photo["stage"] == "returned"]
            result["received_photo_count"] = len(result["received_photos"])
            result["return_photo_count"] = len(result["return_photos"])
            return result

        def parse_custody_photos(self, data: dict[str, Any], key: str) -> list[dict[str, str]] | None:
            if key not in data:
                return None
            raw = data.get(key)
            if raw in (None, ""):
                return []
            if not isinstance(raw, list) or len(raw) > 6:
                raise APIError(422, "يمكن إرفاق ست صور كحد أقصى لكل مرحلة.", "validation_error", {"field": key})
            photos: list[dict[str, str]] = []
            for index, item in enumerate(raw):
                if not isinstance(item, dict):
                    raise APIError(422, "بيانات صورة العهدة غير صالحة.", "validation_error", {"field": key, "index": index})
                data_url = validate_data_url(item.get("data_url"), "صورة العهدة", ("image/png", "image/jpeg", "image/webp"), 2_000_000)
                assert data_url is not None
                mime_type = data_url[5:data_url.index(";")]
                suffix = {"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp"}[mime_type]
                file_name = optional_text(item, "file_name", 240) or f"custody-{key}-{index + 1}{suffix}"
                if Path(file_name).suffix.lower() not in {".png", ".jpg", ".jpeg", ".webp"}:
                    file_name = f"custody-{key}-{index + 1}{suffix}"
                photos.append({"file_name": file_name, "mime_type": mime_type, "data_url": data_url, "caption": optional_text(item, "caption", 500)})
            return photos

        def insert_custody_photos(self, custody_id: int, stage: str, photos: list[dict[str, str]], user_id: int, stamp: str) -> None:
            self.db.executemany(
                "INSERT INTO employee_custody_photos(custody_id,stage,file_name,mime_type,data_url,caption,uploaded_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                [(custody_id, stage, photo["file_name"], photo["mime_type"], photo["data_url"], photo["caption"], user_id, stamp) for photo in photos],
            )

        def parse_custody(self, data: dict[str, Any], current: sqlite3.Row | None = None) -> dict[str, Any]:
            values: dict[str, Any] = {}
            for key, limit in (("asset_name", 180), ("asset_type", 120), ("serial_number", 180), ("return_condition", 500), ("notes", 2000)):
                if current is not None and key not in data:
                    values[key] = current[key]
                elif key == "asset_name":
                    values[key] = require_text(data, key, limit)
                else:
                    values[key] = optional_text(data, key, limit)
            condition = data.get("received_condition", current["received_condition"] if current is not None else "")
            if condition not in CUSTODY_CONDITIONS:
                raise APIError(422, "حالة العهدة عند الاستلام غير صالحة.", "validation_error", {"field": "received_condition"})
            values["received_condition"] = condition
            received_value = data.get("received_on", current["received_on"] if current is not None else None)
            if not received_value:
                raise APIError(422, "تاريخ استلام العهدة مطلوب.", "validation_error", {"field": "received_on"})
            values["received_on"] = parse_date(received_value, "received_on").isoformat()
            returned_value = data.get("returned_on", current["returned_on"] if current is not None else None)
            values["returned_on"] = parse_date(returned_value, "returned_on").isoformat() if returned_value else None
            if values["returned_on"] and values["returned_on"] < values["received_on"]:
                raise APIError(422, "تاريخ تسليم العهدة لا يمكن أن يسبق تاريخ الاستلام.", "validation_error", {"field": "returned_on"})
            if values["returned_on"] and not values["return_condition"]:
                raise APIError(422, "أدخل الحالة عند تسليم العهدة.", "return_condition_required")
            return values

        def api_employee_custody_get(self, employee_id: int) -> None:
            self.custody_employee_access(employee_id)
            rows = self.db.execute(
                "SELECT c.*,u.display_name AS created_by_name FROM employee_custody c LEFT JOIN users u ON u.id=c.created_by WHERE c.employee_id=? ORDER BY c.received_on DESC,c.id DESC",
                (employee_id,),
            ).fetchall()
            self.send_json(200, {"items": [self.serialize_custody(row) for row in rows], "counts": {"total": len(rows), "assigned": sum(not row["returned_on"] for row in rows), "returned": sum(bool(row["returned_on"]) for row in rows)}})

        def api_employee_custody_post(self, employee_id: int) -> None:
            user = self.require_permission("employee_custody.manage")
            if not self.db.execute("SELECT 1 FROM employees WHERE id=?", (employee_id,)).fetchone():
                raise APIError(404, "الموظف غير موجود.", "not_found")
            data = self.read_json()
            values = self.parse_custody(data)
            received_photos = self.parse_custody_photos(data, "received_photos") or []
            return_photos = self.parse_custody_photos(data, "return_photos") or []
            if return_photos and not values["returned_on"]:
                raise APIError(422, "أدخل تاريخ التسليم قبل إرفاق صور التسليم.", "return_date_required")
            stamp = now_iso()
            with self.db:
                cur = self.db.execute(
                    """INSERT INTO employee_custody(employee_id,asset_name,asset_type,serial_number,received_on,returned_on,received_condition,return_condition,notes,created_by,updated_by,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (employee_id, values["asset_name"], values["asset_type"], values["serial_number"], values["received_on"], values["returned_on"], values["received_condition"], values["return_condition"], values["notes"], user["id"], user["id"], stamp, stamp),
                )
                self.insert_custody_photos(cur.lastrowid, "received", received_photos, user["id"], stamp)
                self.insert_custody_photos(cur.lastrowid, "returned", return_photos, user["id"], stamp)
                audit(self.db, user["id"], "employee_custody.create", "employee_custody", cur.lastrowid, {"employee_id": employee_id, "asset_type": values["asset_type"]})
            row = self.db.execute("SELECT * FROM employee_custody WHERE id=?", (cur.lastrowid,)).fetchone()
            self.send_json(201, {"custody": self.serialize_custody(row)})

        def api_employee_custody_patch(self, custody_id: int) -> None:
            user = self.require_permission("employee_custody.manage")
            row = self.db.execute("SELECT * FROM employee_custody WHERE id=?", (custody_id,)).fetchone()
            if row is None:
                raise APIError(404, "سجل العهدة غير موجود.", "not_found")
            data = self.read_json()
            values = self.parse_custody(data, row)
            received_photos = self.parse_custody_photos(data, "received_photos")
            return_photos = self.parse_custody_photos(data, "return_photos")
            if return_photos and not values["returned_on"]:
                raise APIError(422, "أدخل تاريخ التسليم قبل إرفاق صور التسليم.", "return_date_required")
            values.update({"updated_by": user["id"], "updated_at": now_iso()})
            with self.db:
                self.db.execute("UPDATE employee_custody SET " + ",".join(f"{key}=?" for key in values) + " WHERE id=?", (*values.values(), custody_id))
                if received_photos is not None:
                    self.db.execute("DELETE FROM employee_custody_photos WHERE custody_id=? AND stage='received'", (custody_id,))
                    self.insert_custody_photos(custody_id, "received", received_photos, user["id"], values["updated_at"])
                if return_photos is not None:
                    self.db.execute("DELETE FROM employee_custody_photos WHERE custody_id=? AND stage='returned'", (custody_id,))
                    self.insert_custody_photos(custody_id, "returned", return_photos, user["id"], values["updated_at"])
                audit(self.db, user["id"], "employee_custody.update", "employee_custody", custody_id, {"employee_id": row["employee_id"], "returned": bool(values.get("returned_on"))})
            self.send_json(200, {"custody": self.serialize_custody(self.db.execute("SELECT * FROM employee_custody WHERE id=?", (custody_id,)).fetchone())})

        def api_employee_custody_print(self, custody_id: int) -> None:
            user = self.require_permission("employee_custody.print")
            row = self.db.execute("SELECT c.*,e.full_name AS employee_name,e.employee_no,o.display_name AS organization_name,o.legal_name AS organization_legal_name,o.logo_data FROM employee_custody c JOIN employees e ON e.id=c.employee_id JOIN organization o ON o.id=1 WHERE c.id=?", (custody_id,)).fetchone()
            if row is None:
                raise APIError(404, "سجل العهدة غير موجود.", "not_found")
            data = self.read_json() if int(self.headers.get("Content-Length", "0") or 0) > 0 else {}
            print_type = str(data.get("print_type", "receipt"))
            if print_type not in {"receipt", "return"}:
                raise APIError(422, "نوع سجل الطباعة غير صالح.", "validation_error", {"field": "print_type"})
            if print_type == "return" and not row["returned_on"]:
                raise APIError(409, "لا يمكن طباعة تسليم عهدة قبل تسجيل تاريخ الإرجاع.", "return_not_recorded")
            with self.db:
                audit(self.db, user["id"], "employee_custody.print", "employee_custody", custody_id, {"print_type": print_type, "employee_id": row["employee_id"]})
            self.send_json(200, {"custody": self.serialize_custody(row), "print_type": print_type, "organization": {"display_name": row["organization_name"], "legal_name": row["organization_legal_name"], "logo_data": row["logo_data"]}})

        def api_employee_actions_post(self, employee_id: int) -> None:
            user=self.require_permission("employee_action.manage"); data=self.read_json(); action_type=str(data.get("action_type",""))
            if action_type not in {"violation","undertaking"}: raise APIError(422,"نوع السجل غير صالح.","validation_error")
            attachment=None
            if data.get("attachment_data"): attachment=validate_data_url(data["attachment_data"],"مرفق السجل",("image/png","image/jpeg","image/webp","application/pdf"),2_000_000)
            stamp=now_iso(); action_date=parse_date(data.get("action_date",local_now().date().isoformat()),"action_date").isoformat()
            with self.db:
                cur=self.db.execute("INSERT INTO employee_actions(employee_id,action_type,action_date,description,penalty,attachment_data,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",(employee_id,action_type,action_date,require_text(data,"description",2000),optional_text(data,"penalty",500),attachment,user["id"],stamp,stamp))
                audit(self.db,user["id"],"employee_action.create","employee_action",cur.lastrowid,{"employee_id":employee_id,"action_type":action_type})
            self.send_json(201,{"action":dict(self.db.execute("SELECT * FROM employee_actions WHERE id=?",(cur.lastrowid,)).fetchone())})

        def api_employee_action_patch(self, action_id: int) -> None:
            user=self.require_permission("employee_action.manage"); data=self.read_json(); row=self.db.execute("SELECT * FROM employee_actions WHERE id=?",(action_id,)).fetchone()
            if not row: raise APIError(404,"السجل غير موجود.","not_found")
            values={}
            for key in ("description","penalty"):
                if key in data: values[key]=optional_text(data,key,2000 if key=="description" else 500)
            if "status" in data:
                if data["status"] not in {"open","closed","cancelled"}: raise APIError(422,"الحالة غير صالحة.","validation_error")
                values["status"]=data["status"]
                if data["status"]=="closed": values.update({"closed_by":user["id"],"closed_at":now_iso()})
            if not values: raise APIError(422,"لا توجد تغييرات.","validation_error")
            values["updated_at"]=now_iso()
            with self.db:
                self.db.execute("UPDATE employee_actions SET "+",".join(f"{k}=?" for k in values)+" WHERE id=?",(*values.values(),action_id)); audit(self.db,user["id"],"employee_action.update","employee_action",action_id,values)
            self.send_json(200,{"action":dict(self.db.execute("SELECT * FROM employee_actions WHERE id=?",(action_id,)).fetchone())})

        def employee_card_payload(self, employee_id: int) -> dict[str, Any]:
            employee = self.db.execute(employee_query(False) + " WHERE e.id=?", (employee_id,)).fetchone()
            if employee is None:
                raise APIError(404, "الموظف غير موجود.", "not_found")
            organization = self.db.execute("SELECT * FROM organization WHERE id=1").fetchone()
            org_data = serialize_org(organization)
            org_data.pop("stamp_data", None)
            contracts=self.db.execute("SELECT * FROM employee_documents WHERE employee_id=? AND document_type='contract' AND archived=0 ORDER BY expires_on DESC,id DESC",(employee_id,)).fetchall()
            today=local_now().date(); employee_data=normalize_employee(employee); assert employee_data is not None
            def contract_date(row: sqlite3.Row, key: str) -> date | None:
                try: return date.fromisoformat(row[key]) if row[key] else None
                except (TypeError, ValueError): return None
            contract=next((row for row in contracts if contract_date(row,"issued_on") and contract_date(row,"expires_on") and contract_date(row,"issued_on") <= today <= contract_date(row,"expires_on")), None)
            contract=contract or next((row for row in contracts if contract_date(row,"issued_on") and contract_date(row,"issued_on") > today), None) or (contracts[0] if contracts else None)
            if not employee_data["active"]: status,status_label,reason,valid_until="closed","مغلقة","تم إنهاء خدمة الموظف، ولا يمكن إصدار بطاقة جديدة.",None
            elif contract is None: status,status_label,reason,valid_until="not_issuable","غير قابلة للإصدار","أضف عقد عمل بتاريخ بداية وانتهاء لإصدار البطاقة.",None
            else:
                start_date=contract_date(contract,"issued_on"); end_date=contract_date(contract,"expires_on"); valid_until=contract["expires_on"]
                if not start_date or not end_date:
                    status,status_label,reason="not_issuable","غير قابلة للإصدار","يجب إدخال تاريخ بداية ونهاية عقد العمل."
                elif today < start_date:
                    status,status_label,reason="not_started","لم يبدأ العقد بعد",f"تبدأ صلاحية البطاقة في {contract['issued_on']}."
                elif today > end_date:
                    status,status_label,reason="expired","منتهية","عقد العمل المرتبط بالبطاقة منتهٍ."
                else:
                    status,status_label,reason="active","سارية", ""
            reference=f"CARD-{employee_data['employee_no']}-{employee_id:06d}"
            languages=self.employee_languages(employee_id)
            employee_data["languages"]=languages
            template=org_data.get("card_template") or "portrait_orbit"
            orientation="horizontal" if template=="executive_horizontal" else "vertical"
            dimensions={"width_mm":85.6,"height_mm":53.98} if orientation=="horizontal" else {"width_mm":53.98,"height_mm":85.6}
            contact_phone=org_data.get("card_contact_phone") or org_data.get("phone") or "غير محدد"
            contact_email=org_data.get("card_contact_email") or org_data.get("email") or "غير محدد"
            instructions=org_data.get("card_back_instructions") or DEFAULT_CARD_INSTRUCTIONS
            design={"template":template,"orientation":orientation,"dimensions_mm":dimensions,"primary_color":org_data.get("card_primary_color") or "#123d34","accent_color":org_data.get("card_accent_color") or "#c6a15b","back_instructions":instructions,"contact_phone":contact_phone,"contact_email":contact_email}
            front={"side":"front","fields":["organization","photo","full_name","job_title","employee_no","department","job_grade","languages","valid_until","reference"]}
            back={"side":"back","fields":["organization","instructions","contact_phone","contact_email","reference","status","valid_until","verification_path"]}
            return {"employee": employee_data, "organization": org_data,"status":status,"status_label":status_label,"reason":reason,"valid_from":contract["issued_on"] if contract else None,"valid_until":valid_until,"can_print":status=="active","verification_reference":reference,"verification_path":f"/api/cards/verify/{reference}","contract_document_id":contract["id"] if contract else None,"languages":languages,"design":design,"faces":{"front":front,"back":back}}

        def api_employee_card(self, employee_id: int) -> None:
            if not self.may_access_employee(employee_id):
                raise APIError(403, "لا يمكنك عرض بطاقة هذا الموظف.", "forbidden")
            self.send_json(200, {"card": self.employee_card_payload(employee_id)})

        def api_employee_card_print(self, employee_id: int) -> None:
            if not self.may_access_employee(employee_id): raise APIError(403,"لا يمكنك طباعة بطاقة هذا الموظف.","forbidden")
            user=self.current_user(True); assert user is not None; card=self.employee_card_payload(employee_id)
            data=self.read_json() if int(self.headers.get("Content-Length","0") or 0)>0 else {}
            face=str(data.get("face","both"))
            if face not in {"front","back","both"}: raise APIError(422,"وجه الطباعة غير صالح.","validation_error",{"field":"face"})
            if not card["can_print"]: raise APIError(409,card["reason"],"card_not_printable",{"status":card["status"]})
            with self.db: audit(self.db,user["id"],"employee_card.print","employee",employee_id,{"reference":card["verification_reference"],"valid_until":card["valid_until"],"face":face,"template":card["design"]["template"]})
            self.send_json(200,{"card":card,"print_authorized":True,"print_face":face})

        def api_card_verify(self, reference: str) -> None:
            user = self.current_user(True); assert user is not None
            try: employee_id=int(reference.rsplit("-",1)[1])
            except (IndexError,ValueError): raise APIError(404,"مرجع البطاقة غير موجود.","not_found")
            if employee_id != user.get("employee_id") and not self.has_privileged_people_access(user, "employee.view"):
                raise APIError(403, "لا يمكنك التحقق من بطاقة موظف آخر.", "forbidden")
            card=self.employee_card_payload(employee_id)
            if not hmac.compare_digest(card["verification_reference"],reference): raise APIError(404,"مرجع البطاقة غير موجود.","not_found")
            self.send_json(200,{"verification":{"reference":reference,"status":card["status"],"status_label":card["status_label"],"valid_from":card["valid_from"],"valid_until":card["valid_until"],"employee_no":card["employee"]["employee_no"],"full_name":card["employee"]["full_name"],"organization":card["organization"]["display_name"]}})

        def api_my_card(self) -> None:
            self.send_json(200, {"card": self.employee_card_payload(self.own_employee_id())})

        def api_my_dashboard(self) -> None:
            user = self.current_user(True)
            assert user is not None
            employee_id = self.own_employee_id()
            employee = self.db.execute(employee_query(True) + " WHERE e.id=?", (employee_id,)).fetchone()
            org = self.db.execute("SELECT * FROM organization WHERE id=1").fetchone()
            year = local_now().year
            balances = self.leave_balance_rows(employee_id, year)
            attendance = self.db.execute("SELECT * FROM attendance WHERE employee_id=? AND work_date=?", (employee_id, local_now().date().isoformat())).fetchone()
            overtime = self.db.execute("SELECT * FROM overtime_requests WHERE employee_id=? ORDER BY created_at DESC LIMIT 10", (employee_id,)).fetchall()
            leaves = self.db.execute("SELECT lr.*,lt.name AS leave_type_name FROM leave_requests lr JOIN leave_types lt ON lt.id=lr.leave_type_id WHERE lr.employee_id=? ORDER BY lr.created_at DESC LIMIT 10", (employee_id,)).fetchall()
            evaluation = self.db.execute("SELECT e.*,c.year,c.name AS cycle_name FROM evaluations e JOIN evaluation_cycles c ON c.id=e.cycle_id WHERE e.employee_id=? ORDER BY c.year DESC LIMIT 1", (employee_id,)).fetchone()
            gross_cents = money_cents(salary_breakdown_from_row(employee)["total"], "salary")
            payroll_month = local_now().strftime("%Y-%m")
            current_payroll = self.db.execute(
                """SELECT i.basic_cents,i.allowances_cents,i.deductions_cents,i.advance_cents,i.net_cents
                     FROM payroll_items i JOIN payroll_runs r ON r.id=i.run_id
                    WHERE i.employee_id=? AND r.payroll_month=? AND r.status IN ('approved','paid')
                    ORDER BY r.id DESC LIMIT 1""",
                (employee_id, payroll_month),
            ).fetchone()
            if current_payroll:
                salary_snapshot = {
                    "month": payroll_month,
                    "gross": cents_value(int(current_payroll["basic_cents"]) + int(current_payroll["allowances_cents"])),
                    "advance": cents_value(current_payroll["advance_cents"]),
                    "net": cents_value(current_payroll["net_cents"]),
                }
            else:
                scheduled = self.db.execute(
                    """SELECT COALESCE(SUM(ai.amount_cents),0)
                         FROM advance_installments ai JOIN advances a ON a.id=ai.advance_id
                        WHERE a.employee_id=? AND a.status='approved'
                          AND ai.due_month=? AND ai.status='scheduled'""",
                    (employee_id, payroll_month),
                ).fetchone()[0]
                advance_cents = int(scheduled or 0)
                salary_snapshot = {
                    "month": payroll_month, "gross": cents_value(gross_cents),
                    "advance": cents_value(advance_cents),
                    "net": cents_value(max(0, gross_cents - advance_cents)),
                }
            unread = self.db.execute(
                """SELECT COUNT(*) FROM notification_recipients r
                   JOIN notifications n ON n.id=r.notification_id
                   WHERE r.user_id=? AND r.read_at IS NULL
                     AND (n.available_at IS NULL OR n.available_at<=?)""",
                (user["id"], now_iso()),
            ).fetchone()[0]
            self.send_json(200, {
                "employee": normalize_employee(employee), "organization": serialize_org(org), "salary": salary_snapshot,
                "leave_balances": balances, "attendance_today": row_dict(attendance),
                "overtime_requests": [dict(r) for r in overtime], "leave_requests": [self.leave_request_payload(r, user) for r in leaves],
                "evaluation": row_dict(evaluation), "notifications_unread": unread,
            })

        # Attendance and work shifts
        def shift_for_employee(self, employee_id: int, work_date: date) -> dict[str, Any] | None:
            row = self.db.execute(
                """SELECT s.*,a.effective_from,a.effective_to
                   FROM employee_shift_assignments a JOIN shifts s ON s.id=a.shift_id
                   WHERE a.employee_id=? AND a.effective_from<=?
                     AND (a.effective_to IS NULL OR a.effective_to>=?) AND s.active=1
                   ORDER BY a.effective_from DESC,a.id DESC LIMIT 1""",
                (employee_id, work_date.isoformat(), work_date.isoformat()),
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["working_days"] = parse_json_text(result["working_days"], [])
            result["rest_days"] = parse_json_text(result["rest_days"], [])
            result["active"] = bool(result["active"])
            return result

        def attendance_metrics(self, row: sqlite3.Row, shift: dict[str, Any] | None, approved_overtime: int = 0) -> dict[str, Any]:
            result = dict(row)
            result.update({"shift": shift, "required_minutes": 0, "late_minutes": 0, "early_minutes": 0, "gross_minutes": 0, "net_minutes": 0, "approved_overtime_minutes": approved_overtime, "day_status": "working_day"})
            work_day = date.fromisoformat(row["work_date"])
            if shift is None:
                result["day_status"] = "no_shift"
            elif work_day.weekday() in shift["rest_days"]:
                result["day_status"] = "weekly_rest"
            else:
                result["required_minutes"] = int(shift["daily_limit_minutes"])
            check_in = datetime.fromisoformat(row["check_in_at"]) if row["check_in_at"] else None
            check_out = datetime.fromisoformat(row["check_out_at"]) if row["check_out_at"] else None
            if check_in and check_out:
                gross = max(0, int((check_out - check_in).total_seconds() // 60))
                result["gross_minutes"] = gross
                result["net_minutes"] = max(0, gross - (int(shift["break_minutes"]) if shift else 0))
            elif check_in:
                result["day_status"] = "open"
            elif result["day_status"] == "working_day":
                result["day_status"] = "absent"
            if shift and check_in and work_day.weekday() not in shift["rest_days"]:
                expected_start = datetime.combine(work_day, parse_clock(shift["start_time"], "start_time"), UAE_TZ)
                grace_end = expected_start + timedelta(minutes=int(shift["grace_minutes"]))
                result["late_minutes"] = max(0, int((check_in - grace_end).total_seconds() // 60))
                if check_out:
                    expected_end = datetime.combine(work_day, parse_clock(shift["end_time"], "end_time"), UAE_TZ)
                    if expected_end <= expected_start:
                        expected_end += timedelta(days=1)
                    result["early_minutes"] = max(0, int((expected_end - check_out).total_seconds() // 60))
            return result

        def api_attendance_punch(self) -> None:
            user = self.current_user(True)
            assert user is not None
            employee_id = self.own_employee_id()
            data = self.read_json()
            action = str(data.get("action", ""))
            if action not in {"check_in", "check_out"}:
                raise APIError(422, "نوع التسجيل يجب أن يكون check_in أو check_out.", "validation_error")
            latitude = as_float(data.get("latitude"), "latitude", -90, 90)
            longitude = as_float(data.get("longitude"), "longitude", -180, 180)
            accuracy = as_float(data.get("accuracy", 0), "accuracy", 0, 100_000)
            employee = self.db.execute("SELECT branch_id,active FROM employees WHERE id=?", (employee_id,)).fetchone()
            if not employee or not bool(employee["active"]):
                raise APIError(403, "ملف الموظف غير نشط.", "inactive_employee")
            branch = self.db.execute("SELECT * FROM branches WHERE id=?", (employee["branch_id"],)).fetchone() if employee["branch_id"] else None
            if branch is None or not bool(branch["active"]):
                with self.db:
                    self.db.execute("INSERT INTO attendance_attempts(employee_id,branch_id,action,latitude,longitude,accuracy,accepted,reason,created_at) VALUES(?,?,?,?,?,?,0,?,?)", (employee_id, employee["branch_id"], action, latitude, longitude, accuracy, "no_active_branch", now_iso()))
                raise APIError(403, "لا يوجد فرع نشط مرتبط بملفك. راجع الموارد البشرية.", "no_active_branch")
            distance = haversine_m(latitude, longitude, branch["latitude"], branch["longitude"])
            inside = distance <= branch["radius_m"]
            stamp = local_now().isoformat(timespec="seconds")
            with self.db:
                self.db.execute(
                    "INSERT INTO attendance_attempts(employee_id,branch_id,action,latitude,longitude,accuracy,distance_m,accepted,reason,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (employee_id, branch["id"], action, latitude, longitude, accuracy, round(distance, 2), int(inside), None if inside else "outside_geofence", stamp),
                )
            if not inside:
                raise APIError(
                    403,
                    f"أنت خارج نطاق فرع «{branch['name']}». المسافة الحالية {round(distance)} م، والنطاق المطلوب {branch['radius_m']} م.",
                    "outside_geofence",
                    {"distance_m": round(distance, 1), "radius_m": branch["radius_m"], "branch": branch["name"]},
                )
            work_date = local_now().date().isoformat()
            current = self.db.execute("SELECT * FROM attendance WHERE employee_id=? AND work_date=?", (employee_id, work_date)).fetchone()
            with self.db:
                if action == "check_in":
                    if current and current["check_in_at"]:
                        raise APIError(409, "تم تسجيل الدخول لهذا اليوم بالفعل.", "already_checked_in")
                    if current:
                        self.db.execute("UPDATE attendance SET check_in_at=?,check_in_lat=?,check_in_lng=?,check_in_accuracy=?,check_in_distance_m=?,updated_at=? WHERE id=?", (stamp, latitude, longitude, accuracy, round(distance, 2), stamp, current["id"]))
                    else:
                        self.db.execute("INSERT INTO attendance(employee_id,work_date,branch_id,check_in_at,check_in_lat,check_in_lng,check_in_accuracy,check_in_distance_m,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (employee_id, work_date, branch["id"], stamp, latitude, longitude, accuracy, round(distance, 2), stamp, stamp))
                else:
                    if not current or not current["check_in_at"]:
                        raise APIError(409, "يجب تسجيل الدخول قبل تسجيل الخروج.", "not_checked_in")
                    if current["check_out_at"]:
                        raise APIError(409, "تم تسجيل الخروج لهذا اليوم بالفعل.", "already_checked_out")
                    self.db.execute("UPDATE attendance SET check_out_at=?,check_out_lat=?,check_out_lng=?,check_out_accuracy=?,check_out_distance_m=?,updated_at=? WHERE id=?", (stamp, latitude, longitude, accuracy, round(distance, 2), stamp, current["id"]))
                audit(self.db, user["id"], f"attendance.{action}", "employee", employee_id, {"branch_id": branch["id"], "distance_m": round(distance, 2)})
            saved = self.db.execute("SELECT * FROM attendance WHERE employee_id=? AND work_date=?", (employee_id, work_date)).fetchone()
            shift = self.shift_for_employee(employee_id, date.fromisoformat(work_date))
            overtime = self.db.execute("SELECT COALESCE(SUM(duration_minutes),0) FROM overtime_requests WHERE employee_id=? AND work_date=? AND status='approved'", (employee_id, work_date)).fetchone()[0]
            self.send_json(200, {"attendance": self.attendance_metrics(saved, shift, overtime), "distance_m": round(distance, 1)})

        def api_attendance_daily(self) -> None:
            user = self.current_user(True)
            assert user is not None
            work_date = parse_date(self.query.get("date", local_now().date().isoformat())).isoformat()
            employee_filter = self.query.get("employee_id")
            params: list[Any] = []
            conditions = ["e.active=1"]
            broad_scope = self.has_privileged_people_access(user, "attendance.view")
            team_scope = bool(not broad_scope and has_permission(self.db, user, "attendance.team") and user.get("employee_id"))
            response_scope = "all" if broad_scope else "team_attendance" if team_scope else "self"
            if employee_filter:
                employee_id = as_int(employee_filter, "employee_id", 1)
                is_own = employee_id == user.get("employee_id")
                is_team_member = bool(team_scope and self.team_member_row(int(user["employee_id"]), employee_id))
                if not is_own and not broad_scope and not is_team_member:
                    raise APIError(403, "لا يمكنك عرض حضور هذا الموظف.", "forbidden")
                conditions.append("e.id=?")
                params.append(employee_id)
                response_scope = "self" if is_own else "all" if broad_scope else "team_attendance"
            elif broad_scope:
                pass
            elif team_scope:
                conditions.append("e.id<>? AND (e.manager_id=? OR EXISTS (SELECT 1 FROM departments td WHERE td.id=e.department_id AND td.manager_employee_id=?))")
                params.extend([user["employee_id"], user["employee_id"], user["employee_id"]])
            else:
                conditions.append("e.id=?")
                params.append(self.own_employee_id())
            employees = self.db.execute(
                "SELECT e.id,e.employee_no,e.full_name,e.branch_id,b.name AS branch_name FROM employees e LEFT JOIN branches b ON b.id=e.branch_id WHERE " + " AND ".join(conditions) + " ORDER BY e.full_name",
                params,
            ).fetchall()
            items = []
            for employee in employees:
                attendance = self.db.execute("SELECT * FROM attendance WHERE employee_id=? AND work_date=?", (employee["id"], work_date)).fetchone()
                if attendance:
                    source = dict(attendance)
                else:
                    source = {
                        "id": None, "employee_id": employee["id"], "work_date": work_date,
                        "branch_id": employee["branch_id"], "check_in_at": None, "check_out_at": None,
                        "check_in_lat": None, "check_in_lng": None, "check_in_accuracy": None,
                        "check_in_distance_m": None, "check_out_lat": None, "check_out_lng": None,
                        "check_out_accuracy": None, "check_out_distance_m": None, "decision": "missing",
                        "rejection_reason": None, "created_at": None, "updated_at": None,
                    }
                source.update({"employee_no": employee["employee_no"], "full_name": employee["full_name"], "branch_name": employee["branch_name"]})
                shift = self.shift_for_employee(employee["id"], date.fromisoformat(work_date))
                overtime = self.db.execute("SELECT COALESCE(SUM(duration_minutes),0) FROM overtime_requests WHERE employee_id=? AND work_date=? AND status='approved'", (employee["id"], work_date)).fetchone()[0]
                metrics = self.attendance_metrics(source, shift, overtime)
                if response_scope == "team_attendance":
                    items.append({
                        "id": employee["id"], "employee_no": employee["employee_no"],
                        "full_name": employee["full_name"], "work_date": work_date,
                        "check_in_at": metrics.get("check_in_at"), "check_out_at": metrics.get("check_out_at"),
                    })
                else:
                    items.append(metrics)
            self.send_json(200, {"date": work_date, "scope": response_scope, "items": items})

        def attendance_range_payload(self, user: dict[str, Any]) -> dict[str, Any]:
            today = local_now().date()
            date_from = parse_date(self.query.get("date_from", today.replace(day=1).isoformat()), "date_from")
            date_to = parse_date(self.query.get("date_to", today.isoformat()), "date_to")
            if date_from > date_to:
                raise APIError(400, "تاريخ البداية يجب ألا يكون بعد تاريخ النهاية.", "invalid_date_range", {"field": "date_from"})
            if date_to > today:
                raise APIError(422, "لا يمكن أن تنتهي فترة الحضور في تاريخ مستقبلي.", "validation_error", {"field": "date_to"})
            if (date_to - date_from).days > 366:
                raise APIError(422, "فترة الحضور لا يمكن أن تتجاوز 367 يوماً.", "validation_error", {"field": "date_from"})

            employee_filter = self.query.get("employee_id")
            params: list[Any] = []
            conditions = ["e.active=1"]
            broad_scope = self.has_privileged_people_access(user, "attendance.view")
            team_scope = bool(not broad_scope and has_permission(self.db, user, "attendance.team") and user.get("employee_id"))
            response_scope = "all" if broad_scope else "team_attendance" if team_scope else "self"
            if employee_filter:
                employee_id = as_int(employee_filter, "employee_id", 1)
                is_own = employee_id == user.get("employee_id")
                is_team_member = bool(team_scope and self.team_member_row(int(user["employee_id"]), employee_id))
                if not is_own and not broad_scope and not is_team_member:
                    raise APIError(403, "لا يمكنك عرض حضور هذا الموظف.", "forbidden")
                conditions.append("e.id=?")
                params.append(employee_id)
                response_scope = "self" if is_own else "all" if broad_scope else "team_attendance"
            elif broad_scope:
                pass
            elif team_scope:
                conditions.append("e.id<>? AND (e.manager_id=? OR EXISTS (SELECT 1 FROM departments td WHERE td.id=e.department_id AND td.manager_employee_id=?))")
                params.extend([user["employee_id"], user["employee_id"], user["employee_id"]])
            else:
                conditions.append("e.id=?")
                params.append(self.own_employee_id())

            q = str(self.query.get("q", "")).strip()
            if len(q) > 120:
                raise APIError(422, "عبارة البحث طويلة جداً.", "validation_error", {"field": "q"})
            department_filter = as_int(self.query["department_id"], "department_id", 1) if self.query.get("department_id") else None
            branch_filter = as_int(self.query["branch_id"], "branch_id", 1) if self.query.get("branch_id") else None
            status_filter = str(self.query.get("status", "")).strip()
            allowed_statuses = {"", "present", "open", "late", "absent", "weekly_rest", "approved_leave", "no_shift"}
            if status_filter not in allowed_statuses:
                raise APIError(422, "حالة الحضور المطلوبة غير صالحة.", "validation_error", {"field": "status"})
            if response_scope == "team_attendance" and (department_filter or branch_filter or status_filter):
                raise APIError(403, "فلاتر القسم والفرع والحالة غير متاحة في عرض أوقات الفريق المحدود.", "forbidden")
            if q:
                conditions.append("(LOWER(e.full_name) LIKE LOWER(?) OR LOWER(e.employee_no) LIKE LOWER(?))")
                params.extend([f"%{q}%", f"%{q}%"])
            if department_filter:
                conditions.append("e.department_id=?")
                params.append(department_filter)
            if branch_filter:
                conditions.append("e.branch_id=?")
                params.append(branch_filter)
            employees = self.db.execute(
                "SELECT e.id,e.employee_no,e.full_name,e.branch_id,e.department_id,e.hire_date,b.name AS branch_name,d.name AS department_name FROM employees e LEFT JOIN branches b ON b.id=e.branch_id LEFT JOIN departments d ON d.id=e.department_id WHERE "
                + " AND ".join(conditions) + " ORDER BY e.full_name", params,
            ).fetchall()
            employee_ids = [int(employee["id"]) for employee in employees]
            attendance_by_key: dict[tuple[int, str], sqlite3.Row] = {}
            overtime_by_key: dict[tuple[int, str], int] = {}
            approved_leave_days: set[tuple[int, str]] = set()
            if employee_ids:
                placeholders = ",".join("?" for _ in employee_ids)
                for row in self.db.execute(
                    f"SELECT * FROM attendance WHERE employee_id IN ({placeholders}) AND work_date BETWEEN ? AND ?",
                    (*employee_ids, date_from.isoformat(), date_to.isoformat()),
                ).fetchall():
                    attendance_by_key[(int(row["employee_id"]), row["work_date"])] = row
                for row in self.db.execute(
                    f"SELECT employee_id,work_date,COALESCE(SUM(duration_minutes),0) AS minutes FROM overtime_requests WHERE employee_id IN ({placeholders}) AND work_date BETWEEN ? AND ? AND status='approved' GROUP BY employee_id,work_date",
                    (*employee_ids, date_from.isoformat(), date_to.isoformat()),
                ).fetchall():
                    overtime_by_key[(int(row["employee_id"]), row["work_date"])] = int(row["minutes"] or 0)
                leave_rows = self.db.execute(
                    f"SELECT employee_id,start_date,end_date FROM leave_requests WHERE employee_id IN ({placeholders}) AND status='approved' AND start_date<=? AND end_date>=?",
                    (*employee_ids, date_to.isoformat(), date_from.isoformat()),
                ).fetchall()
                for leave in leave_rows:
                    cursor = max(date_from, date.fromisoformat(leave["start_date"]))
                    leave_end = min(date_to, date.fromisoformat(leave["end_date"]))
                    while cursor <= leave_end:
                        approved_leave_days.add((int(leave["employee_id"]), cursor.isoformat()))
                        cursor += timedelta(days=1)

            items: list[dict[str, Any]] = []
            summary = {
                "work_days": 0, "net_work_minutes": 0, "late_minutes": 0,
                "absence_days": 0, "weekly_rest_days": 0, "leave_days": 0,
                "approved_overtime_minutes": 0, "attendance_records": 0,
                "expected_employee_days": 0, "present_days": 0, "open_days": 0, "late_days": 0,
            }
            cursor = date_from
            while cursor <= date_to:
                work_date = cursor.isoformat()
                for employee in employees:
                    employee_id = int(employee["id"])
                    attendance = attendance_by_key.get((employee_id, work_date))
                    if employee["hire_date"] and cursor < date.fromisoformat(employee["hire_date"]) and attendance is None:
                        continue
                    if response_scope == "team_attendance" and attendance is None:
                        continue
                    source: dict[str, Any]
                    if attendance is not None:
                        source = dict(attendance)
                    else:
                        source = {
                            "id": None, "employee_id": employee_id, "work_date": work_date,
                            "branch_id": employee["branch_id"], "check_in_at": None, "check_out_at": None,
                        }
                    if response_scope == "team_attendance":
                        if attendance is not None:
                            summary["attendance_records"] += 1
                        items.append({
                            "id": source.get("id"), "employee_id": employee_id,
                            "employee_no": employee["employee_no"], "full_name": employee["full_name"],
                            "work_date": work_date, "check_in_at": source.get("check_in_at"),
                            "check_out_at": source.get("check_out_at"),
                        })
                        continue
                    shift = self.shift_for_employee(employee_id, cursor)
                    approved_overtime = overtime_by_key.get((employee_id, work_date), 0)
                    metrics = self.attendance_metrics(source, shift, approved_overtime)
                    has_leave = (employee_id, work_date) in approved_leave_days
                    if has_leave and not metrics.get("check_in_at") and metrics["day_status"] in {"working_day", "absent"}:
                        metrics["day_status"] = "approved_leave"
                    metrics.update({
                        "employee_no": employee["employee_no"], "full_name": employee["full_name"],
                        "branch_name": employee["branch_name"], "department_name": employee["department_name"], "approved_leave": has_leave,
                    })
                    matches_status = (
                        not status_filter
                        or (status_filter == "present" and bool(metrics.get("check_in_at")))
                        or (status_filter == "late" and int(metrics.get("late_minutes") or 0) > 0)
                        or status_filter == metrics["day_status"]
                    )
                    if not matches_status:
                        continue
                    if attendance is not None:
                        summary["attendance_records"] += 1
                    summary["net_work_minutes"] += int(metrics["net_minutes"])
                    summary["late_minutes"] += int(metrics["late_minutes"])
                    summary["approved_overtime_minutes"] += int(metrics["approved_overtime_minutes"])
                    if metrics["required_minutes"]:
                        summary["work_days"] += 1
                        summary["expected_employee_days"] += 1
                    if metrics.get("check_in_at"):
                        summary["present_days"] += 1
                    if metrics["day_status"] == "open":
                        summary["open_days"] += 1
                    if int(metrics.get("late_minutes") or 0) > 0:
                        summary["late_days"] += 1
                    if metrics["day_status"] == "absent":
                        summary["absence_days"] += 1
                    elif metrics["day_status"] == "weekly_rest":
                        summary["weekly_rest_days"] += 1
                    elif metrics["day_status"] == "approved_leave":
                        summary["leave_days"] += 1
                    items.append(metrics)
                cursor += timedelta(days=1)
            if response_scope == "team_attendance":
                summary = {"attendance_records": summary["attendance_records"]}
            filter_options: dict[str, list[dict[str, Any]]] = {"employees": []}
            if response_scope in {"all", "team_attendance"}:
                filter_options["employees"] = [
                    {"id": int(employee["id"]), "employee_no": employee["employee_no"], "full_name": employee["full_name"]}
                    for employee in employees
                ]
            if response_scope == "all":
                filter_options["departments"] = [
                    {"id": int(value[0]), "name": value[1]}
                    for value in sorted({(employee["department_id"], employee["department_name"]) for employee in employees if employee["department_id"]}, key=lambda item: item[1] or "")
                ]
                filter_options["branches"] = [
                    {"id": int(value[0]), "name": value[1]}
                    for value in sorted({(employee["branch_id"], employee["branch_name"]) for employee in employees if employee["branch_id"]}, key=lambda item: item[1] or "")
                ]
            return {
                "date_from": date_from.isoformat(), "date_to": date_to.isoformat(),
                "scope": response_scope, "employee_count": len(employees), "summary": summary, "items": items,
                "filters": {"q": q, "employee_id": employee_filter or None, "department_id": department_filter, "branch_id": branch_filter, "status": status_filter},
                "filter_options": filter_options,
            }

        def api_attendance_range(self) -> None:
            user = self.current_user(True)
            assert user is not None
            self.send_json(200, self.attendance_range_payload(user))

        def api_attendance_range_csv(self) -> None:
            user = self.require_permission("attendance.export")
            payload = self.attendance_range_payload(user)
            if payload["scope"] == "team_attendance":
                rows: list[list[Any]] = [["التاريخ", "اسم الموظف", "الرقم الوظيفي", "تسجيل الدخول", "تسجيل الخروج"]]
                rows.extend([[item["work_date"], item["full_name"], item["employee_no"], item.get("check_in_at") or "", item.get("check_out_at") or ""] for item in payload["items"]])
            else:
                rows = [["التاريخ", "اسم الموظف", "الرقم الوظيفي", "القسم", "الفرع", "المناوبة", "الدخول", "الخروج", "صافي الدقائق", "دقائق التأخير", "الإضافي المعتمد", "الموقع بالمتر", "الحالة"]]
                rows.extend([
                    [
                        item["work_date"], item["full_name"], item["employee_no"], item.get("department_name") or "",
                        item.get("branch_name") or "", (item.get("shift") or {}).get("name") or "", item.get("check_in_at") or "",
                        item.get("check_out_at") or "", item.get("net_minutes") or 0, item.get("late_minutes") or 0,
                        item.get("approved_overtime_minutes") or 0, item.get("check_in_distance_m") if item.get("check_in_distance_m") is not None else "",
                        item.get("day_status") or "",
                    ]
                    for item in payload["items"]
                ])
            with self.db:
                audit(self.db, user["id"], "attendance.range_export", "attendance", None, {"date_from": payload["date_from"], "date_to": payload["date_to"], "row_count": len(payload["items"]), "filters": payload["filters"]})
            self.send_csv(f"attendance-{payload['date_from']}-{payload['date_to']}.csv", rows)

        def serialize_shift(self, row: sqlite3.Row) -> dict[str, Any]:
            data = dict(row)
            data["working_days"] = parse_json_text(data["working_days"], [])
            data["rest_days"] = parse_json_text(data["rest_days"], [])
            data["active"] = bool(data["active"])
            return data

        def parse_shift(self, data: dict[str, Any], partial: bool = False) -> dict[str, Any]:
            result: dict[str, Any] = {}
            if not partial or "name" in data:
                result["name"] = require_text(data, "name", 120)
            for key in ("start_time", "end_time"):
                if not partial or key in data:
                    result[key] = parse_clock(data.get(key), key).strftime("%H:%M")
            for key, default, lower, upper in (("break_minutes", 60, 0, 480), ("grace_minutes", 10, 0, 240), ("daily_limit_minutes", 480, 60, 1440)):
                if key in data or not partial:
                    result[key] = as_int(data.get(key, default), key, lower, upper)
            if "working_days" in data or not partial:
                days = data.get("working_days", [0, 1, 2, 3, 4])
                if not isinstance(days, list) or not days or any(not isinstance(day, int) or day < 0 or day > 6 for day in days):
                    raise APIError(422, "أيام العمل يجب أن تكون قائمة أرقام من 0 إلى 6.", "validation_error")
                result["working_days"] = json_text(sorted(set(days)))
            if "rest_days" in data or not partial:
                days = data.get("rest_days", [5, 6])
                if not isinstance(days, list) or any(not isinstance(day, int) or day < 0 or day > 6 for day in days):
                    raise APIError(422, "أيام الراحة يجب أن تكون قائمة أرقام من 0 إلى 6.", "validation_error")
                result["rest_days"] = json_text(sorted(set(days)))
            if "active" in data:
                result["active"] = 1 if bool(data["active"]) else 0
            elif not partial:
                result["active"] = 1
            return result

        def api_shifts_get(self) -> None:
            user = self.current_user(True); assert user is not None
            rows = self.db.execute("SELECT s.*,(SELECT COUNT(*) FROM employee_shift_assignments a WHERE a.shift_id=s.id AND (a.effective_to IS NULL OR a.effective_to>=date('now'))) AS assigned_count FROM shifts s ORDER BY s.active DESC,s.name").fetchall()
            assignment_sql = \
                """SELECT a.id,a.employee_id,e.employee_no,e.full_name AS employee_name,
                          a.shift_id,s.name AS shift_name,a.effective_from,a.effective_to,
                          s.working_days,s.rest_days,a.created_at
                   FROM employee_shift_assignments a JOIN employees e ON e.id=a.employee_id
                   JOIN shifts s ON s.id=a.shift_id
                """
            assignment_params: tuple[Any, ...] = ()
            if not self.has_privileged_people_access(user, "shift.view"):
                assignment_sql += " WHERE a.employee_id=?"
                assignment_params = (self.own_employee_id(),)
            assignment_sql += " ORDER BY a.effective_from DESC,a.id DESC"
            assignment_rows = self.db.execute(assignment_sql, assignment_params).fetchall()
            assignments = []
            for row in assignment_rows:
                item = dict(row)
                item["working_days"] = parse_json_text(item["working_days"], [])
                item["rest_days"] = parse_json_text(item["rest_days"], [])
                assignments.append(item)
            self.send_json(200, {"items": [self.serialize_shift(r) for r in rows], "assignments": assignments})

        def api_shifts_post(self) -> None:
            user = self.require_permission("shift.manage")
            values = self.parse_shift(self.read_json())
            stamp = now_iso()
            try:
                with self.db:
                    cols = list(values) + ["created_at", "updated_at"]
                    cur = self.db.execute(f"INSERT INTO shifts({','.join(cols)}) VALUES({','.join('?' for _ in cols)})", (*values.values(), stamp, stamp))
                    shift_id = int(cur.lastrowid)
                    audit(self.db, user["id"], "shift.create", "shift", shift_id, values)
            except sqlite3.IntegrityError as exc:
                raise APIError(409, "يوجد مناوبة بالاسم نفسه.", "duplicate_shift") from exc
            row = self.db.execute("SELECT * FROM shifts WHERE id=?", (shift_id,)).fetchone()
            self.send_json(201, {"shift": self.serialize_shift(row)})

        def api_shift_patch(self, shift_id: int) -> None:
            user = self.require_permission("shift.manage")
            if not self.db.execute("SELECT 1 FROM shifts WHERE id=?", (shift_id,)).fetchone():
                raise APIError(404, "المناوبة غير موجودة.", "not_found")
            values = self.parse_shift(self.read_json(), partial=True)
            if not values:
                raise APIError(422, "لا توجد تغييرات للحفظ.", "validation_error")
            values["updated_at"] = now_iso()
            try:
                with self.db:
                    self.db.execute("UPDATE shifts SET " + ",".join(f"{k}=?" for k in values) + " WHERE id=?", (*values.values(), shift_id))
                    audit(self.db, user["id"], "shift.update", "shift", shift_id, values)
            except sqlite3.IntegrityError as exc:
                raise APIError(409, "يوجد مناوبة بالاسم نفسه.", "duplicate_shift") from exc
            row = self.db.execute("SELECT * FROM shifts WHERE id=?", (shift_id,)).fetchone()
            self.send_json(200, {"shift": self.serialize_shift(row)})

        def api_shift_delete(self, shift_id: int) -> None:
            user = self.require_permission("shift.manage")
            if self.db.execute("SELECT 1 FROM employee_shift_assignments WHERE shift_id=?", (shift_id,)).fetchone():
                raise APIError(409, "لا يمكن حذف مناوبة لها تعيينات محفوظة. يمكن تعطيلها بدلاً من ذلك.", "shift_has_assignments")
            with self.db:
                result = self.db.execute("DELETE FROM shifts WHERE id=?", (shift_id,))
                if not result.rowcount:
                    raise APIError(404, "المناوبة غير موجودة.", "not_found")
                audit(self.db, user["id"], "shift.delete", "shift", shift_id)
            self.send_json(200, {"ok": True})

        def api_shift_assign(self, shift_id: int) -> None:
            user = self.require_permission("shift.manage")
            if not self.db.execute("SELECT 1 FROM shifts WHERE id=? AND active=1", (shift_id,)).fetchone():
                raise APIError(404, "المناوبة غير موجودة أو غير نشطة.", "not_found")
            data = self.read_json()
            employee_id = as_int(data.get("employee_id"), "employee_id", 1)
            if not self.db.execute("SELECT 1 FROM employees WHERE id=? AND active=1", (employee_id,)).fetchone():
                raise APIError(404, "الموظف غير موجود.", "not_found")
            effective_from = parse_date(data.get("effective_from"), "effective_from")
            effective_to = parse_date(data["effective_to"], "effective_to") if data.get("effective_to") else None
            if effective_to and effective_to < effective_from:
                raise APIError(422, "تاريخ نهاية التعيين يسبق تاريخ بدايته.", "validation_error")
            previous_day = (effective_from - timedelta(days=1)).isoformat()
            with self.db:
                self.db.execute("UPDATE employee_shift_assignments SET effective_to=? WHERE employee_id=? AND effective_from<? AND (effective_to IS NULL OR effective_to>=?)", (previous_day, employee_id, effective_from.isoformat(), effective_from.isoformat()))
                self.db.execute("DELETE FROM employee_shift_assignments WHERE employee_id=? AND effective_from>=? AND (? IS NULL OR effective_from<=?)", (employee_id, effective_from.isoformat(), effective_to.isoformat() if effective_to else None, effective_to.isoformat() if effective_to else None))
                cur = self.db.execute("INSERT INTO employee_shift_assignments(employee_id,shift_id,effective_from,effective_to,created_by,created_at) VALUES(?,?,?,?,?,?)", (employee_id, shift_id, effective_from.isoformat(), effective_to.isoformat() if effective_to else None, user["id"], now_iso()))
                audit(self.db, user["id"], "shift.assign", "employee", employee_id, {"shift_id": shift_id, "assignment_id": cur.lastrowid})
            assignment = self.db.execute("SELECT a.*,s.name AS shift_name FROM employee_shift_assignments a JOIN shifts s ON s.id=a.shift_id WHERE a.id=?", (cur.lastrowid,)).fetchone()
            self.send_json(201, {"assignment": dict(assignment)})

        # Overtime
        def api_overtime_get(self) -> None:
            user = self.current_user(True)
            assert user is not None
            status = self.query.get("status")
            params: list[Any] = []
            conditions: list[str] = []
            if status:
                conditions.append("o.status=?")
                params.append(status)
            if not self.has_privileged_people_access(user, "overtime.view"):
                conditions.append("o.employee_id=?")
                params.append(self.own_employee_id())
            where = " WHERE " + " AND ".join(conditions) if conditions else ""
            rows = self.db.execute("SELECT o.*,e.employee_no,e.full_name,d.name AS department_name,u.display_name AS decided_by_name FROM overtime_requests o JOIN employees e ON e.id=o.employee_id LEFT JOIN departments d ON d.id=e.department_id LEFT JOIN users u ON u.id=o.decided_by" + where + " ORDER BY o.created_at DESC", params).fetchall()
            self.send_json(200, {"items": [dict(r) for r in rows]})

        def api_overtime_post(self) -> None:
            user = self.current_user(True)
            assert user is not None
            employee_id = self.own_employee_id()
            data = self.read_json()
            work_date = parse_date(data.get("work_date"), "work_date").isoformat()
            start = parse_clock(data.get("start_time"), "start_time")
            end = parse_clock(data.get("end_time"), "end_time")
            start_dt = datetime.combine(date.fromisoformat(work_date), start)
            end_dt = datetime.combine(date.fromisoformat(work_date), end)
            if end_dt <= start_dt:
                end_dt += timedelta(days=1)
            duration = int((end_dt - start_dt).total_seconds() // 60)
            if duration <= 0 or duration > 720:
                raise APIError(422, "مدة العمل الإضافي يجب أن تكون بين دقيقة و12 ساعة.", "validation_error")
            reason = require_text(data, "reason", 1000)
            stamp = now_iso()
            with self.db:
                cur = self.db.execute("INSERT INTO overtime_requests(employee_id,work_date,start_time,end_time,duration_minutes,reason,status,created_at,updated_at) VALUES(?,?,?,?,?,?,'submitted',?,?)", (employee_id, work_date, start.strftime("%H:%M"), end.strftime("%H:%M"), duration, reason, stamp, stamp))
                request_id = int(cur.lastrowid)
                self.db.execute("INSERT INTO overtime_audit(request_id,actor_user_id,from_status,to_status,comment,created_at) VALUES(?,?,NULL,'submitted','',?)", (request_id, user["id"], stamp))
                employee = self.db.execute("SELECT employee_no,full_name FROM employees WHERE id=?", (employee_id,)).fetchone()
                approvers = self.approval_recipient_ids("overtime.approve", int(user["id"]))
                create_internal_notification(
                    self.db, int(user["id"]), approvers,
                    "طلب عمل إضافي بانتظار الاعتماد",
                    f"قدم {employee['full_name']} ({employee['employee_no']}) طلب عمل إضافي بتاريخ {work_date} لمدة {duration/60:g} ساعة.",
                )
                audit(self.db, user["id"], "overtime.submit", "overtime_request", request_id)
            row = self.db.execute("SELECT * FROM overtime_requests WHERE id=?", (request_id,)).fetchone()
            self.send_json(201, {"request": dict(row)})

        def api_overtime_decision(self, request_id: int) -> None:
            user = self.require_permission("overtime.approve")
            data = self.read_json()
            action = str(data.get("action", ""))
            if action not in {"approve", "reject"}:
                raise APIError(422, "القرار يجب أن يكون approve أو reject.", "validation_error")
            request_row = self.db.execute("SELECT * FROM overtime_requests WHERE id=?", (request_id,)).fetchone()
            if request_row is None:
                raise APIError(404, "طلب العمل الإضافي غير موجود.", "not_found")
            if request_row["status"] != "submitted":
                raise APIError(409, "تم اتخاذ قرار على هذا الطلب سابقاً.", "invalid_status")
            if user.get("employee_id") == request_row["employee_id"]:
                raise APIError(403, "لا يمكن اعتماد طلبك الشخصي.", "self_approval_forbidden")
            reason = optional_text(data, "reason", 1000)
            if action == "reject" and not reason:
                raise APIError(422, "سبب الرفض مطلوب.", "validation_error")
            status = "approved" if action == "approve" else "rejected"
            stamp = now_iso()
            with self.db:
                self.db.execute("UPDATE overtime_requests SET status=?,rejection_reason=?,decided_by=?,decided_at=?,updated_at=? WHERE id=?", (status, reason if status == "rejected" else None, user["id"], stamp, stamp, request_id))
                self.db.execute("INSERT INTO overtime_audit(request_id,actor_user_id,from_status,to_status,comment,created_at) VALUES(?,?,'submitted',?,?,?)", (request_id, user["id"], status, reason, stamp))
                audit(self.db, user["id"], f"overtime.{status}", "overtime_request", request_id, {"reason": reason})
            saved = self.db.execute("SELECT * FROM overtime_requests WHERE id=?", (request_id,)).fetchone()
            self.send_json(200, {"request": dict(saved)})

        # Leave balances and requests
        def approval_recipient_ids(self, permission: str, exclude_user_id: int | None = None) -> list[int]:
            recipients: list[int] = []
            for row in self.db.execute("SELECT * FROM users WHERE active=1"):
                if exclude_user_id and int(row["id"]) == int(exclude_user_id):
                    continue
                candidate = dict(row) | {"active": bool(row["active"]), "is_super_admin": bool(row["is_super_admin"])}
                if has_permission(self.db, candidate, permission):
                    recipients.append(int(row["id"]))
            return recipients

        def leave_hr_recipient_ids(self) -> list[int]:
            return self.approval_recipient_ids("leave.approve")

        def api_leave_holidays_get(self) -> None:
            self.current_user(True)
            rows = self.db.execute("SELECT * FROM public_holidays ORDER BY holiday_date,id").fetchall()
            self.send_json(200, {"items": [dict(row) | {"active": bool(row["active"])} for row in rows]})

        def api_leave_holiday_post(self) -> None:
            user = self.require_permission("leave.approve")
            data = self.read_json()
            holiday_date = parse_date(data.get("holiday_date"), "holiday_date").isoformat()
            name = require_text(data, "name", 160)
            stamp = now_iso()
            try:
                with self.db:
                    cursor = self.db.execute(
                        "INSERT INTO public_holidays(holiday_date,name,active,created_by,created_at,updated_at) VALUES(?,?,1,?,?,?)",
                        (holiday_date, name, user["id"], stamp, stamp),
                    )
            except sqlite3.IntegrityError:
                raise APIError(409, "يوجد يوم عطلة مسجل بهذا التاريخ.", "duplicate_holiday")
            row = self.db.execute("SELECT * FROM public_holidays WHERE id=?", (cursor.lastrowid,)).fetchone()
            audit(self.db, user["id"], "leave_holiday.create", "public_holiday", int(cursor.lastrowid), {"holiday_date": holiday_date})
            self.send_json(201, {"holiday": dict(row) | {"active": bool(row["active"])}})

        def api_leave_holiday_patch(self, holiday_id: int) -> None:
            user = self.require_permission("leave.approve")
            row = self.db.execute("SELECT * FROM public_holidays WHERE id=?", (holiday_id,)).fetchone()
            if row is None:
                raise APIError(404, "العطلة الرسمية غير موجودة.", "not_found")
            data = self.read_json()
            updates: list[str] = []
            values: list[Any] = []
            if "holiday_date" in data:
                updates.append("holiday_date=?")
                values.append(parse_date(data.get("holiday_date"), "holiday_date").isoformat())
            if "name" in data:
                updates.append("name=?")
                values.append(require_text(data, "name", 160))
            if "active" in data:
                if not isinstance(data["active"], bool):
                    raise APIError(422, "قيمة تفعيل العطلة غير صحيحة.", "validation_error")
                updates.append("active=?")
                values.append(1 if data["active"] else 0)
            if not updates:
                raise APIError(422, "لم يتم إرسال أي تعديل.", "validation_error")
            stamp = now_iso()
            values.extend([stamp, holiday_id])
            try:
                with self.db:
                    self.db.execute(f"UPDATE public_holidays SET {','.join(updates)},updated_at=? WHERE id=?", values)
            except sqlite3.IntegrityError:
                raise APIError(409, "يوجد يوم عطلة مسجل بهذا التاريخ.", "duplicate_holiday")
            saved = self.db.execute("SELECT * FROM public_holidays WHERE id=?", (holiday_id,)).fetchone()
            audit(self.db, user["id"], "leave_holiday.update", "public_holiday", holiday_id)
            self.send_json(200, {"holiday": dict(saved) | {"active": bool(saved["active"])}})

        def api_leave_holiday_delete(self, holiday_id: int) -> None:
            user = self.require_permission("leave.approve")
            if self.db.execute("SELECT 1 FROM public_holidays WHERE id=?", (holiday_id,)).fetchone() is None:
                raise APIError(404, "العطلة الرسمية غير موجودة.", "not_found")
            with self.db:
                self.db.execute("DELETE FROM public_holidays WHERE id=?", (holiday_id,))
            audit(self.db, user["id"], "leave_holiday.delete", "public_holiday", holiday_id)
            self.send_json(200, {"deleted": True, "id": holiday_id})

        def leave_request_payload(self, row: sqlite3.Row | dict[str, Any], user: dict[str, Any]) -> dict[str, Any]:
            data = dict(row)
            status = data.get("status")
            manager_decision = data.get("manager_decision") or "pending"
            if status == "approved":
                workflow_stage = "approved"
            elif status == "rejected":
                workflow_stage = "manager_rejected" if manager_decision == "rejected" else "hr_rejected"
            elif status == "cancelled":
                workflow_stage = "cancelled"
            elif manager_decision == "approved":
                workflow_stage = "pending_hr"
            else:
                workflow_stage = "pending_manager"
            is_direct_manager = bool(
                user.get("employee_id")
                and int(user["employee_id"]) == int(data.get("manager_employee_id") or 0)
                and has_permission(self.db, user, "leave.team")
            )
            is_hr_final_approver = bool(
                has_permission(self.db, user, "leave.approve")
            )
            can_decide = bool(
                status == "submitted"
                and (
                    (manager_decision == "pending" and is_direct_manager)
                    or (manager_decision == "approved" and is_hr_final_approver)
                )
            )
            data.update({
                "workflow_stage": workflow_stage,
                "can_decide": can_decide,
                "decision_role": "manager" if can_decide and manager_decision == "pending" else "hr" if can_decide else None,
            })
            is_team_record = bool(is_direct_manager and data.get("employee_id") != user.get("employee_id"))
            if is_team_record and not self.has_privileged_people_access(user, "leave.view"):
                allowed = {
                    "id", "employee_id", "employee_no", "full_name", "leave_type_id",
                    "leave_type_code", "leave_type_name", "start_date", "end_date", "days",
                    "start_time", "end_time", "hours",
                    "reason", "status", "manager_decision", "workflow_stage", "can_decide", "decision_role",
                }
                data = {key: value for key, value in data.items() if key in allowed}
            return data

        def leave_balance_rows(self, employee_id: int, year: int) -> list[dict[str, Any]]:
            leave_types = self.db.execute("SELECT * FROM leave_types WHERE active=1 ORDER BY id").fetchall()
            employee = self.db.execute("SELECT hire_date,gender FROM employees WHERE id=?", (employee_id,)).fetchone()
            hire_date = employee["hire_date"] if employee else None
            gender = str(employee["gender"] if employee and "gender" in employee.keys() else "unspecified").lower()
            today = local_now().date()
            rows: list[dict[str, Any]] = []
            for leave in leave_types:
                # Sick-leave balances are not displayed as an accrued balance;
                # sick leave remains available as a request type. Maternity
                # leave is visible only for female employee profiles.
                if leave["code"] == "sick" or (leave["code"] == "maternity" and gender != "female"):
                    continue
                balance = self.db.execute("SELECT * FROM leave_balances WHERE employee_id=? AND leave_type_id=? AND year=?", (employee_id, leave["id"], year)).fetchone()
                if leave["code"] == "annual":
                    entitlement = annual_leave_entitlement_for_year(hire_date, year, today)
                    previous_entitlement = annual_leave_entitlement_for_year(hire_date, year - 1, date(year - 1, 12, 31))
                    previous = self.db.execute("SELECT carried,used FROM leave_balances WHERE employee_id=? AND leave_type_id=? AND year=?", (employee_id, leave["id"], year - 1)).fetchone()
                    previous_carried = float(previous["carried"] if previous else 0)
                    previous_used = float(previous["used"] if previous else 0)
                    # Carry only unused entitlement from the immediately prior
                    # year, capped at five days and never chained indefinitely.
                    previous_fresh_remaining = max(0.0, previous_entitlement - max(0.0, previous_used - min(previous_used, previous_carried)))
                    carried = min(5.0, previous_fresh_remaining)
                else:
                    entitlement = float(balance["entitlement"] if balance else leave["annual_entitlement"])
                    carried = min(5.0, float(balance["carried"] if balance else 0))
                used = float(balance["used"] if balance else 0)
                pending = float(self.db.execute("SELECT COALESCE(SUM(days),0) FROM leave_requests WHERE employee_id=? AND leave_type_id=? AND status='submitted' AND substr(start_date,1,4)=?", (employee_id, leave["id"], str(year))).fetchone()[0])
                pending_sale = 0.0
                if leave["code"] == "annual":
                    pending_sale = float(self.db.execute("SELECT COALESCE(SUM(days),0) FROM leave_sale_requests WHERE employee_id=? AND status='submitted'", (employee_id,)).fetchone()[0])
                raw_available = entitlement + carried - used - pending - pending_sale
                available = min(60.0, max(0.0, raw_available)) if leave["code"] == "annual" else max(0.0, raw_available)
                rows.append({
                    "leave_type_id": leave["id"], "code": leave["code"], "name": leave["name"],
                    "year": year, "entitlement": entitlement, "carried": carried, "used": used,
                    "pending": pending, "pending_sale": pending_sale, "raw_available": max(0.0, raw_available), "frozen": max(0.0, raw_available - 60.0) if leave["code"] == "annual" else 0.0,
                    "available": available, "service_months": completed_service_months(hire_date, today),
                    "paid_eligible": completed_service_months(hire_date, today) >= 6 if leave["code"] == "annual" else bool(leave["paid"]),
                    "accrual_note": "لا يستحق الموظف إجازة سنوية مدفوعة قبل إتمام ٦ أشهر، ويضاف يومان عن كل شهر حتى إتمام السنة." if leave["code"] == "annual" else "",
                    "requires_attachment": bool(leave["requires_attachment"]), "min_notice_days": leave["min_notice_days"], "paid": bool(leave["paid"]),
                })
            return rows

        def api_leave_types(self) -> None:
            user = self.current_user(True)
            assert user is not None
            target_id = as_int(self.query["employee_id"], "employee_id", 1) if self.query.get("employee_id") else user.get("employee_id")
            target_gender = None
            if target_id:
                employee = self.db.execute("SELECT gender FROM employees WHERE id=?", (target_id,)).fetchone()
                target_gender = str(employee["gender"] if employee and "gender" in employee.keys() else "unspecified").lower() if employee else None
            rows = self.db.execute("SELECT * FROM leave_types WHERE active=1 ORDER BY id").fetchall()
            if target_gender != "female":
                rows = [row for row in rows if row["code"] != "maternity"]
            self.send_json(200, {"items": [dict(r) | {"active": bool(r["active"]), "paid": bool(r["paid"]), "requires_attachment": bool(r["requires_attachment"]), "max_hours": float(r["max_hours"] or 0)} for r in rows]})

        def api_leave_balances(self) -> None:
            user = self.current_user(True)
            assert user is not None
            year = as_int(self.query.get("year", local_now().year), "year", 2000, 2200)
            employee_id = as_int(self.query["employee_id"], "employee_id", 1) if "employee_id" in self.query else self.own_employee_id()
            if employee_id != user.get("employee_id") and not self.has_privileged_people_access(user, "leave.view"):
                raise APIError(403, "لا يمكنك عرض رصيد هذا الموظف.", "forbidden")
            self.send_json(200, {"employee_id": employee_id, "year": year, "items": self.leave_balance_rows(employee_id, year)})

        def api_leave_requests_get(self) -> None:
            user = self.current_user(True)
            assert user is not None
            params: list[Any] = []
            where = ""
            if self.has_privileged_people_access(user, "leave.view"):
                pass
            elif has_permission(self.db, user, "leave.team") and user.get("employee_id"):
                where = " WHERE (lr.employee_id=? OR (lr.manager_employee_id=? AND lr.status='submitted' AND lr.manager_decision='pending'))"
                params = [user["employee_id"], user["employee_id"]]
            else:
                where = " WHERE lr.employee_id=?"
                params = [self.own_employee_id()]
            if self.query.get("status"):
                where += (" AND " if where else " WHERE ") + "lr.status=?"
                params.append(self.query["status"])
            rows = self.db.execute("SELECT lr.*,lt.code AS leave_type_code,lt.name AS leave_type_name,e.employee_no,e.full_name,m.full_name AS manager_name,u.display_name AS decided_by_name FROM leave_requests lr JOIN leave_types lt ON lt.id=lr.leave_type_id JOIN employees e ON e.id=lr.employee_id LEFT JOIN employees m ON m.id=lr.manager_employee_id LEFT JOIN users u ON u.id=lr.decided_by" + where + " ORDER BY lr.created_at DESC", params).fetchall()
            self.send_json(200, {"items": [self.leave_request_payload(row, user) for row in rows]})

        def api_leave_requests_post(self) -> None:
            user = self.current_user(True)
            assert user is not None
            employee_id = self.own_employee_id()
            data = self.read_json()
            leave_type_id = as_int(data.get("leave_type_id"), "leave_type_id", 1)
            leave_type = self.db.execute("SELECT * FROM leave_types WHERE id=? AND active=1", (leave_type_id,)).fetchone()
            if leave_type is None:
                raise APIError(404, "نوع الإجازة غير موجود.", "not_found")
            employee_profile = self.db.execute("SELECT gender FROM employees WHERE id=?", (employee_id,)).fetchone()
            employee_gender = str(employee_profile["gender"] if employee_profile and "gender" in employee_profile.keys() else "unspecified").lower()
            if leave_type["code"] == "maternity" and employee_gender != "female":
                raise APIError(422, "إجازة الأمومة متاحة للموظفات فقط.", "gender_restricted_leave")
            start = parse_date(data.get("start_date"), "start_date")
            end = parse_date(data.get("end_date"), "end_date")
            if end < start:
                raise APIError(422, "تاريخ نهاية الإجازة يسبق بدايتها.", "validation_error")
            if start.year != end.year:
                raise APIError(422, "قسّم الطلب الذي يمتد بين سنتين إلى طلبين.", "cross_year_leave")
            start_time_value = None
            end_time_value = None
            hours = 0.0
            if leave_type["code"] == "work_permission":
                if start != end:
                    raise APIError(422, "ترخيص ساعات العمل يجب أن يكون في يوم واحد.", "permission_one_day")
                start_clock = parse_clock(data.get("start_time"), "start_time")
                end_clock = parse_clock(data.get("end_time"), "end_time")
                duration_minutes = int((datetime.combine(start, end_clock) - datetime.combine(start, start_clock)).total_seconds() / 60)
                if duration_minutes <= 0:
                    raise APIError(422, "وقت نهاية الترخيص يجب أن يكون بعد وقت البداية.", "permission_time_order")
                max_hours = float(leave_type["max_hours"] or 2)
                hours = round(duration_minutes / 60, 2)
                if hours > max_hours:
                    raise APIError(422, f"لا يجوز أن يتجاوز الترخيص {max_hours:g} ساعتين في الطلب الواحد.", "permission_max_hours", {"max_hours": max_hours})
                start_time_value = start_clock.strftime("%H:%M")
                end_time_value = end_clock.strftime("%H:%M")
                days = round(duration_minutes / 480, 4)
            else:
                days = leave_days_excluding_public_holidays(self.db, start, end) if leave_type["code"] == "annual" else float((end - start).days + 1)
            if days <= 0:
                raise APIError(422, "الفترة المحددة تقع بالكامل ضمن عطل رسمية ولا تُحتسب كإجازة سنوية.", "no_leave_days")
            notice = (start - local_now().date()).days
            if notice < int(leave_type["min_notice_days"]):
                raise APIError(422, f"هذا النوع يتطلب التقديم قبل {leave_type['min_notice_days']} أيام على الأقل.", "notice_period")
            attachment = None
            if data.get("attachment_data"):
                attachment = validate_data_url(data["attachment_data"], "مرفق الإجازة", ("image/png", "image/jpeg", "image/webp", "application/pdf"), 2_000_000)
            if leave_type["requires_attachment"] and not attachment:
                raise APIError(422, "المرفق مطلوب لهذا النوع من الإجازات.", "attachment_required")
            overlap = self.db.execute("SELECT 1 FROM leave_requests WHERE employee_id=? AND status IN ('submitted','approved') AND start_date<=? AND end_date>=?", (employee_id, end.isoformat(), start.isoformat())).fetchone()
            if overlap:
                raise APIError(409, "يوجد طلب إجازة متداخل مع هذه الفترة.", "overlapping_leave")
            employee_record = self.db.execute("SELECT hire_date FROM employees WHERE id=?", (employee_id,)).fetchone()
            hire_value = employee_record["hire_date"] if employee_record else None
            service_months = completed_service_months(hire_value, start)
            if leave_type["code"] == "annual" and service_months < 6:
                eligible_on = None
                if hire_value:
                    hire = date.fromisoformat(str(hire_value)[:10])
                    eligible_on = add_calendar_months(hire, 6).isoformat()
                raise APIError(422, "لا يستحق الموظف إجازة سنوية مدفوعة قبل إتمام ٦ أشهر من الخدمة.", "annual_leave_before_eligibility", {"service_months": service_months, "eligible_on": eligible_on})
            balance = next((x for x in self.leave_balance_rows(employee_id, start.year) if x["leave_type_id"] == leave_type_id), None)
            if balance and leave_type["annual_entitlement"] > 0 and days > balance["available"]:
                raise APIError(422, "الرصيد المتاح لا يكفي لهذا الطلب.", "insufficient_balance", {"requested": days, "available": balance["available"]})
            department_head = self.is_department_head(employee_id)
            manager_employee_id = None if department_head else self.direct_manager_employee_id(employee_id)
            manager_user = None
            if not department_head:
                if manager_employee_id is None:
                    raise APIError(409, "لا يمكن إرسال الطلب قبل تعيين مسؤول مباشر للموظف.", "direct_manager_required")
                manager_user = self.db.execute("SELECT * FROM users WHERE employee_id=? AND active=1", (manager_employee_id,)).fetchone()
                if manager_user is None or not has_permission(self.db, dict(manager_user), "leave.team"):
                    raise APIError(409, "المسؤول المباشر لا يملك حساباً نشطاً وصلاحية مراجعة إجازات الفريق.", "manager_account_required")
            hr_recipients = self.leave_hr_recipient_ids()
            if department_head and not hr_recipients:
                raise APIError(409, "لا يوجد مسؤول موارد بشرية أو مستخدم مخول لاعتماد الإجازات.", "leave_approver_required")
            employee = self.db.execute("SELECT employee_no,full_name FROM employees WHERE id=?", (employee_id,)).fetchone()
            stamp = now_iso()
            with self.db:
                manager_decision = "approved" if department_head else "pending"
                cur = self.db.execute("INSERT INTO leave_requests(employee_id,leave_type_id,start_date,end_date,days,start_time,end_time,hours,reason,attachment_data,status,manager_employee_id,manager_decision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,'submitted',?,?,?,?)", (employee_id, leave_type_id, start.isoformat(), end.isoformat(), days, start_time_value, end_time_value, hours, optional_text(data, "reason", 1000), attachment, manager_employee_id, manager_decision, stamp, stamp))
                request_id = int(cur.lastrowid)
                create_internal_notification(
                    self.db, int(user["id"]), hr_recipients if department_head else [int(manager_user["id"])],
                    "طلب إجازة رئيس قسم بانتظار الموارد البشرية" if department_head else "طلب إجازة بانتظار قرارك",
                    f"قدم {employee['full_name']} ({employee['employee_no']}) طلب {leave_type['name']} من {start.isoformat()} إلى {end.isoformat()}.",
                )
                audit(self.db, user["id"], "leave.submit", "leave_request", request_id, {"manager_employee_id": manager_employee_id, "department_head_direct_to_hr": department_head})
            row = self.db.execute("SELECT lr.*,lt.code AS leave_type_code,lt.name AS leave_type_name,e.employee_no,e.full_name,m.full_name AS manager_name FROM leave_requests lr JOIN leave_types lt ON lt.id=lr.leave_type_id JOIN employees e ON e.id=lr.employee_id LEFT JOIN employees m ON m.id=lr.manager_employee_id WHERE lr.id=?", (request_id,)).fetchone()
            self.send_json(201, {"request": self.leave_request_payload(row, user)})

        def api_leave_request_decision(self, request_id: int) -> None:
            user = self.current_user(True)
            assert user is not None
            request_row = self.db.execute("SELECT lr.*,e.employee_no,e.full_name,lt.name AS leave_type_name,lt.code AS leave_type_code,lt.annual_entitlement FROM leave_requests lr JOIN employees e ON e.id=lr.employee_id JOIN leave_types lt ON lt.id=lr.leave_type_id WHERE lr.id=?", (request_id,)).fetchone()
            if request_row is None:
                raise APIError(404, "طلب الإجازة غير موجود.", "not_found")
            if user.get("employee_id") == request_row["employee_id"]:
                raise APIError(403, "لا يمكن اعتماد طلبك الشخصي.", "self_approval_forbidden")
            data = self.read_json()
            action = str(data.get("action", ""))
            if action not in {"approve", "reject"}:
                raise APIError(422, "القرار يجب أن يكون approve أو reject.", "validation_error")
            reason = optional_text(data, "reason", 1000)
            if action == "reject" and not reason:
                raise APIError(422, "سبب الرفض مطلوب.", "validation_error")
            is_direct_manager = bool(
                user.get("employee_id")
                and int(user["employee_id"]) == int(request_row["manager_employee_id"] or 0)
                and has_permission(self.db, user, "leave.team")
            )
            is_hr_final_approver = bool(
                has_permission(self.db, user, "leave.approve")
            )
            if not is_direct_manager and not is_hr_final_approver:
                raise APIError(403, "لا تملك صلاحية اتخاذ قرار على هذا الطلب.", "forbidden")
            if request_row["status"] != "submitted":
                raise APIError(409, "تم اتخاذ قرار نهائي على هذا الطلب سابقاً.", "invalid_status")
            stamp = now_iso()
            employee_user = self.db.execute("SELECT id FROM users WHERE employee_id=? AND active=1", (request_row["employee_id"],)).fetchone()
            manager_user = self.db.execute("SELECT id FROM users WHERE employee_id=? AND active=1", (request_row["manager_employee_id"],)).fetchone()
            with self.db:
                if request_row["manager_decision"] == "pending":
                    if not is_direct_manager:
                        raise APIError(409, "يجب أن يعتمد المسؤول المباشر الطلب أولاً.", "manager_approval_required")
                    manager_decision = "approved" if action == "approve" else "rejected"
                    status = "submitted" if action == "approve" else "rejected"
                    self.db.execute(
                        "UPDATE leave_requests SET manager_decision=?,manager_comment=?,manager_decided_by=?,manager_decided_at=?,status=?,rejection_reason=?,updated_at=? WHERE id=?",
                        (manager_decision, reason, user["id"], stamp, status, reason if action == "reject" else None, stamp, request_id),
                    )
                    hr_recipients = self.leave_hr_recipient_ids()
                    create_internal_notification(
                        self.db, int(user["id"]), hr_recipients,
                        "قرار المسؤول المباشر على طلب إجازة",
                        f"{('وافق' if action == 'approve' else 'رفض')} المسؤول المباشر طلب {request_row['leave_type_name']} للموظف {request_row['full_name']} ({request_row['employee_no']})."
                        + (" الطلب بانتظار الاعتماد النهائي من الموارد البشرية." if action == "approve" else f" سبب الرفض: {reason}"),
                    )
                    if employee_user:
                        create_internal_notification(
                            self.db, int(user["id"]), [int(employee_user["id"])],
                            "تحديث طلب الإجازة",
                            "وافق مسؤولك المباشر على الطلب وأرسله للاعتماد النهائي لدى الموارد البشرية."
                            if action == "approve" else f"رفض مسؤولك المباشر طلب الإجازة. السبب: {reason}",
                        )
                    audit(self.db, user["id"], f"leave.manager_{manager_decision}", "leave_request", request_id, {"reason": reason, "hr_recipient_count": len(hr_recipients)})
                else:
                    if request_row["manager_decision"] != "approved":
                        raise APIError(409, "رفض المسؤول المباشر هذا الطلب ولا يمكن اعتماده نهائياً.", "manager_rejected")
                    if not is_hr_final_approver:
                        raise APIError(403, "الاعتماد النهائي متاح لموظف الموارد البشرية المخول فقط.", "hr_final_approval_required")
                    status = "approved" if action == "approve" else "rejected"
                    if status == "approved" and float(request_row["annual_entitlement"]) > 0:
                        year = date.fromisoformat(request_row["start_date"]).year
                        balance = self.db.execute("SELECT * FROM leave_balances WHERE employee_id=? AND leave_type_id=? AND year=?", (request_row["employee_id"], request_row["leave_type_id"], year)).fetchone()
                        if balance is None:
                            employee_record = self.db.execute("SELECT hire_date FROM employees WHERE id=?", (request_row["employee_id"],)).fetchone()
                            entitlement = annual_leave_entitlement_for_year(employee_record["hire_date"] if employee_record else None, year, local_now().date()) if request_row["leave_type_code"] == "annual" else request_row["annual_entitlement"]
                            self.db.execute("INSERT INTO leave_balances(employee_id,leave_type_id,year,entitlement) VALUES(?,?,?,?)", (request_row["employee_id"], request_row["leave_type_id"], year, entitlement))
                            balance = self.db.execute("SELECT * FROM leave_balances WHERE employee_id=? AND leave_type_id=? AND year=?", (request_row["employee_id"], request_row["leave_type_id"], year)).fetchone()
                        rows = {item["leave_type_id"]: item for item in self.leave_balance_rows(int(request_row["employee_id"]), year)}
                        available = float((rows.get(int(request_row["leave_type_id"])) or {}).get("available", balance["entitlement"] + balance["carried"] - balance["used"])) + float(request_row["days"])
                        if float(request_row["days"]) > available:
                            raise APIError(409, "لم يعد الرصيد كافياً لاعتماد الطلب.", "insufficient_balance", {"available": available})
                        self.db.execute("UPDATE leave_balances SET used=used+? WHERE employee_id=? AND leave_type_id=? AND year=?", (request_row["days"], request_row["employee_id"], request_row["leave_type_id"], year))
                    self.db.execute("UPDATE leave_requests SET status=?,rejection_reason=?,decided_by=?,decided_at=?,updated_at=? WHERE id=?", (status, reason if status == "rejected" else None, user["id"], stamp, stamp, request_id))
                    recipients = [int(row["id"]) for row in (employee_user, manager_user) if row]
                    create_internal_notification(
                        self.db, int(user["id"]), recipients,
                        "القرار النهائي لطلب الإجازة",
                        f"{('اعتمدت' if action == 'approve' else 'رفضت')} الموارد البشرية نهائياً طلب {request_row['leave_type_name']} للموظف {request_row['full_name']}."
                        + (f" السبب: {reason}" if action == "reject" else ""),
                    )
                    audit(self.db, user["id"], f"leave.hr_{status}", "leave_request", request_id, {"reason": reason})
            saved = self.db.execute("SELECT lr.*,lt.code AS leave_type_code,lt.name AS leave_type_name,e.employee_no,e.full_name FROM leave_requests lr JOIN leave_types lt ON lt.id=lr.leave_type_id JOIN employees e ON e.id=lr.employee_id WHERE lr.id=?", (request_id,)).fetchone()
            self.send_json(200, {"request": self.leave_request_payload(saved, user)})

        def leave_sale_payload(self, row: sqlite3.Row | dict[str, Any], user: dict[str, Any]) -> dict[str, Any]:
            data = dict(row)
            data["amount"] = cents_value(data.get("amount_cents"))
            data["daily_rate"] = cents_value(data.get("daily_rate_cents"))
            data["can_decide"] = bool(
                has_permission(self.db, user, "leave.approve")
                and data.get("status") == "submitted"
            )
            is_own = user.get("employee_id") == data.get("employee_id")
            if not is_own and not data["can_decide"]:
                for key in ("amount_cents", "daily_rate_cents", "amount", "daily_rate", "reason", "decision_note"):
                    data.pop(key, None)
            return data

        def api_leave_sales_get(self) -> None:
            user = self.current_user(True)
            assert user is not None
            is_hr = bool(has_permission(self.db, user, "leave.approve"))
            if is_hr:
                rows = self.db.execute(
                    """SELECT s.*,e.employee_no,e.full_name AS employee_name,u.display_name AS decided_by_name
                       FROM leave_sale_requests s JOIN employees e ON e.id=s.employee_id
                       LEFT JOIN users u ON u.id=s.decided_by ORDER BY s.created_at DESC,s.id DESC"""
                ).fetchall()
            else:
                employee_id = self.own_employee_id()
                rows = self.db.execute(
                    """SELECT s.*,e.employee_no,e.full_name AS employee_name,u.display_name AS decided_by_name
                       FROM leave_sale_requests s JOIN employees e ON e.id=s.employee_id
                       LEFT JOIN users u ON u.id=s.decided_by WHERE s.employee_id=? ORDER BY s.created_at DESC,s.id DESC""",
                    (employee_id,),
                ).fetchall()
            self.send_json(200, {"items": [self.leave_sale_payload(row, user) for row in rows]})

        def api_leave_sales_post(self) -> None:
            user = self.current_user(True)
            assert user is not None
            employee_id = self.own_employee_id()
            data = self.read_json()
            days = as_float(data.get("days"), "days", 0.01, 366)
            annual = self.db.execute("SELECT id FROM leave_types WHERE code='annual' AND active=1").fetchone()
            if annual is None:
                raise APIError(409, "نوع الإجازة السنوية غير مهيأ.", "annual_leave_type_missing")
            balance = next((row for row in self.leave_balance_rows(employee_id, local_now().year) if row["leave_type_id"] == annual["id"]), None)
            available_for_sale = float(balance.get("raw_available", balance.get("available", 0)) if balance else 0)
            if days > available_for_sale + 1e-9:
                raise APIError(422, "عدد الأيام المطلوب بيعها يتجاوز الرصيد المتاح للبيع.", "insufficient_balance", {"available": max(0, available_for_sale)})
            employee = self.db.execute("SELECT employee_no,full_name,salary,basic_salary FROM employees WHERE id=?", (employee_id,)).fetchone()
            # UAE annual-leave cash-out uses the basic monthly salary divided
            # by 30, never the gross salary or allowances.
            salary = Decimal(str((employee["basic_salary"] if employee and employee["basic_salary"] is not None else employee["salary"]) or 0)) if employee else Decimal("0")
            daily_rate_cents = money_cents(salary / Decimal("30"))
            amount_cents = money_cents((Decimal(daily_rate_cents) / Decimal("100")) * Decimal(str(days)))
            stamp = now_iso()
            with self.db:
                cursor = self.db.execute(
                    """INSERT INTO leave_sale_requests(employee_id,days,daily_rate_cents,amount_cents,reason,status,created_at,updated_at)
                       VALUES(?,?,?,?,?,'submitted',?,?)""",
                    (employee_id, days, daily_rate_cents, amount_cents, optional_text(data, "reason", 1000), stamp, stamp),
                )
                request_id = int(cursor.lastrowid)
                recipients = self.leave_hr_recipient_ids()
                create_internal_notification(
                    self.db, int(user["id"]), recipients,
                    "طلب بيع رصيد إجازة",
                    f"قدم {employee['full_name']} ({employee['employee_no']}) طلب بيع {days:g} يوم من رصيد إجازته.",
                )
                audit(self.db, user["id"], "leave_sale.submit", "leave_sale_request", request_id, {"days": days, "hr_recipient_count": len(recipients)})
            row = self.db.execute(
                """SELECT s.*,e.employee_no,e.full_name AS employee_name,u.display_name AS decided_by_name
                   FROM leave_sale_requests s JOIN employees e ON e.id=s.employee_id
                   LEFT JOIN users u ON u.id=s.decided_by WHERE s.id=?""",
                (request_id,),
            ).fetchone()
            self.send_json(201, {"request": self.leave_sale_payload(row, user)})

        def api_leave_sale_decision(self, request_id: int) -> None:
            user = self.current_user(True)
            assert user is not None
            if not has_permission(self.db, user, "leave.approve"):
                raise APIError(403, "اعتماد بيع رصيد الإجازة متاح للموارد البشرية المخولة فقط.", "forbidden")
            row = self.db.execute("SELECT s.*,e.employee_no,e.full_name AS employee_name FROM leave_sale_requests s JOIN employees e ON e.id=s.employee_id WHERE s.id=?", (request_id,)).fetchone()
            if row is None:
                raise APIError(404, "طلب بيع الرصيد غير موجود.", "not_found")
            if row["status"] != "submitted":
                raise APIError(409, "تم اتخاذ قرار نهائي على طلب بيع الرصيد سابقاً.", "invalid_status")
            data = self.read_json()
            action = str(data.get("action", ""))
            if action not in {"approve", "reject"}:
                raise APIError(422, "القرار يجب أن يكون approve أو reject.", "validation_error")
            note = optional_text(data, "reason", 1000)
            if action == "reject" and not note:
                raise APIError(422, "سبب الرفض مطلوب.", "validation_error")
            stamp = now_iso()
            with self.db:
                if action == "approve":
                    annual = self.db.execute("SELECT id FROM leave_types WHERE code='annual' AND active=1").fetchone()
                    balance = self.db.execute("SELECT * FROM leave_balances WHERE employee_id=? AND leave_type_id=? AND year=?", (row["employee_id"], annual["id"], local_now().year)).fetchone() if annual else None
                    balance_rows = {item["leave_type_id"]: item for item in self.leave_balance_rows(int(row["employee_id"]), local_now().year)}
                    balance_item = balance_rows.get(int(annual["id"])) if annual else None
                    available = float((balance_item or {}).get("raw_available", (balance_item or {}).get("available", 0))) + float(row["days"])
                    if float(row["days"]) > available + 1e-9:
                        raise APIError(409, "لم يعد الرصيد كافياً لاعتماد بيع الأيام.", "insufficient_balance", {"available": max(0, available)})
                    if balance is None and annual:
                        employee_record = self.db.execute("SELECT hire_date FROM employees WHERE id=?", (row["employee_id"],)).fetchone()
                        entitlement = annual_leave_entitlement_for_year(employee_record["hire_date"] if employee_record else None, local_now().year, local_now().date())
                        self.db.execute("INSERT INTO leave_balances(employee_id,leave_type_id,year,entitlement) VALUES(?,?,?,?)", (row["employee_id"], annual["id"], local_now().year, entitlement))
                    if annual:
                        self.db.execute("UPDATE leave_balances SET used=used+? WHERE employee_id=? AND leave_type_id=? AND year=?", (row["days"], row["employee_id"], annual["id"], local_now().year))
                status = "approved" if action == "approve" else "rejected"
                self.db.execute("UPDATE leave_sale_requests SET status=?,decision_note=?,decided_by=?,decided_at=?,updated_at=? WHERE id=?", (status, note, user["id"], stamp, stamp, request_id))
                employee_user = self.db.execute("SELECT id FROM users WHERE employee_id=? AND active=1", (row["employee_id"],)).fetchone()
                if employee_user:
                    create_internal_notification(
                        self.db, int(user["id"]), [int(employee_user["id"])],
                        "قرار طلب بيع رصيد الإجازة",
                        f"{'اعتمدت' if action == 'approve' else 'رفضت'} الموارد البشرية طلب بيع {row['days']:g} يوم من رصيدك."
                        + (f" السبب: {note}" if action == "reject" else f" المبلغ المحتسب: {cents_value(row['amount_cents']):,.2f}.")
                    )
                audit(self.db, user["id"], f"leave_sale.{status}", "leave_sale_request", request_id, {"days": row["days"], "reason": note})
            saved = self.db.execute(
                """SELECT s.*,e.employee_no,e.full_name AS employee_name,u.display_name AS decided_by_name
                   FROM leave_sale_requests s JOIN employees e ON e.id=s.employee_id
                   LEFT JOIN users u ON u.id=s.decided_by WHERE s.id=?""",
                (request_id,),
            ).fetchone()
            self.send_json(200, {"request": self.leave_sale_payload(saved, user)})

        # Annual evaluations
        def evaluation_goal_template_scope(self) -> tuple[dict[str, Any], sqlite3.Row]:
            user = self.current_user(True)
            assert user is not None
            requested = as_int(self.query["job_title_id"], "job_title_id", 1) if self.query.get("job_title_id") else None
            if requested is not None and has_permission(self.db, user, "reference.manage"):
                job_title_id = requested
            else:
                employee_id = user.get("employee_id")
                if not employee_id:
                    raise APIError(422, "اختر مسمى وظيفياً لعرض أهدافه.", "job_title_required")
                employee = self.db.execute("SELECT job_title_id FROM employees WHERE id=?", (employee_id,)).fetchone()
                if employee is None or not employee["job_title_id"]:
                    raise APIError(409, "ملفك غير مرتبط بمسمى وظيفي معتمد.", "job_title_missing")
                job_title_id = int(employee["job_title_id"])
                if requested is not None and requested != job_title_id:
                    raise APIError(403, "لا يمكنك عرض أهداف مسمى وظيفي آخر.", "forbidden")
            title = self.db.execute("SELECT id,name,active FROM job_titles WHERE id=?", (job_title_id,)).fetchone()
            if title is None:
                raise APIError(404, "المسمى الوظيفي غير موجود.", "not_found")
            return user, title

        def api_evaluation_goal_templates_get(self) -> None:
            user, title = self.evaluation_goal_template_scope()
            include_inactive = has_permission(self.db, user, "reference.manage") and self.query.get("include_inactive") == "1"
            sql = "SELECT * FROM evaluation_goal_templates WHERE job_title_id=?"
            if not include_inactive:
                sql += " AND active=1"
            rows = self.db.execute(sql + " ORDER BY sort_order,id", (title["id"],)).fetchall()
            self.send_json(200, {
                "job_title": {"id": title["id"], "name": title["name"], "active": bool(title["active"])},
                "items": [dict(row) | {"active": bool(row["active"])} for row in rows],
                "weight_total": round(sum(float(row["default_weight"]) for row in rows if bool(row["active"])), 2),
                "can_manage": has_permission(self.db, user, "reference.manage"),
            })

        def parse_goal_template(self, data: dict[str, Any], partial: bool = False) -> dict[str, Any]:
            values: dict[str, Any] = {}
            if not partial or "title" in data:
                values["title"] = require_text(data, "title", 240)
            for key, max_len in (("description", 2000), ("measure", 500)):
                if key in data or not partial:
                    values[key] = optional_text(data, key, max_len)
            if not partial or "default_weight" in data:
                values["default_weight"] = as_float(data.get("default_weight"), "default_weight", 0.01, 100)
            if "sort_order" in data or not partial:
                values["sort_order"] = as_int(data.get("sort_order", 0), "sort_order", 0, 999)
            if "active" in data:
                values["active"] = 1 if bool(data["active"]) else 0
            return values

        def api_evaluation_goal_template_post(self) -> None:
            user = self.require_permission("reference.manage")
            data = self.read_json()
            job_title_id = as_int(data.get("job_title_id"), "job_title_id", 1)
            if self.db.execute("SELECT 1 FROM job_titles WHERE id=?", (job_title_id,)).fetchone() is None:
                raise APIError(404, "المسمى الوظيفي غير موجود.", "not_found")
            values = self.parse_goal_template(data)
            stamp = now_iso()
            try:
                with self.db:
                    columns = ["job_title_id", *values.keys(), "created_at", "updated_at"]
                    cursor = self.db.execute(
                        f"INSERT INTO evaluation_goal_templates({','.join(columns)}) VALUES({','.join('?' for _ in columns)})",
                        (job_title_id, *values.values(), stamp, stamp),
                    )
                    template_id = int(cursor.lastrowid)
                    audit(self.db, user["id"], "evaluation_goal_template.create", "evaluation_goal_template", template_id, {"job_title_id": job_title_id, **values})
            except sqlite3.IntegrityError as exc:
                raise APIError(409, "هذا الهدف موجود مسبقاً للمسمى الوظيفي.", "duplicate_goal_template") from exc
            row = self.db.execute("SELECT * FROM evaluation_goal_templates WHERE id=?", (template_id,)).fetchone()
            self.send_json(201, {"template": dict(row) | {"active": bool(row["active"])}})

        def api_evaluation_goal_template_patch(self, template_id: int) -> None:
            user = self.require_permission("reference.manage")
            if self.db.execute("SELECT 1 FROM evaluation_goal_templates WHERE id=?", (template_id,)).fetchone() is None:
                raise APIError(404, "الهدف الرئيسي غير موجود.", "not_found")
            values = self.parse_goal_template(self.read_json(), partial=True)
            if not values:
                raise APIError(422, "لا توجد تغييرات للحفظ.", "validation_error")
            values["updated_at"] = now_iso()
            try:
                with self.db:
                    self.db.execute(
                        "UPDATE evaluation_goal_templates SET " + ",".join(f"{key}=?" for key in values) + " WHERE id=?",
                        (*values.values(), template_id),
                    )
                    audit(self.db, user["id"], "evaluation_goal_template.update", "evaluation_goal_template", template_id, values)
            except sqlite3.IntegrityError as exc:
                raise APIError(409, "هذا الهدف موجود مسبقاً للمسمى الوظيفي.", "duplicate_goal_template") from exc
            row = self.db.execute("SELECT * FROM evaluation_goal_templates WHERE id=?", (template_id,)).fetchone()
            self.send_json(200, {"template": dict(row) | {"active": bool(row["active"])}})

        def evaluation_access(self, evaluation_id: int) -> tuple[sqlite3.Row, dict[str, Any]]:
            user = self.current_user(True)
            assert user is not None
            evaluation = self.db.execute("SELECT e.*,c.year,c.name AS cycle_name,emp.full_name,emp.employee_no FROM evaluations e JOIN evaluation_cycles c ON c.id=e.cycle_id JOIN employees emp ON emp.id=e.employee_id WHERE e.id=?", (evaluation_id,)).fetchone()
            if evaluation is None:
                raise APIError(404, "التقييم غير موجود.", "not_found")
            is_approver = bool(user.get("employee_id") and self.db.execute("SELECT 1 FROM evaluation_approvals WHERE evaluation_id=? AND approver_employee_id=?", (evaluation_id, user["employee_id"])).fetchone())
            if evaluation["employee_id"] != user.get("employee_id") and not is_approver and not self.has_privileged_people_access(user, "evaluation.view"):
                raise APIError(403, "لا يمكنك عرض هذا التقييم.", "forbidden")
            return evaluation, user

        def evaluation_payload(self, evaluation_id: int) -> dict[str, Any]:
            evaluation = self.db.execute("SELECT e.*,c.year,c.name AS cycle_name,emp.full_name,emp.employee_no FROM evaluations e JOIN evaluation_cycles c ON c.id=e.cycle_id JOIN employees emp ON emp.id=e.employee_id WHERE e.id=?", (evaluation_id,)).fetchone()
            goals = self.db.execute("SELECT * FROM evaluation_goals WHERE evaluation_id=? ORDER BY id", (evaluation_id,)).fetchall()
            approvals = self.db.execute("SELECT a.*,e.full_name AS approver_name,u.role AS approver_role FROM evaluation_approvals a JOIN employees e ON e.id=a.approver_employee_id LEFT JOIN users u ON u.employee_id=e.id WHERE a.evaluation_id=? ORDER BY a.step_no", (evaluation_id,)).fetchall()
            weight_total = sum(float(g["weight"]) for g in goals)
            return {"evaluation": dict(evaluation), "goals": [dict(g) for g in goals], "weight_total": weight_total, "approvals": [dict(a) for a in approvals]}

        def api_evaluations_get(self) -> None:
            user = self.current_user(True)
            assert user is not None
            if self.has_privileged_people_access(user, "evaluation.view"):
                rows = self.db.execute("SELECT e.*,c.year,c.name AS cycle_name,emp.full_name,emp.employee_no FROM evaluations e JOIN evaluation_cycles c ON c.id=e.cycle_id JOIN employees emp ON emp.id=e.employee_id ORDER BY c.year DESC,emp.full_name").fetchall()
            else:
                employee_id = self.own_employee_id()
                rows = self.db.execute("SELECT DISTINCT e.*,c.year,c.name AS cycle_name,emp.full_name,emp.employee_no FROM evaluations e JOIN evaluation_cycles c ON c.id=e.cycle_id JOIN employees emp ON emp.id=e.employee_id LEFT JOIN evaluation_approvals a ON a.evaluation_id=e.id WHERE e.employee_id=? OR a.approver_employee_id=? ORDER BY c.year DESC", (employee_id, employee_id)).fetchall()
            pending = [dict(r) for r in rows if user.get("employee_id") and self.db.execute("SELECT 1 FROM evaluation_approvals WHERE evaluation_id=? AND approver_employee_id=? AND step_no=? AND status='pending'", (r["id"], user["employee_id"], r["current_step"])).fetchone()]
            self.send_json(200, {"items": [dict(r) for r in rows], "pending_for_me": pending})

        def api_evaluations_post(self) -> None:
            user = self.current_user(True)
            assert user is not None
            employee_id = self.own_employee_id()
            data = self.read_json()
            year = as_int(data.get("year", local_now().year), "year", 2000, 2200)
            cycle = self.db.execute("SELECT * FROM evaluation_cycles WHERE year=? AND active=1", (year,)).fetchone()
            if cycle is None:
                raise APIError(404, "لا توجد دورة تقييم نشطة لهذه السنة.", "cycle_not_found")
            existing = self.db.execute("SELECT id FROM evaluations WHERE cycle_id=? AND employee_id=?", (cycle["id"], employee_id)).fetchone()
            if existing:
                self.send_json(200, self.evaluation_payload(existing["id"]))
                return
            stamp = now_iso()
            with self.db:
                cur = self.db.execute("INSERT INTO evaluations(cycle_id,employee_id,created_at,updated_at) VALUES(?,?,?,?)", (cycle["id"], employee_id, stamp, stamp))
                evaluation_id = int(cur.lastrowid)
                audit(self.db, user["id"], "evaluation.create", "evaluation", evaluation_id)
            self.send_json(201, self.evaluation_payload(evaluation_id))

        def api_evaluation_get(self, evaluation_id: int) -> None:
            self.evaluation_access(evaluation_id)
            self.send_json(200, self.evaluation_payload(evaluation_id))

        def ensure_goal_owner(self, evaluation_id: int) -> tuple[sqlite3.Row, dict[str, Any]]:
            evaluation, user = self.evaluation_access(evaluation_id)
            if evaluation["employee_id"] != user.get("employee_id"):
                raise APIError(403, "الموظف وحده يحرر أهداف تقييمه.", "forbidden")
            if evaluation["status"] not in {"draft", "returned"}:
                raise APIError(409, "لا يمكن تعديل الأهداف بعد إرسال التقييم.", "invalid_status")
            return evaluation, user

        def parse_goal(self, data: dict[str, Any], partial: bool = False) -> dict[str, Any]:
            result: dict[str, Any] = {}
            if not partial or "title" in data:
                result["title"] = require_text(data, "title", 240)
            if not partial or "measure" in data:
                result["measure"] = require_text(data, "measure", 500)
            for key, max_len in (("description", 2000), ("employee_comment", 2000), ("evidence_note", 4000)):
                if key in data or not partial:
                    result[key] = optional_text(data, key, max_len)
            if not partial or "weight" in data:
                result["weight"] = as_float(data.get("weight"), "weight", 0.01, 100)
            if "achievement" in data or not partial:
                result["achievement"] = as_float(data.get("achievement", 0), "achievement", 0, 100)
            if not partial or "goal_type" in data:
                goal_type = str(data.get("goal_type", "result"))
                if goal_type not in {"result", "behaviour", "development"}:
                    raise APIError(422, "نوع الهدف غير صالح.", "invalid_goal_type")
                result["goal_type"] = goal_type
            if not partial or "progress_status" in data:
                progress = str(data.get("progress_status", "not_completed"))
                if progress not in {"completed", "in_progress", "not_completed"}:
                    raise APIError(422, "حالة تقدم الهدف غير صالحة.", "invalid_progress_status")
                result["progress_status"] = progress
            for field in ("start_date", "end_date"):
                if not partial or field in data:
                    result[field] = parse_date(data.get(field), field).isoformat()
            return result

        def validate_evaluation_goal(self, evaluation: sqlite3.Row | dict[str, Any], goal: dict[str, Any], require_evidence: bool = False) -> None:
            if str(goal.get("goal_type") or "") not in {"result", "behaviour", "development"}:
                raise APIError(422, "نوع الهدف غير صالح.", "invalid_goal_type")
            start = parse_date(goal.get("start_date"), "start_date")
            end = parse_date(goal.get("end_date"), "end_date")
            period_start = parse_date(evaluation["period_start"], "period_start")
            period_end = parse_date(evaluation["period_end"], "period_end")
            if start > end:
                raise APIError(422, "تاريخ بداية الهدف يجب أن يسبق نهايته.", "invalid_goal_dates")
            if start < period_start or end > period_end:
                raise APIError(422, "تواريخ الهدف يجب أن تقع داخل فترة أداء الدورة.", "goal_outside_cycle_period", {"period_start": period_start.isoformat(), "period_end": period_end.isoformat()})
            achievement = float(goal.get("achievement") or 0)
            progress = str(goal.get("progress_status") or "")
            if progress not in {"completed", "in_progress", "not_completed"}:
                raise APIError(422, "حالة تقدم الهدف غير صالحة.", "invalid_progress_status")
            if (progress == "completed" and abs(achievement - 100) > 0.000001) or (progress == "not_completed" and abs(achievement) > 0.000001) or (progress == "in_progress" and not 0 < achievement < 100):
                raise APIError(422, "حالة التقدم لا تتوافق مع نسبة الإنجاز: منجز 100٪، لم يُنجز 0٪، وقيد التقدم بينهما.", "goal_progress_mismatch")
            if require_evidence and not str(goal.get("evidence_note") or "").strip():
                raise APIError(422, "أدخل نتيجة أو دليل إنجاز لكل هدف قبل الإرسال.", "goal_evidence_required", {"goal_id": goal.get("id")})

        def api_evaluation_goal_post(self, evaluation_id: int) -> None:
            evaluation, user = self.ensure_goal_owner(evaluation_id)
            data = self.read_json()
            template_id = as_int(data["template_id"], "template_id", 1) if data.get("template_id") else None
            if template_id:
                template = self.db.execute(
                    """SELECT t.* FROM evaluation_goal_templates t
                       JOIN employees e ON e.job_title_id=t.job_title_id
                       WHERE t.id=? AND e.id=? AND t.active=1""",
                    (template_id, evaluation["employee_id"]),
                ).fetchone()
                if template is None:
                    raise APIError(403, "الهدف المختار لا يتبع مسماك الوظيفي أو أنه متوقف.", "invalid_goal_template")
                values = {
                    "source_template_id": template_id,
                    "title": template["title"],
                    "description": template["description"],
                    "weight": float(template["default_weight"]),
                    "measure": template["measure"],
                    "achievement": as_float(data.get("achievement", 0), "achievement", 0, 100),
                    "employee_comment": optional_text(data, "employee_comment", 2000),
                    "goal_type": str(data.get("goal_type", "result")),
                    "start_date": parse_date(data.get("start_date", evaluation["period_start"]), "start_date").isoformat(),
                    "end_date": parse_date(data.get("end_date", evaluation["period_end"]), "end_date").isoformat(),
                    "progress_status": str(data.get("progress_status", "not_completed")),
                    "evidence_note": optional_text(data, "evidence_note", 4000),
                }
            else:
                values = self.parse_goal(data)
            self.validate_evaluation_goal(evaluation, values)
            current = float(self.db.execute("SELECT COALESCE(SUM(weight),0) FROM evaluation_goals WHERE evaluation_id=?", (evaluation_id,)).fetchone()[0])
            if current + values["weight"] > 100.000001:
                raise APIError(422, "مجموع الأوزان لا يمكن أن يتجاوز 100.", "invalid_weight_total", {"current": current})
            stamp = now_iso()
            try:
                with self.db:
                    cols = ["evaluation_id"] + list(values) + ["created_at", "updated_at"]
                    cur = self.db.execute(f"INSERT INTO evaluation_goals({','.join(cols)}) VALUES({','.join('?' for _ in cols)})", (evaluation_id, *values.values(), stamp, stamp))
                    goal_id = int(cur.lastrowid)
                    audit(self.db, user["id"], "evaluation.goal_create", "evaluation_goal", goal_id, {"source_template_id": template_id, "goal_type": values.get("goal_type"), "start_date": values.get("start_date"), "end_date": values.get("end_date")})
            except sqlite3.IntegrityError as exc:
                raise APIError(409, "سبق اختيار هذا الهدف الرئيسي في تقييمك.", "duplicate_goal_template") from exc
            self.send_json(201, self.evaluation_payload(evaluation_id))

        def api_evaluation_goals_from_templates(self, evaluation_id: int) -> None:
            evaluation, user = self.ensure_goal_owner(evaluation_id)
            data = self.read_json()
            raw_ids = data.get("template_ids")
            if data.get("all") is True:
                rows = self.db.execute(
                    """SELECT t.* FROM evaluation_goal_templates t JOIN employees e ON e.job_title_id=t.job_title_id
                       WHERE e.id=? AND t.active=1 ORDER BY t.sort_order,t.id""",
                    (evaluation["employee_id"],),
                ).fetchall()
            else:
                if not isinstance(raw_ids, list) or not raw_ids or len(raw_ids) > 25:
                    raise APIError(422, "اختر هدفاً رئيسياً واحداً على الأقل.", "template_ids_required")
                template_ids = list(dict.fromkeys(as_int(item, "template_id", 1) for item in raw_ids))
                marks = ",".join("?" for _ in template_ids)
                rows = self.db.execute(
                    f"""SELECT t.* FROM evaluation_goal_templates t JOIN employees e ON e.job_title_id=t.job_title_id
                        WHERE e.id=? AND t.active=1 AND t.id IN ({marks}) ORDER BY t.sort_order,t.id""",
                    (evaluation["employee_id"], *template_ids),
                ).fetchall()
                if len(rows) != len(template_ids):
                    raise APIError(403, "تتضمن القائمة هدفاً لا يتبع مسماك الوظيفي.", "invalid_goal_template")
            if not rows:
                raise APIError(404, "لا توجد أهداف رئيسية نشطة لمسماك الوظيفي.", "goal_templates_missing")
            existing = {int(row[0]) for row in self.db.execute("SELECT source_template_id FROM evaluation_goals WHERE evaluation_id=? AND source_template_id IS NOT NULL", (evaluation_id,)).fetchall()}
            rows = [row for row in rows if int(row["id"]) not in existing]
            if not rows:
                raise APIError(409, "أضفت جميع الأهداف المختارة مسبقاً.", "goal_templates_already_added")
            current = float(self.db.execute("SELECT COALESCE(SUM(weight),0) FROM evaluation_goals WHERE evaluation_id=?", (evaluation_id,)).fetchone()[0])
            added_weight = sum(float(row["default_weight"]) for row in rows)
            if current + added_weight > 100.000001:
                raise APIError(422, "الأوزان المختارة ستتجاوز 100. اختر أهدافاً أقل أو عدّل أهدافك المخصصة.", "invalid_weight_total", {"current": current, "selected": added_weight})
            stamp = now_iso()
            with self.db:
                added_ids = []
                for template in rows:
                    cursor = self.db.execute(
                        """INSERT INTO evaluation_goals
                           (evaluation_id,source_template_id,title,description,weight,measure,achievement,employee_comment,
                            goal_type,start_date,end_date,progress_status,evidence_note,created_at,updated_at)
                           VALUES(?,?,?,?,?,?,0,'','result',?,?,'not_completed','',?,?)""",
                        (evaluation_id, template["id"], template["title"], template["description"], template["default_weight"], template["measure"], evaluation["period_start"], evaluation["period_end"], stamp, stamp),
                    )
                    added_ids.append(int(cursor.lastrowid))
                audit(self.db, user["id"], "evaluation.goals_from_templates", "evaluation", evaluation_id, {"template_ids": [int(row["id"]) for row in rows], "goal_ids": added_ids})
            self.send_json(201, self.evaluation_payload(evaluation_id))

        def api_evaluation_goal_patch(self, goal_id: int) -> None:
            goal = self.db.execute("SELECT * FROM evaluation_goals WHERE id=?", (goal_id,)).fetchone()
            if goal is None:
                raise APIError(404, "الهدف غير موجود.", "not_found")
            evaluation, user = self.ensure_goal_owner(goal["evaluation_id"])
            values = self.parse_goal(self.read_json(), partial=True)
            if not values:
                raise APIError(422, "لا توجد تغييرات للحفظ.", "validation_error")
            if "weight" in values:
                other = float(self.db.execute("SELECT COALESCE(SUM(weight),0) FROM evaluation_goals WHERE evaluation_id=? AND id<>?", (goal["evaluation_id"], goal_id)).fetchone()[0])
                if other + values["weight"] > 100.000001:
                    raise APIError(422, "مجموع الأوزان لا يمكن أن يتجاوز 100.", "invalid_weight_total", {"other_goals": other})
            self.validate_evaluation_goal(evaluation, dict(goal) | values)
            values["updated_at"] = now_iso()
            with self.db:
                self.db.execute("UPDATE evaluation_goals SET " + ",".join(f"{k}=?" for k in values) + " WHERE id=?", (*values.values(), goal_id))
                audit(self.db, user["id"], "evaluation.goal_update", "evaluation_goal", goal_id, values)
            self.send_json(200, self.evaluation_payload(goal["evaluation_id"]))

        def api_evaluation_goal_delete(self, goal_id: int) -> None:
            goal = self.db.execute("SELECT * FROM evaluation_goals WHERE id=?", (goal_id,)).fetchone()
            if goal is None:
                raise APIError(404, "الهدف غير موجود.", "not_found")
            _, user = self.ensure_goal_owner(goal["evaluation_id"])
            with self.db:
                self.db.execute("DELETE FROM evaluation_goals WHERE id=?", (goal_id,))
                audit(self.db, user["id"], "evaluation.goal_delete", "evaluation_goal", goal_id)
            self.send_json(200, self.evaluation_payload(goal["evaluation_id"]))

        def build_approval_chain(self, employee_id: int) -> list[int]:
            chain: list[int] = []
            seen = {employee_id}
            current = self.db.execute("SELECT manager_id FROM employees WHERE id=?", (employee_id,)).fetchone()
            manager_id = current["manager_id"] if current else None
            found_gm = False
            while manager_id and manager_id not in seen and len(chain) < 20:
                seen.add(manager_id)
                account = self.db.execute("SELECT role,active FROM users WHERE employee_id=?", (manager_id,)).fetchone()
                if account and bool(account["active"]):
                    chain.append(int(manager_id))
                    if account["role"] == "general_manager":
                        found_gm = True
                        break
                next_row = self.db.execute("SELECT manager_id FROM employees WHERE id=?", (manager_id,)).fetchone()
                manager_id = next_row["manager_id"] if next_row else None
            if not chain or not found_gm:
                raise APIError(409, "سلسلة الاعتماد غير مكتملة حتى المدير العام. حدّث المدير المباشر في ملف الموظف.", "approval_chain_incomplete")
            return chain

        def api_evaluation_submit(self, evaluation_id: int) -> None:
            evaluation, user = self.ensure_goal_owner(evaluation_id)
            goals = self.db.execute("SELECT * FROM evaluation_goals WHERE evaluation_id=?", (evaluation_id,)).fetchall()
            total = sum(float(g["weight"]) for g in goals)
            if not goals or abs(total - 100.0) > 0.000001:
                raise APIError(422, "لا يمكن الإرسال إلا عندما يساوي مجموع الأوزان 100 تماماً.", "invalid_weight_total", {"weight_total": total})
            score = sum(float(g["weight"]) * float(g["achievement"]) / 100.0 for g in goals)
            rating = "ممتاز" if score >= 90 else "جيد جداً" if score >= 80 else "جيد" if score >= 70 else "مقبول" if score >= 60 else "ضعيف / لم يستوف المتطلبات"
            chain = self.build_approval_chain(evaluation["employee_id"])
            stamp = now_iso()
            with self.db:
                self.db.execute("DELETE FROM evaluation_approvals WHERE evaluation_id=?", (evaluation_id,))
                for step, approver in enumerate(chain, 1):
                    self.db.execute("INSERT INTO evaluation_approvals(evaluation_id,step_no,approver_employee_id,created_at) VALUES(?,?,?,?)", (evaluation_id, step, approver, stamp))
                self.db.execute("UPDATE evaluations SET status='in_review',weighted_score=?,rating=?,current_step=1,submitted_at=?,finalized_at=NULL,updated_at=? WHERE id=?", (round(score, 2), rating, stamp, stamp, evaluation_id))
                audit(self.db, user["id"], "evaluation.submit", "evaluation", evaluation_id, {"score": score, "approval_steps": len(chain)})
            self.send_json(200, self.evaluation_payload(evaluation_id))

        def api_evaluation_decision(self, evaluation_id: int) -> None:
            evaluation, user = self.evaluation_access(evaluation_id)
            if evaluation["status"] != "in_review":
                raise APIError(409, "التقييم ليس في مرحلة الاعتماد.", "invalid_status")
            if not user.get("employee_id"):
                raise APIError(403, "يجب ربط حساب المعتمد بملف موظف.", "employee_not_linked")
            approval = self.db.execute("SELECT * FROM evaluation_approvals WHERE evaluation_id=? AND step_no=?", (evaluation_id, evaluation["current_step"])).fetchone()
            if approval is None or approval["approver_employee_id"] != user["employee_id"]:
                raise APIError(403, "هذا التقييم لا ينتظر إجراءك في المرحلة الحالية.", "not_current_approver")
            if evaluation["employee_id"] == user["employee_id"]:
                raise APIError(403, "لا يمكن اعتماد تقييمك الشخصي.", "self_approval_forbidden")
            data = self.read_json()
            action = str(data.get("action", ""))
            if action not in {"approve", "reject", "return"}:
                raise APIError(422, "القرار يجب أن يكون approve أو reject أو return.", "validation_error")
            comment = optional_text(data, "comment", 2000)
            if action in {"reject", "return"} and not comment:
                raise APIError(422, "التعليق مطلوب للرفض أو الإعادة.", "validation_error")
            stamp = now_iso()
            with self.db:
                approval_status = "approved" if action == "approve" else "rejected" if action == "reject" else "returned"
                self.db.execute("UPDATE evaluation_approvals SET status=?,comment=?,decided_at=? WHERE id=?", (approval_status, comment, stamp, approval["id"]))
                if action == "approve":
                    next_step = self.db.execute("SELECT step_no FROM evaluation_approvals WHERE evaluation_id=? AND step_no>? ORDER BY step_no LIMIT 1", (evaluation_id, approval["step_no"])).fetchone()
                    if next_step:
                        self.db.execute("UPDATE evaluations SET current_step=?,updated_at=? WHERE id=?", (next_step["step_no"], stamp, evaluation_id))
                    else:
                        self.db.execute("UPDATE evaluations SET status='approved',finalized_at=?,updated_at=? WHERE id=?", (stamp, stamp, evaluation_id))
                elif action == "return":
                    self.db.execute("UPDATE evaluations SET status='returned',current_step=0,updated_at=? WHERE id=?", (stamp, evaluation_id))
                else:
                    self.db.execute("UPDATE evaluations SET status='rejected',updated_at=? WHERE id=?", (stamp, evaluation_id))
                audit(self.db, user["id"], f"evaluation.{action}", "evaluation", evaluation_id, {"step": approval["step_no"], "comment": comment})
            self.send_json(200, self.evaluation_payload(evaluation_id))

        # V5.1 HR-governed performance cycles
        def evaluation_cycle_row(self, cycle_id: int) -> sqlite3.Row:
            row = self.db.execute(
                """SELECT c.*,creator.display_name AS creator_name,announcer.display_name AS announcer_name
                     FROM evaluation_cycles c
                     LEFT JOIN users creator ON creator.id=c.created_by
                     LEFT JOIN users announcer ON announcer.id=c.announced_by
                    WHERE c.id=?""",
                (cycle_id,),
            ).fetchone()
            if row is None:
                raise APIError(404, "دورة التقييم غير موجودة.", "not_found")
            return row

        def parse_evaluation_cycle(self, data: dict[str, Any], current: sqlite3.Row | None = None) -> dict[str, Any]:
            merged = dict(current) if current is not None else {}
            values: dict[str, Any] = {}
            if current is None or "year" in data:
                values["year"] = as_int(data.get("year"), "year", 2000, 2200)
            if current is None or "name" in data:
                values["name"] = require_text(data, "name", 180)
            for field in ("period_start", "period_end", "self_opens_on", "self_due_on", "manager_due_on", "hr_due_on"):
                if current is None or field in data:
                    values[field] = parse_date(data.get(field), field).isoformat()
            for field, limit in (("announcement_title", 240), ("announcement_body", 3000)):
                if field in data or current is None:
                    values[field] = optional_text(data, field, limit)
            merged.update(values)
            period_start = parse_date(merged.get("period_start"), "period_start")
            period_end = parse_date(merged.get("period_end"), "period_end")
            self_open = parse_date(merged.get("self_opens_on"), "self_opens_on")
            self_due = parse_date(merged.get("self_due_on"), "self_due_on")
            manager_due = parse_date(merged.get("manager_due_on"), "manager_due_on")
            hr_due = parse_date(merged.get("hr_due_on"), "hr_due_on")
            if period_start > period_end:
                raise APIError(422, "بداية فترة الأداء يجب أن تسبق نهايتها.", "invalid_cycle_dates")
            if not (self_open <= self_due <= manager_due <= hr_due):
                raise APIError(422, "يجب ترتيب فتح التقييم وموعد الموظف ثم المسؤول ثم الموارد البشرية.", "invalid_cycle_dates")
            if self_open > period_end:
                raise APIError(422, "لا يمكن فتح التقييم الذاتي بعد نهاية فترة الأداء.", "invalid_cycle_dates")
            return values

        def evaluation_cycle_counts(self, cycle: sqlite3.Row) -> dict[str, int]:
            today = local_now().date()
            due = parse_date(cycle["self_due_on"], "self_due_on")
            rows = self.db.execute("SELECT * FROM evaluations WHERE cycle_id=?", (cycle["id"],)).fetchall()
            counts = {
                "total": len(rows), "not_started": 0, "submitted_to_manager": 0,
                "returned_to_manager": 0, "waiting_hr": 0,
                "approved_waiting_disclosure": 0, "published": 0,
                "late": 0, "missing_manager": 0,
            }
            for evaluation in rows:
                status = str(evaluation["status"])
                if status == "draft": counts["not_started"] += 1
                elif status == "submitted": counts["submitted_to_manager"] += 1
                elif status == "returned": counts["returned_to_manager"] += 1
                elif status == "in_review": counts["waiting_hr"] += 1
                elif status == "approved":
                    disclosure = evaluation["disclosure_date"]
                    if int(evaluation["workflow_version"] or 1) < 2 or (disclosure and parse_date(disclosure, "disclosure_date") <= today):
                        counts["published"] += 1
                    else:
                        counts["approved_waiting_disclosure"] += 1
                if bool(evaluation["submitted_late"]) or (status == "draft" and today > due):
                    counts["late"] += 1
                if evaluation["manager_employee_id"] is None:
                    counts["missing_manager"] += 1
            return counts

        def evaluation_cycle_payload(self, cycle_id: int, include_recipients: bool = False) -> dict[str, Any]:
            cycle = self.evaluation_cycle_row(cycle_id)
            data = dict(cycle)
            data["active"] = bool(data["active"])
            counts = self.evaluation_cycle_counts(cycle)
            data["counts"] = counts
            data["preview"] = {
                "eligible": int(self.db.execute("SELECT COUNT(*) FROM employees WHERE active=1").fetchone()[0]),
                "already_assigned": counts["total"],
                "missing_manager": int(self.db.execute(
                    """SELECT COUNT(*) FROM employees e LEFT JOIN departments d ON d.id=e.department_id
                        WHERE e.active=1 AND (COALESCE(e.manager_id,d.manager_employee_id) IS NULL OR COALESCE(e.manager_id,d.manager_employee_id)=e.id)"""
                ).fetchone()[0]),
            }
            if include_recipients:
                today = local_now().date()
                due = parse_date(cycle["self_due_on"], "self_due_on")
                recipients = []
                rows = self.db.execute(
                    """SELECT ev.id AS evaluation_id,ev.status,ev.submitted_late,ev.manager_employee_id,
                              emp.id AS employee_id,emp.full_name,emp.employee_no,mgr.full_name AS manager_name
                         FROM evaluations ev JOIN employees emp ON emp.id=ev.employee_id
                         LEFT JOIN employees mgr ON mgr.id=ev.manager_employee_id
                        WHERE ev.cycle_id=? ORDER BY emp.full_name""",
                    (cycle_id,),
                ).fetchall()
                for row in rows:
                    item = dict(row)
                    item["due_state"] = "missing_manager" if row["manager_employee_id"] is None else "late" if (bool(row["submitted_late"]) or (row["status"] == "draft" and today > due)) else "on_track"
                    item["submitted_late"] = bool(row["submitted_late"])
                    recipients.append(item)
                data["recipients"] = recipients
            return data

        def require_cycle_console(self) -> dict[str, Any]:
            user = self.current_user(True)
            assert user is not None
            if not (has_permission(self.db, user, "evaluation.cycle.manage") or has_permission(self.db, user, "evaluation.review")):
                raise APIError(403, "لا تملك صلاحية عرض إدارة دورات التقييم.", "forbidden")
            return user

        def api_evaluation_cycles_get(self) -> None:
            self.require_cycle_console()
            rows = self.db.execute("SELECT id FROM evaluation_cycles ORDER BY year DESC,id DESC").fetchall()
            self.send_json(200, {"items": [self.evaluation_cycle_payload(int(row["id"])) for row in rows]})

        def api_evaluation_cycle_get(self, cycle_id: int) -> None:
            self.require_cycle_console()
            self.send_json(200, {"cycle": self.evaluation_cycle_payload(cycle_id, include_recipients=True)})

        def api_evaluation_cycle_post(self) -> None:
            user = self.require_permission("evaluation.cycle.manage")
            data = self.read_json()
            values = self.parse_evaluation_cycle(data)
            values["announcement_title"] = values["announcement_title"] or f"إعلان {values['name']}"
            preview_values = values | {"name": values["name"]}
            values["announcement_body"] = values["announcement_body"] or evaluation_cycle_announcement_body(preview_values)
            stamp = now_iso()
            columns = ["year", "name", "starts_on", "ends_on", "active", "status", "created_by", "created_at", "updated_at", *[key for key in values if key not in {"year", "name"}]]
            params = [values["year"], values["name"], values["period_start"], values["period_end"], 1, "draft", user["id"], stamp, stamp, *[values[key] for key in values if key not in {"year", "name"}]]
            try:
                with self.db:
                    cursor = self.db.execute(
                        f"INSERT INTO evaluation_cycles({','.join(columns)}) VALUES({','.join('?' for _ in columns)})",
                        params,
                    )
                    cycle_id = int(cursor.lastrowid)
                    audit(self.db, user["id"], "evaluation.cycle_create", "evaluation_cycle", cycle_id, {key: values[key] for key in values})
            except sqlite3.IntegrityError as exc:
                raise APIError(409, "توجد دورة تقييم لهذه السنة بالفعل.", "duplicate_cycle") from exc
            self.send_json(201, {"cycle": self.evaluation_cycle_payload(cycle_id, include_recipients=True)})

        def api_evaluation_cycle_patch(self, cycle_id: int) -> None:
            user = self.require_permission("evaluation.cycle.manage")
            cycle = self.evaluation_cycle_row(cycle_id)
            data = self.read_json()
            stamp = now_iso()
            if str(cycle["status"]) == "closed":
                raise APIError(409, "الدورة مغلقة ولا يمكن تعديلها.", "cycle_closed")
            if str(cycle["status"]) == "draft":
                values = self.parse_evaluation_cycle(data, cycle)
                if not values:
                    raise APIError(422, "لا توجد تغييرات للحفظ.", "validation_error")
                if "period_start" in values: values["starts_on"] = values["period_start"]
                if "period_end" in values: values["ends_on"] = values["period_end"]
            else:
                if data.get("status") == "closed":
                    reason = require_text(data, "reason", 1000)
                    values = {"status": "closed", "active": 0, "extension_reason": reason}
                else:
                    reason = require_text(data, "reason", 1000)
                    allowed = {"self_due_on", "manager_due_on", "hr_due_on"}
                    if not any(field in data for field in allowed) or any(key not in allowed | {"reason"} for key in data):
                        raise APIError(422, "بعد الإعلان لا يسمح إلا بتمديد المواعيد مع ذكر السبب.", "announced_cycle_locked")
                    values = self.parse_evaluation_cycle({key: data[key] for key in allowed if key in data}, cycle)
                    for field in allowed:
                        if field in values and parse_date(values[field], field) < parse_date(cycle[field], field):
                            raise APIError(422, "لا يمكن تقصير موعد دورة معلنة.", "cycle_date_cannot_shorten", {"field": field})
                    values["extension_reason"] = reason
            values["updated_at"] = stamp
            with self.db:
                self.db.execute("UPDATE evaluation_cycles SET " + ",".join(f"{key}=?" for key in values) + " WHERE id=?", (*values.values(), cycle_id))
                audit(self.db, user["id"], "evaluation.cycle_close" if values.get("status") == "closed" else "evaluation.cycle_update", "evaluation_cycle", cycle_id, values)
            self.send_json(200, {"cycle": self.evaluation_cycle_payload(cycle_id, include_recipients=True)})

        def api_evaluation_cycle_announce(self, cycle_id: int) -> None:
            user = self.require_permission("evaluation.cycle.manage")
            cycle = self.evaluation_cycle_row(cycle_id)
            if cycle["status"] == "closed":
                raise APIError(409, "لا يمكن إعلان دورة مغلقة.", "cycle_closed")
            if cycle["status"] == "announced":
                self.send_json(200, {"cycle": self.evaluation_cycle_payload(cycle_id, include_recipients=True), "idempotent": True})
                return
            stamp = now_iso()
            title = cycle["announcement_title"] or f"إعلان {cycle['name']}"
            body = cycle["announcement_body"] or evaluation_cycle_announcement_body(cycle)
            with self.db:
                self.db.execute(
                    """UPDATE evaluation_cycles SET status='announced',active=1,announcement_title=?,announcement_body=?,
                       announced_by=?,announced_at=?,updated_at=? WHERE id=?""",
                    (title, body, user["id"], stamp, stamp, cycle_id),
                )
                scope = enroll_evaluation_cycle(self.db, cycle_id, user["id"], notify=True)
                audit(self.db, user["id"], "evaluation.cycle_announce", "evaluation_cycle", cycle_id, scope)
            self.send_json(200, {"cycle": self.evaluation_cycle_payload(cycle_id, include_recipients=True), "idempotent": False})

        def api_evaluation_cycle_reminders(self, cycle_id: int) -> None:
            user = self.require_permission("evaluation.cycle.manage")
            cycle = self.evaluation_cycle_row(cycle_id)
            if cycle["status"] != "announced":
                raise APIError(409, "لا ترسل التذكيرات إلا لدورة معلنة.", "cycle_not_announced")
            data = self.read_json()
            raw_ids = data.get("employee_ids")
            if not isinstance(raw_ids, list) or not raw_ids or len(raw_ids) > 500:
                raise APIError(422, "اختر موظفاً واحداً على الأقل للتذكير.", "employee_ids_required")
            employee_ids = list(dict.fromkeys(as_int(item, "employee_id", 1) for item in raw_ids))
            key = f"manual:{local_now().date().isoformat()}"
            sent = 0
            skipped = 0
            with self.db:
                for employee_id in employee_ids:
                    evaluation = self.db.execute(
                        "SELECT id FROM evaluations WHERE cycle_id=? AND employee_id=? AND status='draft'",
                        (cycle_id, employee_id),
                    ).fetchone()
                    account = self.db.execute("SELECT id FROM users WHERE employee_id=? AND active=1", (employee_id,)).fetchone()
                    if evaluation is None or account is None:
                        skipped += 1
                        continue
                    cursor = self.db.execute(
                        """INSERT OR IGNORE INTO evaluation_reminders
                           (cycle_id,employee_id,reminder_type,notification_id,created_by,sent_at)
                           VALUES(?,?,?,NULL,?,?)""",
                        (cycle_id, employee_id, key, user["id"], now_iso()),
                    )
                    if cursor.rowcount == 0:
                        skipped += 1
                        continue
                    notification_id = create_internal_notification(
                        self.db, user["id"], [int(account["id"])], "تذكير بإكمال التقييم الذاتي",
                        f"الدورة: {cycle['name']}. آخر موعد للإرسال {cycle['self_due_on']}. افتح صفحة التقييم السنوي (#evaluations).",
                    )
                    self.db.execute("UPDATE evaluation_reminders SET notification_id=? WHERE cycle_id=? AND employee_id=? AND reminder_type=?", (notification_id, cycle_id, employee_id, key))
                    sent += 1
                audit(self.db, user["id"], "evaluation.cycle_remind", "evaluation_cycle", cycle_id, {"employee_ids": employee_ids, "sent": sent, "skipped": skipped, "rate_key": key})
            self.send_json(200, {"sent": sent, "skipped": skipped, "rate_key": key})

        # V5 annual evaluation workflow. Initialization upgrades actionable V1
        # rows that have a direct manager; terminal history and configuration-
        # blocked rows remain V1. Every new row uses employee -> manager -> HR
        # with a server-side disclosure gate.
        @staticmethod
        def evaluation_rating(score: float) -> str:
            return "ممتاز" if score >= 90 else "جيد جداً" if score >= 80 else "جيد" if score >= 70 else "مقبول" if score >= 60 else "ضعيف / لم يستوف المتطلبات"

        def evaluation_row(self, evaluation_id: int) -> sqlite3.Row:
            row = self.db.execute(
                """SELECT e.*,c.year,c.name AS cycle_name,emp.full_name,emp.employee_no,
                          c.period_start,c.period_end,c.self_opens_on,c.self_due_on,c.manager_due_on,c.hr_due_on,
                          c.status AS cycle_status,c.announcement_title,c.announcement_body,c.announced_at,
                          mgr.full_name AS manager_name,hr.display_name AS hr_reviewer_name
                     FROM evaluations e JOIN evaluation_cycles c ON c.id=e.cycle_id
                     JOIN employees emp ON emp.id=e.employee_id
                     LEFT JOIN employees mgr ON mgr.id=e.manager_employee_id
                     LEFT JOIN users hr ON hr.id=e.hr_reviewed_by WHERE e.id=?""",
                (evaluation_id,),
            ).fetchone()
            if row is None:
                raise APIError(404, "التقييم غير موجود.", "not_found")
            return row

        def evaluation_is_published(self, evaluation: sqlite3.Row | dict[str, Any]) -> bool:
            if int(evaluation.get("workflow_version", 1) if isinstance(evaluation, dict) else evaluation["workflow_version"]) < 2:
                return str(evaluation["status"]) == "approved"
            disclosure = evaluation["disclosure_date"]
            return str(evaluation["status"]) == "approved" and bool(disclosure) and parse_date(disclosure, "disclosure_date") <= local_now().date()

        def evaluation_access(self, evaluation_id: int) -> tuple[sqlite3.Row, dict[str, Any]]:
            user = self.current_user(True)
            assert user is not None
            evaluation = self.evaluation_row(evaluation_id)
            own = evaluation["employee_id"] == user.get("employee_id")
            current_manager = self.direct_manager_employee_id(int(evaluation["employee_id"]))
            direct_manager = bool(user.get("employee_id") and current_manager == user["employee_id"] and evaluation["manager_employee_id"] == user["employee_id"])
            hr_reviewer = has_permission(self.db, user, "evaluation.review")
            legacy_approver = bool(
                int(evaluation["workflow_version"] or 1) < 2
                and user.get("employee_id")
                and self.db.execute("SELECT 1 FROM evaluation_approvals WHERE evaluation_id=? AND approver_employee_id=?", (evaluation_id, user["employee_id"])).fetchone()
            )
            if not (own or direct_manager or hr_reviewer or legacy_approver):
                raise APIError(403, "لا يمكنك عرض هذا التقييم.", "forbidden")
            return evaluation, user

        def evaluation_payload(self, evaluation_id: int) -> dict[str, Any]:
            evaluation, user = self.evaluation_access(evaluation_id)
            evaluation_data = dict(evaluation)
            goal_rows = [dict(row) for row in self.db.execute("SELECT * FROM evaluation_goals WHERE evaluation_id=? ORDER BY id", (evaluation_id,))]
            approvals = [dict(row) for row in self.db.execute(
                """SELECT a.*,e.full_name AS approver_name,u.role AS approver_role
                     FROM evaluation_approvals a JOIN employees e ON e.id=a.approver_employee_id
                     LEFT JOIN users u ON u.employee_id=e.id WHERE a.evaluation_id=? ORDER BY a.step_no""",
                (evaluation_id,),
            )]
            grievance_row = self.db.execute("SELECT * FROM evaluation_grievances WHERE evaluation_id=?", (evaluation_id,)).fetchone()
            own = evaluation["employee_id"] == user.get("employee_id")
            published = self.evaluation_is_published(evaluation)
            hr_reviewer = has_permission(self.db, user, "evaluation.review")
            manager_override = has_permission(self.db, user, "evaluation.override_manager") and str(user.get("role")) in {"hr", "admin"} and not own
            current_manager = self.direct_manager_employee_id(int(evaluation["employee_id"]))
            direct_manager = bool(user.get("employee_id") and current_manager == user["employee_id"] and evaluation["manager_employee_id"] == user["employee_id"])
            if own and not published and int(evaluation["workflow_version"] or 1) >= 2:
                for field in ("weighted_score", "rating", "manager_report", "manager_submitted_at", "hr_comment", "finalized_at"):
                    evaluation_data[field] = None
                for goal in goal_rows:
                    goal.pop("awarded_points", None)
            grievance = dict(grievance_row) if grievance_row and (own or hr_reviewer) else None
            weight_total = sum(float(goal["weight"]) for goal in goal_rows)
            score_visible = published or (not own and (direct_manager or hr_reviewer))
            score_total = sum(float(goal.get("awarded_points") or 0) for goal in goal_rows) if score_visible else None
            evaluation_data.update({
                "published": published,
                "can_manager_review": bool((direct_manager or manager_override) and int(evaluation["workflow_version"] or 1) >= 2 and evaluation["status"] in {"submitted", "returned"}),
                "can_manager_override": bool(manager_override and int(evaluation["workflow_version"] or 1) >= 2 and evaluation["status"] in {"submitted", "returned"}),
                "can_hr_review": bool(hr_reviewer and not own and int(evaluation["workflow_version"] or 1) >= 2 and evaluation["status"] == "in_review"),
                "can_grieve": bool(own and published and grievance_row is None),
                "score_total": round(score_total, 2) if score_total is not None else None,
            })
            return {"evaluation": evaluation_data, "goals": goal_rows, "weight_total": weight_total, "approvals": approvals, "grievance": grievance}

        def evaluation_summary_for_user(self, evaluation_id: int) -> dict[str, Any]:
            payload = self.evaluation_payload(evaluation_id)
            evaluation = payload["evaluation"]
            return {key: evaluation.get(key) for key in (
                "id", "cycle_id", "employee_id", "year", "cycle_name", "full_name", "employee_no", "status",
                "workflow_version", "manager_employee_id", "manager_name", "weighted_score", "rating", "disclosure_date",
                "published", "can_manager_review", "can_hr_review", "can_grieve", "score_total", "submitted_late",
                "can_manager_override",
                "period_start", "period_end", "self_opens_on", "self_due_on", "manager_due_on", "hr_due_on",
                "cycle_status", "announcement_title", "announcement_body", "announced_at",
            )} | {"grievance_status": payload["grievance"]["status"] if payload["grievance"] else None}

        def api_evaluations_get(self) -> None:
            user = self.current_user(True)
            assert user is not None
            rows = self.db.execute(
                """SELECT e.id,e.employee_id,e.manager_employee_id,e.workflow_version,c.status AS cycle_status
                     FROM evaluations e JOIN evaluation_cycles c ON c.id=e.cycle_id ORDER BY c.year DESC,e.id DESC"""
            ).fetchall()
            visible_ids: list[int] = []
            for row in rows:
                cycle_visible = row["cycle_status"] in {"announced", "closed"}
                own = cycle_visible and row["employee_id"] == user.get("employee_id")
                direct = bool(cycle_visible and user.get("employee_id") and row["manager_employee_id"] == user["employee_id"] and self.direct_manager_employee_id(int(row["employee_id"])) == user["employee_id"])
                legacy = bool(int(row["workflow_version"] or 1) < 2 and user.get("employee_id") and self.db.execute("SELECT 1 FROM evaluation_approvals WHERE evaluation_id=? AND approver_employee_id=?", (row["id"], user["employee_id"])).fetchone())
                if own or direct or has_permission(self.db, user, "evaluation.review") or legacy:
                    visible_ids.append(int(row["id"]))
            summaries = [self.evaluation_summary_for_user(evaluation_id) for evaluation_id in visible_ids]
            pending = [
                row for row in summaries
                if row.get("can_manager_review") or row.get("can_hr_review")
                or (has_permission(self.db, user, "evaluation.review") and row.get("grievance_status") == "submitted")
            ]
            self.send_json(200, {"items": summaries, "pending_for_me": pending})

        def api_evaluations_post(self) -> None:
            user = self.current_user(True)
            assert user is not None
            employee_id = self.own_employee_id()
            data = self.read_json()
            if "employee_id" in data:
                raise APIError(403, "لا يمكن اختيار موظف آخر للتقييم.", "employee_selection_forbidden")
            params: list[Any] = [employee_id]
            where = "e.employee_id=? AND c.status IN ('announced','closed')"
            if data.get("cycle_id") not in (None, ""):
                where += " AND c.id=?"; params.append(as_int(data["cycle_id"], "cycle_id", 1))
            elif data.get("year") not in (None, ""):
                where += " AND c.year=?"; params.append(as_int(data["year"], "year", 2000, 2200))
            existing = self.db.execute(
                f"""SELECT e.id FROM evaluations e JOIN evaluation_cycles c ON c.id=e.cycle_id
                      WHERE {where} ORDER BY c.year DESC LIMIT 1""",
                params,
            ).fetchone()
            if existing is None:
                raise APIError(403, "لم تعلن الموارد البشرية دورة مسندة إلى حسابك.", "evaluation_not_assigned")
            self.send_json(200, self.evaluation_payload(int(existing["id"])))

        def api_evaluation_get(self, evaluation_id: int) -> None:
            self.send_json(200, self.evaluation_payload(evaluation_id))

        def ensure_goal_owner(self, evaluation_id: int) -> tuple[sqlite3.Row, dict[str, Any]]:
            evaluation, user = self.evaluation_access(evaluation_id)
            if evaluation["employee_id"] != user.get("employee_id"):
                raise APIError(403, "الموظف وحده يحرر أهداف تقييمه.", "forbidden")
            allowed = {"draft", "returned"} if int(evaluation["workflow_version"] or 1) < 2 else {"draft"}
            if evaluation["status"] not in allowed:
                raise APIError(409, "لا يمكن تعديل الأهداف بعد إرسال التقييم.", "invalid_status")
            if int(evaluation["workflow_version"] or 1) >= 2:
                if evaluation["cycle_status"] != "announced":
                    raise APIError(409, "دورة التقييم ليست مفتوحة للعمل.", "cycle_not_open")
                if local_now().date() < parse_date(evaluation["self_opens_on"], "self_opens_on"):
                    raise APIError(409, "لم تبدأ نافذة التقييم الذاتي بعد.", "self_window_not_open")
            return evaluation, user

        def api_evaluation_submit(self, evaluation_id: int) -> None:
            evaluation, user = self.ensure_goal_owner(evaluation_id)
            if int(evaluation["workflow_version"] or 1) < 2:
                goals = self.db.execute("SELECT * FROM evaluation_goals WHERE evaluation_id=?", (evaluation_id,)).fetchall()
                total = sum(float(goal["weight"]) for goal in goals)
                if not goals or abs(total - 100.0) > 0.000001:
                    raise APIError(422, "لا يمكن الإرسال إلا عندما يساوي مجموع الأوزان 100 تماماً.", "invalid_weight_total")
                chain = self.build_approval_chain(evaluation["employee_id"])
                stamp = now_iso()
                score = sum(float(goal["weight"]) * float(goal["achievement"]) / 100 for goal in goals)
                with self.db:
                    self.db.execute("DELETE FROM evaluation_approvals WHERE evaluation_id=?", (evaluation_id,))
                    for step, approver in enumerate(chain, 1):
                        self.db.execute("INSERT INTO evaluation_approvals(evaluation_id,step_no,approver_employee_id,created_at) VALUES(?,?,?,?)", (evaluation_id, step, approver, stamp))
                    self.db.execute("UPDATE evaluations SET status='in_review',weighted_score=?,rating=?,current_step=1,submitted_at=?,updated_at=? WHERE id=?", (round(score, 2), self.evaluation_rating(score), stamp, stamp, evaluation_id))
                    audit(self.db, user["id"], "evaluation.submit", "evaluation", evaluation_id, {"legacy": True})
                self.send_json(200, self.evaluation_payload(evaluation_id))
                return
            goals = self.db.execute("SELECT * FROM evaluation_goals WHERE evaluation_id=?", (evaluation_id,)).fetchall()
            total = sum(float(goal["weight"]) for goal in goals)
            if not goals or abs(total - 100.0) > 0.000001:
                raise APIError(422, "لا يمكن الإرسال إلا عندما يساوي مجموع الأوزان 100 تماماً.", "invalid_weight_total", {"weight_total": total})
            for goal in goals:
                self.validate_evaluation_goal(evaluation, dict(goal), require_evidence=True)
            manager_id = self.direct_manager_employee_id(int(evaluation["employee_id"]))
            manager_user = self.db.execute("SELECT id FROM users WHERE employee_id=? AND active=1", (manager_id,)).fetchone() if manager_id else None
            if not manager_id or manager_user is None:
                raise APIError(409, "يجب ربط الموظف بمسؤول مباشر له حساب نشط.", "manager_missing")
            stamp = now_iso()
            submitted_late = int(local_now().date() > parse_date(evaluation["self_due_on"], "self_due_on"))
            with self.db:
                self.db.execute("DELETE FROM evaluation_approvals WHERE evaluation_id=?", (evaluation_id,))
                self.db.execute("INSERT INTO evaluation_approvals(evaluation_id,step_no,approver_employee_id,created_at) VALUES(?,1,?,?)", (evaluation_id, manager_id, stamp))
                self.db.execute("UPDATE evaluation_goals SET awarded_points=NULL,updated_at=? WHERE evaluation_id=?", (stamp, evaluation_id))
                self.db.execute("UPDATE evaluations SET status='submitted',manager_employee_id=?,weighted_score=NULL,rating=NULL,current_step=1,submitted_at=?,submitted_late=?,finalized_at=NULL,manager_report='',manager_submitted_at=NULL,hr_comment='',disclosure_date=NULL,updated_at=? WHERE id=?", (manager_id, stamp, submitted_late, stamp, evaluation_id))
                create_internal_notification(self.db, user["id"], [manager_user["id"]], "تقييم سنوي بانتظار تقييمك", "أرسل موظفك أهدافه. أدخل نقاط كل هدف وتقريرك ثم أرسلها إلى الموارد البشرية.")
                audit(self.db, user["id"], "evaluation.employee_submit_late" if submitted_late else "evaluation.employee_submit", "evaluation", evaluation_id, {"manager_employee_id": manager_id, "submitted_late": bool(submitted_late), "self_due_on": evaluation["self_due_on"]})
            self.send_json(200, self.evaluation_payload(evaluation_id))

        def api_evaluation_manager_review(self, evaluation_id: int) -> None:
            evaluation, user = self.evaluation_access(evaluation_id)
            if int(evaluation["workflow_version"] or 1) < 2:
                raise APIError(409, "هذا السجل يستخدم مسار الاعتماد القديم.", "legacy_workflow")
            manager_id = self.direct_manager_employee_id(int(evaluation["employee_id"]))
            manager_override = bool(
                evaluation["employee_id"] != user.get("employee_id")
                and str(user.get("role")) in {"hr", "admin"}
                and has_permission(self.db, user, "evaluation.override_manager")
            )
            is_direct_manager = bool(
                user.get("employee_id")
                and manager_id == user["employee_id"]
                and evaluation["manager_employee_id"] == user["employee_id"]
            )
            if not manager_override and not is_direct_manager:
                raise APIError(403, "المسؤول المباشر الحالي وحده يقيّم هذا الموظف.", "not_direct_manager")
            if evaluation["status"] not in {"submitted", "returned"}:
                raise APIError(409, "التقييم ليس في مرحلة تقييم المسؤول.", "invalid_status")
            data = self.read_json()
            report = require_text(data, "manager_report", 5000)
            submitted_goals = data.get("goals")
            goals = self.db.execute("SELECT id,weight FROM evaluation_goals WHERE evaluation_id=? ORDER BY id", (evaluation_id,)).fetchall()
            if not isinstance(submitted_goals, list) or len(submitted_goals) != len(goals):
                raise APIError(422, "أدخل نقاط كل هدف.", "goal_scores_required")
            submitted_map: dict[int, float] = {}
            for item in submitted_goals:
                if not isinstance(item, dict):
                    raise APIError(422, "بيانات النقاط غير صالحة.", "validation_error")
                goal_id = as_int(item.get("id"), "goal_id", 1)
                if goal_id in submitted_map:
                    raise APIError(422, "تكرر الهدف في كشف النقاط.", "duplicate_goal")
                submitted_map[goal_id] = as_float(item.get("awarded_points"), "awarded_points", 0, 100)
            expected_ids = {int(goal["id"]) for goal in goals}
            if set(submitted_map) != expected_ids:
                raise APIError(422, "كشف النقاط لا يطابق أهداف التقييم.", "goal_mismatch")
            for goal in goals:
                if submitted_map[int(goal["id"])] > float(goal["weight"]) + 0.000001:
                    raise APIError(422, "نقاط الهدف لا يمكن أن تتجاوز وزنه.", "points_exceed_weight", {"goal_id": goal["id"], "weight": goal["weight"]})
            score = round(sum(submitted_map.values()), 2)
            stamp = now_iso()
            resubmission = evaluation["status"] == "returned"
            reviewers = [int(row["id"]) for row in self.db.execute("SELECT * FROM users WHERE active=1") if has_permission(self.db, dict(row), "evaluation.review") and row["id"] != user["id"]]
            old_manager_user = self.db.execute("SELECT id FROM users WHERE employee_id=? AND active=1", (evaluation["manager_employee_id"],)).fetchone()
            with self.db:
                for goal_id, points in submitted_map.items():
                    self.db.execute("UPDATE evaluation_goals SET awarded_points=?,updated_at=? WHERE id=? AND evaluation_id=?", (points, stamp, goal_id, evaluation_id))
                self.db.execute("UPDATE evaluation_approvals SET status='approved',comment=?,decided_at=? WHERE evaluation_id=? AND step_no=1", (report, stamp, evaluation_id))
                self.db.execute("UPDATE evaluations SET status='in_review',manager_report=?,manager_submitted_at=?,weighted_score=?,rating=?,hr_comment='',updated_at=? WHERE id=?", (report, stamp, score, self.evaluation_rating(score), stamp, evaluation_id))
                create_internal_notification(self.db, user["id"], reviewers, "تقييم سنوي بانتظار مراجعة HR", "أكمل المسؤول المباشر النقاط وتقرير الموظف.")
                if manager_override and old_manager_user and int(old_manager_user["id"]) != int(user["id"]):
                    create_internal_notification(
                        self.db,
                        user["id"],
                        [int(old_manager_user["id"])],
                        "تم استكمال تقييم موظفك من الموارد البشرية",
                        "استكملت الموارد البشرية مرحلة المسؤول المباشر لهذا التقييم نيابةً عنك بسبب عدم اتخاذ إجراء، وأصبح التقييم بانتظار المراجعة النهائية.",
                    )
                audit(
                    self.db,
                    user["id"],
                    "evaluation.manager_override" if manager_override else ("evaluation.manager_resubmit" if resubmission else "evaluation.manager_submit"),
                    "evaluation",
                    evaluation_id,
                    {"score": score, "manager_override": manager_override, "former_manager_employee_id": evaluation["manager_employee_id"]},
                )
            self.send_json(200, self.evaluation_payload(evaluation_id))

        def api_evaluation_hr_review(self, evaluation_id: int) -> None:
            user = self.require_permission("evaluation.review")
            evaluation = self.evaluation_row(evaluation_id)
            if evaluation["employee_id"] == user.get("employee_id"):
                raise APIError(403, "لا يمكن مراجعة تقييمك الشخصي.", "self_review_forbidden")
            if int(evaluation["workflow_version"] or 1) < 2 or evaluation["status"] != "in_review":
                raise APIError(409, "التقييم ليس بانتظار مراجعة الموارد البشرية.", "invalid_status")
            data = self.read_json()
            action = str(data.get("action", ""))
            if action not in {"return", "approve"}:
                raise APIError(422, "القرار يجب أن يكون return أو approve.", "validation_error")
            comment = optional_text(data, "comment", 3000)
            stamp = now_iso()
            manager_user = self.db.execute("SELECT id FROM users WHERE employee_id=? AND active=1", (evaluation["manager_employee_id"],)).fetchone()
            employee_user = self.db.execute("SELECT id FROM users WHERE employee_id=? AND active=1", (evaluation["employee_id"],)).fetchone()
            with self.db:
                if action == "return":
                    if not comment:
                        raise APIError(422, "تعليق الإعادة مطلوب.", "comment_required")
                    self.db.execute("UPDATE evaluations SET status='returned',hr_reviewed_by=?,hr_comment=?,updated_at=? WHERE id=?", (user["id"], comment, stamp, evaluation_id))
                    if manager_user:
                        create_internal_notification(self.db, user["id"], [manager_user["id"]], "أعيد التقييم من HR", comment)
                    audit(self.db, user["id"], "evaluation.hr_return", "evaluation", evaluation_id, {"comment": comment})
                else:
                    disclosure = parse_date(data.get("disclosure_date"), "disclosure_date")
                    if disclosure < local_now().date():
                        raise APIError(422, "تاريخ الإفصاح لا يمكن أن يكون في الماضي.", "invalid_disclosure_date")
                    goals = self.db.execute("SELECT awarded_points FROM evaluation_goals WHERE evaluation_id=?", (evaluation_id,)).fetchall()
                    if not goals or any(goal["awarded_points"] is None for goal in goals):
                        raise APIError(409, "لم يكتمل كشف نقاط المسؤول.", "scores_incomplete")
                    score = round(sum(float(goal["awarded_points"]) for goal in goals), 2)
                    self.db.execute("UPDATE evaluations SET status='approved',weighted_score=?,rating=?,hr_reviewed_by=?,hr_comment=?,disclosure_date=?,finalized_at=?,updated_at=? WHERE id=?", (score, self.evaluation_rating(score), user["id"], comment, disclosure.isoformat(), stamp, stamp, evaluation_id))
                    available_at = datetime.combine(disclosure, time.min, UAE_TZ).astimezone(timezone.utc).isoformat(timespec="seconds")
                    if employee_user:
                        create_internal_notification(self.db, user["id"], [employee_user["id"]], "نتيجة التقييم السنوي", "أصبحت نتيجة تقييمك متاحة في صفحة التقييم السنوي.", available_at)
                    audit(self.db, user["id"], "evaluation.hr_approve", "evaluation", evaluation_id, {"score": score, "disclosure_date": disclosure.isoformat()})
            self.send_json(200, self.evaluation_payload(evaluation_id))

        def published_evaluation_summaries(self, employee_id: int) -> list[dict[str, Any]]:
            rows = self.db.execute(
                """SELECT e.id FROM evaluations e JOIN evaluation_cycles c ON c.id=e.cycle_id
                    WHERE e.employee_id=? AND e.status='approved'
                      AND (e.workflow_version<2 OR e.disclosure_date<=?) ORDER BY c.year DESC""",
                (employee_id, local_now().date().isoformat()),
            ).fetchall()
            return [self.evaluation_summary_for_user(int(row["id"])) for row in rows]

        def api_evaluation_history(self) -> None:
            employee_id = self.own_employee_id()
            self.send_json(200, {"items": self.published_evaluation_summaries(employee_id)})

        def api_employee_evaluation_history(self, employee_id: int) -> None:
            self.require_permission("evaluation.review")
            if self.db.execute("SELECT 1 FROM employees WHERE id=?", (employee_id,)).fetchone() is None:
                raise APIError(404, "الموظف غير موجود.", "not_found")
            self.send_json(200, {"items": self.published_evaluation_summaries(employee_id)})

        def api_evaluation_grievance_post(self, evaluation_id: int) -> None:
            evaluation, user = self.evaluation_access(evaluation_id)
            if evaluation["employee_id"] != user.get("employee_id"):
                raise APIError(403, "الموظف وحده يقدم التظلم.", "forbidden")
            if not self.evaluation_is_published(evaluation):
                raise APIError(409, "لا يمكن التظلم قبل نشر النتيجة.", "not_published")
            if self.db.execute("SELECT 1 FROM evaluation_grievances WHERE evaluation_id=?", (evaluation_id,)).fetchone():
                raise APIError(409, "سبق تقديم تظلم على هذا التقييم.", "grievance_exists")
            data = self.read_json()
            reason = require_text(data, "reason", 240)
            note = require_text(data, "note", 4000)
            stamp = now_iso()
            reviewers = [int(row["id"]) for row in self.db.execute("SELECT * FROM users WHERE active=1") if has_permission(self.db, dict(row), "evaluation.review") and row["id"] != user["id"]]
            with self.db:
                cursor = self.db.execute("INSERT INTO evaluation_grievances(evaluation_id,employee_id,reason,note,submitted_at,updated_at) VALUES(?,?,?,?,?,?)", (evaluation_id, evaluation["employee_id"], reason, note, stamp, stamp))
                grievance_id = int(cursor.lastrowid)
                create_internal_notification(self.db, user["id"], reviewers, "تظلم على نتيجة تقييم", "قدم الموظف تظلماً يتطلب قرار الموارد البشرية.")
                audit(self.db, user["id"], "evaluation.grievance_submit", "evaluation_grievance", grievance_id, {"evaluation_id": evaluation_id, "reason": reason})
            self.send_json(201, self.evaluation_payload(evaluation_id))

        def api_evaluation_grievance_resolve(self, grievance_id: int) -> None:
            user = self.require_permission("evaluation.review")
            grievance = self.db.execute("SELECT * FROM evaluation_grievances WHERE id=?", (grievance_id,)).fetchone()
            if grievance is None:
                raise APIError(404, "التظلم غير موجود.", "not_found")
            if grievance["status"] != "submitted":
                raise APIError(409, "سبق حل هذا التظلم.", "already_resolved")
            evaluation = self.evaluation_row(int(grievance["evaluation_id"]))
            if evaluation["employee_id"] == user.get("employee_id"):
                raise APIError(403, "لا يمكن حل تظلمك الشخصي.", "self_review_forbidden")
            data = self.read_json()
            action = str(data.get("action", ""))
            if action not in {"reject", "amend"}:
                raise APIError(422, "القرار يجب أن يكون reject أو amend.", "validation_error")
            note = require_text(data, "resolution_note", 4000)
            before = float(evaluation["weighted_score"] or 0)
            stamp = now_iso()
            after = before
            with self.db:
                if action == "amend":
                    score_rows = data.get("goals")
                    if not isinstance(score_rows, list) or not score_rows:
                        raise APIError(422, "أدخل النقاط المعدلة.", "goal_scores_required")
                    known = {int(row["id"]): row for row in self.db.execute("SELECT id,weight FROM evaluation_goals WHERE evaluation_id=?", (evaluation["id"],))}
                    changes: dict[int, float] = {}
                    for item in score_rows:
                        goal_id = as_int(item.get("id") if isinstance(item, dict) else None, "goal_id", 1)
                        if goal_id not in known:
                            raise APIError(422, "الهدف المعدل لا يتبع لهذا التقييم.", "goal_mismatch")
                        points = as_float(item.get("awarded_points"), "awarded_points", 0, float(known[goal_id]["weight"]))
                        changes[goal_id] = points
                    for goal_id, points in changes.items():
                        self.db.execute("UPDATE evaluation_goals SET awarded_points=?,updated_at=? WHERE id=?", (points, stamp, goal_id))
                    after = round(sum(float(row[0] or 0) for row in self.db.execute("SELECT awarded_points FROM evaluation_goals WHERE evaluation_id=?", (evaluation["id"],))), 2)
                    self.db.execute("UPDATE evaluations SET weighted_score=?,rating=?,updated_at=? WHERE id=?", (after, self.evaluation_rating(after), stamp, evaluation["id"]))
                status = "amended" if action == "amend" else "rejected"
                self.db.execute("UPDATE evaluation_grievances SET status=?,resolution_note=?,resolved_by=?,score_before=?,score_after=?,resolved_at=?,updated_at=? WHERE id=?", (status, note, user["id"], before, after, stamp, stamp, grievance_id))
                employee_user = self.db.execute("SELECT id FROM users WHERE employee_id=? AND active=1", (evaluation["employee_id"],)).fetchone()
                if employee_user:
                    create_internal_notification(self.db, user["id"], [employee_user["id"]], "تم حل تظلم التقييم", note)
                audit(self.db, user["id"], "evaluation.grievance_amend" if action == "amend" else "evaluation.grievance_reject", "evaluation_grievance", grievance_id, {"evaluation_id": evaluation["id"], "score_before": before, "score_after": after, "resolution_note": note})
            self.send_json(200, self.evaluation_payload(int(evaluation["id"])))

        # Notifications
        def require_notification_admin(self) -> dict[str, Any]:
            user = self.current_user(True)
            assert user is not None
            if str(user.get("role")) != "admin":
                raise APIError(403, "إدارة الرسائل الداخلية متاحة لمسؤول النظام فقط.", "forbidden", {"permission": "notification.manage"})
            return user

        def api_notification_manage_get(self) -> None:
            self.require_notification_admin()
            rows = self.db.execute(
                """SELECT n.id,n.title,n.body,n.message_type,n.audience_type,n.audience_ref,n.available_at,
                          n.created_at,n.edited_at,n.hidden_at,u.display_name AS sender_name,
                          (SELECT COUNT(*) FROM notification_recipients r WHERE r.notification_id=n.id) AS recipient_count,
                          (SELECT COUNT(*) FROM notification_recipients r WHERE r.notification_id=n.id AND r.read_at IS NOT NULL) AS read_count
                   FROM notifications n JOIN users u ON u.id=n.sender_user_id
                   ORDER BY n.created_at DESC LIMIT 200"""
            ).fetchall()
            self.send_json(200, {"items": [dict(row) | {"hidden": bool(row["hidden_at"])} for row in rows]})

        def api_notification_patch(self, notification_id: int) -> None:
            user = self.require_notification_admin()
            row = self.db.execute("SELECT * FROM notifications WHERE id=?", (notification_id,)).fetchone()
            if row is None:
                raise APIError(404, "الإشعار غير موجود.", "not_found")
            data = self.read_json(); updates: dict[str, Any] = {}; stamp = now_iso()
            if "title" in data: updates["title"] = require_text(data, "title", 240)
            if "body" in data: updates["body"] = require_text(data, "body", 5000)
            if "message_type" in data:
                message_type = {"قانون": "law", "إشعار": "notice", "تهنئة": "congratulation"}.get(str(data["message_type"]), str(data["message_type"]))
                if message_type not in {"law", "notice", "congratulation"}:
                    raise APIError(422, "نوع الرسالة غير صالح.", "validation_error", {"field": "message_type"})
                updates["message_type"] = message_type
            if "hidden" in data:
                if not isinstance(data["hidden"], bool):
                    raise APIError(422, "قيمة إخفاء الرسالة غير صالحة.", "validation_error", {"field": "hidden"})
                updates["hidden_at"] = stamp if data["hidden"] else None
                updates["hidden_by"] = user["id"] if data["hidden"] else None
            if not updates:
                raise APIError(422, "لا توجد تغييرات للحفظ.", "validation_error")
            if any(key in updates for key in ("title", "body", "message_type")):
                updates["edited_at"] = stamp
            with self.db:
                self.db.execute("UPDATE notifications SET " + ",".join(f"{key}=?" for key in updates) + " WHERE id=?", (*updates.values(), notification_id))
                audit(self.db, user["id"], "notification.update" if not ("hidden_at" in updates) else ("notification.hide" if updates.get("hidden_at") else "notification.unhide"), "notification", notification_id, {"fields": list(updates)})
            updated = self.db.execute("SELECT n.*,u.display_name AS sender_name,(SELECT COUNT(*) FROM notification_recipients r WHERE r.notification_id=n.id) AS recipient_count FROM notifications n JOIN users u ON u.id=n.sender_user_id WHERE n.id=?", (notification_id,)).fetchone()
            self.send_json(200, {"notification": dict(updated) | {"hidden": bool(updated["hidden_at"])}})

        def api_notification_send(self) -> None:
            user = self.require_permission("notification.send")
            data = self.read_json()
            title = require_text(data, "title", 240)
            body = require_text(data, "body", 5000)
            type_aliases = {"قانون": "law", "إشعار": "notice", "تهنئة": "congratulation"}
            message_type = type_aliases.get(str(data.get("message_type", "")), str(data.get("message_type", "")))
            if message_type not in {"law", "notice", "congratulation"}:
                raise APIError(422, "نوع الرسالة غير صالح.", "validation_error")
            audience_aliases = {"الجميع": "all", "قسم": "department", "فرع": "branch", "موظفون": "employees"}
            audience_type = audience_aliases.get(str(data.get("audience_type", "")), str(data.get("audience_type", "")))
            if audience_type not in {"all", "department", "branch", "employees"}:
                raise APIError(422, "نوع الجمهور غير صالح.", "validation_error")
            audience_ref: Any = data.get("audience_ref")
            if audience_type == "all":
                recipient_rows = self.db.execute("SELECT id FROM users WHERE active=1").fetchall()
                stored_ref = None
            elif audience_type == "department":
                department_id = as_int(audience_ref, "audience_ref", 1)
                recipient_rows = self.db.execute("SELECT u.id FROM users u JOIN employees e ON e.id=u.employee_id WHERE u.active=1 AND e.active=1 AND e.department_id=?", (department_id,)).fetchall()
                stored_ref = str(department_id)
            elif audience_type == "branch":
                branch_id = as_int(audience_ref, "audience_ref", 1)
                recipient_rows = self.db.execute("SELECT u.id FROM users u JOIN employees e ON e.id=u.employee_id WHERE u.active=1 AND e.active=1 AND e.branch_id=?", (branch_id,)).fetchall()
                stored_ref = str(branch_id)
            else:
                employee_ids = data.get("employee_ids", audience_ref)
                if not isinstance(employee_ids, list) or not employee_ids:
                    raise APIError(422, "اختر موظفاً واحداً على الأقل.", "validation_error")
                normalized = sorted(set(as_int(x, "employee_ids", 1) for x in employee_ids))
                placeholders = ",".join("?" for _ in normalized)
                recipient_rows = self.db.execute(f"SELECT id FROM users WHERE active=1 AND employee_id IN ({placeholders})", normalized).fetchall()
                stored_ref = json_text(normalized)
            recipient_ids = sorted(set(int(r["id"]) for r in recipient_rows))
            if not recipient_ids:
                raise APIError(422, "لا يوجد مستلمون نشطون ضمن الجمهور المحدد.", "empty_audience")
            stamp = now_iso()
            with self.db:
                cur = self.db.execute("INSERT INTO notifications(sender_user_id,title,body,message_type,audience_type,audience_ref,created_at) VALUES(?,?,?,?,?,?,?)", (user["id"], title, body, message_type, audience_type, stored_ref, stamp))
                notification_id = int(cur.lastrowid)
                self.db.executemany("INSERT INTO notification_recipients(notification_id,user_id) VALUES(?,?)", [(notification_id, recipient_id) for recipient_id in recipient_ids])
                audit(self.db, user["id"], "notification.send", "notification", notification_id, {"recipient_count": len(recipient_ids), "audience_type": audience_type})
            self.send_json(201, {"notification": {"id": notification_id, "title": title, "body": body, "message_type": message_type, "audience_type": audience_type, "audience_ref": stored_ref, "created_at": stamp, "recipient_count": len(recipient_ids)}})

        def api_notification_inbox(self) -> None:
            user = self.current_user(True)
            assert user is not None
            ensure_document_expiry_notifications(self.db)
            rows = self.db.execute(
                """SELECT n.id,n.title,n.body,n.message_type,n.audience_type,n.created_at,n.available_at,
                          u.display_name AS sender_name,r.read_at,n.edited_at
                   FROM notification_recipients r JOIN notifications n ON n.id=r.notification_id
                   JOIN users u ON u.id=n.sender_user_id
                   WHERE r.user_id=? AND n.hidden_at IS NULL AND (n.available_at IS NULL OR n.available_at<=?)
                   ORDER BY n.created_at DESC""",
                (user["id"], now_iso()),
            ).fetchall()
            unread = sum(1 for row in rows if row["read_at"] is None)
            self.send_json(200, {"items": [dict(r) for r in rows], "unread_count": unread})

        def api_notification_unread_count(self) -> None:
            user = self.current_user(True)
            assert user is not None
            ensure_document_expiry_notifications(self.db)
            count = self.db.execute(
                """SELECT COUNT(*) FROM notification_recipients r
                   JOIN notifications n ON n.id=r.notification_id
                   WHERE r.user_id=? AND r.read_at IS NULL AND n.hidden_at IS NULL
                     AND (n.available_at IS NULL OR n.available_at<=?)""",
                (user["id"], now_iso()),
            ).fetchone()[0]
            self.send_json(200, {"unread_count": count})

        def api_notification_get(self, notification_id: int) -> None:
            user = self.current_user(True)
            assert user is not None
            row = self.db.execute(
                """SELECT n.*,u.display_name AS sender_name,r.read_at,
                          (SELECT COUNT(*) FROM notification_recipients x WHERE x.notification_id=n.id) AS recipient_count
                   FROM notifications n JOIN users u ON u.id=n.sender_user_id
                   LEFT JOIN notification_recipients r ON r.notification_id=n.id AND r.user_id=? WHERE n.id=?""",
                (user["id"], notification_id),
            ).fetchone()
            if row is None:
                raise APIError(404, "الإشعار غير موجود.", "not_found")
            privileged = str(user.get("role")) == "admin" or row["sender_user_id"] == user["id"] or has_permission(self.db, user, "notification.send")
            if row["hidden_at"] and str(user.get("role")) != "admin":
                raise APIError(404, "الإشعار غير موجود.", "not_found")
            if row["available_at"] and row["available_at"] > now_iso() and not privileged:
                raise APIError(404, "الإشعار غير موجود.", "not_found")
            if not privileged:
                recipient = self.db.execute("SELECT 1 FROM notification_recipients WHERE notification_id=? AND user_id=?", (notification_id, user["id"])).fetchone()
                if not recipient:
                    raise APIError(403, "هذا الإشعار ليس موجهاً إليك.", "forbidden")
            self.send_json(200, {"notification": dict(row)})

        def api_notification_read(self, notification_id: int) -> None:
            user = self.current_user(True)
            assert user is not None
            with self.db:
                stamp = now_iso()
                result = self.db.execute(
                    """UPDATE notification_recipients SET read_at=COALESCE(read_at,?)
                       WHERE notification_id=? AND user_id=?
                         AND notification_id IN (
                           SELECT id FROM notifications WHERE hidden_at IS NULL AND (available_at IS NULL OR available_at<=?)
                         )""",
                    (stamp, notification_id, user["id"], stamp),
                )
            if not result.rowcount:
                raise APIError(404, "الإشعار غير موجود في صندوقك.", "not_found")
            self.send_json(200, {"ok": True})

        def api_notification_read_all(self) -> None:
            user = self.current_user(True)
            assert user is not None
            stamp = now_iso()
            with self.db:
                result = self.db.execute(
                    """UPDATE notification_recipients SET read_at=?
                       WHERE user_id=? AND read_at IS NULL
                         AND notification_id IN (
                           SELECT id FROM notifications WHERE hidden_at IS NULL AND (available_at IS NULL OR available_at<=?)
                         )""",
                    (stamp, user["id"], stamp),
                )
            self.send_json(200, {"ok": True, "updated": result.rowcount})

        # Salary certificates
        def certificate_payload(self, row: sqlite3.Row) -> dict[str, Any]:
            expected = certificate_integrity_hash(db_path, row)
            integrity_valid = bool(row["integrity_hash"]) and hmac.compare_digest(str(row["integrity_hash"]), expected)
            payload = {
                "id": row["id"], "certificate_no": row["certificate_no"], "employee_id": row["employee_id"],
                "verification_code": row["verification_code"], "verification_status": row["verification_status"],
                "request_status": row["request_status"] if "request_status" in row.keys() else "issued",
                "requester_id": row["requester_id"] if "requester_id" in row.keys() else None,
                "requested_at": row["requested_at"] if "requested_at" in row.keys() else None,
                "approved_by": row["approved_by"] if "approved_by" in row.keys() else None,
                "approved_at": row["approved_at"] if "approved_at" in row.keys() else None,
                "decision_note": row["decision_note"] if "decision_note" in row.keys() else "",
                "email_outbox_id": row["email_outbox_id"] if "email_outbox_id" in row.keys() else None,
                "integrity_valid": integrity_valid, "document_fingerprint": expected[:16].upper(),
                "issued_by": row["issued_by"], "purpose": row["purpose"], "salary": row["salary_snapshot"],
                "organization": parse_json_text(row["organization_snapshot"], {}),
                "employee": parse_json_text(row["employee_snapshot"], {}),
                "issued_at": row["issued_at"], "print_count": row["print_count"], "last_printed_at": row["last_printed_at"],
                "verification_count": row["verification_count"], "last_verified_at": row["last_verified_at"],
            }
            payload["salary_breakdown"] = (payload["employee"].get("salary_breakdown") or {}) if isinstance(payload["employee"], dict) else {}
            outbox_id = payload.get("email_outbox_id")
            if outbox_id:
                outbox = self.db.execute("SELECT to_email,status,last_error,sent_at FROM email_outbox WHERE id=?", (outbox_id,)).fetchone()
                if outbox:
                    payload["email_to"] = outbox["to_email"]
                    payload["email_status"] = outbox["status"]
                    payload["email_error"] = outbox["last_error"] or ""
                    payload["email_sent_at"] = outbox["sent_at"]
            return payload

        def _certificate_safe_request(self, row: sqlite3.Row, privileged: bool = False) -> dict[str, Any]:
            payload = self.certificate_payload(row)
            if privileged:
                issuer = self.db.execute("SELECT display_name AS name,email FROM users WHERE id=?", (row["issued_by"],)).fetchone()
                payload["issuer"] = dict(issuer) if issuer else None
                keys = row.keys()
                payload["employee_name"] = row["employee_name"] if "employee_name" in keys else (payload.get("employee") or {}).get("full_name")
                payload["employee_no"] = row["employee_no"] if "employee_no" in keys else (payload.get("employee") or {}).get("employee_no")
                payload["requester_name"] = row["requester_name"] if "requester_name" in keys else None
                return payload
            # An employee can track the workflow and recipient only.  Salary,
            # snapshots, verification codes and issuer data remain server-side.
            return {key: payload.get(key) for key in ("id","employee_id","purpose","request_status","requested_at","approved_at","decision_note")}

        def api_certificate_requests_get(self) -> None:
            user = self.current_user(True)
            assert user is not None
            privileged = has_permission(self.db, user, "salary_certificate.issue")
            if privileged:
                rows = self.db.execute(
                    """SELECT c.*,e.full_name AS employee_name,e.employee_no,u.display_name AS requester_name
                       FROM salary_certificates c JOIN employees e ON e.id=c.employee_id
                       LEFT JOIN users u ON u.id=c.requester_id
                       WHERE c.request_status IN ('requested','approved','rejected')
                       ORDER BY COALESCE(c.requested_at,c.issued_at) DESC,c.id DESC"""
                ).fetchall()
            else:
                if not user.get("employee_id"):
                    return self.send_json(200, {"items": []})
                rows = self.db.execute(
                    "SELECT * FROM salary_certificates WHERE employee_id=? AND request_status IN ('requested','approved','rejected') ORDER BY COALESCE(requested_at,issued_at) DESC,id DESC",
                    (user["employee_id"],),
                ).fetchall()
            self.send_json(200, {"items": [self._certificate_safe_request(row, privileged) for row in rows]})

        def api_certificate_history_get(self) -> None:
            user = self.require_permission("salary_certificate.verify")
            if str(user.get("role")) not in {"admin", "hr"}:
                raise APIError(403, "سجل شهادات الراتب متاح للموارد البشرية ومدير النظام فقط.", "forbidden")
            rows = self.db.execute(
                """SELECT c.*,e.full_name AS employee_name,e.employee_no,u.display_name AS requester_name
                   FROM salary_certificates c JOIN employees e ON e.id=c.employee_id
                   LEFT JOIN users u ON u.id=c.requester_id
                   ORDER BY c.id DESC"""
            ).fetchall()
            self.send_json(200, {"items": [self._certificate_safe_request(row, True) for row in rows]})

        def api_certificate_request_post(self) -> None:
            user = self.current_user(True)
            assert user is not None
            employee_id = user.get("employee_id")
            if not employee_id:
                raise APIError(403, "يجب ربط حسابك بملف موظف لتقديم الطلب.", "employee_required")
            purpose = require_text(self.read_json(), "purpose", 500)
            if self.db.execute("SELECT 1 FROM salary_certificates WHERE employee_id=? AND request_status='requested'", (employee_id,)).fetchone():
                raise APIError(409, "لديك طلب شهادة راتب قيد المراجعة بالفعل.", "request_pending")
            stamp = now_iso(); year = local_now().year
            with self.db:
                sequence = int(self.db.execute("SELECT COALESCE(MAX(id),0)+1 FROM salary_certificates").fetchone()[0])
                certificate_no = f"REQ-{year}-{sequence:06d}"
                verification_code = f"REQ-{year}-{secrets.token_hex(6).upper()}"
                cur = self.db.execute(
                    """INSERT INTO salary_certificates(certificate_no,verification_code,integrity_hash,verification_status,employee_id,issued_by,purpose,salary_snapshot,organization_snapshot,employee_snapshot,issued_at,request_status,requester_id,requested_at)
                       SELECT ?,?,'','valid',e.id,?, ?,e.salary,'{}','{}',?,?,?,? FROM employees e WHERE e.id=? AND e.active=1""",
                    (certificate_no, verification_code, user["id"], purpose, stamp, "requested", user["id"], stamp, employee_id),
                )
                if not cur.rowcount:
                    raise APIError(404, "ملف الموظف غير موجود أو غير نشط.", "not_found")
                request_id = int(cur.lastrowid)
                hr_recipients = self.approval_recipient_ids("salary_certificate.issue", int(user["id"]))
                if hr_recipients:
                    create_internal_notification(self.db, user["id"], hr_recipients, "طلب شهادة راتب جديد", "يوجد طلب شهادة راتب جديد يحتاج مراجعة الموارد البشرية.")
                audit(self.db, user["id"], "salary_certificate.request", "salary_certificate", request_id, {"employee_id": employee_id, "purpose": purpose})
            self.send_json(201, {"request": self._certificate_safe_request(self.db.execute("SELECT * FROM salary_certificates WHERE id=?", (request_id,)).fetchone())})

        def api_certificate_request_decision(self, certificate_id: int) -> None:
            user = self.require_permission("salary_certificate.issue")
            data = self.read_json(); action = str(data.get("action") or data.get("decision") or "").strip().lower()
            if action in {"approve", "approved", "اعتماد", "اعتمد"}: action = "approve"
            elif action in {"reject", "rejected", "رفض", "ارفض"}: action = "reject"
            else: raise APIError(422, "اختر الاعتماد أو الرفض.", "validation_error")
            note = optional_text(data, "decision_note", 1000) or optional_text(data, "note", 1000)
            row = self.db.execute("SELECT * FROM salary_certificates WHERE id=?", (certificate_id,)).fetchone()
            if row is None: raise APIError(404, "طلب شهادة الراتب غير موجود.", "not_found")
            if row["request_status"] != "requested": raise APIError(409, "تمت معالجة هذا الطلب مسبقاً ولا يمكن تغييره.", "request_already_decided")
            if row["requester_id"] == user["id"]: raise APIError(403, "لا يمكنك اعتماد طلبك الشخصي.", "self_approval_forbidden")
            stamp = now_iso(); email_outbox_id = None; email_status = None
            requester = self.db.execute("SELECT id,email,display_name FROM users WHERE id=? AND active=1", (row["requester_id"],)).fetchone()
            if action == "reject":
                with self.db:
                    self.db.execute("UPDATE salary_certificates SET request_status='rejected',approved_by=?,approved_at=?,decision_note=? WHERE id=?", (user["id"], stamp, note, certificate_id))
                    if requester: create_internal_notification(self.db, user["id"], [requester["id"]], "تم رفض طلب شهادة الراتب", note or "تم رفض الطلب من الموارد البشرية.")
                    audit(self.db, user["id"], "salary_certificate.reject", "salary_certificate", certificate_id, {"note": note})
            else:
                employee = self.db.execute(employee_query(True) + " WHERE e.id=? AND e.active=1", (row["employee_id"],)).fetchone()
                if employee is None: raise APIError(404, "ملف الموظف غير موجود أو غير نشط.", "not_found")
                org = self.db.execute("SELECT * FROM organization WHERE id=1").fetchone()
                sequence = int(self.db.execute("SELECT COALESCE(MAX(id),0)+1 FROM salary_certificates").fetchone()[0])
                certificate_no = f"SAL-{local_now().year}-{sequence:06d}"
                verification_code = new_certificate_verification_code(self.db, local_now().year)
                values = {"certificate_no": certificate_no, "verification_code": verification_code, "employee_id": row["employee_id"], "issued_by": user["id"], "purpose": row["purpose"], "salary_snapshot": employee["salary"], "organization_snapshot": json_text(serialize_org(org)), "employee_snapshot": json_text(normalize_employee(employee)), "issued_at": stamp}
                digest = certificate_integrity_hash(db_path, values)
                with self.db:
                    self.db.execute("""UPDATE salary_certificates SET certificate_no=?,verification_code=?,integrity_hash=?,verification_status='valid',issued_by=?,salary_snapshot=?,organization_snapshot=?,employee_snapshot=?,issued_at=?,request_status='approved',approved_by=?,approved_at=?,decision_note=? WHERE id=?""", (certificate_no, verification_code, digest, user["id"], employee["salary"], values["organization_snapshot"], values["employee_snapshot"], stamp, user["id"], stamp, note, certificate_id))
                    row = self.db.execute("SELECT * FROM salary_certificates WHERE id=?", (certificate_id,)).fetchone()
                    certificate = self.certificate_payload(row)
                    pdf_data = build_salary_certificate_pdf(certificate)
                    # Always deliver the approved copy to the employee's current
                    # registered address.  The requester account can be an
                    # administrator submitting on somebody else's behalf, so it
                    # is not a safe email recipient for this document.
                    employee_email = clean_email(employee["email"])
                    if not employee_email and requester:
                        employee_email = clean_email(requester["email"])
                    if employee_email:
                        email_outbox_id, email_status = self.queue_email("salary_certificate", employee_email, f"Salary Certificate | {certificate_no}", "تم اعتماد طلب شهادة الراتب. تجد الشهادة الإلكترونية الموقعة مرفقة بهذه الرسالة.", user_id=user["id"], attachment={"name": f"salary-certificate-{certificate_no}.pdf", "content_type": "application/pdf", "data": pdf_data})
                        self.db.execute("UPDATE salary_certificates SET email_outbox_id=? WHERE id=?", (email_outbox_id, certificate_id))
                    if requester:
                        notice = "تم اعتماد الطلب وإرسال الشهادة إلى بريدك المؤسسي." if email_status in {"sent", "queued"} else "تم اعتماد الطلب. راجع بريدك المؤسسي عند تفعيل SMTP أو تحديث بريد ملفك الوظيفي."
                        create_internal_notification(self.db, user["id"], [requester["id"]], "تم اعتماد شهادة الراتب", notice)
                    audit(self.db, user["id"], "salary_certificate.approve", "salary_certificate", certificate_id, {"certificate_no": certificate_no, "email_to": employee_email or None, "email_status": email_status or "no_email"})
            saved = self.db.execute("SELECT * FROM salary_certificates WHERE id=?", (certificate_id,)).fetchone()
            response = self._certificate_safe_request(saved, True)
            response["email_status"] = email_status
            self.send_json(200, {"request": response})

        def api_certificate_post(self) -> None:
            user = self.require_permission("salary_certificate.issue")
            data = self.read_json()
            employee_id = as_int(data.get("employee_id"), "employee_id", 1)
            if employee_id != user.get("employee_id") and not self.has_privileged_people_access(user, "employee.view"):
                raise APIError(403, "لا يمكنك إصدار شهادة راتب لموظف آخر.", "forbidden")
            employee = self.db.execute(employee_query(True) + " WHERE e.id=? AND e.active=1", (employee_id,)).fetchone()
            if employee is None:
                raise APIError(404, "الموظف غير موجود.", "not_found")
            org = self.db.execute("SELECT * FROM organization WHERE id=1").fetchone()
            stamp = now_iso()
            with self.db:
                sequence = int(self.db.execute("SELECT COALESCE(MAX(id),0)+1 FROM salary_certificates").fetchone()[0])
                certificate_no = f"SAL-{local_now().year}-{sequence:06d}"
                verification_code = new_certificate_verification_code(self.db, local_now().year)
                org_snapshot = serialize_org(org)
                employee_snapshot = normalize_employee(employee)
                values = {
                    "certificate_no": certificate_no,
                    "verification_code": verification_code,
                    "employee_id": employee_id,
                    "issued_by": user["id"],
                    "purpose": optional_text(data, "purpose", 500),
                    "salary_snapshot": employee["salary"],
                    "organization_snapshot": json_text(org_snapshot),
                    "employee_snapshot": json_text(employee_snapshot),
                    "issued_at": stamp,
                }
                integrity_hash = certificate_integrity_hash(db_path, values)
                cur = self.db.execute(
                    "INSERT INTO salary_certificates(certificate_no,verification_code,integrity_hash,employee_id,issued_by,purpose,salary_snapshot,organization_snapshot,employee_snapshot,issued_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (certificate_no, verification_code, integrity_hash, employee_id, user["id"], values["purpose"], employee["salary"], values["organization_snapshot"], values["employee_snapshot"], stamp),
                )
                cert_id = int(cur.lastrowid)
                audit(self.db, user["id"], "salary_certificate.issue", "salary_certificate", cert_id, {"employee_id": employee_id, "certificate_no": certificate_no, "verification_code_suffix": verification_code[-4:]})
            row = self.db.execute("SELECT * FROM salary_certificates WHERE id=?", (cert_id,)).fetchone()
            self.send_json(201, {"certificate": self.certificate_payload(row)})

        def api_certificate_get(self, certificate_id: int) -> None:
            user = self.current_user(True)
            assert user is not None
            row = self.db.execute("SELECT * FROM salary_certificates WHERE id=?", (certificate_id,)).fetchone()
            if row is None:
                raise APIError(404, "شهادة الراتب غير موجودة.", "not_found")
            if row["employee_id"] != user.get("employee_id") and not self.has_privileged_people_access(user, "employee.view"):
                raise APIError(403, "لا يمكنك عرض هذه الشهادة.", "forbidden")
            if row["employee_id"] == user.get("employee_id") and row["request_status"] in {"requested", "rejected"}:
                self.send_json(200, {"request": self._certificate_safe_request(row)})
                return
            self.send_json(200, {"certificate": self.certificate_payload(row)})

        def api_certificate_verify(self) -> None:
            user = self.require_permission("salary_certificate.verify")
            if str(user.get("role")) not in {"admin", "hr"}:
                raise APIError(403, "التحقق من شهادات الراتب متاح للموارد البشرية ومدير النظام فقط.", "forbidden")
            data = self.read_json()
            submitted = str(data.get("code") or data.get("verification_code") or data.get("certificate_no") or "").strip().upper()
            submitted = re.sub(r"\s+", "", submitted)
            if not re.fullmatch(r"[A-Z0-9-]{8,48}", submitted):
                raise APIError(422, "أدخل رقم تحقق أو رقم إصدار صحيحاً.", "validation_error")
            row = self.db.execute(
                "SELECT * FROM salary_certificates WHERE request_status IN ('approved','issued') AND (UPPER(verification_code)=? OR UPPER(certificate_no)=?)",
                (submitted, submitted),
            ).fetchone()
            stamp = now_iso()
            if row is None:
                with self.db:
                    audit(self.db, user["id"], "salary_certificate.verify", "salary_certificate", None, {"result": "not_found", "code_suffix": submitted[-4:]})
                self.send_json(200, {"valid": False, "status": "not_found", "message": "لم يتم العثور على شهادة صادرة بهذا الرقم."})
                return
            expected = certificate_integrity_hash(db_path, row)
            integrity_valid = bool(row["integrity_hash"]) and hmac.compare_digest(str(row["integrity_hash"]), expected)
            result = "valid" if integrity_valid and row["verification_status"] == "valid" else ("revoked" if row["verification_status"] == "revoked" else "integrity_error")
            with self.db:
                self.db.execute("UPDATE salary_certificates SET verification_count=verification_count+1,last_verified_at=? WHERE id=?", (stamp, row["id"]))
                audit(self.db, user["id"], "salary_certificate.verify", "salary_certificate", row["id"], {"result": result, "code_suffix": submitted[-4:]})
            saved = self.db.execute("SELECT * FROM salary_certificates WHERE id=?", (row["id"],)).fetchone()
            issuer = self.db.execute("SELECT display_name,email FROM users WHERE id=?", (row["issued_by"],)).fetchone()
            self.send_json(200, {
                "valid": result == "valid",
                "status": result,
                "message": "الشهادة صحيحة ومطابقة لسجل الإصدار." if result == "valid" else ("الشهادة ملغاة ولا يجوز اعتمادها." if result == "revoked" else "فشلت مطابقة بصمة الشهادة؛ لا تعتمد المستند."),
                "certificate": self.certificate_payload(saved),
                "issuer": {"name": issuer["display_name"], "email": issuer["email"]} if issuer else None,
                "verified_at": stamp,
            })

        def api_certificate_print(self, certificate_id: int) -> None:
            user = self.current_user(True)
            assert user is not None
            if bool(user.get("must_change_password")):
                raise APIError(428, "يجب تغيير كلمة المرور المؤقتة قبل متابعة العمل.", "password_change_required")
            row = self.db.execute("SELECT * FROM salary_certificates WHERE id=?", (certificate_id,)).fetchone()
            if row is None:
                raise APIError(404, "شهادة الراتب غير موجودة.", "not_found")
            # A certificate requested by an employee and approved by HR is part
            # of that employee's self-service record.  It is printable by its
            # owner without granting the broad HR print permission.  Direct HR
            # issues remain restricted to authorized issuers.
            owner_request = row["employee_id"] == user.get("employee_id") and row["requester_id"] == user["id"]
            if not owner_request and not has_permission(self.db, user, "salary_certificate.print"):
                raise APIError(403, "لا تملك الصلاحية اللازمة لهذا الإجراء.", "forbidden", {"permission": "salary_certificate.print"})
            if row["employee_id"] != user.get("employee_id") and not self.has_privileged_people_access(user, "employee.view"):
                raise APIError(403, "لا يمكنك طباعة شهادة راتب لموظف آخر.", "forbidden")
            certificate = self.certificate_payload(row)
            if row["request_status"] not in {"approved", "issued"} or row["verification_status"] != "valid" or not certificate["integrity_valid"]:
                raise APIError(409, "تعذر طباعة الشهادة لأن حالتها أو بصمتها غير صالحة.", "certificate_invalid")
            stamp = now_iso()
            with self.db:
                self.db.execute("UPDATE salary_certificates SET print_count=print_count+1,last_printed_at=? WHERE id=?", (stamp, certificate_id))
                audit(self.db, user["id"], "salary_certificate.print", "salary_certificate", certificate_id)
            saved = self.db.execute("SELECT * FROM salary_certificates WHERE id=?", (certificate_id,)).fetchone()
            self.send_json(200, {"certificate": self.certificate_payload(saved), "print_authorized": True})

        # Payroll runs, employee payslips and advances
        def advance_schedule_summary(self, employee_id: int, exclude_month: str | None = None) -> dict[str, Any]:
            """Return the approved advance amount still scheduled for an employee.

            Installments are the source of truth.  Once the final installment is
            marked paid, there is no scheduled amount left and the next payroll
            automatically returns to the employee's full gross salary.
            """
            query = """SELECT ai.due_month,ai.amount_cents
                          FROM advance_installments ai
                          JOIN advances a ON a.id=ai.advance_id
                         WHERE a.employee_id=? AND a.status='approved'
                           AND ai.status='scheduled'"""
            params: list[Any] = [employee_id]
            if exclude_month:
                query += " AND ai.due_month<>?"
                params.append(exclude_month)
            rows = self.db.execute(query + " ORDER BY ai.due_month,ai.installment_no", params).fetchall()
            total = sum(int(row["amount_cents"]) for row in rows)
            return {
                "remaining_cents": total,
                "next_due_month": str(rows[0]["due_month"]) if rows else None,
                "installment_count": len(rows),
            }

        def payroll_item_payload(self, row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
            item = dict(row)
            for key in ("basic_cents", "allowances_cents", "deductions_cents", "advance_cents", "net_cents"):
                item[key.removesuffix("_cents")] = cents_value(item[key])
            gross_cents = int(item["basic_cents"]) + int(item["allowances_cents"])
            total_deductions_cents = int(item["deductions_cents"]) + int(item["advance_cents"])
            item["gross_cents"] = gross_cents
            item["gross"] = cents_value(gross_cents)
            item["total_deductions_cents"] = total_deductions_cents
            item["total_deductions"] = cents_value(total_deductions_cents)
            exclude_month = str(item.get("payroll_month") or "") if item.get("status") in {"approved", "paid"} else None
            summary = self.advance_schedule_summary(int(item["employee_id"]), exclude_month or None)
            item["advance_label"] = "سلفة" if int(item["advance_cents"]) > 0 else ""
            item["advance_remaining_cents"] = summary["remaining_cents"]
            item["advance_remaining"] = cents_value(summary["remaining_cents"])
            item["advance_next_due_month"] = summary["next_due_month"]
            return item

        def payroll_payload(self, run_id: int) -> dict[str, Any]:
            run=self.db.execute("SELECT * FROM payroll_runs WHERE id=?",(run_id,)).fetchone()
            if not run: raise APIError(404,"مسير الرواتب غير موجود.","not_found")
            rows=self.db.execute("SELECT * FROM payroll_items WHERE run_id=? ORDER BY employee_name",(run_id,)).fetchall()
            items=[]
            totals={"basic_cents":0,"allowances_cents":0,"deductions_cents":0,"advance_cents":0,"net_cents":0}
            for row in rows:
                item=self.payroll_item_payload(row)
                for key in totals: totals[key]+=int(item[key])
                items.append(item)
            result=dict(run)|{"items":items,"employee_count":len(items)}
            for key,value in totals.items(): result[key]=value; result[key.removesuffix("_cents")]=cents_value(value)
            result["gross_cents"] = totals["basic_cents"] + totals["allowances_cents"]
            result["gross"] = cents_value(result["gross_cents"])
            result["total_deductions_cents"] = totals["deductions_cents"] + totals["advance_cents"]
            result["total_deductions"] = cents_value(result["total_deductions_cents"])
            return result

        def api_payroll_runs_get(self) -> None:
            user = self.require_permission("salary.view")
            if not self.has_privileged_people_access(user, "salary.view"):
                raise APIError(403, "مسيرات الرواتب متاحة للإدارة المخولة فقط.", "forbidden")
            rows=self.db.execute("SELECT r.*,(SELECT COUNT(*) FROM payroll_items i WHERE i.run_id=r.id) AS employee_count,(SELECT COALESCE(SUM(net_cents),0) FROM payroll_items i WHERE i.run_id=r.id) AS net_cents FROM payroll_runs r ORDER BY payroll_month DESC").fetchall()
            self.send_json(200,{"items":[dict(r)|{"net":cents_value(r["net_cents"])} for r in rows]})

        def api_payroll_runs_post(self) -> None:
            user=self.require_permission("payroll.manage"); data=self.read_json(); month=str(data.get("payroll_month",data.get("month","")))
            if not self.has_privileged_people_access(user,"employee.view"): raise APIError(403,"إدارة المسيرات متاحة للإدارة المخولة فقط.","forbidden")
            if not re.fullmatch(r"\d{4}-(?:0[1-9]|1[0-2])",month): raise APIError(422,"الشهر يجب أن يكون YYYY-MM.","validation_error")
            allowances=money_cents(data.get("allowances",0),"allowances"); deductions=money_cents(data.get("deductions",0),"deductions"); stamp=now_iso()
            if self.db.execute("SELECT 1 FROM payroll_runs WHERE payroll_month=?",(month,)).fetchone(): raise APIError(409,"يوجد مسير لهذا الشهر.","duplicate_payroll_run")
            employees=self.db.execute(employee_query(True)+" WHERE e.active=1 ORDER BY e.full_name").fetchall()
            with self.db:
                cur=self.db.execute("INSERT INTO payroll_runs(payroll_month,created_by,created_at,updated_at) VALUES(?,?,?,?)",(month,user["id"],stamp,stamp)); run_id=int(cur.lastrowid)
                for employee in employees:
                    basic=money_cents(employee["basic_salary"] or employee["salary"] or 0,"basic_salary")
                    employee_allowances=money_cents(salary_breakdown_from_row(employee)["allowances_total"],"allowances")
                    installment=self.db.execute("SELECT COALESCE(SUM(ai.amount_cents),0) FROM advance_installments ai JOIN advances a ON a.id=ai.advance_id WHERE a.employee_id=? AND a.status='approved' AND ai.due_month=? AND ai.status='scheduled'",(employee["id"],month)).fetchone()[0]
                    total_allowances=employee_allowances+allowances
                    net=max(0,basic+total_allowances-deductions-int(installment))
                    self.db.execute("INSERT INTO payroll_items(run_id,employee_id,employee_no,employee_name,job_title,job_grade,basic_cents,allowances_cents,deductions_cents,advance_cents,net_cents) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(run_id,employee["id"],employee["employee_no"],employee["full_name"],employee["job_title"],employee["job_grade"],basic,total_allowances,deductions,int(installment),net))
                audit(self.db,user["id"],"payroll.create","payroll_run",run_id,{"month":month,"employees":len(employees)})
            self.send_json(201,{"run":self.payroll_payload(run_id)})

        def api_payroll_run_get(self, run_id: int) -> None:
            user=self.require_permission("salary.view")
            if not self.has_privileged_people_access(user,"salary.view"): raise APIError(403,"مسيرات الرواتب متاحة للإدارة المخولة فقط.","forbidden")
            self.send_json(200,{"run":self.payroll_payload(run_id)})

        def api_payroll_transition(self, run_id: int) -> None:
            data=self.read_json(); target=str(data.get("status",data.get("action",""))); row=self.db.execute("SELECT * FROM payroll_runs WHERE id=?",(run_id,)).fetchone()
            if not row: raise APIError(404,"مسير الرواتب غير موجود.","not_found")
            allowed={"draft":"review","review":"approved","approved":"paid"}
            if allowed.get(row["status"])!=target: raise APIError(409,"انتقال حالة المسير غير صالح.","invalid_status")
            permission={"review":"payroll.manage","approved":"payroll.approve","paid":"payroll.pay"}[target]; user=self.require_permission(permission)
            if not self.has_privileged_people_access(user,"employee.view"): raise APIError(403,"اعتماد المسيرات متاح للإدارة المخولة فقط.","forbidden")
            stamp=now_iso(); extra={}
            if target=="approved": extra={"approved_by":user["id"],"approved_at":stamp}
            if target=="paid": extra={"paid_by":user["id"],"paid_at":stamp}
            values={"status":target,"updated_at":stamp}|extra
            with self.db:
                self.db.execute("UPDATE payroll_runs SET "+",".join(f"{k}=?" for k in values)+" WHERE id=?",(*values.values(),run_id))
                if target=="paid":
                    self.db.execute("UPDATE advance_installments SET status='paid',payroll_item_id=(SELECT pi.id FROM payroll_items pi WHERE pi.run_id=? AND pi.employee_id=(SELECT a.employee_id FROM advances a WHERE a.id=advance_installments.advance_id)) WHERE due_month=? AND status='scheduled' AND advance_id IN (SELECT id FROM advances WHERE status='approved')",(run_id,row["payroll_month"]))
                    self.db.execute("UPDATE advances SET status='completed',updated_at=? WHERE status='approved' AND NOT EXISTS (SELECT 1 FROM advance_installments ai WHERE ai.advance_id=advances.id AND ai.status='scheduled')",(stamp,))
                audit(self.db,user["id"],f"payroll.{target}","payroll_run",run_id)
            self.send_json(200,{"run":self.payroll_payload(run_id)})

        def api_payroll_csv(self, run_id: int) -> None:
            user=self.require_permission("salary.view")
            if not self.has_privileged_people_access(user,"salary.view"): raise APIError(403,"تصدير المسيرات متاح للإدارة المخولة فقط.","forbidden")
            run=self.payroll_payload(run_id)
            rows=[["الشهر",run["payroll_month"],"الحالة",run["status"]],["الرقم الوظيفي","الموظف","المسمى","الدرجة","الأساسي","البدلات","الاستقطاعات","قسط السلفة","الصافي"]]
            rows += [[i["employee_no"],i["employee_name"],i["job_title"],i["job_grade"],f'{i["basic"]:.2f}',f'{i["allowances"]:.2f}',f'{i["deductions"]:.2f}',f'{i["advance"]:.2f}',f'{i["net"]:.2f}'] for i in run["items"]]
            self.send_csv(f'payroll-{run["payroll_month"]}.csv',rows)

        def api_my_payslips(self) -> None:
            user = self.current_user(True)
            assert user is not None
            employee_id=self.own_employee_id(); rows=self.db.execute("SELECT i.*,r.payroll_month,r.status FROM payroll_items i JOIN payroll_runs r ON r.id=i.run_id WHERE i.employee_id=? AND r.status IN ('approved','paid') ORDER BY r.payroll_month DESC",(employee_id,)).fetchall()
            certificates = self.db.execute(
                """SELECT * FROM salary_certificates
                   WHERE employee_id=? AND requester_id=?
                     AND request_status IN ('approved','issued')
                     AND verification_status='valid'
                   ORDER BY COALESCE(approved_at,issued_at) DESC,id DESC""",
                (employee_id, user["id"]),
            ).fetchall()
            payslips = [self.payroll_item_payload(r) for r in rows]
            self.send_json(200,{"items":payslips,"salary_certificates":[self.certificate_payload(row) for row in certificates]})

        def api_payslip_get(self, item_id: int) -> None:
            row=self.db.execute("SELECT i.*,r.payroll_month,r.status FROM payroll_items i JOIN payroll_runs r ON r.id=i.run_id WHERE i.id=?",(item_id,)).fetchone()
            if not row: raise APIError(404,"قسيمة الراتب غير موجودة.","not_found")
            user=self.current_user(True); assert user is not None
            if row["employee_id"]!=user.get("employee_id") and not self.has_privileged_people_access(user,"salary.view"): raise APIError(403,"لا يمكنك عرض هذه القسيمة.","forbidden")
            self.send_json(200,{"payslip":self.payroll_item_payload(row)})

        def advance_payload(self, advance_id: int) -> dict[str, Any]:
            row=self.db.execute("SELECT a.*,e.full_name,e.employee_no FROM advances a JOIN employees e ON e.id=a.employee_id WHERE a.id=?",(advance_id,)).fetchone()
            if not row: raise APIError(404,"طلب السلفة غير موجود.","not_found")
            installments=self.db.execute("SELECT * FROM advance_installments WHERE advance_id=? ORDER BY installment_no",(advance_id,)).fetchall()
            paid_cents=sum(int(i["amount_cents"]) for i in installments if i["status"]=="paid")
            remaining_cents=sum(int(i["amount_cents"]) for i in installments if i["status"]=="scheduled")
            next_due=next((str(i["due_month"]) for i in installments if i["status"]=="scheduled"),None)
            return dict(row)|{
                "amount":cents_value(row["amount_cents"]),
                "paid_cents":paid_cents,"paid":cents_value(paid_cents),
                "remaining_cents":remaining_cents,"remaining":cents_value(remaining_cents),
                "next_due_month":next_due,
                "installments":[dict(i)|{"amount":cents_value(i["amount_cents"])} for i in installments],
            }

        def api_advances_get(self) -> None:
            user=self.current_user(True); assert user is not None
            if self.has_privileged_people_access(user,"advance.view"): rows=self.db.execute("SELECT id FROM advances ORDER BY created_at DESC").fetchall()
            else: rows=self.db.execute("SELECT id FROM advances WHERE employee_id=? ORDER BY created_at DESC",(self.own_employee_id(),)).fetchall()
            self.send_json(200,{"items":[self.advance_payload(r["id"]) for r in rows]})

        def api_advances_post(self) -> None:
            user=self.current_user(True); assert user is not None; employee_id=self.own_employee_id(); data=self.read_json(); amount=money_cents(data.get("amount"),"amount",Decimal("0.01")); months=as_int(data.get("months"),"months",1,6)
            salary=self.db.execute("SELECT salary FROM employees WHERE id=?",(employee_id,)).fetchone()[0]
            if amount>money_cents(Decimal(str(salary))*3,"policy_limit"): raise APIError(422,"المبلغ يتجاوز حد السياسة (ثلاثة رواتب).","advance_policy_limit")
            if self.db.execute("SELECT 1 FROM advances WHERE employee_id=? AND status IN ('submitted','approved')",(employee_id,)).fetchone(): raise APIError(409,"لديك سلفة نشطة بالفعل.","active_advance_exists")
            base, remainder=divmod(amount,months); schedule=[base]*(months-1)+[base+remainder]; today=local_now().date(); stamp=now_iso()
            with self.db:
                cur=self.db.execute("INSERT INTO advances(employee_id,amount_cents,months,reason,created_at,updated_at) VALUES(?,?,?,?,?,?)",(employee_id,amount,months,require_text(data,"reason",1000),stamp,stamp)); advance_id=int(cur.lastrowid)
                for index,cents in enumerate(schedule,1):
                    serial=today.year*12+(today.month-1)+index; due=f"{serial//12:04d}-{serial%12+1:02d}"
                    self.db.execute("INSERT INTO advance_installments(advance_id,installment_no,due_month,amount_cents) VALUES(?,?,?,?)",(advance_id,index,due,cents))
                employee = self.db.execute("SELECT employee_no,full_name FROM employees WHERE id=?", (employee_id,)).fetchone()
                approvers = self.approval_recipient_ids("advance.approve", int(user["id"]))
                create_internal_notification(
                    self.db, int(user["id"]), approvers,
                    "طلب سلفة بانتظار الاعتماد",
                    f"قدم {employee['full_name']} ({employee['employee_no']}) طلب سلفة بقيمة {cents_value(amount)} لمدة {months} أشهر.",
                )
                audit(self.db,user["id"],"advance.submit","advance",advance_id,{"amount_cents":amount,"months":months})
            self.send_json(201,{"advance":self.advance_payload(advance_id)})

        def api_advance_decision(self, advance_id: int) -> None:
            user=self.require_permission("advance.approve"); data=self.read_json(); action=str(data.get("action","")); row=self.db.execute("SELECT * FROM advances WHERE id=?",(advance_id,)).fetchone()
            if not row: raise APIError(404,"طلب السلفة غير موجود.","not_found")
            if row["status"]!="submitted": raise APIError(409,"تم اتخاذ قرار سابقاً.","invalid_status")
            if user.get("employee_id")==row["employee_id"]: raise APIError(403,"لا يمكنك اعتماد سلفتك.","self_approval_forbidden")
            if action not in {"approve","reject"}: raise APIError(422,"القرار غير صالح.","validation_error")
            reason=optional_text(data,"reason",1000)
            if action=="reject" and not reason: raise APIError(422,"سبب الرفض مطلوب.","validation_error")
            status="approved" if action=="approve" else "rejected"; stamp=now_iso()
            with self.db:
                self.db.execute("UPDATE advances SET status=?,decided_by=?,decided_at=?,rejection_reason=?,updated_at=? WHERE id=?",(status,user["id"],stamp,reason if status=="rejected" else None,stamp,advance_id))
                if status=="rejected": self.db.execute("UPDATE advance_installments SET status='cancelled' WHERE advance_id=?",(advance_id,))
                audit(self.db,user["id"],f"advance.{status}","advance",advance_id,{"reason":reason})
            self.send_json(200,{"advance":self.advance_payload(advance_id)})

        # Operational employee lifecycle and live reports
        def lifecycle_row(self, case_id: int) -> dict[str, Any]:
            row=self.db.execute("SELECT c.*,e.full_name AS employee_name,u.display_name AS owner_name FROM lifecycle_cases c LEFT JOIN employees e ON e.id=c.employee_id LEFT JOIN users u ON u.id=c.owner_user_id WHERE c.id=?",(case_id,)).fetchone()
            if not row: raise APIError(404,"عنصر دورة الموارد البشرية غير موجود.","not_found")
            return dict(row)

        def api_lifecycle_get(self) -> None:
            self.require_permission("lifecycle.view"); conditions=[]; params=[]
            for key in ("module","status"):
                if self.query.get(key): conditions.append(f"c.{key}=?"); params.append(self.query[key])
            where=" WHERE "+" AND ".join(conditions) if conditions else ""
            rows=self.db.execute("SELECT c.*,e.full_name AS employee_name,u.display_name AS owner_name FROM lifecycle_cases c LEFT JOIN employees e ON e.id=c.employee_id LEFT JOIN users u ON u.id=c.owner_user_id"+where+" ORDER BY c.updated_at DESC",params).fetchall(); self.send_json(200,{"items":[dict(r) for r in rows]})

        def api_lifecycle_post(self) -> None:
            user=self.require_permission("lifecycle.manage"); data=self.read_json(); module=str(data.get("module","")); modules={"recruitment","onboarding","learning","benefits","offboarding"}
            if module not in modules: raise APIError(422,"الوحدة التشغيلية غير صالحة.","validation_error")
            employee_id=as_int(data["employee_id"],"employee_id",1) if data.get("employee_id") else None; owner=as_int(data["owner_user_id"],"owner_user_id",1) if data.get("owner_user_id") else user["id"]; due=parse_date(data["due_date"],"due_date").isoformat() if data.get("due_date") else None; stamp=now_iso()
            with self.db:
                cur=self.db.execute("INSERT INTO lifecycle_cases(module,title,employee_id,candidate_name,owner_user_id,due_date,notes,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",(module,require_text(data,"title",220),employee_id,optional_text(data,"candidate_name",180),owner,due,optional_text(data,"notes",3000),user["id"],stamp,stamp)); audit(self.db,user["id"],"lifecycle.create","lifecycle_case",cur.lastrowid,{"module":module})
            self.send_json(201,{"case":self.lifecycle_row(cur.lastrowid)})

        def api_lifecycle_patch(self, case_id: int) -> None:
            user=self.require_permission("lifecycle.manage"); original=self.lifecycle_row(case_id); data=self.read_json(); values={}
            for key in ("title","candidate_name","notes"):
                if key in data: values[key]=optional_text(data,key,3000)
            if "status" in data:
                if data["status"] not in {"open","in_progress","closed","cancelled"}: raise APIError(422,"الحالة غير صالحة.","validation_error")
                values["status"]=data["status"]; values["closed_at"]=now_iso() if data["status"]=="closed" else None
            if "employee_id" in data: values["employee_id"]=as_int(data["employee_id"],"employee_id",1) if data["employee_id"] else None
            if "due_date" in data: values["due_date"]=parse_date(data["due_date"],"due_date").isoformat() if data["due_date"] else None
            if not values: raise APIError(422,"لا توجد تغييرات.","validation_error")
            values["updated_at"]=now_iso()
            with self.db:
                self.db.execute("UPDATE lifecycle_cases SET "+",".join(f"{k}=?" for k in values)+" WHERE id=?",(*values.values(),case_id))
                if values.get("status")=="closed" and original["module"]=="offboarding" and original.get("employee_id"):
                    self.db.execute("UPDATE employees SET active=0,updated_at=? WHERE id=?",(now_iso(),original["employee_id"]))
                    audit(self.db,user["id"],"employee.offboard","employee",original["employee_id"],{"lifecycle_case_id":case_id})
                audit(self.db,user["id"],"lifecycle.update","lifecycle_case",case_id,values)
            self.send_json(200,{"case":self.lifecycle_row(case_id)})

        def api_lifecycle_delete(self, case_id: int) -> None:
            user=self.require_permission("lifecycle.manage")
            with self.db:
                result=self.db.execute("DELETE FROM lifecycle_cases WHERE id=?",(case_id,))
                if not result.rowcount: raise APIError(404,"العنصر غير موجود.","not_found")
                audit(self.db,user["id"],"lifecycle.delete","lifecycle_case",case_id)
            self.send_json(200,{"ok":True})

        def report_summary(self) -> dict[str, Any]:
            today=local_now().date().isoformat()
            values={
                "employees":self.db.execute("SELECT COUNT(*) FROM employees WHERE active=1").fetchone()[0],
                "branches":self.db.execute("SELECT COUNT(*) FROM branches WHERE active=1").fetchone()[0],
                "departments":self.db.execute("SELECT COUNT(*) FROM departments WHERE active=1").fetchone()[0],
                "attendance_today":self.db.execute("SELECT COUNT(*) FROM attendance WHERE work_date=? AND check_in_at IS NOT NULL",(today,)).fetchone()[0],
                "leave_pending":self.db.execute("SELECT COUNT(*) FROM leave_requests WHERE status='submitted'").fetchone()[0],
                "overtime_pending":self.db.execute("SELECT COUNT(*) FROM overtime_requests WHERE status='submitted'").fetchone()[0],
                "payroll_runs":self.db.execute("SELECT COUNT(*) FROM payroll_runs").fetchone()[0],
                "payroll_net_cents":self.db.execute("SELECT COALESCE(SUM(i.net_cents),0) FROM payroll_items i JOIN payroll_runs r ON r.id=i.run_id WHERE r.status IN ('approved','paid')").fetchone()[0],
            }
            values["payroll_net"]=cents_value(values["payroll_net_cents"]); values["as_of"]=now_iso(); return values

        def api_report_summary(self) -> None:
            self.require_permission("report.view"); self.send_json(200,{"summary":self.report_summary()})

        def api_report_summary_csv(self) -> None:
            self.require_permission("report.view"); s=self.report_summary(); labels={"employees":"الموظفون النشطون","branches":"الفروع النشطة","departments":"الأقسام","attendance_today":"حضور اليوم","leave_pending":"طلبات الإجازة المعلقة","overtime_pending":"طلبات الإضافي المعلقة","payroll_runs":"مسيرات الرواتب","payroll_net":"صافي الرواتب المعتمدة"}; self.send_csv("hr-summary.csv",[["المؤشر","القيمة"]]+[[label,s[key]] for key,label in labels.items()])

    return HRHandler


class HRThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(db_path: str | Path = DEFAULT_DB, host: str = "127.0.0.1", port: int = 8765, static_root: str | Path = APP_DIR) -> HRThreadingHTTPServer:
    resolved_db = Path(db_path).expanduser().resolve()
    # Fail closed before opening a listening socket in production. In local
    # development the legacy deterministic key remains available for existing
    # single-user databases and test fixtures.
    if os.environ.get("HR_ENV", "development").strip().lower() in {"prod", "production"}:
        secret_key(resolved_db)
    initialize_database(resolved_db)
    handler = make_handler(resolved_db, Path(static_root).expanduser().resolve())
    return HRThreadingHTTPServer((host, int(port)), handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="خادم منصة موارد البشرية")
    parser.add_argument("--host", default=os.environ.get("HR_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("HR_PORT", "8765")))
    parser.add_argument("--db", default=os.environ.get("HR_DB_PATH", str(DEFAULT_DB)))
    args = parser.parse_args(argv)
    server = make_server(args.db, args.host, args.port)
    browser_host = "localhost" if args.host in {"127.0.0.1", "::1"} else args.host
    print(f"منصة موارد تعمل على http://{browser_host}:{args.port}/")
    print(f"قاعدة البيانات: {Path(args.db).expanduser().resolve()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nتم إيقاف الخادم.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
