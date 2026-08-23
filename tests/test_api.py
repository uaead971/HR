from __future__ import annotations

import json
import http.client
import re
import contextlib
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from datetime import date, datetime, timedelta
from http.cookiejar import CookieJar
from pathlib import Path
from unittest import mock
from zoneinfo import ZoneInfo

import server as hr_server


class APIClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.cookies = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies))
        self.csrf_token = ""

    def request(self, method: str, path: str, body=None, expected: int = 200):
        payload = None
        headers = {"Accept": "application/json"}
        if method in {"POST", "PATCH", "DELETE"} and self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
        if body is not None:
            payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base_url + path, data=payload, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=10) as response:
                status = response.status
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            status = exc.code
            data = json.loads(exc.read().decode("utf-8"))
            exc.close()
        if status != expected:
            raise AssertionError(f"{method} {path}: expected {expected}, got {status}: {data}")
        if isinstance(data, dict) and data.get("csrf_token"):
            self.csrf_token = data["csrf_token"]
        return data

    def login(self, email: str, password: str):
        return self.request("POST", "/api/auth/login", {"email": email, "password": password})

    def raw_request(self, path: str, expected: int = 200):
        request = urllib.request.Request(self.base_url + path, headers={"Accept": "text/csv"})
        with self.opener.open(request, timeout=10) as response:
            if response.status != expected:
                raise AssertionError(f"GET {path}: expected {expected}, got {response.status}")
            return response.headers, response.read()


class HRAPIEndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="hr-api-tests-")
        cls.db_path = Path(cls.tmp.name) / "hr.sqlite3"
        cls._start_server()

    @classmethod
    def _start_server(cls):
        cls.httpd = hr_server.make_server(cls.db_path, "127.0.0.1", 0, Path(__file__).parents[1])
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def _restart_server(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)
        cls._start_server()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)
        cls.tmp.cleanup()

    def client(self, email: str, password: str) -> APIClient:
        client = APIClient(self.base_url)
        client.login(email, password)
        return client

    def test_01_authentication_and_server_side_authorization(self):
        public = APIClient(self.base_url)
        health = public.request("GET", "/api/health")
        self.assertTrue(health["ok"])
        self.assertEqual(hr_server.APP_VERSION, "5.7.0")
        self.assertEqual(health["version"], "5.7.0")
        org = public.request("GET", "/api/org")["organization"]
        self.assertTrue(org["display_name"])
        public.request("GET", "/api/auth/me", expected=401)
        public.request("POST", "/api/auth/login", {"email": "employee@demo.ae", "password": "wrong"}, expected=401)

        employee = self.client("employee@demo.ae", "Emp@12345")
        me = employee.request("GET", "/api/auth/me")
        self.assertEqual(me["user"]["role"], "employee")
        employee.request(
            "POST", "/api/branches",
            {"name": "ممنوع", "latitude": 25, "longitude": 55, "radius_m": 100},
            expected=403,
        )
        employee.request("POST", "/api/auth/logout", {})
        employee.request("GET", "/api/auth/me", expected=401)

        admin = self.client("admin@demo.ae", "Admin@123")
        suffix = uuid.uuid4().hex[:7]
        email = f"new-{suffix}@demo.ae"
        created = admin.request(
            "POST", "/api/employees",
            {
                "employee_no": f"T-{suffix}", "full_name": "موظف اختبار", "email": email,
                "job_title": "محلل", "job_grade": "G-05", "salary": 8000,
                "photo_data": "data:image/png;base64,iVBORw0KGgo=", "create_user": True,
                "password": "NewUser@123", "role": "employee",
            }, expected=201,
        )["employee"]
        self.assertTrue(created["photo_data"].startswith("data:image/png"))
        new_user = self.client(email, "NewUser@123")
        self.assertEqual(new_user.request("GET", "/api/auth/me")["user"]["employee_id"], created["id"])

    def test_local_browser_url_uses_localhost_without_weakening_cookie(self):
        root = Path(__file__).parents[1]
        launcher = (root / "تشغيل التطبيق.command").read_text(encoding="utf-8")
        readme = (root / "README.md").read_text(encoding="utf-8")
        server_source = (root / "server.py").read_text(encoding="utf-8")
        self.assertIn("http://localhost:${APP_PORT}/", launcher)
        self.assertIn("http://localhost:8765/", readme)
        self.assertIn('browser_host = "localhost"', server_source)
        self.assertIn("HttpOnly; SameSite=Lax", server_source)

    def test_frontend_map_rtl_and_role_accurate_evaluation_regressions(self):
        root = Path(__file__).parents[1]
        app = (root / "app.js").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")
        index = (root / "index.html").read_text(encoding="utf-8")
        self.assertIn(".leaflet-container{direction:ltr!important", styles)
        self.assertIn("isolation:isolate", styles)
        self.assertIn("function clearMapFallback", app)
        self.assertIn("map.invalidateSize({pan:false})", app)
        self.assertIn("لا توجد تقييمات بانتظار إجراءك", app)
        self.assertIn("function resetTransientUi", app)
        self.assertIn("toast('تمت إعادتك إلى مساحتك لأن الوحدة المطلوبة غير متاحة لحسابك.')", app)
        self.assertNotIn("alertMessage('لا يملك حسابك صلاحية فتح هذه الوحدة.'", app)
        self.assertIn('integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY="', index)
        self.assertNotIn('sha256-p4NxAoJBhIINfQ3ynAu/EGyWbKofNLF4MZwvMZ8CHwM=', index)
        self.assertIn('styles.css?v=5.7.0', index)
        self.assertIn('app.js?v=5.7.0', index)

    def test_52_v54_visual_identity_crud_publish_rbac_audit_restart_and_frontend_contract(self):
        admin = self.client("admin@demo.ae", "Admin@123")
        employee = self.client("employee@demo.ae", "Emp@12345")
        public = APIClient(self.base_url)

        initial_public = public.request("GET", "/api/org")["organization"]["visual_identity"]
        self.assertFalse(initial_public["enabled"])
        self.assertEqual(initial_public["mode"], "static")
        self.assertEqual(initial_public["interval_seconds"], 20)
        self.assertEqual(initial_public["slides"], [])
        employee.request("GET", "/api/org/visual-identity", expected=403)
        employee.request("PATCH", "/api/org/visual-identity", {"enabled": True}, expected=403)
        admin.request("PATCH", "/api/org/visual-identity", {"interval_seconds": 4}, expected=422)
        admin.request("PATCH", "/api/org/visual-identity", {"interval_seconds": 301}, expected=422)
        admin.request("PATCH", "/api/org/visual-identity", {"mode": "video"}, expected=422)
        admin.request("PATCH", "/api/org/visual-identity", {"enabled": "false"}, expected=422)
        admin.request("POST", "/api/org/visual-identity/slides", {"title_ar": "اختبار", "active": "false"}, expected=422)

        first = admin.request(
            "POST", "/api/org/visual-identity/slides",
            {"title_ar": "الموظف في المركز", "title_en": "People at the centre", "focus_position": "center", "active": True},
            expected=201,
        )["slide"]
        tiny_png = "data:image/png;base64,iVBORw0KGgo="
        second = admin.request(
            "POST", "/api/org/visual-identity/slides",
            {"image_data": tiny_png, "title_ar": "معاً ننجح", "title_en": "Together we thrive", "alt_ar": "فريق عمل", "alt_en": "A team", "focus_position": "top", "active": True},
            expected=201,
        )["slide"]
        third = admin.request("POST", "/api/org/visual-identity/slides", {"title_ar": "التطوير مستمر", "active": False}, expected=201)["slide"]
        fourth = admin.request("POST", "/api/org/visual-identity/slides", {"title_en": "Secure by design", "active": True}, expected=201)["slide"]
        fifth = admin.request("POST", "/api/org/visual-identity/slides", {"title_ar": "قيمنا تقودنا", "active": True}, expected=201)["slide"]
        admin.request("POST", "/api/org/visual-identity/slides", {"title_ar": "سادسة"}, expected=409)
        admin.request("PATCH", f"/api/org/visual-identity/slides/{first['id']}", {"image_data": "data:image/png;base64,ZmFrZQ==", "alt_ar": "غير صالح"}, expected=422)

        configured = admin.request(
            "PATCH", "/api/org/visual-identity",
            {"enabled": True, "mode": "static", "surface": "both", "interval_seconds": 20, "overlay": 64},
        )["visual_identity"]
        self.assertTrue(configured["enabled"])
        self.assertEqual(len(configured["slides"]), 5)
        static_public = public.request("GET", "/api/org")["organization"]["visual_identity"]
        self.assertEqual([slide["id"] for slide in static_public["slides"]], [first["id"]])

        rotation = admin.request("PATCH", "/api/org/visual-identity", {"mode": "rotation", "interval_seconds": 5})["visual_identity"]
        self.assertEqual(rotation["interval_seconds"], 5)
        rotated_public = public.request("GET", "/api/org")["organization"]["visual_identity"]
        self.assertEqual(len(rotated_public["slides"]), 4)
        self.assertNotIn(third["id"], [slide["id"] for slide in rotated_public["slides"]])

        malicious = '<img src=x onerror=alert(1)>'
        patched = admin.request("PATCH", f"/api/org/visual-identity/slides/{second['id']}", {"title_ar": malicious, "focus_position": "left"})["slide"]
        self.assertEqual(patched["title_ar"], malicious)
        order = [fifth["id"], fourth["id"], third["id"], second["id"], first["id"]]
        reordered = admin.request("PATCH", "/api/org/visual-identity/slides/order", {"slide_ids": order})["visual_identity"]
        self.assertEqual([slide["id"] for slide in reordered["slides"]], order)
        admin.request("PATCH", "/api/org/visual-identity/slides/order", {"slide_ids": order[:-1]}, expected=409)

        cookie = next(iter(admin.cookies)).value
        no_csrf = urllib.request.Request(
            self.base_url + "/api/org/visual-identity", data=b'{"enabled":false}',
            headers={"Accept": "application/json", "Content-Type": "application/json", "Cookie": f"hr_session={cookie}"}, method="PATCH",
        )
        with self.assertRaises(urllib.error.HTTPError) as csrf_error:
            urllib.request.urlopen(no_csrf, timeout=10)
        self.assertEqual(csrf_error.exception.code, 403)
        csrf_error.exception.close()

        admin.request("DELETE", f"/api/org/visual-identity/slides/{third['id']}")
        remaining = admin.request("GET", "/api/org/visual-identity")["visual_identity"]["slides"]
        self.assertEqual([slide["sort_order"] for slide in remaining], [1, 2, 3, 4])
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            actions = {row[0] for row in db.execute("SELECT action FROM audit_log WHERE action LIKE 'visual_identity.%'")}
            self.assertTrue({"visual_identity.settings_update", "visual_identity.slide_create", "visual_identity.slide_update", "visual_identity.slides_reorder", "visual_identity.slide_delete"}.issubset(actions))

        self._restart_server()
        admin = self.client("admin@demo.ae", "Admin@123")
        persisted = admin.request("GET", "/api/org/visual-identity")["visual_identity"]
        self.assertTrue(persisted["enabled"])
        self.assertEqual(persisted["mode"], "rotation")
        self.assertEqual(persisted["interval_seconds"], 5)
        self.assertEqual(len(persisted["slides"]), 4)

        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8")
        app = (root / "app.js").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")
        i18n = (root / "i18n.js").read_text(encoding="utf-8")
        schema = (root / "schema.sql").read_text(encoding="utf-8")
        server_source = (root / "server.py").read_text(encoding="utf-8")
        for marker in ("visualIdentityStudio", "visualIdentitySettingsForm", "visualIdentitySlides", "loginVisualIdentity", "dashboardVisualIdentity", "visualIdentityPreview"):
            self.assertIn(marker, index)
        for marker in ("compressIdentityImage", "MAX_VISUAL_IDENTITY_IMAGE_BYTES", "prefers-reduced-motion", "visibilitychange", "clearInterval", "pagehide", "aria-live=\"polite\""):
            self.assertIn(marker, app + server_source + styles + index)
        self.assertNotIn("localStorage", app)
        self.assertIn("visual_identity_slides", schema + server_source)
        self.assertIn("استوديو العلامة المؤسسية", i18n)
        self.assertIn("Organization brand studio", i18n)
        for asset in ("styles.css", "i18n.js", "app.js"):
            self.assertIn(f'{asset}?v=5.7.0', index)

    def test_53_v54_migrates_v532_visual_identity_without_changing_tenant_data(self):
        with tempfile.TemporaryDirectory(prefix="hr-v54-migration-") as folder:
            legacy_path = Path(folder) / "legacy.sqlite3"
            hr_server.initialize_database(legacy_path)
            with contextlib.closing(sqlite3.connect(legacy_path)) as legacy:
                legacy.execute("DROP TABLE visual_identity_slides")
                for column in ("visual_identity_enabled", "visual_identity_mode", "visual_identity_surface", "visual_identity_interval_seconds", "visual_identity_overlay"):
                    legacy.execute(f"ALTER TABLE organization DROP COLUMN {column}")
                legacy.execute("UPDATE organization SET display_name='مؤسسة محفوظة',legal_name='مؤسسة محفوظة ذ.م.م',primary_color='#123f35',accent_color='#c48a3a' WHERE id=1")
                legacy.commit()
            hr_server.initialize_database(legacy_path)
            with contextlib.closing(sqlite3.connect(legacy_path)) as migrated:
                migrated.row_factory = sqlite3.Row
                organization = migrated.execute("SELECT * FROM organization WHERE id=1").fetchone()
                self.assertEqual(organization["display_name"], "مؤسسة محفوظة")
                self.assertEqual(organization["legal_name"], "مؤسسة محفوظة ذ.م.م")
                self.assertEqual(organization["primary_color"], "#123f35")
                self.assertEqual(organization["visual_identity_enabled"], 0)
                self.assertEqual(organization["visual_identity_mode"], "static")
                self.assertEqual(organization["visual_identity_surface"], "both")
                self.assertEqual(organization["visual_identity_interval_seconds"], 20)
                self.assertEqual(organization["visual_identity_overlay"], 58)
                self.assertTrue(migrated.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='visual_identity_slides'").fetchone())

    def test_54_v54_visual_identity_english_controls_static_state_and_readability_regressions(self):
        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8")
        app = (root / "app.js").read_text(encoding="utf-8")
        i18n = (root / "i18n.js").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")

        for value, arabic, english in (
            ("static", "صورة ثابتة", "Static image"),
            ("rotation", "عرض متغير", "Rotating display"),
            ("both", "شاشة الدخول ولوحة التحكم", "Sign-in and dashboard"),
            ("login", "شاشة الدخول فقط", "Sign-in only"),
            ("dashboard", "لوحة التحكم فقط", "Dashboard only"),
        ):
            self.assertIn(f'<option value="{value}" data-i18n-option>{arabic}</option>', index)
            self.assertIn(f"'{arabic}':'{english}'", i18n)
        self.assertIn('option:not([value=""]):not([data-i18n-option])', i18n)

        self.assertIn('id="visualOverlayValue" for="visualOverlayRange" aria-live="polite" aria-atomic="true"', index)
        self.assertIn('id="visualOverlayRange"', index)
        self.assertIn('aria-describedby="visualOverlayValue"', index)
        self.assertIn("function syncVisualOverlayOutput(value)", app)
        self.assertIn("i18n()?.locale==='en'?'%':'٪'", app)
        self.assertIn("output.setAttribute('aria-label'", app)
        self.assertIn("range.setAttribute('aria-valuetext',localized)", app)
        self.assertIn("document.addEventListener('hr:localechange'", app)

        self.assertIn("slides=(config?.mode==='static'?activeSlides.slice(0,1):activeSlides)", app)
        self.assertIn("canRotate=config?.mode==='rotation'&&slides.length>1", app)
        self.assertIn("controls.hidden=!canRotate", app)
        self.assertIn("timeline.hidden=!canRotate", app)
        self.assertIn("controls.setAttribute('aria-hidden',String(!canRotate))", app)

        self.assertRegex(styles, r"studio-section-title p,[^{]+visual-slide-meta,[^{]+identity-editor-note p\{font-size:12px\}")
        self.assertRegex(styles, r"@media\(max-width:650px\)\{[^}]+visual-slide-actions \.text-btn\{font-size:13px\}")
        self.assertIn(".visual-slide-body{min-height:255px;padding:16px}", styles)

    def test_55_comprehensive_employee_report_calculations_rbac_audit_and_frontend_contract(self):
        admin = self.client("admin@demo.ae", "Admin@123")
        hr = self.client("hr@demo.ae", "HR@12345")
        manager = self.client("manager@demo.ae", "Manager@12345")
        employee = self.client("employee@demo.ae", "Emp@12345")
        today = date.today()
        period_start = today - timedelta(days=today.weekday() + 7)
        period_end = period_start + timedelta(days=6)
        requested_start = period_start - timedelta(days=3)
        suffix = uuid.uuid4().hex[:8]
        with contextlib.closing(sqlite3.connect(self.db_path)) as seed:
            branch_id = seed.execute("SELECT id FROM branches WHERE active=1 ORDER BY id LIMIT 1").fetchone()[0]
        created = admin.request(
            "POST", "/api/employees",
            {
                "employee_no": f"RPT-{suffix}", "full_name": f"موظف التقرير {suffix}",
                "email": f"report-{suffix}@demo.ae", "job_title": "محلل تقارير",
                "job_grade": "G-06", "salary": 19750, "hire_date": period_start.isoformat(),
                "branch_id": branch_id, "active": True,
            }, expected=201,
        )["employee"]
        employee_id = created["id"]
        stamp = datetime.now(ZoneInfo("Asia/Dubai")).isoformat(timespec="seconds")
        due_months = []
        due_cursor = period_start.replace(day=1)
        for _ in range(3):
            due_months.append(due_cursor.strftime("%Y-%m"))
            due_cursor = due_cursor.replace(
                year=due_cursor.year + (1 if due_cursor.month == 12 else 0),
                month=1 if due_cursor.month == 12 else due_cursor.month + 1,
            )
        with contextlib.closing(sqlite3.connect(self.db_path)) as seed:
            seed.row_factory = sqlite3.Row
            admin_id = seed.execute("SELECT id FROM users WHERE email='admin@demo.ae'").fetchone()["id"]
            annual_id = seed.execute("SELECT id FROM leave_types WHERE code='annual'").fetchone()["id"]
            shift_id = seed.execute(
                """INSERT INTO shifts(name,start_time,end_time,break_minutes,working_days,rest_days,grace_minutes,daily_limit_minutes,active,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,1,?,?)""",
                (f"Report shift {suffix}", "09:00", "17:00", 60, "[0,1,2,3,4]", "[5,6]", 10, 480, stamp, stamp),
            ).lastrowid
            seed.execute(
                "INSERT INTO employee_shift_assignments(employee_id,shift_id,effective_from,effective_to,created_by,created_at) VALUES(?,?,?,?,?,?)",
                (employee_id, shift_id, period_start.isoformat(), period_end.isoformat(), admin_id, stamp),
            )
            monday = period_start
            tuesday = period_start + timedelta(days=1)
            wednesday = period_start + timedelta(days=2)
            thursday = period_start + timedelta(days=3)
            friday = period_start + timedelta(days=4)
            for work_day, check_in, check_out in (
                (monday, "09:15:00", "17:00:00"),
                (tuesday, "09:00:00", "18:00:00"),
            ):
                seed.execute(
                    """INSERT INTO attendance(employee_id,work_date,branch_id,check_in_at,check_out_at,decision,created_at,updated_at)
                       VALUES(?,?,?,?,?,'accepted',?,?)""",
                    (employee_id, work_day.isoformat(), branch_id,
                     f"{work_day.isoformat()}T{check_in}+04:00", f"{work_day.isoformat()}T{check_out}+04:00", stamp, stamp),
                )
            # A placeholder attendance row with no check-in remains a true absence.
            seed.execute(
                "INSERT INTO attendance(employee_id,work_date,branch_id,decision,created_at,updated_at) VALUES(?,?,?,'accepted',?,?)",
                (employee_id, thursday.isoformat(), branch_id, stamp, stamp),
            )
            seed.execute(
                """INSERT INTO leave_requests(employee_id,leave_type_id,start_date,end_date,days,reason,status,created_at,updated_at)
                   VALUES(?,?,?,?,1,'إجازة معتمدة للاختبار','approved',?,?)""",
                (employee_id, annual_id, wednesday.isoformat(), wednesday.isoformat(), stamp, stamp),
            )
            seed.execute(
                "UPDATE leave_balances SET entitlement=30,carried=2,used=6 WHERE employee_id=? AND leave_type_id=? AND year=?",
                (employee_id, annual_id, period_end.year),
            )
            for action_type, action_date, status in (
                ("violation", monday, "open"), ("undertaking", tuesday, "closed"), ("violation", thursday, "cancelled"),
            ):
                seed.execute(
                    """INSERT INTO employee_actions(employee_id,action_type,action_date,description,status,penalty,created_by,created_at,updated_at)
                       VALUES(?,?,?,?,?,'',?,?,?)""",
                    (employee_id, action_type, action_date.isoformat(), f"{action_type} test", status, admin_id, stamp, stamp),
                )
            for work_day, duration, status in ((monday, 120, "approved"), (tuesday, 60, "submitted")):
                seed.execute(
                    """INSERT INTO overtime_requests(employee_id,work_date,start_time,end_time,duration_minutes,reason,status,created_at,updated_at)
                       VALUES(?,?,'18:00','20:00',?,'اختبار التقرير',?,?,?)""",
                    (employee_id, work_day.isoformat(), duration, status, stamp, stamp),
                )
            advance_id = seed.execute(
                """INSERT INTO advances(employee_id,amount_cents,months,reason,status,decided_by,decided_at,created_at,updated_at)
                   VALUES(?,60000,3,'سلفة اختبار','approved',?,?,?,?)""",
                (employee_id, admin_id, stamp, stamp, stamp),
            ).lastrowid
            seed.executemany(
                "INSERT INTO advance_installments(advance_id,installment_no,due_month,amount_cents,status) VALUES(?,?,?,?,?)",
                [(advance_id, index + 1, month, 20000, "paid" if index == 0 else "scheduled") for index, month in enumerate(due_months)],
            )
            seed.commit()

        employee.request("GET", f"/api/employee-reports/search?q={suffix}", expected=403)
        manager.request("GET", f"/api/employee-reports/search?q={suffix}", expected=403)
        search = hr.request("GET", f"/api/employee-reports/search?q={suffix}")["items"]
        self.assertEqual(len(search), 1)
        self.assertEqual(search[0]["id"], employee_id)
        self.assertEqual(
            set(search[0]),
            {"id", "employee_no", "full_name", "hire_date", "active", "job_title", "department_name"},
        )
        generated = hr.request(
            "POST", f"/api/employees/{employee_id}/comprehensive-report",
            {"date_from": requested_start.isoformat(), "date_to": period_end.isoformat()},
        )["report"]
        self.assertRegex(generated["report_reference"], rf"^ER-\d{{4}}-RPT{suffix.upper()}-[A-F0-9]{{10}}$")
        self.assertEqual(generated["period"]["requested_from"], requested_start.isoformat())
        self.assertEqual(generated["period"]["effective_from"], period_start.isoformat())
        self.assertTrue(generated["period"]["adjusted_to_service"])
        self.assertNotIn("salary", generated)
        self.assertNotIn("salary", generated["employee"])
        self.assertEqual(generated["summary"]["net_work_minutes"], 885)
        self.assertEqual(generated["summary"]["attendance_completed_days"], 2)
        self.assertEqual(generated["summary"]["attendance_open_days"], 0)
        self.assertEqual(generated["summary"]["late_minutes"], 5)
        self.assertEqual(generated["summary"]["absence_days"], 2)
        self.assertEqual(generated["absence"]["dates"], [thursday.isoformat(), friday.isoformat()])
        self.assertEqual(generated["summary"]["weekly_rest_days"], 2)
        self.assertEqual(generated["summary"]["approved_leave_days"], 1)
        self.assertEqual(generated["summary"]["approved_overtime_minutes"], 120)
        self.assertEqual(generated["summary"]["violation_count"], 1)
        self.assertEqual(generated["summary"]["undertaking_count"], 1)
        annual = next(item for item in generated["leave_balances"]["items"] if item["leave_type_code"] == "annual")
        self.assertEqual(annual["remaining"], 26)
        self.assertEqual(len(generated["overtime"]), 1)
        self.assertEqual(len(generated["actions"]), 2)
        self.assertEqual(generated["summary"]["active_advance_remaining_cents"], 40000)
        self.assertEqual(generated["advances"][0]["paid_cents"], 20000)
        self.assertEqual(generated["advances"][0]["last_due_month"], due_months[-1])
        self.assertTrue(generated["calculation_notes"])
        self.assertIn("attendance + employee_shift_assignments + shifts", generated["calculation_sources"]["net_work_minutes"]["table"])

        export = hr.request(
            "POST", f"/api/employees/{employee_id}/comprehensive-report/export",
            {
                "format": "print_pdf", "report_reference": generated["report_reference"],
                "date_from": requested_start.isoformat(), "date_to": period_end.isoformat(),
            },
        )
        self.assertTrue(export["print_authorized"])
        self.assertEqual(export["report_reference"], generated["report_reference"])
        hr.request(
            "POST", f"/api/employees/{employee_id}/comprehensive-report/export",
            {"format": "server_pdf", "date_from": period_start.isoformat(), "date_to": period_end.isoformat()}, expected=422,
        )
        hr.request(
            "POST", f"/api/employees/{employee_id}/comprehensive-report",
            {"date_from": period_end.isoformat(), "date_to": period_start.isoformat()}, expected=422,
        )

        with contextlib.closing(sqlite3.connect(self.db_path)) as permissions:
            manager_id = permissions.execute("SELECT id FROM users WHERE email='manager@demo.ae'").fetchone()[0]
            permissions.execute(
                "INSERT OR REPLACE INTO user_permissions(user_id,permission,granted) VALUES(?,?,1)",
                (manager_id, "employee_report.view"),
            )
            permissions.commit()
        manager.request("POST", f"/api/employees/{employee_id}/comprehensive-report", {"date_from": period_start.isoformat(), "date_to": period_end.isoformat()})
        manager.request(
            "POST", f"/api/employees/{employee_id}/comprehensive-report/export",
            {"format": "print_pdf", "date_from": period_start.isoformat(), "date_to": period_end.isoformat()}, expected=403,
        )
        with contextlib.closing(sqlite3.connect(self.db_path)) as checked:
            checked.execute("DELETE FROM user_permissions WHERE user_id=? AND permission='employee_report.view'", (manager_id,))
            checked.commit()
            actions = [row[0] for row in checked.execute(
                "SELECT action FROM audit_log WHERE entity_type='employee' AND entity_id=? AND action LIKE 'employee_report.%'",
                (str(employee_id),),
            )]
        self.assertIn("employee_report.generate", actions)
        self.assertIn("employee_report.export", actions)

        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8")
        app = (root / "app.js").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")
        i18n = (root / "i18n.js").read_text(encoding="utf-8")
        server_source = (root / "server.py").read_text(encoding="utf-8")
        for marker in ("employeeReportForm", "employeeReportSearch", "employeeComprehensiveReport", "report-summary-grid", "printEmployeeReport"):
            self.assertIn(marker, index + app)
        for marker in ("employee_report.view", "employee_report.export", "/api/employee-reports/search", "comprehensive-report/export"):
            self.assertIn(marker, index + app + server_source)
        self.assertIn("@page employeeReport{size:A4", styles)
        self.assertIn("page:employeeReport", styles)
        self.assertIn("thead{display:table-header-group}", styles)
        self.assertIn("window.print()", app)
        self.assertIn("format:'print_pdf'", app)
        self.assertIn("Comprehensive employee report", i18n)
        self.assertIn("Print / Save PDF", i18n)

    def test_56_v55_tablet_scroll_english_headers_and_domain_status_contract(self):
        root = Path(__file__).parents[1]
        app = (root / "app.js").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")
        i18n = (root / "i18n.js").read_text(encoding="utf-8")

        # Tablet and mobile tables must scroll inside their report sections instead
        # of widening the application document at the required 768 px viewport.
        tablet = styles[styles.index("@media(max-width:900px){.report-document-table-wrap"):]
        tablet = tablet[:tablet.index("@media(max-width:700px)")]
        self.assertIn("max-width:100%;overflow-x:auto", tablet)
        self.assertIn("overscroll-behavior-inline:contain", tablet)
        self.assertIn(".report-document-table{min-width:760px}", tablet)
        self.assertIn("مرر أفقياً لرؤية كل الأعمدة", tablet)
        self.assertIn("Scroll horizontally to view all columns", tablet)
        self.assertIn(".employee-report-workspace{position:relative;z-index:1;min-width:0", styles)
        self.assertIn(".employee-report-result{display:grid;grid-template-columns:minmax(0,1fr);min-width:0", styles)
        self.assertIn("max-width:100%;min-width:0;min-height:297mm", styles)
        self.assertIn(".employee-comprehensive-report.print-target .report-document-table-wrap:before{display:none!important}", styles)
        self.assertIn(".employee-comprehensive-report.print-target .report-document-table{min-width:0!important}", styles)

        # Every system-generated table heading has a deterministic English label.
        report_headers = {
            "التاريخ": "Date", "الدخول": "Check-in", "الخروج": "Check-out",
            "صافي العمل": "Net work", "التأخير": "Late", "الحالة": "Status",
            "النوع": "Type", "من": "From", "إلى": "To", "داخل الفترة": "Within period",
            "السبب": "Reason", "الاستحقاق": "Entitlement", "المرحل": "Carried",
            "المستخدم": "Used", "المتبقي": "Remaining", "الوصف": "Description",
            "الجزاء": "Penalty", "من / إلى": "From / To", "المدة": "Duration",
            "مبلغ الاقتراض": "Borrowed amount", "تاريخ الطلب": "Request date",
            "الأشهر": "Months", "المدفوع": "Paid", "آخر استحقاق": "Last due month",
        }
        for arabic, english in report_headers.items():
            self.assertIn(f"'{arabic}':'{english}'", i18n)

        # The same raw status may mean different things in different HR domains.
        self.assertIn("function reportStatus(domain,value)", app)
        self.assertIn("attendance:{working_day:'يوم عمل',weekly_rest:'راحة أسبوعية',open:'تسجيل مفتوح',no_shift:'لا توجد مناوبة',absent:'غائب'}", app)
        self.assertIn("action:{open:'مفتوح',closed:'مغلق',cancelled:'ملغي'}", app)
        self.assertIn("advance:{submitted:'مقدم',approved:'معتمد',rejected:'مرفوض',completed:'مكتمل',cancelled:'ملغي'}", app)
        self.assertIn("reportStatus('attendance',r.day_status)", app)
        self.assertIn("reportStatus('action',r.status)", app)
        self.assertIn("reportStatus('advance',r.status)", app)
        self.assertNotIn("reportStatus(r.status)", app)
        for arabic, english in {
            "تسجيل مفتوح": "Open attendance", "مفتوح": "Open", "مغلق": "Closed",
            "ملغي": "Cancelled", "مقدم": "Submitted", "معتمد": "Approved",
            "مرفوض": "Rejected", "مكتمل": "Completed",
        }.items():
            self.assertIn(f"'{arabic}':'{english}'", i18n)
        self.assertIn("function reportPreserved(value)", app)
        self.assertIn("data-i18n-preserve", app)

    def test_49_v53_executive_theme_svg_icons_responsive_and_print_isolation(self):
        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8")
        app = (root / "app.js").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")

        for asset in ("styles.css", "i18n.js", "app.js"):
            self.assertIn(f'{asset}?v=5.7.0', index)
        for token in ("--mineral-950:#071b22", "--mineral-900:#0b2530", "--emerald-700:#0e6655", "--bronze-500:#c99545", "--parchment-100:#f4f2ec"):
            self.assertIn(token, styles)
        for symbol in ("dashboard", "home", "users", "org", "map", "clock", "calendar", "shift", "overtime", "wallet", "certificate", "loan", "target", "recruitment", "onboarding", "learning", "benefits", "offboarding", "bell", "mail", "report", "shield", "settings", "search", "menu", "print", "edit", "archive", "download"):
            self.assertIn(f'id="icon-{symbol}"', index)
        self.assertIn('class="icon-sprite"', index)
        self.assertIn('function icon(name,className=', app)
        self.assertIn("function emptyState(message,iconName=", app)
        self.assertIn("const actionIcons=", app)
        nav = index[index.index('<nav id="mainNav"'):index.index('</nav>')]
        for glyph in "▦⌂♙⌘⌖◷◫☼＋◈▥↺◇◎△♡⇥✦✉⌾⚙":
            self.assertNotIn(glyph, nav)
        self.assertGreaterEqual(index.count('aria-hidden="true"'), 25)
        self.assertIn('stroke:currentColor', styles)
        self.assertIn(':focus-visible', styles)
        self.assertIn('@media(prefers-reduced-motion:reduce)', styles)
        for breakpoint in ("1200px", "900px", "650px", "390px"):
            self.assertIn(f'@media(max-width:{breakpoint})', styles)
        self.assertGreaterEqual(index.count('data-locale="ar"'), 2)
        self.assertGreaterEqual(index.count('data-locale="en"'), 2)
        self.assertIn('@page cardPortrait{size:53.98mm 85.60mm', styles)
        self.assertIn('@page cardLandscape{size:85.60mm 53.98mm', styles)
        self.assertIn('.certificate.print-target{width:210mm!important', styles)
        self.assertIn('.icon-sprite{display:none!important}', styles)

    def test_50_v531_mobile_drawer_toolbar_i18n_icons_and_type_regressions(self):
        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8")
        app = (root / "app.js").read_text(encoding="utf-8")
        i18n = (root / "i18n.js").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")

        for asset in ("styles.css", "i18n.js", "app.js"):
            self.assertIn(f'{asset}?v=5.7.0', index)
        self.assertIn('.sidebar-collapsed .sidebar,.sidebar-collapsed .sidebar.open{width:min(310px,88vw)}', styles)
        self.assertIn('.sidebar-collapsed .sidebar a>span,', styles)
        self.assertIn('.sidebar-collapsed .sidebar .nav-label,', styles)
        self.assertIn('.sidebar-collapsed .sidebar .server-state small{display:revert}', styles)
        self.assertIn('@media(min-width:901px) and (max-width:1500px)', styles)
        self.assertIn('grid-template-columns:minmax(200px,1fr) minmax(120px,160px) minmax(120px,160px) repeat(3,max-content)', styles)
        self.assertIn('.page :where(p,small,label,button,input,select,textarea,th,td)', styles)
        self.assertIn('font-size:13px;line-height:1.55', styles)

        self.assertIn("function iconLabel(name,label)", app)
        self.assertIn("function decorateActionButton(button,name)", app)
        self.assertIn("function enhanceActionIcons(root=document)", app)
        for action in ("addEmployee:'plus'", "addBranch:'plus'", "zoomOrganization:'expand'", "printOrganization:'print'", "createEvaluationCycle:'plus'"):
            self.assertIn(action, app)
        self.assertIn('id="icon-expand"', index)
        self.assertIn("enhanceActionIcons(root)", app)

        for routed_label in ("${tr('اسم الفرع')}", "${tr('مدير الفرع')}", "${esc(tr(group.label))}", "${esc(tr(p.label))}", "${tr('كلمة مرور مؤقتة')}"):
            self.assertIn(routed_label, app)
        for english_label in ("Add Branch & Set Geofence", "Branch manager", "Leadership & Reports", "View executive dashboard", "Explicit denial", "Disable account"):
            self.assertIn(english_label, i18n)
        self.assertIn('@page cardPortrait{size:53.98mm 85.60mm', styles)
        self.assertIn('.certificate.print-target{width:210mm!important', styles)

    def test_51_v532_dynamic_kpis_are_render_time_translated_and_catalogued(self):
        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8")
        app = (root / "app.js").read_text(encoding="utf-8")
        i18n = (root / "i18n.js").read_text(encoding="utf-8")

        for asset in ("styles.css", "i18n.js", "app.js"):
            self.assertIn(f'{asset}?v=5.7.0', index)
        self.assertIn("function metricValue(value)", app)
        self.assertIn("<small>${esc(tr(m[0]))}</small>", app)
        self.assertIn("<span>${esc(tr(m[2]))}</span>", app)
        self.assertIn("$('#reportAsOf').textContent=tr('حتى')", app)
        for container in ("myMetrics", "campaignMetrics", "branchMetrics", "overtimeMetrics", "payrollMetrics", "advanceMetrics", "reportMetrics"):
            self.assertIn(f"$('#{container}').innerHTML=", app)

        expected_english = (
            "Registered branches", "Stored in the database", "Active geofences", "Assigned employees",
            "Awaiting approval", "Approved this month", "Approved hours", "Overtime record",
            "Payroll runs", "Approved or paid", "Approved net", "Available payslips",
            "Requests", "Active total", "With exact-cent schedules",
            "Campaigns", "Sent messages", "Awaiting send", "Retry available",
            "Active employees", "Active branches", "Actual check-ins", "Approved payroll net",
        )
        for translated in expected_english:
            self.assertIn(translated, i18n)

        metric_literals = set()
        for line in app.splitlines():
            for metric_array in re.findall(r"\[\[(.*?)\]\]\.map\(metricHtml\)", line):
                metric_literals.update(value.strip() for value in re.findall(r"'([^']*)'", metric_array) if re.search(r"[\u0600-\u06ff]", value))
        self.assertGreaterEqual(len(metric_literals), 40)
        missing = sorted(value for value in metric_literals if f"'{value}':" not in i18n)
        self.assertEqual(missing, [], f"Uncatalogued hard-coded KPI literals: {missing}")

    def test_46_v52_bilingual_contract_and_safe_khaisha_identity_migration(self):
        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8")
        app = (root / "app.js").read_text(encoding="utf-8")
        i18n = (root / "i18n.js").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")
        self.assertIn('i18n.js?v=5.7.0', index)
        self.assertIn('styles.css?v=5.7.0', index)
        self.assertIn('app.js?v=5.7.0', index)
        self.assertGreaterEqual(index.count('data-locale="ar"'), 2)
        self.assertGreaterEqual(index.count('data-locale="en"'), 2)
        self.assertIn("khaisha.ui.locale", index + i18n)
        self.assertIn("document.documentElement.dir", i18n)
        self.assertIn("new Intl.DateTimeFormat", i18n)
        self.assertIn("new Intl.NumberFormat", i18n)
        self.assertIn("currency: 'AED'", i18n)
        self.assertIn('html[dir="ltr"] .sidebar', styles)
        self.assertIn("hr:localechange", app + i18n)
        ids = re.findall(r'\bid="([^"]+)"', index)
        self.assertEqual(len(ids), len(set(ids)))

        with tempfile.TemporaryDirectory(prefix="hr-v52-fresh-") as folder:
            fresh = Path(folder) / "fresh.sqlite3"
            hr_server.initialize_database(fresh)
            with contextlib.closing(sqlite3.connect(fresh)) as connection:
                self.assertEqual(connection.execute("SELECT display_name FROM organization WHERE id=1").fetchone()[0], "خيشة - Khaisha")
                self.assertEqual(connection.execute("SELECT legal_name FROM organization WHERE id=1").fetchone()[0], "خيشة - Khaisha")

        with tempfile.TemporaryDirectory(prefix="hr-v52-migration-") as folder:
            legacy = Path(folder) / "legacy.sqlite3"
            hr_server.initialize_database(legacy)
            with contextlib.closing(sqlite3.connect(legacy)) as connection:
                connection.execute("UPDATE organization SET display_name='مجموعة أفق المؤسسية',legal_name='مجموعة أفق المؤسسية ذ.م.م' WHERE id=1")
                connection.commit()
            hr_server.initialize_database(legacy)
            with contextlib.closing(sqlite3.connect(legacy)) as connection:
                self.assertEqual(connection.execute("SELECT display_name,legal_name FROM organization WHERE id=1").fetchone(), ("خيشة - Khaisha", "خيشة - Khaisha"))
                connection.execute("UPDATE organization SET display_name='مؤسسة العميل',legal_name='مؤسسة العميل ذ.م.م' WHERE id=1")
                connection.commit()
            hr_server.initialize_database(legacy)
            with contextlib.closing(sqlite3.connect(legacy)) as connection:
                self.assertEqual(connection.execute("SELECT display_name,legal_name FROM organization WHERE id=1").fetchone(), ("مؤسسة العميل", "مؤسسة العميل ذ.م.م"))
        self.assertIn('data-org-view="hierarchical"', index)
        self.assertIn('data-org-view="grid"', index)
        self.assertIn('data-org-view="sequential"', index)
        self.assertIn("85.6mm", styles)
        self.assertIn("53.98mm", styles)
        for page_id in ("organization", "payroll", "advances", "lifecycle", "reports"):
            self.assertIn(f'id="{page_id}"', index)
        for loader in ("loadOrganizationStructure", "loadPayroll", "loadAdvances", "loadLifecycle", "loadReports"):
            self.assertIn(f"function {loader}", app)

    def test_47_v52_i18n_observer_idempotence_and_dynamic_surface_coverage(self):
        root = Path(__file__).parents[1]
        app = (root / "app.js").read_text(encoding="utf-8")
        i18n = (root / "i18n.js").read_text(encoding="utf-8")

        # Regression for the authenticated-shell starvation bug: writes that
        # can emit childList/attribute mutations must be idempotent, and the
        # observer must never re-run the control updater from its callback.
        self.assertIn("if (node.nodeValue !== next) node.nodeValue = next", i18n)
        self.assertIn("if (role.textContent !== next) role.textContent = next", i18n)
        self.assertIn("if (button.getAttribute('aria-pressed') !== String(selected))", i18n)
        observer_body = i18n.split("const observer = new MutationObserver", 1)[1].split("observer.observe", 1)[0]
        self.assertNotIn("updateControls()", observer_body)
        self.assertIn("{ childList: true, subtree: true }", i18n)
        self.assertNotIn("attributes: true", observer_body)

        required_dynamic_resources = (
            "بطاقة موظف مؤسسية", "الوجه الأمامي للبطاقة", "الوجه الخلفي للبطاقة",
            "بطاقة موظف", "العناية بالبطاقة", "تعليمات مهمة", "طباعة الوجهين",
            "طباعة الأمام", "طباعة الخلف", "الغرض من الشهادة", "إنشاء الشهادة",
            "شهادة راتب", "التحقق من الأصالة", "إدارة الموارد البشرية",
            "طباعة الشهادة", "رفع وثيقة إلى ملف الموظف", "بيانات الوثيقة",
            "تنزيل الملف", "تعديل بيانات الوثيقة", "حفظ التعديلات",
        )
        for source in required_dynamic_resources:
            self.assertRegex(i18n, rf"['\"]{re.escape(source)}['\"]\s*:")

        # Dynamic and print renderers use the locale helper while building
        # markup; this also covers text containing dates, codes, and salaries
        # that cannot be translated reliably by exact DOM text replacement.
        for marker in (
            "tr('صالحة حتى {date}'", "tr('الصلاحية {date}'",
            "tr('رقم الإصدار: {number}'", "tr('السادة/ {purpose} المحترمون،'",
            "tr('تشهد {organization}", "tr('طباعة الشهادة')",
            "tr('رفع وثيقة إلى ملف الموظف')", "tr('بيانات الوثيقة')",
            "tr('تنزيل الملف')", "tr('حفظ التعديلات')",
        ):
            self.assertIn(marker, app)
        self.assertNotIn("'<button class=\"text-btn\" data-card-settings>${tr(", app)

    def test_48_v52_performance_i18n_accessibility_and_role_aware_initial_route(self):
        root = Path(__file__).parents[1]
        app = (root / "app.js").read_text(encoding="utf-8")
        i18n = (root / "i18n.js").read_text(encoding="utf-8")

        # A stale admin hash must be validated against the newly authenticated
        # user's effective pages before the first page is displayed.
        self.assertIn("requestedAllowed=Boolean(requested&&pageLabels[requested]&&mayOpenPage(requested)", app)
        self.assertIn("initial=requestedAllowed?requested:fallback", app)
        self.assertIn("fallback=hasPermission('dashboard.view')?'dashboard':user.employee_id?'my-space':'access-denied'", app)
        self.assertIn("if(requested&&!requestedAllowed)history.replaceState", app)
        index = (root / "index.html").read_text(encoding="utf-8")
        for asset in ("styles.css", "i18n.js", "app.js"):
            self.assertIn(f'{asset}?v=5.7.0', index)

        required_performance_resources = (
            "الفترة من", "متبقٍ {days} يوم", "مسودة الموظف", "أهداف الموظف",
            "تقييم المسؤول", "مراجعة HR", "الإفصاح", "دفتر أهدافي ونتائجي",
            "مكتبة الأهداف المعتمدة", "اختر الأهداف قبل الإرسال. يحدد المسؤول النقاط في المرحلة التالية.",
            "إضافة المتبقية", "+ اختيار", "إرسال الأهداف", "النقاط والتقرير",
            "المراجعة النهائية", "يحدده HR", "إنجاز الموظف", "الدليل / النتيجة",
            "نقاط المسؤول", "إرسال النقاط والتقرير للموارد البشرية", "اعتماد وتحديد الإفصاح",
            "فترة الأداء", "التقييم الذاتي", "موعد المسؤول", "قرار HR",
            "تعذر تحميل سجل التقييم.", "لا توجد دورة معلنة ومسندة إلى حسابك حالياً.",
        )
        for source in required_performance_resources:
            self.assertRegex(i18n, rf"['\"]{re.escape(source)}['\"]\s*:")

        for marker in (
            "tr('متبقٍ {days} يوم'", "tr('أهداف الموظف')", "tr('الفترة من')",
            "tr('مكتبة الأهداف المعتمدة')", "tr('إضافة المتبقية')", "tr('+ اختيار')",
            "tr('إنجاز الموظف')", "tr('إرسال الأهداف')", "tr('المراجعة النهائية')",
            "tr('دفتر أهدافي ونتائجي')", "tr('ملف تقييم {name}'",
        ):
            self.assertIn(marker, app)

        # Exact smaller leaks from employee, dossier and certificate surfaces.
        self.assertIn("e.shift_name||tr('من وحدة المناوبات')", app)
        self.assertRegex(i18n, r"['\"]أقسام ملف الموظف['\"]\s*:")
        self.assertIn("tr('الدرجة الوظيفية')", app)
        self.assertIn("tr('باركود رقم التحقق {code}'", app)
        self.assertRegex(i18n, r"['\"]المسؤول['\"]\s*:\s*['\"]Manager['\"]")
        self.assertRegex(i18n, r"['\"]المسؤول المباشر['\"]\s*:\s*['\"]Line manager['\"]")

    def test_41_v511_form_submit_router_avoids_named_property_shadowing(self):
        root = Path(__file__).parents[1]
        app = (root / "app.js").read_text(encoding="utf-8")
        index = (root / "index.html").read_text(encoding="utf-8")

        # HTML form controls named id/action/name can shadow native HTMLFormElement
        # properties. Routing must therefore use the literal id attribute, and
        # reserved field names must be renamed or read through form.elements.
        self.assertIn("form.getAttribute('id')", app)
        self.assertIn("form?.elements?.namedItem(name)", app)
        self.assertNotRegex(app, r'name=["\'](?:id|action)["\']')
        self.assertNotRegex(app, r"\b(?:form|f)\.id\b")
        self.assertNotRegex(app, r"\b(?:form|f)\.name\.value\b")
        self.assertNotIn("form.action.value", app)

        for field_name in (
            "document_id", "branch_id", "goal_id", "cycle_id",
            "department_id", "resolution_action",
        ):
            self.assertIn(f'name="{field_name}"', app)

        # Deterministic dispatch contracts for create/edit cycle and goal flows.
        self.assertIn("if(route==='evaluationCycleForm')saveEvaluationCycle(f)", app)
        self.assertIn("if(route==='goalForm')saveGoal(f)", app)
        self.assertRegex(
            app,
            r"api\(id\?`/api/evaluation-cycles/\$\{id\}`:'/api/evaluation-cycles',"
            r"\{method:id\?'PATCH':'POST',body\}\)",
        )
        self.assertRegex(
            app,
            r"api\(id\?`/api/evaluation-goals/\$\{id\}`:"
            r"`/api/evaluations/\$\{state\.evaluation\.id\}/goals`,"
            r"\{method:id\?'PATCH':'POST',body\}\)",
        )

        # Employee submission remains a direct, explicit POST action.
        self.assertIn("$('#submitEvaluation').addEventListener('click',submitEvaluation)", app)
        self.assertRegex(
            app,
            r"api\(`/api/evaluations/\$\{state\.evaluation\.id\}/submit`,"
            r"\{method:'POST'\}\)",
        )
        self.assertIn('styles.css?v=5.7.0', index)
        self.assertIn('app.js?v=5.7.0', index)

    def test_42_v512_dossier_observer_and_mobile_weight_badge_contract(self):
        root = Path(__file__).parents[1]
        app = (root / "app.js").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")
        index = (root / "index.html").read_text(encoding="utf-8")

        self.assertIn("const modalBody=$('#modalBody')", app)
        self.assertIn("$('.employee-dossier',modalBody)", app)
        self.assertNotIn("$('.employee-dossier','#modalBody')", app)
        self.assertNotRegex(
            app,
            r"\$\$?\(\s*(?:'[^'\n]*'|\"[^\"\n]*\"|`[^`\n]*`)\s*,"
            r"\s*(?:'[^'\n]*'|\"[^\"\n]*\")\s*\)",
        )
        self.assertIn('data-profile-tab="evaluations-history"', app)
        self.assertIn('id="dossierEvaluationHistory"', app)

        weight_rule = re.search(r"\.weight-badge\{([^}]*)\}", styles)
        self.assertIsNotNone(weight_rule)
        self.assertIn("white-space:nowrap", weight_rule.group(1))
        self.assertIn("flex:0 0 auto", weight_rule.group(1))
        self.assertIn("min-width:max-content", weight_rule.group(1))
        self.assertIn("@media(max-width:440px)", styles)
        self.assertIn('styles.css?v=5.7.0', index)
        self.assertIn('app.js?v=5.7.0', index)

    def test_keep_alive_connection_refreshes_authentication_each_request(self):
        """Anonymous -> login -> authenticated -> logout must work on one TCP connection."""
        connection = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=10)
        try:
            connection.request("GET", "/api/auth/me", headers={"Accept": "application/json"})
            anonymous = connection.getresponse()
            self.assertEqual(anonymous.status, 401)
            anonymous.read()

            body = json.dumps({"email": "employee@demo.ae", "password": "Emp@12345"}).encode("utf-8")
            connection.request(
                "POST", "/api/auth/login", body=body,
                headers={"Accept": "application/json", "Content-Type": "application/json", "Content-Length": str(len(body))},
            )
            login = connection.getresponse()
            self.assertEqual(login.status, 200)
            cookie = login.getheader("Set-Cookie").split(";", 1)[0]
            login_payload = json.loads(login.read())
            csrf_token = login_payload["csrf_token"]

            connection.request("GET", "/api/auth/me", headers={"Accept": "application/json", "Cookie": cookie})
            authenticated = connection.getresponse()
            self.assertEqual(authenticated.status, 200)
            self.assertEqual(json.loads(authenticated.read())["user"]["role"], "employee")

            connection.request(
                "POST", "/api/auth/logout",
                headers={"Accept": "application/json", "Cookie": cookie, "X-CSRF-Token": csrf_token},
            )
            logout = connection.getresponse()
            self.assertEqual(logout.status, 200)
            logout.read()

            connection.request("GET", "/api/auth/me", headers={"Accept": "application/json", "Cookie": cookie})
            after_logout = connection.getresponse()
            self.assertEqual(after_logout.status, 401)
            after_logout.read()
        finally:
            connection.close()

    def test_02_branch_geofence_shift_and_restart_persistence(self):
        admin = self.client("admin@demo.ae", "Admin@123")
        employee = self.client("employee@demo.ae", "Emp@12345")
        employee_id = employee.request("GET", "/api/auth/me")["user"]["employee_id"]
        suffix = uuid.uuid4().hex[:7]
        branch = admin.request(
            "POST", "/api/branches",
            {
                "name": f"فرع الاختبار {suffix}", "address": "دبي",
                "latitude": 25.204849, "longitude": 55.270783, "radius_m": 120, "active": True,
            }, expected=201,
        )["branch"]
        admin.request("POST", f"/api/branches/{branch['id']}/assign", {"employee_id": employee_id})

        outside = employee.request(
            "POST", "/api/attendance/punch",
            {"action": "check_in", "latitude": 25.304849, "longitude": 55.370783, "accuracy": 8},
            expected=403,
        )
        self.assertEqual(outside["code"], "outside_geofence")
        self.assertGreater(outside["details"]["distance_m"], branch["radius_m"])
        inside = employee.request(
            "POST", "/api/attendance/punch",
            {"action": "check_in", "latitude": branch["latitude"], "longitude": branch["longitude"], "accuracy": 5},
            expected=200,
        )
        self.assertLessEqual(inside["distance_m"], 1)

        shift = admin.request(
            "POST", "/api/shifts",
            {
                "name": f"مناوبة ليلية {suffix}", "start_time": "20:00", "end_time": "04:00",
                "break_minutes": 30, "working_days": [0, 1, 2, 3, 4, 5], "rest_days": [6],
                "grace_minutes": 5, "daily_limit_minutes": 450, "active": True,
            }, expected=201,
        )["shift"]
        assignment = admin.request(
            "POST", f"/api/shifts/{shift['id']}/assign",
            {"employee_id": employee_id, "effective_from": date.today().isoformat()}, expected=201,
        )["assignment"]
        self.assertEqual(assignment["employee_id"], employee_id)

        self._restart_server()
        admin = self.client("admin@demo.ae", "Admin@123")
        branches = admin.request("GET", "/api/branches")["items"]
        shifts = admin.request("GET", "/api/shifts")
        self.assertTrue(any(row["id"] == branch["id"] for row in branches))
        self.assertTrue(any(row["id"] == assignment["id"] for row in shifts["assignments"]))

    def test_03_employee_self_service_overtime_leave_and_certificate(self):
        employee = self.client("employee@demo.ae", "Emp@12345")
        hr = self.client("hr@demo.ae", "HR@12345")
        employee_id = employee.request("GET", "/api/auth/me")["user"]["employee_id"]
        dashboard = employee.request("GET", "/api/me/dashboard")
        self.assertEqual(dashboard["employee"]["id"], employee_id)
        self.assertGreater(dashboard["employee"]["salary"], 0)
        self.assertTrue(dashboard["leave_balances"])
        employee.request("GET", f"/api/employees/{employee_id}")

        overtime = employee.request(
            "POST", "/api/overtime",
            {"work_date": (date.today() + timedelta(days=2)).isoformat(), "start_time": "18:00", "end_time": "20:00", "reason": "إغلاق شهري"},
            expected=201,
        )["request"]
        manager = self.client("manager@demo.ae", "Manager@12345")
        manager.request("POST", f"/api/overtime/{overtime['id']}/decision", {"action": "approve"}, expected=403)
        approved = hr.request("POST", f"/api/overtime/{overtime['id']}/decision", {"action": "approve"})["request"]
        self.assertEqual(approved["status"], "approved")

        annual_type = next(x for x in employee.request("GET", "/api/leaves/types")["items"] if x["code"] == "annual")
        start = date.today() + timedelta(days=20)
        end = start + timedelta(days=1)
        leave = employee.request(
            "POST", "/api/leaves/requests",
            {"leave_type_id": annual_type["id"], "start_date": start.isoformat(), "end_date": end.isoformat(), "reason": "إجازة عائلية"},
            expected=201,
        )["request"]
        manager_step = manager.request("POST", f"/api/leaves/requests/{leave['id']}/decision", {"action": "approve"})["request"]
        self.assertEqual(manager_step["status"], "submitted")
        self.assertEqual(manager_step["workflow_stage"], "pending_hr")
        approved_leave = hr.request("POST", f"/api/leaves/requests/{leave['id']}/decision", {"action": "approve"})["request"]
        self.assertEqual(approved_leave["status"], "approved")

        tiny_png = "data:image/png;base64,iVBORw0KGgo="
        updated_org = hr.request(
            "PATCH", "/api/org",
            {"display_name": "مؤسسة الاختبار", "logo_data": tiny_png, "stamp_data": tiny_png},
        )["organization"]
        certificate = hr.request(
            "POST", "/api/salary-certificates", {"employee_id": employee_id, "purpose": "إلى من يهمه الأمر"}, expected=201,
        )["certificate"]
        self.assertEqual(certificate["organization"]["display_name"], updated_org["display_name"])
        self.assertEqual(certificate["organization"]["stamp_data"], tiny_png)
        employee.request("POST", f"/api/salary-certificates/{certificate['id']}/print", {}, expected=403)
        printed = hr.request("POST", f"/api/salary-certificates/{certificate['id']}/print", {})
        self.assertEqual(printed["certificate"]["print_count"], 1)

    def test_04_evaluation_weight_and_sequential_approval(self):
        employee = self.client("employee@demo.ae", "Emp@12345")
        current_year = date.today().year
        evaluation_payload = employee.request("POST", "/api/evaluations", {"year": current_year})
        evaluation_id = evaluation_payload["evaluation"]["id"]
        first = employee.request(
            "POST", f"/api/evaluations/{evaluation_id}/goals",
            {"title": "رفع جودة العمليات", "description": "تقليل الأخطاء", "weight": 90, "measure": "نسبة الدقة", "achievement": 95, "employee_comment": "تحسن مستمر", "goal_type": "result", "start_date": f"{current_year}-01-01", "end_date": f"{current_year}-12-31", "progress_status": "in_progress", "evidence_note": "انخفضت الأخطاء وفق تقرير الجودة."},
            expected=201,
        )
        self.assertEqual(first["weight_total"], 90)
        rejected = employee.request("POST", f"/api/evaluations/{evaluation_id}/submit", {}, expected=422)
        self.assertEqual(rejected["code"], "invalid_weight_total")
        over_weight = employee.request(
            "POST", f"/api/evaluations/{evaluation_id}/goals",
            {"title": "وزن زائد", "description": "يجب رفضه", "weight": 20, "measure": "التحقق", "achievement": 80, "employee_comment": "", "goal_type": "result", "start_date": f"{current_year}-01-01", "end_date": f"{current_year}-12-31", "progress_status": "in_progress", "evidence_note": "دليل تجريبي."},
            expected=422,
        )
        self.assertEqual(over_weight["code"], "invalid_weight_total")
        employee.request(
            "POST", f"/api/evaluations/{evaluation_id}/goals",
            {"title": "التطوير المهني", "description": "إتمام تدريب", "weight": 10, "measure": "الإكمال", "achievement": 80, "employee_comment": "تم", "goal_type": "development", "start_date": f"{current_year}-01-01", "end_date": f"{current_year}-12-31", "progress_status": "in_progress", "evidence_note": "شهادة إتمام التدريب محفوظة."},
            expected=201,
        )
        submitted = employee.request("POST", f"/api/evaluations/{evaluation_id}/submit", {})
        self.assertEqual(submitted["evaluation"]["status"], "submitted")
        self.assertEqual(submitted["weight_total"], 100)
        hidden = employee.request("GET", f"/api/evaluations/{evaluation_id}")
        self.assertIsNone(hidden["evaluation"]["weighted_score"])
        self.assertNotIn("awarded_points", hidden["goals"][0])
        manager = self.client("manager@demo.ae", "Manager@12345")
        step_one = manager.request(
            "POST", f"/api/evaluations/{evaluation_id}/manager-review",
            {"manager_report": "أداء متفوق مدعوم بمؤشرات الجودة والتطوير.", "goals": [
                {"id": submitted["goals"][0]["id"], "awarded_points": 85},
                {"id": submitted["goals"][1]["id"], "awarded_points": 8},
            ]},
        )
        self.assertEqual(step_one["evaluation"]["status"], "in_review")
        gm = self.client("gm@demo.ae", "GM@12345")
        gm.request("GET", f"/api/evaluations/{evaluation_id}", expected=403)
        hr = self.client("hr@demo.ae", "HR@12345")
        final = hr.request(
            "POST", f"/api/evaluations/{evaluation_id}/hr-review",
            {"action": "approve", "comment": "اكتملت المراجعة", "disclosure_date": date.today().isoformat()},
        )
        self.assertEqual(final["evaluation"]["status"], "approved")
        self.assertEqual(final["evaluation"]["rating"], "ممتاز")
        published = employee.request("GET", f"/api/evaluations/{evaluation_id}")
        self.assertTrue(published["evaluation"]["published"])
        self.assertEqual(published["evaluation"]["weighted_score"], 93)
        self.assertEqual(published["evaluation"]["manager_report"], "أداء متفوق مدعوم بمؤشرات الجودة والتطوير.")
        grievance = employee.request(
            "POST", f"/api/evaluations/{evaluation_id}/grievance",
            {"reason": "مراجعة مؤشر الجودة", "note": "أطلب إعادة التحقق من نقاط الهدف الأول."}, expected=201,
        )
        self.assertEqual(grievance["grievance"]["status"], "submitted")
        employee.request(
            "POST", f"/api/evaluations/{evaluation_id}/grievance",
            {"reason": "طلب ثان", "note": "يجب ألا يقبل."}, expected=409,
        )
        resolved = hr.request(
            "POST", f"/api/evaluation-grievances/{grievance['grievance']['id']}/resolve",
            {"action": "amend", "resolution_note": "عُدلت النقاط بعد مراجعة الأدلة.", "goals": [
                {"id": submitted["goals"][0]["id"], "awarded_points": 88},
                {"id": submitted["goals"][1]["id"], "awarded_points": 9},
            ]},
        )
        self.assertEqual(resolved["evaluation"]["weighted_score"], 97)
        self.assertEqual(resolved["grievance"]["status"], "amended")
        with contextlib.closing(sqlite3.connect(self.db_path)) as audit_db:
            actions = {row[0] for row in audit_db.execute(
                "SELECT action FROM audit_log WHERE entity_type IN ('evaluation','evaluation_grievance')"
            )}
        self.assertTrue({"evaluation.employee_submit", "evaluation.manager_submit", "evaluation.hr_approve", "evaluation.grievance_submit", "evaluation.grievance_amend"}.issubset(actions))

    def test_05_notification_audience_and_read_state(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        employee = self.client("employee@demo.ae", "Emp@12345")
        gm = self.client("gm@demo.ae", "GM@12345")
        ops = next(x for x in hr.request("GET", "/api/departments")["items"] if x["name"] == "العمليات")
        sent = hr.request(
            "POST", "/api/notifications",
            {"title": "تعليمات العمليات", "body": "يرجى مراجعة التعليمات الجديدة.", "message_type": "law", "audience_type": "department", "audience_ref": ops["id"]},
            expected=201,
        )["notification"]
        employee_inbox = employee.request("GET", "/api/notifications/inbox")
        gm_inbox = gm.request("GET", "/api/notifications/inbox")
        self.assertTrue(any(x["id"] == sent["id"] for x in employee_inbox["items"]))
        self.assertFalse(any(x["id"] == sent["id"] for x in gm_inbox["items"]))
        employee.request("POST", f"/api/notifications/{sent['id']}/read", {})
        self.assertEqual(
            employee.request("GET", "/api/notifications/unread-count")["unread_count"],
            max(0, employee_inbox["unread_count"] - 1),
        )

    def test_06_hr_document_expiry_notifications_are_deduplicated(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        employee = hr.request(
            "POST", "/api/employees",
            {"employee_no": "EMP-EXP-90", "full_name": "موظف تنبيهات الوثائق", "email": "expiry-alerts@demo.ae", "job_title": "أخصائي عمليات", "job_grade": "G-07", "salary": 12000},
            expected=201,
        )["employee"]
        tiny_png = "data:image/png;base64,iVBORw0KGgo="
        today = date.today()
        hr.request(
            "POST", f"/api/employees/{employee['id']}/documents",
            {"document_type": "contract", "title": "عقد قريب الانتهاء", "file_name": "contract.png", "data_url": tiny_png, "issued_on": (today - timedelta(days=300)).isoformat(), "expires_on": (today + timedelta(days=89)).isoformat()},
            expected=201,
        )
        hr.request(
            "POST", f"/api/employees/{employee['id']}/documents",
            {"document_type": "passport", "title": "جواز قريب الانتهاء", "file_name": "passport.png", "data_url": tiny_png, "expires_on": (today + timedelta(days=30)).isoformat()},
            expected=201,
        )
        first = hr.request("GET", "/api/notifications/inbox")["items"]
        expiry_alerts = [row for row in first if row["title"].startswith("تنبيه:") and "موظف تنبيهات الوثائق" in row["body"]]
        self.assertEqual(len(expiry_alerts), 2)
        self.assertTrue(any("عقد العمل" in row["title"] and "89" in row["body"] for row in expiry_alerts))
        self.assertTrue(any("جواز السفر" in row["body"] and "30" in row["body"] for row in expiry_alerts))
        second = hr.request("GET", "/api/notifications/inbox")["items"]
        self.assertEqual(len([row for row in second if row["title"].startswith("تنبيه:") and "موظف تنبيهات الوثائق" in row["body"]]), 2)
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM document_expiry_alerts").fetchone()[0], 2)

    def test_07_department_hierarchy_assignment_and_delete_guard(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        employee = next(x for x in hr.request("GET", "/api/employees")["items"] if x["employee_no"] == "EMP-1024")
        branch = hr.request("GET", "/api/branches")["items"][0]
        created = hr.request("POST", "/api/departments", {"name": "قسم الجودة", "branch_id": branch["id"], "active": True}, expected=201)["department"]
        assigned = hr.request("POST", f"/api/departments/{created['id']}/assign", {"employee_id": employee["id"]})["employee"]
        self.assertEqual(assigned["department_id"], created["id"])
        hierarchy = hr.request("GET", "/api/org/hierarchy")
        linked = next(x for x in hierarchy["employees"] if x["id"] == employee["id"])
        self.assertEqual(linked["department_name"], "قسم الجودة")
        refused = hr.request("DELETE", f"/api/departments/{created['id']}", expected=409)
        self.assertEqual(refused["code"], "department_has_employees")

    def test_07_employee_documents_and_violation_counter(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        employee_id = next(x["id"] for x in hr.request("GET", "/api/employees")["items"] if x["employee_no"] == "EMP-1024")
        tiny_png = "data:image/png;base64,iVBORw0KGgo="
        for document_type, title in (("identity", "الهوية الإماراتية"), ("qualification", "المؤهل العلمي")):
            hr.request("POST", f"/api/employees/{employee_id}/documents", {"document_type": document_type, "title": title, "file_name": title + ".png", "data_url": tiny_png, "visible_to_employee": True}, expected=201)
        action = hr.request("POST", f"/api/employees/{employee_id}/actions", {"action_type": "violation", "action_date": date.today().isoformat(), "description": "مخالفة اختبار", "penalty": "تنبيه", "attachment_data": tiny_png}, expected=201)["action"]
        profile = hr.request("GET", f"/api/employees/{employee_id}")["employee"]
        self.assertEqual(profile["violation_count"], 1)
        self.assertGreaterEqual(profile["document_count"], 2)
        hr.request("PATCH", f"/api/employee-actions/{action['id']}", {"status": "closed"})
        own = self.client("employee@demo.ae", "Emp@12345")
        self.assertEqual(len(own.request("GET", f"/api/employees/{employee_id}/documents")["items"]), 2)

    def test_08_payroll_approval_employee_payslip_and_csv(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        month = f"{date.today().year}-{date.today().month:02d}"
        run = hr.request("POST", "/api/payroll/runs", {"payroll_month": month, "allowances": 100, "deductions": 25}, expected=201)["run"]
        self.assertGreater(run["net"], 0)
        run = hr.request("POST", f"/api/payroll/runs/{run['id']}/transition", {"status": "review"})["run"]
        run = hr.request("POST", f"/api/payroll/runs/{run['id']}/transition", {"status": "approved"})["run"]
        self.assertEqual(run["status"], "approved")
        employee = self.client("employee@demo.ae", "Emp@12345")
        slips = employee.request("GET", "/api/me/payslips")["items"]
        self.assertTrue(any(x["run_id"] == run["id"] and x["net"] > 0 for x in slips))
        headers, body = hr.raw_request(f"/api/payroll/runs/{run['id']}/export.csv")
        self.assertIn("text/csv", headers["Content-Type"])
        self.assertIn("الصافي", body.decode("utf-8-sig"))

    def test_09_advance_exact_cent_schedule_and_permission(self):
        employee = self.client("employee@demo.ae", "Emp@12345")
        advance = employee.request("POST", "/api/advances", {"amount": 1000, "months": 3, "reason": "احتياج شخصي"}, expected=201)["advance"]
        self.assertEqual([x["amount"] for x in advance["installments"]], [333.33, 333.33, 333.34])
        employee.request("POST", f"/api/advances/{advance['id']}/decision", {"action": "approve"}, expected=403)
        hr = self.client("hr@demo.ae", "HR@12345")
        approved = hr.request("POST", f"/api/advances/{advance['id']}/decision", {"action": "approve"})["advance"]
        self.assertEqual(approved["status"], "approved")

    def test_10_job_grade_title_propagate_card_and_certificate(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        employee_id = next(x["id"] for x in hr.request("GET", "/api/employees")["items"] if x["employee_no"] == "EMP-1024")
        suffix = uuid.uuid4().hex[:6]
        grade = hr.request("POST", "/api/job-grades", {"code": f"GX-{suffix}", "name": "درجة تخصصية", "min_salary": 9000, "max_salary": 18000}, expected=201)["job_grade"]
        title = hr.request("POST", "/api/job-titles", {"name": f"خبير جودة {suffix}"}, expected=201)["job_title"]
        updated = hr.request("PATCH", f"/api/employees/{employee_id}", {"job_grade_id": grade["id"], "job_title_id": title["id"]})["employee"]
        card = hr.request("GET", f"/api/employees/{employee_id}/card")["card"]["employee"]
        certificate = hr.request("POST", "/api/salary-certificates", {"employee_id": employee_id, "purpose": "اختبار التوافق"}, expected=201)["certificate"]["employee"]
        self.assertEqual(updated["job_title"], title["name"])
        self.assertEqual(card["job_title"], title["name"])
        self.assertEqual(certificate["job_title"], title["name"])
        self.assertEqual(card["job_grade"], grade["code"])

    def test_11_lifecycle_crud_close_and_restart_persistence(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        created_ids = []
        for module in ("recruitment", "onboarding", "learning", "offboarding"):
            case = hr.request("POST", "/api/lifecycle/cases", {"module": module, "title": f"حالة {module}", "candidate_name": "مرشح اختبار", "notes": "بيانات حقيقية"}, expected=201)["case"]
            closed = hr.request("PATCH", f"/api/lifecycle/cases/{case['id']}", {"status": "closed"})["case"]
            self.assertEqual(closed["status"], "closed")
            created_ids.append(case["id"])
        self._restart_server()
        hr = self.client("hr@demo.ae", "HR@12345")
        persisted = hr.request("GET", "/api/lifecycle/cases")["items"]
        self.assertTrue(set(created_ids).issubset({x["id"] for x in persisted}))

    def test_12_live_report_and_csv_reflect_database(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        summary = hr.request("GET", "/api/reports/summary")["summary"]
        self.assertEqual(summary["employees"], len([x for x in hr.request("GET", "/api/employees")["items"] if x["active"]]))
        self.assertEqual(summary["branches"], len([x for x in hr.request("GET", "/api/branches")["items"] if x["active"]]))
        self.assertGreaterEqual(summary["payroll_runs"], 1)
        headers, body = hr.raw_request("/api/reports/summary.csv")
        text = body.decode("utf-8-sig")
        self.assertIn("الموظفون النشطون", text)
        self.assertIn(str(summary["employees"]), text)

    def test_13_v44_employee_dossier_documents_filters_safety_and_visibility(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        branch = hr.request("GET", "/api/branches")["items"][0]
        department = hr.request("GET", "/api/departments")["items"][0]
        grade = hr.request("GET", "/api/job-grades")["items"][0]
        title = hr.request("GET", "/api/job-titles")["items"][0]
        employee = hr.request(
            "POST", "/api/employees",
            {
                "employee_no": "EMP-V44", "full_name": "موظف ملف V4.4",
                "email": "employee-v44@demo.ae", "phone": "+971500000044",
                "nationality": "الإمارات العربية المتحدة", "qualification": "بكالوريوس إدارة أعمال",
                "job_title_id": title["id"], "job_grade_id": grade["id"],
                "department_id": department["id"], "branch_id": branch["id"],
                "hire_date": "2022-06-15", "salary": 14750,
                "create_user": True, "password": "Employee@V44", "role": "employee",
            }, expected=201,
        )["employee"]
        self.assertEqual(employee["qualification"], "بكالوريوس إدارة أعمال")
        self.assertEqual(employee["nationality"], "الإمارات العربية المتحدة")
        self.assertGreater(employee["service_days"], 0)

        tiny_png = "data:image/png;base64,iVBORw0KGgo="
        def upload(document_type, title_text, expires_on=None, no_expiry=False, visible=True):
            return hr.request(
                "POST", f"/api/employees/{employee['id']}/documents",
                {
                    "document_type": document_type, "title": title_text,
                    "document_number": f"DOC-{document_type}", "issuer": "الهيئة المختصة",
                    "issued_on": "2024-01-01", "expires_on": expires_on,
                    "no_expiry": no_expiry, "file_name": f"{document_type}.png",
                    "data_url": tiny_png, "notes": "مستند اختبار", "visible_to_employee": visible,
                }, expected=201,
            )["document"]

        valid = upload("passport", "جواز السفر", (date.today() + timedelta(days=150)).isoformat())
        residency = upload("residency", "الإقامة", (date.today() + timedelta(days=45)).isoformat())
        expired = upload("work_permit", "تصريح العمل", (date.today() - timedelta(days=1)).isoformat())
        permanent = upload("identity", "الهوية", no_expiry=True)
        hidden = upload("bank_document", "المستند البنكي", no_expiry=True, visible=False)
        self.assertEqual(valid["status"], "valid")
        self.assertEqual(residency["status"], "expiring_soon")
        self.assertEqual(residency["alert_window"], 60)
        self.assertEqual(expired["status"], "expired")
        self.assertEqual(permanent["status"], "no_expiry")

        filtered = hr.request("GET", f"/api/employees/{employee['id']}/documents?status=expiring_soon&type=residency")
        self.assertEqual([row["id"] for row in filtered["items"]], [residency["id"]])
        self.assertEqual(filtered["alerts"][0]["days_remaining"], 45)
        fetched = hr.request("GET", f"/api/documents/{valid['id']}")["document"]
        self.assertEqual(fetched["data_url"], tiny_png)

        worker = self.client("employee-v44@demo.ae", "Employee@V44")
        own_documents = worker.request("GET", f"/api/employees/{employee['id']}/documents")["items"]
        self.assertNotIn(hidden["id"], {row["id"] for row in own_documents})
        worker.request("GET", f"/api/documents/{hidden['id']}", expected=403)
        other = self.client("employee@demo.ae", "Emp@12345")
        other.request("GET", f"/api/documents/{valid['id']}", expected=403)

        bad_mime = "data:application/x-msdownload;base64,AAAA"
        hr.request(
            "POST", f"/api/employees/{employee['id']}/documents",
            {"document_type": "other", "title": "ملف خطر", "file_name": "bad.exe", "data_url": bad_mime},
            expected=422,
        )
        hr.request(
            "POST", f"/api/employees/{employee['id']}/documents",
            {"document_type": "other", "title": "امتداد مضلل", "file_name": "image.exe", "data_url": tiny_png},
            expected=422,
        )
        hr.request(
            "POST", f"/api/employees/{employee['id']}/documents",
            {"document_type": "other", "title": "ملف كبير", "file_name": "big.png", "data_url": "data:image/png;base64," + "A" * 2_700_000},
            expected=413,
        )
        archived = hr.request("PATCH", f"/api/documents/{valid['id']}", {"archived": True})["document"]
        self.assertEqual(archived["status"], "archived")
        archive_filter = hr.request("GET", f"/api/employees/{employee['id']}/documents?archived=1")
        self.assertIn(valid["id"], {row["id"] for row in archive_filter["items"]})
        audit_db = sqlite3.connect(self.db_path)
        audit_actions = {row[0] for row in audit_db.execute("SELECT action FROM audit_log WHERE entity_type='employee_document'")}
        audit_db.close()
        self.assertTrue({"employee_document.upload", "employee_document.view", "employee_document.update"}.issubset(audit_actions))

    def test_14_v50_card_contract_print_guards_and_offboarding_closure(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        employee = next(row for row in hr.request("GET", "/api/employees")["items"] if row["employee_no"] == "EMP-V44")
        contract = hr.request(
            "POST", f"/api/employees/{employee['id']}/documents",
            {"document_type": "contract", "title": "عقد العمل المعتمد", "file_name": "contract.png",
             "data_url": "data:image/png;base64,iVBORw0KGgo=", "issued_on": (date.today() - timedelta(days=10)).isoformat(), "expires_on": (date.today() + timedelta(days=120)).isoformat()},
            expected=201,
        )["document"]
        card = hr.request("GET", f"/api/employees/{employee['id']}/card")["card"]
        self.assertEqual(card["status"], "active")
        self.assertEqual(card["valid_until"], contract["expires_on"])
        self.assertEqual(card["contract_document_id"], contract["id"])
        self.assertNotIn("residency_document_id", card)
        self.assertTrue(card["can_print"])
        self.assertTrue(card["employee"]["job_grade"])
        self.assertTrue(card["employee"]["department_name"])
        self.assertTrue(card["organization"]["display_name"])
        self.assertTrue(hr.request("POST", f"/api/employees/{employee['id']}/card/print", {})["print_authorized"])

        hr.request("PATCH", f"/api/documents/{contract['id']}", {"expires_on": (date.today() - timedelta(days=1)).isoformat()})
        expired_card = hr.request("GET", f"/api/employees/{employee['id']}/card")["card"]
        self.assertEqual(expired_card["status"], "expired")
        hr.request("POST", f"/api/employees/{employee['id']}/card/print", {}, expected=409)
        hr.request("PATCH", f"/api/documents/{contract['id']}", {"expires_on": (date.today() + timedelta(days=120)).isoformat()})
        case = hr.request(
            "POST", "/api/lifecycle/cases",
            {"module": "offboarding", "title": "إنهاء خدمة V4.4", "employee_id": employee["id"], "notes": "اختبار إغلاق البطاقة"},
            expected=201,
        )["case"]
        hr.request("PATCH", f"/api/lifecycle/cases/{case['id']}", {"status": "closed"})
        closed = hr.request("GET", f"/api/employees/{employee['id']}/card")["card"]
        self.assertEqual(closed["status"], "closed")
        self.assertFalse(closed["can_print"])
        hr.request("POST", f"/api/employees/{employee['id']}/card/print", {}, expected=409)

    def test_profile_contract_dates_create_and_update_card_window(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        suffix = uuid.uuid4().hex[:8]
        start = date.today() - timedelta(days=5)
        end = date.today() + timedelta(days=365)
        employee = hr.request(
            "POST", "/api/employees",
            {"employee_no": f"EMP-CON-{suffix}", "full_name": "موظف عقد", "email": f"contract-{suffix}@demo.ae",
             "job_title": "أخصائي عمليات", "job_grade": "G-07", "salary": 12000,
             "contract_start_on": start.isoformat(), "contract_end_on": end.isoformat()}, expected=201,
        )["employee"]
        self.assertEqual(employee["contract_start_on"], start.isoformat())
        self.assertEqual(employee["contract_end_on"], end.isoformat())
        card = hr.request("GET", f"/api/employees/{employee['id']}/card")["card"]
        self.assertTrue(card["can_print"])
        self.assertEqual(card["valid_from"], start.isoformat())
        self.assertEqual(card["valid_until"], end.isoformat())
        documents = hr.request("GET", f"/api/employees/{employee['id']}/documents")["items"]
        contract = next(row for row in documents if row["document_type"] == "contract")
        self.assertEqual(contract["expires_on"], end.isoformat())
        self.assertEqual(contract["mime_type"], "application/pdf")
        self.assertTrue(contract["file_name"].endswith(".pdf"))
        contract_detail = hr.request("GET", f"/api/documents/{contract['id']}")["document"]
        self.assertTrue(contract_detail["data_url"].startswith("data:application/pdf;base64,"))
        revised_end = date.today() + timedelta(days=730)
        updated = hr.request("PATCH", f"/api/employees/{employee['id']}", {"contract_end_on": revised_end.isoformat()})["employee"]
        self.assertEqual(updated["contract_end_on"], revised_end.isoformat())
        self.assertEqual(hr.request("GET", f"/api/employees/{employee['id']}/card")["card"]["valid_until"], revised_end.isoformat())

    def test_16_v58_contract_window_and_employee_custody_records(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        employee = hr.request(
            "POST", "/api/employees",
            {"employee_no": "EMP-V58", "full_name": "موظف عهدة واختبار", "email": "custody-v58@demo.ae",
             "job_title": "أخصائي عمليات", "job_grade": "G-07", "salary": 12000}, expected=201,
        )["employee"]
        start = date.today() + timedelta(days=3)
        contract = hr.request(
            "POST", f"/api/employees/{employee['id']}/documents",
            {"document_type": "contract", "title": "عقد مستقبلي", "file_name": "contract.png",
             "data_url": "data:image/png;base64,iVBORw0KGgo=", "issued_on": start.isoformat(),
             "expires_on": (start + timedelta(days=365)).isoformat()}, expected=201,
        )["document"]
        future_card = hr.request("GET", f"/api/employees/{employee['id']}/card")["card"]
        self.assertEqual(future_card["status"], "not_started")
        self.assertEqual(future_card["valid_from"], contract["issued_on"])
        hr.request("POST", f"/api/employees/{employee['id']}/card/print", {}, expected=409)
        hr.request("PATCH", f"/api/documents/{contract['id']}", {"issued_on": date.today().isoformat()})
        active_card = hr.request("GET", f"/api/employees/{employee['id']}/card")["card"]
        self.assertEqual(active_card["status"], "active")
        custody = hr.request(
            "POST", f"/api/employees/{employee['id']}/custody",
            {"asset_name": "هاتف متحرك", "asset_type": "iPhone", "serial_number": "sdfd87f8dsfuufafds8fds8f",
             "received_on": date.today().isoformat(), "received_condition": "new", "notes": "اختبار",
             "received_photos": [{"file_name": "receipt.png", "data_url": "data:image/png;base64,iVBORw0KGgo=", "caption": "الجهاز عند الاستلام"}]}, expected=201,
        )["custody"]
        self.assertEqual(custody["status"], "assigned")
        self.assertEqual(custody["received_photo_count"], 1)
        self.assertEqual(custody["return_photo_count"], 0)
        listed = hr.request("GET", f"/api/employees/{employee['id']}/custody")
        self.assertEqual(listed["counts"]["assigned"], 1)
        receipt = hr.request("POST", f"/api/employee-custody/{custody['id']}/print", {})
        self.assertEqual(receipt["print_type"], "receipt")
        hr.request("POST", f"/api/employee-custody/{custody['id']}/print", {"print_type": "return"}, expected=409)
        returned = hr.request(
            "PATCH", f"/api/employee-custody/{custody['id']}",
            {"returned_on": (date.today() + timedelta(days=10)).isoformat(), "return_condition": "تم التسليم بحالة جيدة",
             "return_photos": [{"file_name": "return.png", "data_url": "data:image/png;base64,iVBORw0KGgo=", "caption": "خدش بسيط عند التسليم"}]},
        )["custody"]
        self.assertEqual(returned["status"], "returned")
        self.assertEqual(returned["received_photo_count"], 1)
        self.assertEqual(returned["return_photo_count"], 1)
        self.assertEqual(returned["received_photos"][0]["caption"], "الجهاز عند الاستلام")
        self.assertEqual(returned["return_photos"][0]["caption"], "خدش بسيط عند التسليم")
        self.assertEqual(hr.request("POST", f"/api/employee-custody/{custody['id']}/print", {"print_type": "return"})["print_type"], "return")

    def test_16_v44_organization_views_share_source_and_support_filters(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        payloads = [hr.request("GET", f"/api/org/hierarchy?view={view}") for view in ("hierarchical", "grid", "sequential")]
        id_sets = [{row["id"] for row in payload["employees"]} for payload in payloads]
        self.assertEqual(id_sets[0], id_sets[1])
        self.assertEqual(id_sets[1], id_sets[2])
        self.assertTrue(all(payload["source"] == "employees.manager_id+departments" for payload in payloads))
        self.assertEqual([payload["view"] for payload in payloads], ["hierarchical", "grid", "sequential"])
        target = next(row for row in payloads[0]["employees"] if row["employee_no"] == "EMP-V44")
        branch = hr.request("GET", f"/api/org/hierarchy?view=grid&branch_id={target['branch_id']}")
        self.assertTrue(branch["employees"])
        self.assertTrue(all(row["branch_id"] == target["branch_id"] for row in branch["employees"]))
        department = hr.request("GET", f"/api/org/hierarchy?view=sequential&department_id={target['department_id']}")
        self.assertTrue(all(row["department_id"] == target["department_id"] for row in department["employees"]))
        search = hr.request("GET", "/api/org/hierarchy?view=hierarchical&q=EMP-V44")
        self.assertEqual([row["employee_no"] for row in search["employees"]], ["EMP-V44"])
        hr.request("GET", "/api/org/hierarchy?view=unknown", expected=422)

    def test_16_v44_legacy_document_schema_migrates_without_data_loss_contract(self):
        with tempfile.TemporaryDirectory(prefix="hr-v44-migration-") as folder:
            db_path = Path(folder) / "legacy.sqlite3"
            hr_server.initialize_database(db_path)
            connection = sqlite3.connect(db_path)
            employee_id = connection.execute("SELECT id FROM employees ORDER BY id LIMIT 1").fetchone()[0]
            user_id = connection.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()[0]
            connection.execute("DROP TABLE employee_documents")
            connection.execute(
                """CREATE TABLE employee_documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id INTEGER NOT NULL,
                    document_type TEXT NOT NULL CHECK (document_type IN ('identity','qualification','general')),
                    title TEXT NOT NULL, file_name TEXT NOT NULL, mime_type TEXT NOT NULL,
                    data_url TEXT NOT NULL, visible_to_employee INTEGER NOT NULL DEFAULT 1,
                    uploaded_by INTEGER NOT NULL, created_at TEXT NOT NULL
                )"""
            )
            connection.execute(
                """INSERT INTO employee_documents(
                    employee_id,document_type,title,file_name,mime_type,data_url,visible_to_employee,uploaded_by,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (employee_id, "identity", "هوية قديمة", "legacy.png", "image/png", "data:image/png;base64,iVBORw0KGgo=", 1, user_id, "2025-01-01T00:00:00+00:00"),
            )
            connection.commit()
            connection.close()
            hr_server.initialize_database(db_path)
            migrated = sqlite3.connect(db_path)
            columns = {row[1] for row in migrated.execute("PRAGMA table_info(employee_documents)")}
            table_sql = migrated.execute("SELECT sql FROM sqlite_master WHERE name='employee_documents'").fetchone()[0]
            legacy = migrated.execute("SELECT title,document_type,visible_to_employee FROM employee_documents WHERE title='هوية قديمة'").fetchone()
            migrated.close()
            self.assertTrue({"document_number", "issuer", "issued_on", "expires_on", "no_expiry", "notes", "archived", "updated_at"}.issubset(columns))
            self.assertIn("'residency'", table_sql)
            self.assertEqual(legacy, ("هوية قديمة", "identity", 1))

    def test_17_v45_employee_languages_validation_rbac_card_flags_and_print_faces(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        branch = hr.request("GET", "/api/branches")["items"][0]
        department = hr.request("GET", "/api/departments")["items"][0]
        grade = hr.request("GET", "/api/job-grades")["items"][0]
        title = hr.request("GET", "/api/job-titles")["items"][0]
        languages = [
            {"code": "ar", "proficiency": "native"},
            {"code": "en", "proficiency": "excellent"},
            {"code": "ur", "proficiency": "very_good"},
            {"code": "zh", "proficiency": "good"},
            {"code": "fil", "proficiency": "basic"},
        ]
        employee = hr.request(
            "POST", "/api/employees",
            {
                "employee_no": "EMP-V45", "full_name": "موظفة بطاقة اللغات",
                "email": "employee-v45@demo.ae", "phone": "+971500000045",
                "job_title_id": title["id"], "job_grade_id": grade["id"],
                "department_id": department["id"], "branch_id": branch["id"],
                "hire_date": "2024-01-15", "salary": 13500,
                "photo_data": "data:image/png;base64,iVBORw0KGgo=",
                "create_user": True, "password": "Employee@V45", "role": "employee",
                "languages": languages,
            }, expected=201,
        )["employee"]
        self.assertEqual([item["code"] for item in employee["languages"]], ["ar", "en", "ur", "zh", "fil"])
        self.assertEqual([item["proficiency"] for item in employee["languages"]], ["native", "excellent", "very_good", "good", "basic"])
        self.assertEqual([item["flag_code"] for item in employee["languages"]], ["AE", "GB", "IN", "CN", "PH"])

        profile = hr.request("GET", f"/api/employees/{employee['id']}")["employee"]
        self.assertEqual([item["code"] for item in profile["languages"]], ["ar", "en", "ur", "zh", "fil"])
        catalog = hr.request("GET", "/api/languages/catalog")
        self.assertEqual(len(catalog["items"]), 12)
        self.assertEqual({item["code"] for item in catalog["proficiencies"]}, {"native", "excellent", "very_good", "good", "basic"})

        worker = self.client("employee-v45@demo.ae", "Employee@V45")
        own = worker.request("GET", f"/api/employees/{employee['id']}/languages")["items"]
        self.assertEqual([item["code"] for item in own], ["ar", "en", "ur", "zh", "fil"])
        worker.request("PATCH", f"/api/employees/{employee['id']}/languages", {"languages": languages}, expected=403)
        for invalid, code in (
            ([{"code": "de", "proficiency": "good"}], "unknown_language"),
            ([{"code": "ar", "proficiency": "fluent"}], "unknown_proficiency"),
            ([{"code": "ar", "proficiency": "native"}, {"code": "ar", "proficiency": "good"}], "duplicate_language"),
        ):
            refused = hr.request("PATCH", f"/api/employees/{employee['id']}/languages", {"languages": invalid}, expected=422)
            self.assertEqual(refused["code"], code)

        reordered = [
            {"code": "fil", "proficiency": "excellent"},
            {"code": "zh", "proficiency": "very_good"},
            {"code": "ur", "proficiency": "good"},
            {"code": "en", "proficiency": "excellent"},
            {"code": "ar", "proficiency": "native"},
        ]
        changed = hr.request("PATCH", f"/api/employees/{employee['id']}/languages", {"languages": reordered})["items"]
        self.assertEqual([item["code"] for item in changed], ["fil", "zh", "ur", "en", "ar"])
        card = hr.request("GET", f"/api/employees/{employee['id']}/card")["card"]
        self.assertEqual(card["status"], "not_issuable")
        self.assertEqual([item["flag_code"] for item in card["languages"]], ["PH", "CN", "IN", "GB", "AE"])
        self.assertEqual(set(card["faces"]), {"front", "back"})
        hr.request("POST", f"/api/employees/{employee['id']}/card/print", {"face": "front"}, expected=409)

        valid_until = (date.today() + timedelta(days=180)).isoformat()
        hr.request(
            "POST", f"/api/employees/{employee['id']}/documents",
            {
                "document_type": "contract", "title": "عقد عمل اختبار V5.0",
                "file_name": "contract.png", "data_url": "data:image/png;base64,iVBORw0KGgo=",
                "issued_on": date.today().isoformat(), "expires_on": valid_until, "visible_to_employee": True,
            }, expected=201,
        )
        active_card = hr.request("GET", f"/api/employees/{employee['id']}/card")["card"]
        self.assertEqual(active_card["status"], "active")
        for face in ("front", "back", "both"):
            printed = hr.request("POST", f"/api/employees/{employee['id']}/card/print", {"face": face})
            self.assertTrue(printed["print_authorized"])
            self.assertEqual(printed["print_face"], face)
        hr.request("POST", f"/api/employees/{employee['id']}/card/print", {"face": "inside"}, expected=422)
        verification = worker.request("GET", active_card["verification_path"])["verification"]
        self.assertEqual(verification["reference"], active_card["verification_reference"])
        self.assertEqual(verification["status"], "active")

        audit_db = sqlite3.connect(self.db_path)
        audit_actions = {row[0] for row in audit_db.execute("SELECT action FROM audit_log WHERE entity_id=?", (employee["id"],))}
        audit_db.close()
        self.assertIn("employee.languages_update", audit_actions)
        self.assertIn("employee_card.print", audit_actions)

    def test_18_v45_card_settings_three_templates_contrast_and_contact_fallback(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        employee_id = next(row["id"] for row in hr.request("GET", "/api/employees")["items"] if row["employee_no"] == "EMP-V45")
        templates = {
            "portrait_orbit": ("vertical", {"width_mm": 53.98, "height_mm": 85.6}),
            "executive_horizontal": ("horizontal", {"width_mm": 85.6, "height_mm": 53.98}),
            "minimal_vertical": ("vertical", {"width_mm": 53.98, "height_mm": 85.6}),
        }
        for template, (orientation, dimensions) in templates.items():
            organization = hr.request(
                "PATCH", "/api/org",
                {
                    "card_template": template,
                    "card_primary_color": "#123d34",
                    "card_accent_color": "#d6b36a",
                    "card_back_instructions": "بطاقة تعريف مؤسسية. عند العثور عليها يرجى التواصل فوراً.",
                    "card_contact_phone": "",
                    "card_contact_email": "cards@demo.ae",
                },
            )["organization"]
            self.assertEqual(organization["card_template"], template)
            card = hr.request("GET", f"/api/employees/{employee_id}/card")["card"]
            self.assertEqual(card["design"]["template"], template)
            self.assertEqual(card["design"]["orientation"], orientation)
            self.assertEqual(card["design"]["dimensions_mm"], dimensions)
            self.assertEqual(card["design"]["contact_phone"], organization["phone"])
            self.assertEqual(card["design"]["contact_email"], "cards@demo.ae")
            self.assertIn("التواصل فوراً", card["design"]["back_instructions"])
        hr.request("PATCH", "/api/org", {"card_template": "copied_brand"}, expected=422)
        hr.request("PATCH", "/api/org", {"card_primary_color": "green"}, expected=422)
        hr.request("PATCH", "/api/org", {"card_primary_color": "#ffffff"}, expected=422)
        hr.request("PATCH", "/api/org", {"card_primary_color": "#123d34", "card_accent_color": "#123d35"}, expected=422)
        hr.request("PATCH", "/api/org", {"card_contact_email": "not-an-email"}, expected=422)

    def test_19_v45_migration_from_v44_preserves_org_employees_and_documents(self):
        with tempfile.TemporaryDirectory(prefix="hr-v45-migration-") as folder:
            db_path = Path(folder) / "legacy-v44.sqlite3"
            hr_server.initialize_database(db_path)
            connection = sqlite3.connect(db_path)
            connection.execute("UPDATE organization SET display_name='مؤسسة ترحيل V4.4',legal_name='مؤسسة ترحيل V4.4 ذ.م.م',phone='+97145551234',email='legacy@example.ae' WHERE id=1")
            employee_id = connection.execute("SELECT id FROM employees ORDER BY id LIMIT 1").fetchone()[0]
            user_id = connection.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()[0]
            connection.execute(
                """INSERT INTO employee_documents(employee_id,document_type,title,file_name,mime_type,data_url,no_expiry,uploaded_by,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (employee_id, "identity", "وثيقة باقية", "legacy.png", "image/png", "data:image/png;base64,iVBORw0KGgo=", 1, user_id, "2025-01-01T00:00:00+00:00", "2025-01-01T00:00:00+00:00"),
            )
            employee_count = connection.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
            document_count = connection.execute("SELECT COUNT(*) FROM employee_documents").fetchone()[0]
            connection.execute("DROP TABLE employee_languages")
            connection.execute("ALTER TABLE organization RENAME TO organization_v45")
            connection.execute(
                """CREATE TABLE organization (
                    id INTEGER PRIMARY KEY CHECK (id=1),display_name TEXT NOT NULL,legal_name TEXT NOT NULL,
                    license_no TEXT NOT NULL DEFAULT '',tax_no TEXT NOT NULL DEFAULT '',sector TEXT NOT NULL DEFAULT '',
                    emirate TEXT NOT NULL DEFAULT 'دبي',address TEXT NOT NULL DEFAULT '',phone TEXT NOT NULL DEFAULT '',
                    email TEXT NOT NULL DEFAULT '',website TEXT NOT NULL DEFAULT '',timezone TEXT NOT NULL DEFAULT 'Asia/Dubai',
                    currency TEXT NOT NULL DEFAULT 'AED',primary_color TEXT NOT NULL DEFAULT '#123f35',
                    accent_color TEXT NOT NULL DEFAULT '#c48a3a',document_template TEXT NOT NULL DEFAULT 'corporate',
                    logo_data TEXT,stamp_data TEXT,updated_at TEXT NOT NULL
                )"""
            )
            legacy_columns = "id,display_name,legal_name,license_no,tax_no,sector,emirate,address,phone,email,website,timezone,currency,primary_color,accent_color,document_template,logo_data,stamp_data,updated_at"
            connection.execute(f"INSERT INTO organization({legacy_columns}) SELECT {legacy_columns} FROM organization_v45")
            connection.execute("DROP TABLE organization_v45")
            connection.commit()
            connection.close()

            hr_server.initialize_database(db_path)
            migrated = sqlite3.connect(db_path)
            migrated.row_factory = sqlite3.Row
            organization = migrated.execute("SELECT * FROM organization WHERE id=1").fetchone()
            language_table = migrated.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='employee_languages'").fetchone()
            self.assertEqual(migrated.execute("SELECT COUNT(*) FROM employees").fetchone()[0], employee_count)
            self.assertEqual(migrated.execute("SELECT COUNT(*) FROM employee_documents").fetchone()[0], document_count)
            self.assertEqual(migrated.execute("SELECT title FROM employee_documents WHERE title='وثيقة باقية'").fetchone()[0], "وثيقة باقية")
            self.assertEqual(organization["display_name"], "مؤسسة ترحيل V4.4")
            self.assertEqual(organization["phone"], "+97145551234")
            self.assertEqual(organization["card_template"], "portrait_orbit")
            self.assertEqual(organization["card_primary_color"], "#123d34")
            self.assertIn("employee_languages", language_table["sql"])
            self.assertIn("smtp_password_encrypted", {row[1] for row in migrated.execute("PRAGMA table_info(organization)")})
            self.assertIn("must_change_password", {row[1] for row in migrated.execute("PRAGMA table_info(users)")})
            self.assertIn("csrf_token", {row[1] for row in migrated.execute("PRAGMA table_info(sessions)")})
            for table in ("password_reset_tokens", "email_campaigns", "email_deliveries", "email_outbox"):
                self.assertTrue(migrated.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone())
            migrated.close()

    def test_20_v45_frontend_card_contract_print_css_flags_and_brand_safety(self):
        root = Path(__file__).parents[1]
        sources = {name: (root / name).read_text(encoding="utf-8") for name in ("index.html", "app.js", "styles.css", "server.py", "schema.sql")}
        index, app, styles = sources["index.html"], sources["app.js"], sources["styles.css"]
        self.assertIn('styles.css?v=5.7.0', index)
        self.assertIn('app.js?v=5.7.0', index)
        for template in ("portrait_orbit", "executive_horizontal", "minimal_vertical"):
            self.assertIn(f'data-card-template-choice="{template}"', index)
            self.assertIn(f"template-{template}", styles)
        self.assertIn('data-card-face="front"', app)
        self.assertIn('data-card-face="back"', app)
        self.assertIn('data-card-print-face="both"', app)
        self.assertIn('data-card-print-face="front"', app)
        self.assertIn('data-card-print-face="back"', app)
        self.assertIn('@page cardPortrait{size:53.98mm 85.60mm', styles)
        self.assertIn('@page cardLandscape{size:85.60mm 53.98mm', styles)
        self.assertIn('[data-print-mode="front"]', styles)
        self.assertIn('[data-print-mode="back"]', styles)
        self.assertIn('box-shadow:none!important', styles)
        self.assertIn('function fitCardSettingsPreview()', app)
        self.assertIn("Math.min(1,availableWidth/naturalWidth,availableHeight/naturalHeight)", app)
        self.assertIn("spread.style.transform=`translate(-50%,-50%) scale(${scale.toFixed(4)})`", app)
        self.assertIn("data-card-fit-stage", app)
        self.assertIn("window.addEventListener('resize',fitAllCardPreviews", app)
        self.assertIn('.card-preview-stage .employee-card-spread{width:max-content;max-width:none;overflow:visible', styles)
        self.assertIn('zoom:1!important', styles)
        self.assertIn("class=\"card-kicker\">${tr('العناية بالبطاقة')}", app)
        self.assertEqual(app.count("${tr('تعليمات مهمة')}</h2>"), 1)
        self.assertIn('font-size:2.4mm;line-height:1.6', styles)
        self.assertIn('font-size:2.05mm;line-height:1.45', styles)
        self.assertIn("function modalFocusable()", app)
        self.assertIn("if(event.key==='Escape')", app)
        self.assertIn("if(event.key!=='Tab')", app)
        self.assertIn("state.modalOpener", app)
        self.assertIn("opener.focus()", app)
        self.assertIn("closeModal(false)", app)
        self.assertIn("p.type=p.type==='password'?'text':'password'", app)
        for flag_code, flag in (("AE", "🇦🇪"), ("GB", "🇬🇧"), ("IN", "🇮🇳"), ("CN", "🇨🇳"), ("PH", "🇵🇭")):
            self.assertIn(flag_code, app)
            self.assertIn(flag, app)
        self.assertIn('aria-label="${esc(language.name)}', app)
        self.assertIn("لا توجد لغات مسجلة", app)
        self.assertIn("KHAISHA", "\n".join(sources.values()).upper())
        card_print_contract = styles[styles.index(".employee-card-spread"):styles.index("/* V4.6")]
        self.assertNotIn("linear-gradient", card_print_contract)

    def test_21_v46_effective_rbac_deny_wins_and_super_admin_protection(self):
        admin = self.client("admin@demo.ae", "Admin@123")
        employee = self.client("employee@demo.ae", "Emp@12345")
        catalog = admin.request("GET", "/api/admin/permissions/catalog")["groups"]
        self.assertTrue(any(p["key"] == "dashboard.view" for group in catalog for p in group["permissions"]))
        users = admin.request("GET", "/api/admin/users")["items"]
        employee_user = next(x for x in users if x["email"] == "employee@demo.ae")
        protected = next(x for x in users if x["email"] == "admin@demo.ae")
        self.assertTrue(protected["is_super_admin"])
        employee.request("GET", "/api/dashboard", expected=403)
        granted = admin.request("PATCH", f"/api/admin/users/{employee_user['id']}/permissions", {"overrides": [{"permission": "dashboard.view", "granted": True}]})["user"]
        self.assertIn("dashboard.view", granted["permissions"])
        self.assertEqual(granted["permission_reasons"]["dashboard.view"], "explicit_grant")
        dashboard = employee.request("GET", "/api/dashboard")
        self.assertIn("employees_active", dashboard["metrics"])
        denied = admin.request("PATCH", f"/api/admin/users/{employee_user['id']}/permissions", {"overrides": [{"permission": "dashboard.view", "granted": False}]})["user"]
        self.assertNotIn("dashboard.view", denied["permissions"])
        self.assertEqual(denied["permission_reasons"]["dashboard.view"], "explicit_deny")
        employee.request("GET", "/api/dashboard", expected=403)
        admin.request("PATCH", f"/api/admin/users/{protected['id']}/permissions", {"overrides": [{"permission": "dashboard.view", "granted": False}]}, expected=409)
        admin.request("PATCH", f"/api/admin/users/{protected['id']}", {"active": False}, expected=409)

    def test_22_v46_executive_dashboard_real_metrics_filters_and_org_grid(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        employee = self.client("employee@demo.ae", "Emp@12345")
        employee.request("GET", "/api/dashboard", expected=403)
        dashboard = hr.request("GET", "/api/dashboard")
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            active = db.execute("SELECT COUNT(*) FROM employees WHERE active=1").fetchone()[0]
        self.assertEqual(dashboard["metrics"]["employees_active"], active)
        self.assertTrue(0 <= dashboard["health"]["score"] <= 100)
        self.assertTrue(dashboard["activity"])
        branches = hr.request("GET", "/api/branches")["items"]
        filtered = hr.request("GET", f"/api/dashboard?branch_id={branches[0]['id']}")
        self.assertLessEqual(filtered["metrics"]["employees_total"], dashboard["metrics"]["employees_total"])
        grid = hr.request("GET", f"/api/org/grid?branch_id={branches[0]['id']}")
        self.assertEqual(grid["view"], "grid")
        self.assertEqual(grid["label"], "المخطط الشبكي")
        self.assertTrue(grid["general_manager"])
        self.assertTrue(all("employees" in department for department in grid["departments"]))

    def test_23_v46_password_change_admin_temporary_reset_and_session_invalidation(self):
        admin = self.client("admin@demo.ae", "Admin@123")
        suffix = uuid.uuid4().hex[:8]
        created = admin.request("POST", "/api/employees", {"employee_no": f"SEC-{suffix}", "full_name": "مستخدم أمان", "email": f"security-{suffix}@demo.ae", "create_user": True, "password": "Start@12345", "role": "employee"}, expected=201)["employee"]
        users = admin.request("GET", "/api/admin/users")["items"]
        account = next(x for x in users if x["employee_id"] == created["id"])
        active_session = self.client(account["email"], "Start@12345")
        admin.request("POST", f"/api/admin/users/{account['id']}/reset-password", {"password": "Temp@98765", "confirm_password": "Temp@98765", "confirm": True})
        active_session.request("GET", "/api/auth/me", expected=401)
        temporary = self.client(account["email"], "Temp@98765")
        self.assertTrue(temporary.request("GET", "/api/auth/me")["user"]["must_change_password"])
        temporary.request("GET", "/api/me/dashboard", expected=428)
        temporary.request("POST", "/api/auth/change-password", {"current_password": "wrong", "password": "Final@98765", "confirm_password": "Final@98765"}, expected=403)
        temporary.request("POST", "/api/auth/change-password", {"current_password": "Temp@98765", "password": "Final@98765", "confirm_password": "Final@98765"})
        temporary.request("GET", "/api/auth/me", expected=401)
        final = self.client(account["email"], "Final@98765")
        self.assertFalse(final.request("GET", "/api/auth/me")["user"]["must_change_password"])

    def test_24_v46_forgot_reset_hash_expiry_single_use_rate_limit_and_secure_outbox(self):
        admin = self.client("admin@demo.ae", "Admin@123")
        suffix = uuid.uuid4().hex[:8]; recovery_email = f"recovery-{suffix}@demo.ae"
        admin.request("POST", "/api/employees", {"employee_no": f"REC-{suffix}", "full_name": "مستخدم استرجاع", "email": recovery_email, "create_user": True, "password": "Before@1234", "role": "employee"}, expected=201)
        public = APIClient(self.base_url)
        known = public.request("POST", "/api/auth/forgot-password", {"email": recovery_email})
        unknown = public.request("POST", "/api/auth/forgot-password", {"email": f"unknown-{uuid.uuid4().hex}@demo.ae"})
        self.assertEqual(known["message"], unknown["message"])
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            db.row_factory = sqlite3.Row
            token_row = db.execute("SELECT * FROM password_reset_tokens ORDER BY id DESC LIMIT 1").fetchone()
            outbox = db.execute("SELECT body FROM email_outbox WHERE kind='password_reset' ORDER BY id DESC LIMIT 1").fetchone()
            self.assertEqual(len(token_row["token_hash"]), 64)
            raw = re.search(r"reset_token=([^#\s]+)", outbox["body"]).group(1)
            self.assertNotEqual(raw, token_row["token_hash"])
        self.assertTrue(public.request("POST", "/api/auth/reset-password/validate", {"token": raw})["valid"])
        public.request("POST", "/api/auth/reset-password", {"token": raw, "password": "Recovered@123", "confirm_password": "Recovered@123"})
        public.request("POST", "/api/auth/reset-password", {"token": raw, "password": "Another@1234", "confirm_password": "Another@1234"}, expected=410)
        self.client(recovery_email, "Recovered@123")
        safe_outbox = admin.request("GET", "/api/admin/outbox")["items"]
        reset_message = next(x for x in safe_outbox if x["kind"] == "password_reset")
        self.assertNotIn(raw, reset_message["body"])
        for _ in range(7):
            public.request("POST", "/api/auth/forgot-password", {"email": "rate-limit@example.invalid"})
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            self.assertGreaterEqual(db.execute("SELECT MAX(attempts) FROM auth_rate_limits WHERE action='forgot_password'").fetchone()[0], 6)

    def test_25_v46_communications_recipient_scopes_queue_retry_rbac_and_audit(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        employee = self.client("employee@demo.ae", "Emp@12345")
        employee.request("POST", "/api/communications/campaigns", {"audience_type": "all", "subject": "ممنوع", "body": "ممنوع"}, expected=403)
        departments = hr.request("GET", "/api/departments")["items"]
        target = next(x for x in departments if x["employee_count"] > 0)
        campaign = hr.request("POST", "/api/communications/campaigns", {"audience_type": "department", "audience_ref": target["id"], "subject": "تحديث سياسة العمل", "body": "يرجى الاطلاع على التحديث المؤسسي المرفق في النظام.", "template": "policy"}, expected=201)["campaign"]
        self.assertGreater(campaign["recipient_count"], 0)
        self.assertEqual(len(campaign["deliveries"]), campaign["recipient_count"])
        self.assertTrue(all(x["status"] == "queued" for x in campaign["deliveries"]))
        retried = hr.request("POST", f"/api/communications/campaigns/{campaign['id']}/retry")["campaign"]
        self.assertTrue(all(x["attempts"] >= 1 for x in retried["deliveries"]))
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            self.assertTrue(db.execute("SELECT 1 FROM audit_log WHERE action='communications.campaign_create' AND entity_id=?", (str(campaign["id"]),)).fetchone())

    def test_26_v46_smtp_secret_masking_csrf_and_frontend_contract(self):
        admin = self.client("admin@demo.ae", "Admin@123")
        smtp = admin.request("PATCH", "/api/admin/smtp", {"smtp_host": "", "smtp_port": 587, "smtp_tls": True, "smtp_ssl": False, "smtp_username": "mailer", "smtp_password": "MailSecret@123", "smtp_from_name": "الموارد البشرية", "smtp_from_email": "hr@example.ae"})["smtp"]
        self.assertEqual(smtp["smtp_password"], "••••••••")
        self.assertTrue(smtp["password_configured"])
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            encrypted = db.execute("SELECT smtp_password_encrypted FROM organization WHERE id=1").fetchone()[0]
            self.assertNotIn("MailSecret", encrypted)
        cookie = next(iter(admin.cookies)).value
        request = urllib.request.Request(self.base_url + "/api/admin/smtp", data=b'{"smtp_port":587}', headers={"Accept":"application/json","Content-Type":"application/json","Cookie":f"hr_session={cookie}"}, method="PATCH")
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(request, timeout=10)
        self.assertEqual(context.exception.code, 403); context.exception.close()
        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8"); app = (root / "app.js").read_text(encoding="utf-8"); styles = (root / "styles.css").read_text(encoding="utf-8")
        for page_id in ("dashboard","communications","access-control","access-denied"):
            self.assertIn(f'id="{page_id}"', index)
        self.assertIn("csrfToken", app); self.assertIn("X-CSRF-Token", app); self.assertIn("/api/org/grid", app)
        self.assertIn("المخطط الشبكي", index); self.assertIn("executive-org-grid", styles); self.assertIn("@media(max-width:650px)", styles)
        self.assertIn(".login-identity{isolation:isolate;background:linear-gradient", styles)
        self.assertIn(".sidebar{width:284px", styles)

    def test_27_v461_frontend_write_controls_use_exact_effective_permissions(self):
        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8")
        app = (root / "app.js").read_text(encoding="utf-8")
        self.assertNotIn("data-manage", index)
        self.assertNotIn("data-admin", index)
        for permission in (
            "branch.manage", "notification.send", "payroll.manage", "lifecycle.manage",
            "employee_document.manage", "employee_action.manage", "reference.manage", "shift.manage",
        ):
            self.assertIn(permission, app + index)
        self.assertIn("mayManage=hasPermission('branch.manage')", app)
        self.assertIn("mayManage=hasPermission('lifecycle.manage')", app)
        self.assertIn("enforceDynamicPermissions($('#modalBody'))", app)
        employee = self.client("employee@demo.ae", "Emp@12345")
        permissions = employee.request("GET", "/api/auth/me")["permissions"]
        self.assertIn("branch.view", permissions)
        self.assertNotIn("branch.manage", permissions)
        employee.request("DELETE", "/api/branches/1", expected=403)

    def test_28_v461_dashboard_absence_is_shift_leave_rest_and_time_aware(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        uae = ZoneInfo("Asia/Dubai")
        monday = date(2030, 1, 7)
        self.assertEqual(monday.weekday(), 0)
        before_start = datetime(2030, 1, 7, 6, 47, tzinfo=uae)
        after_start = datetime(2030, 1, 7, 10, 0, tzinfo=uae)
        with mock.patch.object(hr_server, "local_now", return_value=before_start):
            early = hr.request("GET", f"/api/dashboard?date_from={monday}&date_to={monday}")
        self.assertEqual(early["metrics"]["absent_today"], 0)
        self.assertEqual(early["metrics"]["eligible_to_attend"], 0)
        self.assertGreaterEqual(early["attendance_context"]["not_due_yet"], 4)
        self.assertEqual(early["health"]["absence_denominator"], 0)
        with mock.patch.object(hr_server, "local_now", return_value=after_start):
            due = hr.request("GET", f"/api/dashboard?date_from={monday}&date_to={monday}")
        self.assertGreaterEqual(due["metrics"]["eligible_to_attend"], 3)
        self.assertEqual(due["metrics"]["absent_today"], due["metrics"]["eligible_to_attend"])
        self.assertGreaterEqual(due["attendance_context"]["not_due_yet"], 1)

        saturday = monday + timedelta(days=5)
        with mock.patch.object(hr_server, "local_now", return_value=datetime(2030, 1, 12, 12, 0, tzinfo=uae)):
            rest = hr.request("GET", f"/api/dashboard?date_from={saturday}&date_to={saturday}")
        self.assertEqual(rest["metrics"]["absent_today"], 0)
        self.assertGreaterEqual(rest["attendance_context"]["weekly_rest"], 3)
        self.assertGreaterEqual(rest["attendance_context"]["not_due_yet"], 1)

        leave_day = monday + timedelta(days=1)
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            employee_id = db.execute("SELECT id FROM employees WHERE employee_no='EMP-1024'").fetchone()[0]
            leave_type_id = db.execute("SELECT id FROM leave_types WHERE code='annual'").fetchone()[0]
            stamp = datetime.now(uae).isoformat(timespec="seconds")
            db.execute(
                "INSERT INTO leave_requests(employee_id,leave_type_id,start_date,end_date,days,reason,status,created_at,updated_at) VALUES(?,?,?,?,?,?,'approved',?,?)",
                (employee_id, leave_type_id, leave_day.isoformat(), leave_day.isoformat(), 1, "اختبار استبعاد الغياب", stamp, stamp),
            )
            db.commit()
        with mock.patch.object(hr_server, "local_now", return_value=datetime(2030, 1, 8, 10, 0, tzinfo=uae)):
            leave = hr.request("GET", f"/api/dashboard?date_from={leave_day}&date_to={leave_day}")
        self.assertGreaterEqual(leave["attendance_context"]["approved_leave"], 1)
        self.assertEqual(leave["metrics"]["absent_today"], leave["metrics"]["eligible_to_attend"])

    def test_29_v461_org_fit_uses_measured_container_ratio_and_assets_are_versioned(self):
        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8")
        app = (root / "app.js").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")
        self.assertIn("naturalWidth=Math.ceil(grid.scrollWidth)", app)
        self.assertIn("availableWidth=Math.max(1,viewport.clientWidth-20)", app)
        self.assertIn("availableWidth/Math.max(1,naturalWidth)", app)
        self.assertNotIn("===1?.84", app)
        self.assertIn('class="org-fit-stage"', app)
        self.assertIn(".org-fit-stage.fitted{overflow:hidden}", styles)
        self.assertIn("MutationObserver", app)
        self.assertIn("styles.css?v=5.7.0", index)
        self.assertIn("app.js?v=5.7.0", index)
        self.assertIn('rel="icon" href="favicon.svg"', index)

    def test_30_v47_salary_certificate_serial_barcode_integrity_and_verification(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        employee = self.client("employee@demo.ae", "Emp@12345")
        employee_id = employee.request("GET", "/api/auth/me")["user"]["employee_id"]
        certificate = hr.request(
            "POST", "/api/salary-certificates",
            {"employee_id": employee_id, "purpose": "اختبار التحقق من الأصالة"},
            expected=201,
        )["certificate"]
        self.assertRegex(certificate["certificate_no"], r"^SAL-\d{4}-\d{6}$")
        self.assertRegex(certificate["verification_code"], r"^VRF-\d{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$")
        self.assertTrue(certificate["integrity_valid"])
        self.assertEqual(len(certificate["document_fingerprint"]), 16)

        employee.request("POST", "/api/salary-certificates/verify", {"code": certificate["verification_code"]}, expected=403)
        verified = hr.request("POST", "/api/salary-certificates/verify", {"code": certificate["verification_code"]})
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["status"], "valid")
        self.assertEqual(verified["certificate"]["employee"]["id"], employee_id)
        self.assertEqual(verified["certificate"]["verification_count"], 1)
        self.assertTrue(verified["issuer"]["name"])

        missing = hr.request("POST", "/api/salary-certificates/verify", {"code": "VRF-2099-FFFF-FFFF-FFFF"})
        self.assertFalse(missing["valid"])
        self.assertEqual(missing["status"], "not_found")

        # Simulate a V4.6 certificate lacking verification data; restart must backfill it safely.
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            db.execute("UPDATE salary_certificates SET verification_code='',integrity_hash='' WHERE id=?", (certificate["id"],))
            db.commit()
        self._restart_server()
        hr = self.client("hr@demo.ae", "HR@12345")
        migrated = hr.request("GET", f"/api/salary-certificates/{certificate['id']}")["certificate"]
        self.assertTrue(migrated["verification_code"])
        self.assertTrue(migrated["integrity_valid"])

        # Any change to an immutable issued value breaks the HMAC seal and blocks printing.
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            db.execute("UPDATE salary_certificates SET salary_snapshot=salary_snapshot+1 WHERE id=?", (certificate["id"],))
            db.commit()
        tampered = hr.request("POST", "/api/salary-certificates/verify", {"code": migrated["verification_code"]})
        self.assertFalse(tampered["valid"])
        self.assertEqual(tampered["status"], "integrity_error")
        hr.request("POST", f"/api/salary-certificates/{certificate['id']}/print", {}, expected=409)
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            self.assertTrue(db.execute("SELECT 1 FROM audit_log WHERE action='salary_certificate.verify' AND entity_id=?", (str(certificate["id"]),)).fetchone())

        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8")
        app = (root / "app.js").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")
        self.assertIn('id="certificate-verification"', index)
        self.assertIn('data-permission="salary_certificate.verify"', index)
        self.assertIn("function code39Markup", app)
        self.assertIn("/api/salary-certificates/verify", app)
        self.assertIn("certificate-verification-seal", styles)

    def test_31a_salary_certificate_request_appears_in_payslips_and_emails_employee(self):
        employee = self.client("employee@demo.ae", "Emp@12345")
        hr = self.client("hr@demo.ae", "HR@12345")
        employee_id = employee.request("GET", "/api/auth/me")["user"]["employee_id"]
        requested = employee.request(
            "POST", "/api/salary-certificates/request",
            {"purpose": "بنك الاختبار — شهادة راتب"}, expected=201,
        )["request"]
        self.assertEqual(requested["request_status"], "requested")
        approved = hr.request(
            "POST", f"/api/salary-certificates/{requested['id']}/decision",
            {"action": "approve", "decision_note": "تمت المراجعة"}, expected=200,
        )["request"]
        self.assertEqual(approved["request_status"], "approved")
        self.assertEqual(approved["email_status"], "queued")

        slips = employee.request("GET", "/api/me/payslips")
        certificates = slips["salary_certificates"]
        certificate = next(item for item in certificates if item["id"] == requested["id"])
        self.assertEqual(certificate["employee_id"], employee_id)
        self.assertTrue(certificate["integrity_valid"])
        self.assertEqual(certificate["employee"]["id"], employee_id)
        printed = employee.request("POST", f"/api/salary-certificates/{certificate['id']}/print", {}, expected=200)
        self.assertTrue(printed["print_authorized"])

        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            outbox = db.execute(
                "SELECT to_email,status,attachment_name,attachment_data FROM email_outbox WHERE id=(SELECT email_outbox_id FROM salary_certificates WHERE id=?)",
                (certificate["id"],),
            ).fetchone()
        self.assertEqual(outbox[0], "employee@demo.ae")
        self.assertEqual(outbox[1], "queued")
        self.assertTrue(outbox[2].endswith(".pdf"))
        self.assertTrue(outbox[3])

    def test_31_v48_strict_employee_privacy_team_attendance_and_two_stage_leave(self):
        employee = self.client("employee@demo.ae", "Emp@12345")
        manager = self.client("manager@demo.ae", "Manager@12345")
        hr = self.client("hr@demo.ae", "HR@12345")
        employee_id = employee.request("GET", "/api/auth/me")["user"]["employee_id"]
        manager_id = manager.request("GET", "/api/auth/me")["user"]["employee_id"]

        own_directory = employee.request("GET", "/api/employees")
        self.assertEqual(own_directory["scope"], "self")
        self.assertEqual([row["id"] for row in own_directory["items"]], [employee_id])
        for path in (
            f"/api/employees/{manager_id}",
            f"/api/employees/{manager_id}/documents",
            f"/api/employees/{manager_id}/actions",
            f"/api/employees/{manager_id}/languages",
            f"/api/employees/{manager_id}/card",
            f"/api/leaves/balances?employee_id={manager_id}",
            f"/api/attendance/daily?employee_id={manager_id}",
        ):
            employee.request("GET", path, expected=403)

        team = manager.request("GET", "/api/employees")
        self.assertEqual(team["scope"], "team_identity_only")
        report = next(row for row in team["items"] if row["id"] == employee_id)
        self.assertEqual(set(report), {"id", "employee_no", "full_name"})
        minimal_profile = manager.request("GET", f"/api/employees/{employee_id}")
        self.assertEqual(minimal_profile["scope"], "team_identity_only")
        self.assertEqual(set(minimal_profile["employee"]), {"id", "employee_no", "full_name"})
        for path in (
            f"/api/employees/{employee_id}/documents",
            f"/api/employees/{employee_id}/actions",
            f"/api/employees/{employee_id}/languages",
            f"/api/employees/{employee_id}/card",
            f"/api/leaves/balances?employee_id={employee_id}",
        ):
            manager.request("GET", path, expected=403)

        team_attendance = manager.request("GET", "/api/attendance/daily")
        self.assertEqual(team_attendance["scope"], "team_attendance")
        attendance_row = next(row for row in team_attendance["items"] if row["id"] == employee_id)
        self.assertEqual(
            set(attendance_row),
            {"id", "employee_no", "full_name", "work_date", "check_in_at", "check_out_at"},
        )
        self.assertNotIn("check_in_lat", attendance_row)
        self.assertNotIn("salary", attendance_row)
        self.assertNotIn("leave_balance", attendance_row)

        annual_type = next(row for row in employee.request("GET", "/api/leaves/types")["items"] if row["code"] == "annual")
        start = date.today() + timedelta(days=220)
        balance_path = f"/api/leaves/balances?year={start.year}"
        used_before = next(row for row in employee.request("GET", balance_path)["items"] if row["code"] == "annual")["used"]
        leave = employee.request(
            "POST", "/api/leaves/requests",
            {"leave_type_id": annual_type["id"], "start_date": start.isoformat(), "end_date": start.isoformat(), "reason": "اختبار المسار المتسلسل"},
            expected=201,
        )["request"]
        self.assertEqual(leave["workflow_stage"], "pending_manager")
        self.assertEqual(leave["manager_employee_id"], manager_id)
        hr.request("POST", f"/api/leaves/requests/{leave['id']}/decision", {"action": "approve"}, expected=409)
        self.assertTrue(any(row["title"] == "طلب إجازة بانتظار قرارك" for row in manager.request("GET", "/api/notifications/inbox")["items"]))

        manager_queue = manager.request("GET", "/api/leaves/requests")["items"]
        queued = next(row for row in manager_queue if row["id"] == leave["id"])
        self.assertTrue(queued["can_decide"])
        self.assertEqual(queued["decision_role"], "manager")
        self.assertNotIn("attachment_data", queued)
        self.assertNotIn("manager_name", queued)
        manager_result = manager.request("POST", f"/api/leaves/requests/{leave['id']}/decision", {"action": "approve"})["request"]
        self.assertEqual(manager_result["workflow_stage"], "pending_hr")
        self.assertEqual(manager_result["status"], "submitted")
        used_after_manager = next(row for row in employee.request("GET", balance_path)["items"] if row["code"] == "annual")["used"]
        self.assertEqual(used_after_manager, used_before)
        self.assertTrue(any(row["title"] == "قرار المسؤول المباشر على طلب إجازة" for row in hr.request("GET", "/api/notifications/inbox")["items"]))

        final_result = hr.request("POST", f"/api/leaves/requests/{leave['id']}/decision", {"action": "approve"})["request"]
        self.assertEqual(final_result["workflow_stage"], "approved")
        self.assertEqual(final_result["status"], "approved")
        used_after_hr = next(row for row in employee.request("GET", balance_path)["items"] if row["code"] == "annual")["used"]
        self.assertEqual(used_after_hr, used_before + 1)
        self.assertTrue(any(row["title"] == "القرار النهائي لطلب الإجازة" for row in employee.request("GET", "/api/notifications/inbox")["items"]))

        rejected_date = start + timedelta(days=10)
        rejected = employee.request(
            "POST", "/api/leaves/requests",
            {"leave_type_id": annual_type["id"], "start_date": rejected_date.isoformat(), "end_date": rejected_date.isoformat(), "reason": "اختبار رفض المسؤول"},
            expected=201,
        )["request"]
        manager_rejected = manager.request(
            "POST", f"/api/leaves/requests/{rejected['id']}/decision",
            {"action": "reject", "reason": "تعارض تشغيلي"},
        )["request"]
        self.assertEqual(manager_rejected["workflow_stage"], "manager_rejected")
        self.assertEqual(manager_rejected["status"], "rejected")
        hr.request("POST", f"/api/leaves/requests/{rejected['id']}/decision", {"action": "approve"}, expected=409)
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            actions = {row[0] for row in db.execute("SELECT action FROM audit_log WHERE entity_type='leave_request' AND entity_id IN (?,?)", (str(leave["id"]), str(rejected["id"]))).fetchall()}
        self.assertTrue({"leave.manager_approved", "leave.hr_approved", "leave.manager_rejected"}.issubset(actions))

        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8")
        app = (root / "app.js").read_text(encoding="utf-8")
        self.assertIn('data-permission-any="employee.view,employee.team"', index)
        self.assertIn("team_identity_only", app)
        self.assertIn("team_attendance", app)
        self.assertIn("اعتماد نهائي", app)

    def test_32_v49_job_goal_library_selection_custom_goals_and_management(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        titles = hr.request("GET", "/api/job-titles")["items"]
        operations_title = next(item for item in titles if item["name"] == "أخصائي عمليات")
        manager_id = next(item for item in hr.request("GET", "/api/employees")["items"] if item["employee_no"] == "EMP-1002")["id"]
        grade_id = hr.request("GET", "/api/job-grades")["items"][0]["id"]
        branch_id = hr.request("GET", "/api/branches")["items"][0]["id"]

        approved_library = hr.request(
            "GET", f"/api/evaluation-goal-templates?job_title_id={operations_title['id']}&include_inactive=1"
        )
        self.assertEqual(approved_library["job_title"]["name"], "أخصائي عمليات")
        self.assertEqual(len(approved_library["items"]), 5)
        self.assertEqual(sum(item["default_weight"] for item in approved_library["items"]), 100)
        self.assertTrue(all(item["measure"] and item["description"] for item in approved_library["items"]))

        suffix = uuid.uuid4().hex[:8]
        email = f"goals-{suffix}@demo.ae"
        employee = hr.request(
            "POST", "/api/employees",
            {
                "employee_no": f"GOAL-{suffix}", "full_name": "موظف اختبار الأهداف", "email": email,
                "job_title_id": operations_title["id"], "job_grade_id": grade_id,
                "branch_id": branch_id, "manager_id": manager_id, "hire_date": "2025-01-01",
                "salary": 9000, "create_user": True, "password": "Goal@12345", "role": "employee",
            },
            expected=201,
        )["employee"]
        goal_employee = self.client(email, "Goal@12345")
        own_library = goal_employee.request("GET", "/api/evaluation-goal-templates")
        self.assertEqual(own_library["job_title"]["id"], operations_title["id"])
        self.assertFalse(own_library["can_manage"])
        another_title = next(item for item in titles if item["id"] != operations_title["id"])
        goal_employee.request("GET", f"/api/evaluation-goal-templates?job_title_id={another_title['id']}", expected=403)
        goal_employee.request(
            "POST", "/api/evaluation-goal-templates",
            {"job_title_id": operations_title["id"], "title": "غير مصرح", "measure": "اختبار", "default_weight": 10},
            expected=403,
        )

        evaluation = goal_employee.request("POST", "/api/evaluations", {"year": date.today().year})
        evaluation_id = evaluation["evaluation"]["id"]
        templates = own_library["items"]
        first = goal_employee.request(
            "POST", f"/api/evaluations/{evaluation_id}/goals", {"template_id": templates[0]["id"]}, expected=201
        )
        copied = first["goals"][0]
        self.assertEqual(copied["title"], templates[0]["title"])
        self.assertEqual(copied["measure"], templates[0]["measure"])
        self.assertEqual(copied["weight"], templates[0]["default_weight"])
        self.assertEqual(copied["source_template_id"], templates[0]["id"])
        goal_employee.request(
            "POST", f"/api/evaluations/{evaluation_id}/goals", {"template_id": templates[0]["id"]}, expected=409
        )
        completed = goal_employee.request(
            "POST", f"/api/evaluations/{evaluation_id}/goals/from-templates",
            {"template_ids": [item["id"] for item in templates[1:]]}, expected=201,
        )
        self.assertEqual(completed["weight_total"], 100)
        self.assertEqual(len(completed["goals"]), 5)
        self.assertTrue(all(goal["source_template_id"] for goal in completed["goals"]))
        for goal in completed["goals"]:
            goal_employee.request(
                "PATCH", f"/api/evaluation-goals/{goal['id']}",
                {
                    "goal_type": "result", "start_date": evaluation["evaluation"]["period_start"],
                    "end_date": evaluation["evaluation"]["period_end"], "progress_status": "in_progress",
                    "achievement": 75, "evidence_note": f"دليل إنجاز فعلي للهدف {goal['id']}",
                },
            )
        submitted = goal_employee.request("POST", f"/api/evaluations/{evaluation_id}/submit", {})
        self.assertEqual(submitted["evaluation"]["status"], "submitted")

        # The free-writing path remains independent from the approved library.
        hr_evaluation = hr.request("POST", "/api/evaluations", {"year": date.today().year})
        custom = hr.request(
            "POST", f"/api/evaluations/{hr_evaluation['evaluation']['id']}/goals",
            {"title": "هدف مخصص يكتبه الموظف", "description": "اختيار حر", "weight": 100, "measure": "نسبة الإنجاز", "achievement": 0, "goal_type": "result", "start_date": hr_evaluation["evaluation"]["period_start"], "end_date": hr_evaluation["evaluation"]["period_end"], "progress_status": "not_completed", "evidence_note": ""},
            expected=201,
        )["goals"][0]
        self.assertIsNone(custom["source_template_id"])

        new_title = hr.request(
            "POST", "/api/job-titles", {"name": f"منسق ابتكار {suffix}"}, expected=201
        )["job_title"]
        generic = hr.request("GET", f"/api/evaluation-goal-templates?job_title_id={new_title['id']}&include_inactive=1")
        self.assertEqual(len(generic["items"]), 5)
        self.assertEqual(generic["weight_total"], 100)
        edited = hr.request(
            "PATCH", f"/api/evaluation-goal-templates/{generic['items'][0]['id']}",
            {"title": "جودة الإنجاز المحدثة", "default_weight": 30, "active": False},
        )["template"]
        self.assertEqual(edited["title"], "جودة الإنجاز المحدثة")
        self.assertEqual(edited["default_weight"], 30)
        self.assertFalse(edited["active"])

        # A real V4.8-shaped evaluation_goals table must migrate before the
        # unique source-template index is created, while preserving old goals.
        with tempfile.TemporaryDirectory(prefix="hr-v49-migration-") as folder:
            legacy_path = Path(folder) / "legacy-v48.sqlite3"
            hr_server.initialize_database(legacy_path)
            with contextlib.closing(sqlite3.connect(legacy_path)) as legacy:
                legacy.execute("PRAGMA foreign_keys=OFF")
                cycle_id = legacy.execute("SELECT id FROM evaluation_cycles LIMIT 1").fetchone()[0]
                employee_id = legacy.execute("SELECT id FROM employees WHERE employee_no='EMP-1024'").fetchone()[0]
                stamp = datetime.now().isoformat(timespec="seconds")
                evaluation_id = legacy.execute(
                    "SELECT id FROM evaluations WHERE cycle_id=? AND employee_id=?",
                    (cycle_id, employee_id),
                ).fetchone()[0]
                legacy.execute(
                    "INSERT INTO evaluation_goals(evaluation_id,title,description,weight,measure,achievement,employee_comment,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (evaluation_id, "هدف قديم باقٍ", "", 100, "الإنجاز", 0, "", stamp, stamp),
                )
                legacy.executescript("""
                    DROP INDEX IF EXISTS idx_evaluation_goal_template_once;
                    CREATE TABLE evaluation_goals_v48 (
                      id INTEGER PRIMARY KEY AUTOINCREMENT, evaluation_id INTEGER NOT NULL,
                      title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
                      weight REAL NOT NULL, measure TEXT NOT NULL DEFAULT '', achievement REAL NOT NULL DEFAULT 0,
                      employee_comment TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                    );
                    INSERT INTO evaluation_goals_v48(id,evaluation_id,title,description,weight,measure,achievement,employee_comment,created_at,updated_at)
                      SELECT id,evaluation_id,title,description,weight,measure,achievement,employee_comment,created_at,updated_at FROM evaluation_goals;
                    DROP TABLE evaluation_goals;
                    ALTER TABLE evaluation_goals_v48 RENAME TO evaluation_goals;
                """)
                legacy.commit()
            hr_server.initialize_database(legacy_path)
            with contextlib.closing(sqlite3.connect(legacy_path)) as migrated_db:
                self.assertIn("source_template_id", {row[1] for row in migrated_db.execute("PRAGMA table_info(evaluation_goals)")})
                self.assertTrue(migrated_db.execute("SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_evaluation_goal_template_once'").fetchone())
                self.assertEqual(migrated_db.execute("SELECT title FROM evaluation_goals WHERE id=1").fetchone()[0], "هدف قديم باقٍ")

        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8")
        app = (root / "app.js").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")
        self.assertIn('id="goalTemplateSettings"', index)
        self.assertIn("كتابة هدف مخصص", index + app)
        self.assertIn("/api/evaluation-goal-templates", app)
        self.assertIn("data-add-all-goal-templates", app)
        self.assertIn("recommended-goal-grid", styles)

    def test_33_v50_return_scheduled_disclosure_and_rejected_grievance(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        manager = self.client("manager@demo.ae", "Manager@12345")
        manager_id = manager.request("GET", "/api/auth/me")["user"]["employee_id"]
        branches = hr.request("GET", "/api/branches")["items"]
        titles = hr.request("GET", "/api/job-titles")["items"]
        grades = hr.request("GET", "/api/job-grades")["items"]
        suffix = uuid.uuid4().hex[:7]
        email = f"v50-{suffix}@demo.ae"
        employee_row = hr.request(
            "POST", "/api/employees",
            {
                "employee_no": f"V50-{suffix}", "full_name": "موظف مسار الإفصاح",
                "email": email, "job_title_id": titles[0]["id"], "job_grade_id": grades[0]["id"],
                "branch_id": branches[0]["id"], "manager_id": manager_id,
                "hire_date": "2025-01-01", "salary": 11000,
                "create_user": True, "password": "Employee@V50", "role": "employee",
            }, expected=201,
        )["employee"]
        worker = self.client(email, "Employee@V50")
        evaluation = worker.request("POST", "/api/evaluations", {"year": date.today().year})
        evaluation_id = evaluation["evaluation"]["id"]
        goal = worker.request(
            "POST", f"/api/evaluations/{evaluation_id}/goals",
            {"title": "تحسين زمن الخدمة", "description": "خفض زمن المعاملة", "weight": 100, "measure": "متوسط الزمن", "achievement": 75, "goal_type": "result", "start_date": evaluation["evaluation"]["period_start"], "end_date": evaluation["evaluation"]["period_end"], "progress_status": "in_progress", "evidence_note": "تقرير متوسط زمن الخدمة للفترة."},
            expected=201,
        )["goals"][0]
        worker.request("POST", f"/api/evaluations/{evaluation_id}/submit", {})
        manager.request(
            "POST", f"/api/evaluations/{evaluation_id}/manager-review",
            {"manager_report": "التقرير الأول يحتاج تدقيق HR.", "goals": [{"id": goal["id"], "awarded_points": 72}]},
        )
        hr.request(
            "POST", f"/api/evaluations/{evaluation_id}/hr-review",
            {"action": "return", "comment": ""}, expected=422,
        )
        returned = hr.request(
            "POST", f"/api/evaluations/{evaluation_id}/hr-review",
            {"action": "return", "comment": "أعد مطابقة النتيجة مع مؤشر زمن الخدمة."},
        )
        self.assertEqual(returned["evaluation"]["status"], "returned")
        manager_view = manager.request("GET", f"/api/evaluations/{evaluation_id}")
        self.assertEqual(manager_view["evaluation"]["hr_comment"], "أعد مطابقة النتيجة مع مؤشر زمن الخدمة.")
        manager.request(
            "POST", f"/api/evaluations/{evaluation_id}/manager-review",
            {"manager_report": "تمت إعادة المطابقة مع السجلات التشغيلية.", "goals": [{"id": goal["id"], "awarded_points": 78}]},
        )
        disclosure = date.today() + timedelta(days=1)
        hr.request(
            "POST", f"/api/evaluations/{evaluation_id}/hr-review",
            {"action": "approve", "comment": "مراجعة مكتملة", "disclosure_date": disclosure.isoformat()},
        )
        hidden = worker.request("GET", f"/api/evaluations/{evaluation_id}")
        self.assertFalse(hidden["evaluation"]["published"])
        self.assertIsNone(hidden["evaluation"]["weighted_score"])
        self.assertIsNone(hidden["evaluation"]["manager_report"])
        self.assertNotIn(evaluation_id, {row["id"] for row in worker.request("GET", "/api/evaluations/history")["items"]})
        self.assertFalse(any(row["title"] == "نتيجة التقييم السنوي" for row in worker.request("GET", "/api/notifications/inbox")["items"]))

        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            scheduled = db.execute(
                """SELECT n.id,n.available_at FROM notifications n
                   JOIN notification_recipients r ON r.notification_id=n.id
                   JOIN users u ON u.id=r.user_id
                   WHERE u.employee_id=? AND n.title='نتيجة التقييم السنوي' ORDER BY n.id DESC LIMIT 1""",
                (employee_row["id"],),
            ).fetchone()
        self.assertIsNotNone(scheduled)
        self.assertTrue(scheduled[1])
        worker.request("GET", f"/api/notifications/{scheduled[0]}", expected=404)

        disclosed_now = datetime(disclosure.year, disclosure.month, disclosure.day, 10, 0, tzinfo=ZoneInfo("Asia/Dubai"))
        disclosed_utc = disclosed_now.astimezone(ZoneInfo("UTC")).isoformat(timespec="seconds")
        with mock.patch.object(hr_server, "local_now", return_value=disclosed_now), mock.patch.object(hr_server, "now_iso", return_value=disclosed_utc):
            published = worker.request("GET", f"/api/evaluations/{evaluation_id}")
            self.assertTrue(published["evaluation"]["published"])
            self.assertEqual(published["evaluation"]["weighted_score"], 78)
            self.assertIn(evaluation_id, {row["id"] for row in worker.request("GET", "/api/evaluations/history")["items"]})
            result_notice = next(row for row in worker.request("GET", "/api/notifications/inbox")["items"] if row["id"] == scheduled[0])
            self.assertEqual(result_notice["body"], "أصبحت نتيجة تقييمك متاحة في صفحة التقييم السنوي.")
            grievance = worker.request(
                "POST", f"/api/evaluations/{evaluation_id}/grievance",
                {"reason": "مراجعة القياس", "note": "أطلب مراجعة التقرير النهائي."}, expected=201,
            )["grievance"]
            rejected = hr.request(
                "POST", f"/api/evaluation-grievances/{grievance['id']}/resolve",
                {"action": "reject", "resolution_note": "تمت مراجعة السجلات وتبين سلامة القياس."},
            )
            self.assertEqual(rejected["grievance"]["status"], "rejected")
            self.assertEqual(rejected["evaluation"]["weighted_score"], 78)

    def test_34_v50_frontend_workflow_privacy_contract_and_cache(self):
        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8")
        app = (root / "app.js").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")
        server = (root / "server.py").read_text(encoding="utf-8")
        schema = (root / "schema.sql").read_text(encoding="utf-8")
        self.assertIn('styles.css?v=5.7.0', index)
        self.assertIn('app.js?v=5.7.0', index)
        for marker in ("evaluationWorkflowRibbon", "evaluationPrivacyGate", "myEvaluationHistory", "managerEvaluationForm", "hrApproveForm", "evaluationGrievanceForm"):
            self.assertIn(marker, index + app)
        for endpoint in ("manager-review", "hr-review", "/grievance", "evaluation-grievances"):
            self.assertIn(endpoint, app + server)
        self.assertIn("النتيجة محجوبة حتى الإفصاح", app)
        self.assertIn("if(ev.status==='submitted')return tr('عند المسؤول المباشر')", app)
        self.assertIn("workflow-step", styles)
        self.assertIn("evaluation-history-cards", app + styles)
        self.assertIn("evaluation-history-record", app + styles)
        self.assertIn(".evaluation-history-table{display:none}", styles)
        self.assertIn(".evaluation-history-cards{display:grid", styles)
        self.assertIn("@media(max-width:520px)", styles)
        self.assertNotIn("صفحة التقيم السنوي", server)
        self.assertIn("صفحة التقييم السنوي", server)
        self.assertIn("evaluation_grievances", schema + server)
        self.assertIn("contract_document_id", server)
        self.assertNotIn('document_type=\'residency\' AND archived=0', server)
        self.assertIn("n.available_at IS NULL OR n.available_at<=?", server)

    def test_35_v50_migration_preserves_v49_evaluation_and_adds_workflow_tables(self):
        with tempfile.TemporaryDirectory(prefix="hr-v50-migration-") as folder:
            legacy_path = Path(folder) / "legacy-v49.sqlite3"
            hr_server.initialize_database(legacy_path)
            with contextlib.closing(sqlite3.connect(legacy_path)) as legacy:
                legacy.execute("PRAGMA foreign_keys=OFF")
                cycle_id = legacy.execute("SELECT id FROM evaluation_cycles LIMIT 1").fetchone()[0]
                employee_id = legacy.execute("SELECT id FROM employees WHERE employee_no='EMP-1024'").fetchone()[0]
                manager_id = legacy.execute("SELECT id FROM employees WHERE employee_no='EMP-1002'").fetchone()[0]
                general_manager_id = legacy.execute("SELECT id FROM employees WHERE employee_no='EMP-1001'").fetchone()[0]
                template_id = legacy.execute(
                    """SELECT t.id FROM evaluation_goal_templates t
                       JOIN employees e ON e.job_title_id=t.job_title_id
                       WHERE e.id=? ORDER BY t.id LIMIT 1""",
                    (employee_id,),
                ).fetchone()[0]
                stamp = datetime.now().isoformat(timespec="seconds")
                legacy.executescript("""
                    DROP TABLE IF EXISTS evaluation_grievances;
                    CREATE TABLE evaluations_v49 (
                      id INTEGER PRIMARY KEY AUTOINCREMENT, cycle_id INTEGER NOT NULL, employee_id INTEGER NOT NULL,
                      status TEXT NOT NULL DEFAULT 'draft', weighted_score REAL, rating TEXT, current_step INTEGER NOT NULL DEFAULT 0,
                      submitted_at TEXT, finalized_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                    );
                """)
                in_review_id = legacy.execute(
                    """INSERT INTO evaluations_v49
                       (cycle_id,employee_id,status,weighted_score,rating,current_step,submitted_at,finalized_at,created_at,updated_at)
                       VALUES(?,?,'in_review',76,'جيد',2,?,NULL,?,?)""",
                    (cycle_id, employee_id, stamp, stamp, stamp),
                ).lastrowid
                approved_id = legacy.execute(
                    """INSERT INTO evaluations_v49
                       (cycle_id,employee_id,status,weighted_score,rating,current_step,submitted_at,finalized_at,created_at,updated_at)
                       VALUES(?,?,'approved',88,'جيد جداً',2,?,?,?,?)""",
                    (cycle_id, manager_id, stamp, stamp, stamp, stamp),
                ).lastrowid
                legacy.execute(
                    """INSERT INTO evaluation_goals
                       (evaluation_id,source_template_id,title,description,weight,measure,achievement,awarded_points,employee_comment,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (in_review_id, template_id, "هدف V4.9 محفوظ", "", 100, "الإنجاز", 76, 76, "", stamp, stamp),
                )
                legacy.execute(
                    "INSERT INTO evaluation_approvals(evaluation_id,step_no,approver_employee_id,status,created_at) VALUES(?,1,?,'approved',?)",
                    (in_review_id, manager_id, stamp),
                )
                legacy.execute(
                    "INSERT INTO evaluation_approvals(evaluation_id,step_no,approver_employee_id,status,created_at) VALUES(?,2,?,'pending',?)",
                    (in_review_id, general_manager_id, stamp),
                )
                legacy.executescript("DROP TABLE evaluations; ALTER TABLE evaluations_v49 RENAME TO evaluations;")
                legacy.commit()
            hr_server.initialize_database(legacy_path)
            with contextlib.closing(sqlite3.connect(legacy_path)) as migrated:
                migrated.row_factory = sqlite3.Row
                columns = {row[1] for row in migrated.execute("PRAGMA table_info(evaluations)")}
                self.assertTrue({"workflow_version", "manager_employee_id", "manager_report", "disclosure_date"}.issubset(columns))
                active = migrated.execute("SELECT * FROM evaluations WHERE id=?", (in_review_id,)).fetchone()
                self.assertEqual(active["workflow_version"], 2)
                self.assertEqual(active["status"], "submitted")
                self.assertEqual(active["manager_employee_id"], manager_id)
                self.assertEqual(active["submitted_at"], stamp)
                self.assertIsNone(active["weighted_score"])
                self.assertIsNone(active["rating"])
                self.assertEqual(active["manager_report"], "")
                steps = migrated.execute("SELECT * FROM evaluation_approvals WHERE evaluation_id=? ORDER BY step_no", (in_review_id,)).fetchall()
                self.assertEqual(len(steps), 1)
                self.assertEqual(steps[0]["approver_employee_id"], manager_id)
                self.assertEqual(steps[0]["status"], "pending")
                preserved_goal = migrated.execute("SELECT * FROM evaluation_goals WHERE evaluation_id=?", (in_review_id,)).fetchone()
                self.assertEqual(preserved_goal["title"], "هدف V4.9 محفوظ")
                self.assertEqual(preserved_goal["source_template_id"], template_id)
                self.assertIsNone(preserved_goal["awarded_points"])

                historical = migrated.execute("SELECT * FROM evaluations WHERE id=?", (approved_id,)).fetchone()
                self.assertEqual(historical["workflow_version"], 1)
                self.assertEqual(historical["status"], "approved")
                self.assertEqual(historical["weighted_score"], 88)
                self.assertTrue(migrated.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='evaluation_grievances'").fetchone())
                self.assertIn("awarded_points", {row[1] for row in migrated.execute("PRAGMA table_info(evaluation_goals)")})
                self.assertIn("available_at", {row[1] for row in migrated.execute("PRAGMA table_info(notifications)")})

            # A second startup is idempotent, and approved V1 history remains
            # published through the employee's normal history endpoint.
            httpd = hr_server.make_server(legacy_path, "127.0.0.1", 0, Path(__file__).parents[1])
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                client = APIClient(f"http://127.0.0.1:{httpd.server_address[1]}")
                client.login("manager@demo.ae", "Manager@12345")
                history = client.request("GET", "/api/evaluations/history")["items"]
                self.assertIn(approved_id, {row["id"] for row in history})
                with contextlib.closing(sqlite3.connect(legacy_path)) as checked:
                    self.assertEqual(checked.execute("SELECT COUNT(*) FROM evaluation_approvals WHERE evaluation_id=?", (in_review_id,)).fetchone()[0], 1)
                    self.assertEqual(checked.execute("SELECT COUNT(*) FROM audit_log WHERE action='evaluation.workflow_migrate_v2' AND entity_id=?", (str(in_review_id),)).fetchone()[0], 1)
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=5)

    def test_36_v51_cycle_rbac_scope_preview_announcement_and_extension(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        employee = self.client("employee@demo.ae", "Emp@12345")
        permissions = hr.request("GET", "/api/auth/me")["permissions"]
        self.assertIn("evaluation.cycle.manage", permissions)
        employee.request("GET", "/api/evaluation-cycles", expected=403)
        employee.request("POST", "/api/evaluation-cycles", {}, expected=403)

        today = date.today()
        cycle_body = {
            "year": 2188, "name": "دورة الحوكمة المهنية 2188",
            "period_start": (today - timedelta(days=180)).isoformat(),
            "period_end": (today + timedelta(days=180)).isoformat(),
            "self_opens_on": (today - timedelta(days=10)).isoformat(),
            "self_due_on": (today + timedelta(days=20)).isoformat(),
            "manager_due_on": (today + timedelta(days=30)).isoformat(),
            "hr_due_on": (today + timedelta(days=40)).isoformat(),
            "announcement_title": "انطلاق دورة الحوكمة المهنية",
            "announcement_body": "أكمل تقييمك الذاتي وفق فترة الأداء والمواعيد المعتمدة.",
        }
        created = hr.request("POST", "/api/evaluation-cycles", cycle_body, expected=201)["cycle"]
        cycle_id = created["id"]
        self.assertEqual(created["status"], "draft")
        self.assertEqual(created["counts"]["total"], 0)
        self.assertGreater(created["preview"]["eligible"], 0)
        employee.request("POST", "/api/evaluations", {"cycle_id": cycle_id}, expected=403)

        announced = hr.request("POST", f"/api/evaluation-cycles/{cycle_id}/announce", {})
        self.assertFalse(announced["idempotent"])
        cycle = announced["cycle"]
        self.assertEqual(cycle["status"], "announced")
        self.assertEqual(cycle["counts"]["total"], created["preview"]["eligible"])
        self.assertEqual(len(cycle["recipients"]), created["preview"]["eligible"])
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            assigned = db.execute("SELECT COUNT(*) FROM evaluations WHERE cycle_id=?", (cycle_id,)).fetchone()[0]
            account_scope = db.execute(
                """SELECT COUNT(*) FROM users u JOIN employees e ON e.id=u.employee_id
                     WHERE u.active=1 AND e.active=1"""
            ).fetchone()[0]
            delivery_rows = db.execute(
                "SELECT COUNT(*) FROM evaluation_cycle_notifications WHERE cycle_id=?", (cycle_id,)
            ).fetchone()[0]
            distinct_notifications = db.execute(
                "SELECT COUNT(DISTINCT notification_id) FROM evaluation_cycle_notifications WHERE cycle_id=?", (cycle_id,)
            ).fetchone()[0]
            bodies = [row[0] for row in db.execute(
                """SELECT n.body FROM evaluation_cycle_notifications ecn
                     JOIN notifications n ON n.id=ecn.notification_id WHERE ecn.cycle_id=?""", (cycle_id,)
            )]
        self.assertEqual(assigned, created["preview"]["eligible"])
        self.assertEqual(delivery_rows, account_scope)
        self.assertEqual(distinct_notifications, account_scope)
        self.assertTrue(all(cycle_body["period_start"] in body and cycle_body["self_due_on"] in body for body in bodies))

        second = hr.request("POST", f"/api/evaluation-cycles/{cycle_id}/announce", {})
        self.assertTrue(second["idempotent"])
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM evaluation_cycle_notifications WHERE cycle_id=?", (cycle_id,)).fetchone()[0], delivery_rows)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM evaluations WHERE cycle_id=?", (cycle_id,)).fetchone()[0], assigned)

        employee.request("POST", "/api/evaluations", {"cycle_id": cycle_id, "employee_id": 1}, expected=403)
        own = employee.request("POST", "/api/evaluations", {"cycle_id": cycle_id})
        self.assertEqual(own["evaluation"]["cycle_id"], cycle_id)
        hr.request(
            "PATCH", f"/api/evaluation-cycles/{cycle_id}",
            {"self_due_on": today.isoformat(), "manager_due_on": (today + timedelta(days=30)).isoformat(), "hr_due_on": (today + timedelta(days=40)).isoformat(), "reason": "تقليص غير مسموح"},
            expected=422,
        )
        extended = hr.request(
            "PATCH", f"/api/evaluation-cycles/{cycle_id}",
            {"self_due_on": (today + timedelta(days=22)).isoformat(), "manager_due_on": (today + timedelta(days=32)).isoformat(), "hr_due_on": (today + timedelta(days=42)).isoformat(), "reason": "إتاحة وقت إضافي للفرق التشغيلية"},
        )["cycle"]
        self.assertEqual(extended["extension_reason"], "إتاحة وقت إضافي للفرق التشغيلية")

    def test_37_v51_goal_ownership_validation_and_employee_manager_hr_path(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        worker = self.client("employee@demo.ae", "Emp@12345")
        manager = self.client("manager@demo.ae", "Manager@12345")
        today = date.today()
        cycle = hr.request(
            "POST", "/api/evaluation-cycles",
            {
                "year": 2189, "name": "دورة سجل الأهداف 2189",
                "period_start": (today - timedelta(days=120)).isoformat(), "period_end": (today + timedelta(days=120)).isoformat(),
                "self_opens_on": (today - timedelta(days=5)).isoformat(), "self_due_on": (today + timedelta(days=15)).isoformat(),
                "manager_due_on": (today + timedelta(days=25)).isoformat(), "hr_due_on": (today + timedelta(days=35)).isoformat(),
                "announcement_title": "دورة سجل الأهداف", "announcement_body": "سجّل الأهداف والنتائج والأدلة.",
            }, expected=201,
        )["cycle"]
        hr.request("POST", f"/api/evaluation-cycles/{cycle['id']}/announce", {})
        evaluation = worker.request("POST", "/api/evaluations", {"cycle_id": cycle["id"]})["evaluation"]
        evaluation_id = evaluation["id"]
        base_goal = {
            "title": "تحسين جودة الخدمة", "description": "خفض إعادة العمل", "weight": 100,
            "measure": "نسبة المعاملات الصحيحة", "goal_type": "result",
            "start_date": cycle["period_start"], "end_date": cycle["period_end"],
            "progress_status": "in_progress", "achievement": 65, "evidence_note": "",
        }
        invalid_dates = dict(base_goal, start_date=(today - timedelta(days=200)).isoformat())
        self.assertEqual(worker.request("POST", f"/api/evaluations/{evaluation_id}/goals", invalid_dates, expected=422)["code"], "goal_outside_cycle_period")
        mismatch = dict(base_goal, progress_status="completed", achievement=65)
        self.assertEqual(worker.request("POST", f"/api/evaluations/{evaluation_id}/goals", mismatch, expected=422)["code"], "goal_progress_mismatch")
        goal = worker.request("POST", f"/api/evaluations/{evaluation_id}/goals", base_goal, expected=201)["goals"][0]
        self.assertEqual(worker.request("POST", f"/api/evaluations/{evaluation_id}/submit", {}, expected=422)["code"], "goal_evidence_required")
        worker.request("PATCH", f"/api/evaluation-goals/{goal['id']}", {"evidence_note": "أظهر تقرير الجودة انخفاض إعادة العمل إلى 4%."})

        hr_cycle = hr.request("GET", f"/api/evaluation-cycles/{cycle['id']}")["cycle"]
        hr_employee_id = hr.request("GET", "/api/auth/me")["user"]["employee_id"]
        hr_evaluation_id = next(item["evaluation_id"] for item in hr_cycle["recipients"] if item["employee_id"] == hr_employee_id)
        worker.request("GET", f"/api/evaluations/{hr_evaluation_id}", expected=403)
        manager.request("GET", f"/api/evaluations/{hr_evaluation_id}", expected=403)
        manager.request("PATCH", f"/api/evaluation-goals/{goal['id']}", {"evidence_note": "محاولة مدير"}, expected=403)

        submitted = worker.request("POST", f"/api/evaluations/{evaluation_id}/submit", {})
        self.assertEqual(submitted["evaluation"]["status"], "submitted")
        self.assertEqual(submitted["goals"][0]["achievement"], 65)
        self.assertNotIn("awarded_points", submitted["goals"][0])
        worker.request("PATCH", f"/api/evaluation-goals/{goal['id']}", {"evidence_note": "بعد الإرسال"}, expected=409)
        manager_view = manager.request("GET", f"/api/evaluations/{evaluation_id}")
        self.assertEqual(manager_view["goals"][0]["evidence_note"], "أظهر تقرير الجودة انخفاض إعادة العمل إلى 4%.")
        reviewed = manager.request(
            "POST", f"/api/evaluations/{evaluation_id}/manager-review",
            {"manager_report": "النتيجة موثقة ومتسقة مع مؤشر الجودة.", "goals": [{"id": goal["id"], "awarded_points": 82}]},
        )
        self.assertEqual(reviewed["evaluation"]["status"], "in_review")
        approved = hr.request(
            "POST", f"/api/evaluations/{evaluation_id}/hr-review",
            {"action": "approve", "comment": "اعتمدت الموارد البشرية النتيجة.", "disclosure_date": (today + timedelta(days=1)).isoformat()},
        )
        self.assertEqual(approved["evaluation"]["status"], "approved")

    def test_38_v51_automatic_and_manual_reminders_are_persistent_and_idempotent(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        today = date.today()
        due = today + timedelta(days=10)
        cycle = hr.request(
            "POST", "/api/evaluation-cycles",
            {
                "year": 2190, "name": "دورة التذكيرات 2190",
                "period_start": (today - timedelta(days=100)).isoformat(), "period_end": (today + timedelta(days=100)).isoformat(),
                "self_opens_on": (today - timedelta(days=2)).isoformat(), "self_due_on": due.isoformat(),
                "manager_due_on": (due + timedelta(days=10)).isoformat(), "hr_due_on": (due + timedelta(days=20)).isoformat(),
                "announcement_title": "دورة التذكيرات", "announcement_body": "أكمل تقييمك قبل الموعد.",
            }, expected=201,
        )["cycle"]
        hr.request("POST", f"/api/evaluation-cycles/{cycle['id']}/announce", {})
        with contextlib.closing(hr_server.open_db(self.db_path)) as db:
            employee_id = db.execute("SELECT id FROM employees WHERE employee_no='EMP-1024'").fetchone()["id"]
            db.execute("UPDATE evaluations SET status='submitted' WHERE cycle_id=? AND employee_id=?", (cycle["id"], employee_id))
            db.commit()
            expected_drafts = db.execute(
                """SELECT COUNT(*) FROM evaluations ev JOIN users u ON u.employee_id=ev.employee_id AND u.active=1
                     WHERE ev.cycle_id=? AND ev.status='draft'""", (cycle["id"],)
            ).fetchone()[0]
            self.assertEqual(hr_server.process_evaluation_reminders(db, due - timedelta(days=4)), 0)
            db.commit()
            self.assertEqual(hr_server.process_evaluation_reminders(db, due - timedelta(days=3)), expected_drafts)
            db.commit()
            self.assertEqual(hr_server.process_evaluation_reminders(db, due - timedelta(days=3)), 0)
            db.commit()
            self.assertEqual(hr_server.process_evaluation_reminders(db, due), expected_drafts)
            db.commit()
            self.assertEqual(hr_server.process_evaluation_reminders(db, due + timedelta(days=1)), expected_drafts)
            db.commit()
            grouped = db.execute(
                """SELECT reminder_type,COUNT(*) AS amount FROM evaluation_reminders
                     WHERE cycle_id=? AND reminder_type IN ('due_soon','due_today','overdue') GROUP BY reminder_type""", (cycle["id"],)
            ).fetchall()
            self.assertEqual({row["reminder_type"]: row["amount"] for row in grouped}, {"due_soon": expected_drafts, "due_today": expected_drafts, "overdue": expected_drafts})
            self.assertEqual(db.execute("SELECT COUNT(*) FROM evaluation_reminders WHERE cycle_id=? AND employee_id=?", (cycle["id"], employee_id)).fetchone()[0], 0)
            reminder_target = db.execute("SELECT employee_id FROM evaluations WHERE cycle_id=? AND status='draft' LIMIT 1", (cycle["id"],)).fetchone()["employee_id"]
        with self.assertRaises(sqlite3.ProgrammingError):
            db.execute("SELECT 1")
        first = hr.request("POST", f"/api/evaluation-cycles/{cycle['id']}/reminders", {"employee_ids": [reminder_target]})
        second = hr.request("POST", f"/api/evaluation-cycles/{cycle['id']}/reminders", {"employee_ids": [reminder_target]})
        self.assertEqual(first["sent"], 1)
        self.assertEqual(second["sent"], 0)
        self.assertEqual(second["skipped"], 1)

    def test_39_v51_late_submission_is_allowed_marked_audited_and_closed_cycle_blocks_work(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        worker = self.client("employee@demo.ae", "Emp@12345")
        today = date.today()
        cycle = hr.request(
            "POST", "/api/evaluation-cycles",
            {
                "year": 2191, "name": "دورة الإرسال المتأخر 2191",
                "period_start": (today - timedelta(days=100)).isoformat(), "period_end": (today + timedelta(days=100)).isoformat(),
                "self_opens_on": (today - timedelta(days=20)).isoformat(), "self_due_on": (today - timedelta(days=1)).isoformat(),
                "manager_due_on": (today + timedelta(days=5)).isoformat(), "hr_due_on": (today + timedelta(days=12)).isoformat(),
                "announcement_title": "دورة الإرسال المتأخر", "announcement_body": "يبقى الإرسال ممكناً مع وسم التأخير.",
            }, expected=201,
        )["cycle"]
        hr.request("POST", f"/api/evaluation-cycles/{cycle['id']}/announce", {})
        evaluation = worker.request("POST", "/api/evaluations", {"cycle_id": cycle["id"]})["evaluation"]
        goal = {
            "title": "هدف متأخر موثق", "description": "نتيجة تشغيلية", "weight": 100, "measure": "نسبة الإنجاز",
            "goal_type": "behaviour", "start_date": cycle["period_start"], "end_date": cycle["period_end"],
            "progress_status": "completed", "achievement": 100, "evidence_note": "محضر إنجاز موقع من الفريق.",
        }
        worker.request("POST", f"/api/evaluations/{evaluation['id']}/goals", goal, expected=201)
        submitted = worker.request("POST", f"/api/evaluations/{evaluation['id']}/submit", {})
        self.assertTrue(submitted["evaluation"]["submitted_late"])
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM audit_log WHERE action='evaluation.employee_submit_late' AND entity_id=?", (str(evaluation["id"]),)).fetchone()[0], 1)
        hr.request("PATCH", f"/api/evaluation-cycles/{cycle['id']}", {"status": "closed", "reason": "انتهاء أعمال الدورة"})
        own_hr = hr.request("POST", "/api/evaluations", {"cycle_id": cycle["id"]})["evaluation"]
        hr.request("POST", f"/api/evaluations/{own_hr['id']}/goals", goal, expected=409)

    def test_40_v51_realistic_v50_migration_and_frontend_responsive_contract(self):
        with tempfile.TemporaryDirectory(prefix="hr-v51-migration-") as folder:
            legacy_path = Path(folder) / "legacy-v50.sqlite3"
            hr_server.initialize_database(legacy_path)
            with contextlib.closing(sqlite3.connect(legacy_path)) as legacy:
                legacy.execute("PRAGMA foreign_keys=OFF")
                cycle_id = legacy.execute("SELECT id FROM evaluation_cycles LIMIT 1").fetchone()[0]
                evaluation_id, employee_id = legacy.execute(
                    "SELECT id,employee_id FROM evaluations ORDER BY id DESC LIMIT 1"
                ).fetchone()
                template_id = legacy.execute("SELECT id FROM evaluation_goal_templates ORDER BY id LIMIT 1").fetchone()[0]
                manager_id = legacy.execute("SELECT manager_id FROM employees WHERE id=?", (employee_id,)).fetchone()[0]
                stamp = datetime.now().isoformat(timespec="seconds")
                goal_id = legacy.execute(
                    """INSERT INTO evaluation_goals
                       (evaluation_id,source_template_id,title,description,weight,measure,achievement,goal_type,start_date,end_date,progress_status,evidence_note,awarded_points,employee_comment,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (evaluation_id, template_id, "هدف V5.0 محفوظ", "", 100, "الإنجاز", 42, "result", date.today().isoformat(), date.today().isoformat(), "in_progress", "", 38, "دليل الترحيل الأصلي", stamp, stamp),
                ).lastrowid
                legacy.execute(
                    """UPDATE evaluations SET workflow_version=2,status='in_review',manager_employee_id=?,manager_report='تقرير V5.0 محفوظ',manager_submitted_at=?,weighted_score=38 WHERE id=?""",
                    (manager_id, stamp, evaluation_id),
                )
                legacy.executescript("""
                    DROP INDEX IF EXISTS idx_evaluation_goal_template_once;
                    DROP TABLE evaluation_cycle_notifications;
                    DROP TABLE evaluation_reminders;
                    CREATE TABLE evaluation_goals_v50 (
                      id INTEGER PRIMARY KEY AUTOINCREMENT, evaluation_id INTEGER NOT NULL, source_template_id INTEGER,
                      title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', weight REAL NOT NULL,
                      measure TEXT NOT NULL DEFAULT '', achievement REAL NOT NULL DEFAULT 0, awarded_points REAL,
                      employee_comment TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                    );
                    INSERT INTO evaluation_goals_v50 SELECT id,evaluation_id,source_template_id,title,description,weight,measure,achievement,awarded_points,employee_comment,created_at,updated_at FROM evaluation_goals;
                    DROP TABLE evaluation_goals;
                    ALTER TABLE evaluation_goals_v50 RENAME TO evaluation_goals;
                    CREATE TABLE evaluation_cycles_v50 (
                      id INTEGER PRIMARY KEY AUTOINCREMENT, year INTEGER NOT NULL UNIQUE, name TEXT NOT NULL,
                      starts_on TEXT NOT NULL, ends_on TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
                    );
                    INSERT INTO evaluation_cycles_v50 SELECT id,year,name,starts_on,ends_on,active FROM evaluation_cycles;
                    DROP TABLE evaluation_cycles;
                    ALTER TABLE evaluation_cycles_v50 RENAME TO evaluation_cycles;
                """)
                legacy.commit()
            hr_server.initialize_database(legacy_path)
            with contextlib.closing(sqlite3.connect(legacy_path)) as migrated:
                migrated.row_factory = sqlite3.Row
                cycle = migrated.execute("SELECT * FROM evaluation_cycles WHERE id=?", (cycle_id,)).fetchone()
                evaluation = migrated.execute("SELECT * FROM evaluations WHERE id=?", (evaluation_id,)).fetchone()
                goal = migrated.execute("SELECT * FROM evaluation_goals WHERE id=?", (goal_id,)).fetchone()
                self.assertEqual(cycle["status"], "announced")
                self.assertTrue(cycle["period_start"] and cycle["self_due_on"] and cycle["announced_at"])
                self.assertEqual(evaluation["id"], evaluation_id)
                self.assertEqual(evaluation["status"], "in_review")
                self.assertEqual(evaluation["manager_report"], "تقرير V5.0 محفوظ")
                self.assertEqual(goal["title"], "هدف V5.0 محفوظ")
                self.assertEqual(goal["source_template_id"], template_id)
                self.assertEqual(goal["goal_type"], "result")
                self.assertEqual(goal["progress_status"], "in_progress")
                self.assertEqual(goal["evidence_note"], "دليل الترحيل الأصلي")
                announcement_count = migrated.execute("SELECT COUNT(*) FROM evaluation_cycle_notifications WHERE cycle_id=?", (cycle_id,)).fetchone()[0]
                self.assertGreater(announcement_count, 0)
            hr_server.initialize_database(legacy_path)
            with contextlib.closing(sqlite3.connect(legacy_path)) as checked:
                self.assertEqual(checked.execute("SELECT COUNT(*) FROM evaluation_cycle_notifications WHERE cycle_id=?", (cycle_id,)).fetchone()[0], announcement_count)
                self.assertEqual(checked.execute("SELECT COUNT(*) FROM evaluations WHERE id=?", (evaluation_id,)).fetchone()[0], 1)

        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8")
        app = (root / "app.js").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")
        schema = (root / "schema.sql").read_text(encoding="utf-8")
        for marker in ("evaluationCycleConsole", "evaluationCycleSelect", "evaluationAnnouncement", "goal_type", "progress_status", "evidence_note"):
            self.assertIn(marker, index + app + schema)
        self.assertIn("cycle-control-tower", styles)
        self.assertIn(".cycle-recipient-table{display:none}", styles)
        self.assertIn(".cycle-recipient-cards{display:grid", styles)
        self.assertIn("@media(max-width:720px)", styles)
        self.assertIn("@media(max-width:440px)", styles)
        self.assertIn("overflow-x:hidden", styles)
        self.assertIn("evaluation.cycle.manage", app + schema + (root / "server.py").read_text(encoding="utf-8"))
        self.assertIn('styles.css?v=5.7.0', index)
        self.assertIn('app.js?v=5.7.0', index)


    def test_57_v56_profile_fields_age_privacy_permissions_and_emergency_contacts(self):
        admin = self.client("admin@demo.ae", "Admin@123")
        hr = self.client("hr@demo.ae", "HR@12345")
        manager = self.client("manager@demo.ae", "Manager@12345")
        employee = self.client("employee@demo.ae", "Emp@12345")
        suffix = uuid.uuid4().hex[:8]
        users = admin.request("GET", "/api/admin/users")["items"]
        employee_user = next(user for user in users if user["email"] == "employee@demo.ae")
        hr_user = next(user for user in users if user["email"] == "hr@demo.ae")
        with contextlib.closing(hr_server.open_db(self.db_path)) as db:
            manager_employee_id = db.execute("SELECT employee_id FROM users WHERE email='manager@demo.ae'").fetchone()["employee_id"]
        birth = date(1990, 8, 24)
        target = admin.request(
            "POST", "/api/employees",
            {
                "employee_no": f"V56-{suffix}", "full_name": "موظف ملف موسع",
                "email": f"v56-{suffix}@demo.ae", "phone": "+971501234567",
                "birth_date": birth.isoformat(), "nationality": "الإمارات العربية المتحدة",
                "place_of_birth": "أبوظبي", "passport_no": f"P{suffix.upper()}",
                "passport_expires_on": "2032-08-01", "emirates_id_no": "784-1990-1234567-1",
                "emirates_id_expires_on": "2031-05-15", "qualification": "بكالوريوس",
                "marital_status": "married", "address_country": "الإمارات العربية المتحدة",
                "address_city": "أبوظبي", "address_area": "الزاهية", "address_street": "شارع الاختبار",
                "address_building": "مبنى 8 / 210", "address_po_box": "12345",
                "address_notes": "مدخل المبنى الشرقي", "manager_id": manager_employee_id,
                "hire_date": "2024-01-15", "photo_data": "data:image/png;base64,iVBORw0KGgo=",
                "create_user": True, "password": "Profile@12345", "role": "employee",
            }, expected=201,
        )["employee"]
        expected_age = date.today().year - birth.year - ((date.today().month, date.today().day) < (birth.month, birth.day))
        self.assertEqual(target["age_years"], expected_age)
        self.assertGreater(target["profile_completeness"]["percent"], 60)
        self.assertEqual(target["marital_status"], "married")

        listed = admin.request("GET", "/api/employees")
        listed_target = next(item for item in listed["items"] if item["id"] == target["id"])
        for sensitive in ("birth_date", "passport_no", "passport_expires_on", "emirates_id_no", "emirates_id_expires_on", "address_street"):
            self.assertNotIn(sensitive, listed_target)
        serialized_list = json.dumps(listed, ensure_ascii=False)
        self.assertNotIn(f"P{suffix.upper()}", serialized_list)
        self.assertNotIn("784-1990-1234567-1", serialized_list)

        manager.request("PATCH", f"/api/employees/{target['id']}", {"full_name": "ممنوع"}, expected=403)
        employee.request("PATCH", f"/api/employees/{target['id']}", {"full_name": "ممنوع"}, expected=403)
        hr_updated = hr.request("PATCH", f"/api/employees/{target['id']}", {"place_of_birth": "العين"})["employee"]
        self.assertEqual(hr_updated["place_of_birth"], "العين")
        admin.request("PATCH", f"/api/employees/{target['id']}", {"qualification": "ماجستير"})
        admin.request("PATCH", f"/api/employees/{target['id']}", {"birth_date": (date.today() + timedelta(days=1)).isoformat()}, expected=422)
        admin.request("PATCH", f"/api/employees/{target['id']}", {"birth_date": "2000-01-01", "passport_expires_on": "1999-12-31"}, expected=422)

        admin.request("PATCH", f"/api/admin/users/{employee_user['id']}/permissions", {"overrides": [{"permission": "employee.profile.edit", "granted": True}]})
        employee.request("PATCH", f"/api/employees/{target['id']}", {"place_of_birth": "دبي"})
        explicitly_scoped = employee.request("GET", "/api/employees")
        self.assertEqual(explicitly_scoped["scope"], "all")
        self.assertNotIn("passport_no", next(item for item in explicitly_scoped["items"] if item["id"] == target["id"]))
        admin.request("PATCH", f"/api/admin/users/{employee_user['id']}/permissions", {"overrides": [{"permission": "employee.profile.edit", "granted": False}]})
        employee.request("PATCH", f"/api/employees/{target['id']}", {"place_of_birth": "الشارقة"}, expected=403)
        admin.request("PATCH", f"/api/admin/users/{employee_user['id']}/permissions", {"overrides": []})

        first = admin.request("POST", f"/api/employees/{target['id']}/emergency-contacts", {
            "full_name": "جهة أولى سرية", "relationship": "زوج", "phone": "+971500000001",
            "alternate_phone": "+971500000002", "email": "private-contact@example.test", "notes": "ملاحظة سرية",
        }, expected=201)["contact"]
        self.assertTrue(first["is_primary"])
        hr.request("POST", f"/api/employees/{target['id']}/emergency-contacts", {
            "full_name": "رقم غير صالح", "relationship": "قريب", "phone": "٠٥٠١٢٣٤٥٦٧",
        }, expected=422)
        second = hr.request("POST", f"/api/employees/{target['id']}/emergency-contacts", {
            "full_name": "جهة ثانية", "relationship": "شقيق", "phone": "+971500000003", "is_primary": True,
        }, expected=201)["contact"]
        contacts = admin.request("GET", f"/api/employees/{target['id']}/emergency-contacts")["items"]
        self.assertEqual(sum(bool(contact["is_primary"]) for contact in contacts), 1)
        self.assertTrue(next(contact for contact in contacts if contact["id"] == second["id"])["is_primary"])
        admin.request("PATCH", f"/api/emergency-contacts/{first['id']}", {"is_primary": True})
        contacts = admin.request("GET", f"/api/employees/{target['id']}/emergency-contacts")["items"]
        self.assertEqual([contact["id"] for contact in contacts if contact["is_primary"]], [first["id"]])
        manager.request("GET", f"/api/employees/{target['id']}/emergency-contacts", expected=403)
        target_self = self.client(f"v56-{suffix}@demo.ae", "Profile@12345")
        self.assertEqual(len(target_self.request("GET", f"/api/employees/{target['id']}/emergency-contacts")["items"]), 2)
        target_self.request("POST", f"/api/employees/{target['id']}/emergency-contacts", {"full_name": "ممنوع", "relationship": "قريب", "phone": "+971500000004"}, expected=403)
        admin.request("DELETE", f"/api/emergency-contacts/{first['id']}", expected=405)
        contacts = admin.request("GET", f"/api/employees/{target['id']}/emergency-contacts")["items"]
        self.assertEqual(len(contacts), 2)
        self.assertTrue(next(contact for contact in contacts if contact["id"] == first["id"])["is_primary"])

        admin.request("PATCH", f"/api/admin/users/{hr_user['id']}/permissions", {"overrides": [{"permission": "employee.emergency.manage", "granted": False}]})
        hr.request("POST", f"/api/employees/{target['id']}/emergency-contacts", {"full_name": "ممنوع", "relationship": "قريب", "phone": "+971500000005"}, expected=403)
        admin.request("PATCH", f"/api/admin/users/{hr_user['id']}/permissions", {"overrides": []})
        with contextlib.closing(hr_server.open_db(self.db_path)) as db:
            audit_details = " ".join(row["details"] for row in db.execute("SELECT details FROM audit_log WHERE action LIKE 'employee.emergency_contact.%' AND entity_id=?", (str(target["id"]),)).fetchall())
            self.assertNotIn("جهة أولى سرية", audit_details)
            self.assertNotIn("+971500000001", audit_details)
            self.assertNotIn("private-contact@example.test", audit_details)
            archived = db.execute("SELECT archived FROM employee_emergency_contacts WHERE id=?", (first["id"],)).fetchone()["archived"]
            self.assertEqual(archived, 0)

    def test_58_v56_attendance_range_calculations_and_privacy_scopes(self):
        admin = self.client("admin@demo.ae", "Admin@123")
        hr = self.client("hr@demo.ae", "HR@12345")
        manager = self.client("manager@demo.ae", "Manager@12345")
        suffix = uuid.uuid4().hex[:8]
        today = date.today()
        period_start = today - timedelta(days=today.weekday() + 7)
        period_end = period_start + timedelta(days=6)
        with contextlib.closing(hr_server.open_db(self.db_path)) as db:
            manager_employee_id = db.execute("SELECT employee_id FROM users WHERE email='manager@demo.ae'").fetchone()["employee_id"]
        target = admin.request("POST", "/api/employees", {
            "employee_no": f"ATT56-{suffix}", "full_name": "موظف حضور فترة",
            "email": f"att56-{suffix}@demo.ae", "manager_id": manager_employee_id,
            "branch_id": 1, "hire_date": period_start.isoformat(), "create_user": True,
            "password": "Attendance@12345", "role": "employee",
        }, expected=201)["employee"]
        shift = admin.request("POST", "/api/shifts", {
            "name": f"V56 Shift {suffix}", "start_time": "09:00", "end_time": "18:00",
            "break_minutes": 60, "grace_minutes": 10, "daily_limit_minutes": 480,
            "working_days": [0, 1, 2, 3, 4], "rest_days": [5, 6],
        }, expected=201)["shift"]
        admin.request("POST", f"/api/shifts/{shift['id']}/assign", {"employee_id": target["id"], "effective_from": period_start.isoformat()}, expected=201)
        monday, tuesday, _wednesday, thursday, friday = [period_start + timedelta(days=index) for index in range(5)]
        stamp = datetime.now().isoformat(timespec="seconds")
        def local_dt(day, clock):
            return f"{day.isoformat()}T{clock}:00+04:00"
        with contextlib.closing(hr_server.open_db(self.db_path)) as db:
            db.execute("INSERT INTO attendance(employee_id,work_date,branch_id,check_in_at,check_out_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (target["id"], monday.isoformat(), 1, local_dt(monday, "09:15"), local_dt(monday, "18:15"), stamp, stamp))
            db.execute("INSERT INTO attendance(employee_id,work_date,branch_id,check_in_at,created_at,updated_at) VALUES(?,?,?,?,?,?)", (target["id"], thursday.isoformat(), 1, local_dt(thursday, "09:00"), stamp, stamp))
            db.execute("INSERT INTO attendance(employee_id,work_date,branch_id,check_in_at,check_out_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (target["id"], friday.isoformat(), 1, local_dt(friday, "09:00"), local_dt(friday, "17:00"), stamp, stamp))
            leave_type_id = db.execute("SELECT id FROM leave_types WHERE active=1 ORDER BY id LIMIT 1").fetchone()["id"]
            approver_id = db.execute("SELECT id FROM users WHERE email='hr@demo.ae'").fetchone()["id"]
            db.execute("INSERT INTO leave_requests(employee_id,leave_type_id,start_date,end_date,days,status,manager_decision,decided_by,decided_at,created_at,updated_at) VALUES(?,?,?,?,?,'approved','approved',?,?,?,?)", (target["id"], leave_type_id, tuesday.isoformat(), tuesday.isoformat(), 1, approver_id, stamp, stamp, stamp))
            db.execute("INSERT INTO overtime_requests(employee_id,work_date,start_time,end_time,duration_minutes,reason,status,decided_by,decided_at,created_at,updated_at) VALUES(?,?,?,?,?,?, 'approved',?,?,?,?)", (target["id"], monday.isoformat(), "18:15", "19:45", 90, "إضافي V5.6", approver_id, stamp, stamp, stamp))
            db.commit()
        query = f"date_from={period_start.isoformat()}&date_to={period_end.isoformat()}&employee_id={target['id']}"
        ranged = hr.request("GET", "/api/attendance/range?" + query)
        self.assertEqual(ranged["scope"], "all")
        self.assertEqual(ranged["summary"]["work_days"], 5)
        self.assertEqual(ranged["summary"]["net_work_minutes"], 900)
        self.assertEqual(ranged["summary"]["late_minutes"], 5)
        self.assertEqual(ranged["summary"]["absence_days"], 1)
        self.assertEqual(ranged["summary"]["weekly_rest_days"], 2)
        self.assertEqual(ranged["summary"]["leave_days"], 1)
        self.assertEqual(ranged["summary"]["approved_overtime_minutes"], 90)
        self.assertEqual(ranged["summary"]["attendance_records"], 3)
        statuses = {item["work_date"]: item["day_status"] for item in ranged["items"]}
        self.assertEqual(statuses[tuesday.isoformat()], "approved_leave")
        self.assertEqual(statuses[thursday.isoformat()], "open")
        hr.request("GET", f"/api/attendance/range?date_from={period_end.isoformat()}&date_to={period_start.isoformat()}&employee_id={target['id']}", expected=400)

        team = manager.request("GET", "/api/attendance/range?" + query)
        self.assertEqual(team["scope"], "team_attendance")
        self.assertEqual(len(team["items"]), 3)
        self.assertEqual(set(team["summary"]), {"attendance_records"})
        for item in team["items"]:
            self.assertEqual(set(item), {"id", "employee_id", "employee_no", "full_name", "work_date", "check_in_at", "check_out_at"})
            self.assertNotIn("day_status", item)
        self_user = self.client(f"att56-{suffix}@demo.ae", "Attendance@12345")
        own = self_user.request("GET", f"/api/attendance/range?date_from={period_start.isoformat()}&date_to={period_end.isoformat()}")
        self.assertEqual(own["scope"], "self")
        self.assertTrue(all(item["employee_id"] == target["id"] for item in own["items"]))
        unrelated_id = admin.request("GET", "/api/employees")["items"][0]["id"]
        if unrelated_id != target["id"]:
            self_user.request("GET", f"/api/attendance/range?date_from={period_start.isoformat()}&date_to={period_end.isoformat()}&employee_id={unrelated_id}", expected=403)

    def test_59_v56_migration_frontend_i18n_and_responsive_contract(self):
        with tempfile.TemporaryDirectory(prefix="hr-v56-migration-") as folder:
            legacy_path = Path(folder) / "legacy-v55.sqlite3"
            hr_server.initialize_database(legacy_path)
            with contextlib.closing(sqlite3.connect(legacy_path)) as legacy:
                legacy.execute("PRAGMA foreign_keys=OFF")
                legacy.execute("INSERT INTO employees(employee_no,full_name,email,qualification,nationality,created_at,updated_at) VALUES('LEGACY-V55','موظف محفوظ','legacy-v55@example.test','دبلوم','الإمارات','2025-01-01','2025-01-01')")
                legacy.executescript("""
                    DROP TABLE employee_emergency_contacts;
                    CREATE TABLE employees_v55 (
                      id INTEGER PRIMARY KEY AUTOINCREMENT, employee_no TEXT NOT NULL UNIQUE, full_name TEXT NOT NULL,
                      email TEXT UNIQUE, phone TEXT NOT NULL DEFAULT '', job_title TEXT NOT NULL DEFAULT '', job_grade TEXT NOT NULL DEFAULT '',
                      job_title_id INTEGER, job_grade_id INTEGER, department_id INTEGER, branch_id INTEGER, manager_id INTEGER,
                      hire_date TEXT, qualification TEXT NOT NULL DEFAULT '', nationality TEXT NOT NULL DEFAULT '', salary REAL NOT NULL DEFAULT 0,
                      photo_data TEXT, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                    );
                    INSERT INTO employees_v55 SELECT id,employee_no,full_name,email,phone,job_title,job_grade,job_title_id,job_grade_id,department_id,branch_id,manager_id,hire_date,qualification,nationality,salary,photo_data,active,created_at,updated_at FROM employees;
                    DROP TABLE employees;
                    ALTER TABLE employees_v55 RENAME TO employees;
                """)
                legacy.commit()
            hr_server.initialize_database(legacy_path)
            hr_server.initialize_database(legacy_path)
            with contextlib.closing(sqlite3.connect(legacy_path)) as migrated:
                columns = {row[1] for row in migrated.execute("PRAGMA table_info(employees)")}
                for field in ("birth_date", "passport_no", "emirates_id_no", "marital_status", "address_country", "address_notes"):
                    self.assertIn(field, columns)
                legacy_employee = migrated.execute("SELECT full_name,qualification,nationality,marital_status FROM employees WHERE employee_no='LEGACY-V55'").fetchone()
                self.assertEqual(legacy_employee, ("موظف محفوظ", "دبلوم", "الإمارات", "unspecified"))
                self.assertIsNotNone(migrated.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='employee_emergency_contacts'").fetchone())

        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8")
        app = (root / "app.js").read_text(encoding="utf-8")
        i18n = (root / "i18n.js").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")
        server_source = (root / "server.py").read_text(encoding="utf-8")
        for asset in ("styles.css", "i18n.js", "app.js"):
            self.assertIn(f'{asset}?v=5.7.0', index)
        for marker in ("employee.profile.edit", "employee.emergency.manage", "employee_emergency_contacts", "api_attendance_range", "invalid_date_range"):
            self.assertIn(marker, server_source + app)
        for marker in ("employeeProfileForm", "emergencyContactForm", "profile-completeness", "attendanceRangeForm", "attendanceSummary", "attendance-table-wrap"):
            self.assertIn(marker, index + app + styles)
        list_renderer = app.split("function renderEmployees", 1)[1].split("async function openEmployee", 1)[0]
        for sensitive in ("passport_no", "emirates_id_no", "birth_date"):
            self.assertNotIn(sensitive, list_renderer)
        for source in ("البيانات الشخصية", "جهات الطوارئ", "جهات اتصال الطوارئ", "الاسم الكامل", "الجنسية", "الدولة", "إضافة جهة الاتصال", "رقم جواز السفر", "رقم الهوية الإماراتية", "فترة الكشف", "عرض محدود يحمي خصوصية الفريق", "إجازة معتمدة"):
            self.assertRegex(i18n, rf"['\"]{re.escape(source)}['\"]\s*:")
        self.assertIn("@media(max-width:900px)", styles)
        self.assertIn(".attendance-table-wrap{max-width:100%;overflow-x:auto", styles)
        self.assertIn(".attendance-table-wrap table{min-width:1040px}", styles)
        self.assertIn("overflow-x:hidden", styles)

    def test_60_v57_atomic_full_employee_profile_edit_and_languages(self):
        admin = self.client("admin@demo.ae", "Admin@123")
        suffix = uuid.uuid4().hex[:8]
        employee = admin.request("POST", "/api/employees", {
            "employee_no": f"V57-{suffix}",
            "full_name": "موظف ملف متكامل",
            "email": f"v57-{suffix}@demo.ae",
            "hire_date": "2024-01-15",
        }, expected=201)["employee"]
        updated = admin.request("PATCH", f"/api/employees/{employee['id']}", {
            "full_name": "موظف ملف متكامل محدّث",
            "phone": "+971501234567",
            "birth_date": "1991-06-20",
            "nationality": "الإمارات",
            "place_of_birth": "أبوظبي",
            "passport_no": f"P57{suffix}",
            "passport_expires_on": "2030-06-20",
            "emirates_id_no": "784-1991-1234567-1",
            "emirates_id_expires_on": "2030-06-20",
            "qualification": "بكالوريوس إدارة أعمال",
            "marital_status": "married",
            "job_title": "أخصائي موارد بشرية",
            "job_grade": "G-07",
            "address_country": "الإمارات",
            "address_city": "أبوظبي",
            "address_area": "الروضة",
            "address_street": "شارع المؤسسة",
            "address_building": "مبنى ٧",
            "address_po_box": "12345",
            "address_notes": "عنوان دائم معتمد",
            "languages": [
                {"code": "ar", "proficiency": "native"},
                {"code": "en", "proficiency": "very_good"},
            ],
        })["employee"]
        self.assertEqual(updated["full_name"], "موظف ملف متكامل محدّث")
        self.assertEqual(updated["birth_date"], "1991-06-20")
        self.assertEqual(updated["passport_no"], f"P57{suffix}")
        self.assertEqual(updated["marital_status"], "married")
        self.assertEqual(updated["address_notes"], "عنوان دائم معتمد")
        self.assertEqual([row["code"] for row in updated["languages"]], ["ar", "en"])
        fetched = admin.request("GET", f"/api/employees/{employee['id']}")["employee"]
        self.assertEqual(fetched["emirates_id_no"], "784-1991-1234567-1")
        self.assertEqual(fetched["qualification"], "بكالوريوس إدارة أعمال")
        self.assertEqual([row["proficiency"] for row in fetched["languages"]], ["native", "very_good"])
        with contextlib.closing(hr_server.open_db(self.db_path)) as db:
            audit_row = db.execute(
                "SELECT details FROM audit_log WHERE action='employee.update' AND entity_id=? ORDER BY id DESC LIMIT 1",
                (str(employee["id"]),),
            ).fetchone()
            self.assertIsNotNone(audit_row)
            self.assertIn("languages", audit_row["details"])

    def test_61_v57_attendance_csv_and_frontend_polish_contract(self):
        hr = self.client("hr@demo.ae", "HR@12345")
        today = date.today().isoformat()
        headers, content = hr.raw_request(f"/api/attendance/range.csv?date_from={today}&date_to={today}")
        self.assertIn("text/csv", headers.get("Content-Type", ""))
        self.assertIn("attendance-", headers.get("Content-Disposition", ""))
        self.assertTrue(content.startswith(b"\xef\xbb\xbf"))
        self.assertIn("اسم الموظف".encode("utf-8"), content)
        hr.request("GET", f"/api/attendance/range?date_from={today}&date_to={today}&status=invalid", expected=422)
        with contextlib.closing(hr_server.open_db(self.db_path)) as db:
            self.assertIsNotNone(db.execute("SELECT 1 FROM audit_log WHERE action='attendance.range_export' ORDER BY id DESC LIMIT 1").fetchone())

        root = Path(__file__).parents[1]
        index = (root / "index.html").read_text(encoding="utf-8")
        app = (root / "app.js").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")
        server_source = (root / "server.py").read_text(encoding="utf-8")
        for marker in (
            "function employeeProfileEditModal(employee)", "data-profile-editor-panel=\"${key}\"",
            "employeeProfilePayload", "profile-editor-tabs", "employee-card-viewport",
            "function fitAllCardPreviews", "function renderEmployeeReport(report)",
            "report-executive-grid", "function renderCertificate(data)", "Salary Certificate",
            "salary-certificate-verification", "attendance-presets", "exportAttendanceCsv",
        ):
            self.assertIn(marker, index + app + styles)
        self.assertIn('@page salaryCertificate{size:A4 portrait', styles)
        self.assertIn('font-family:var(--font-ar)', styles)
        self.assertIn('attendance.export', server_source)
        self.assertIn(r'/api/attendance/range\.csv', server_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
