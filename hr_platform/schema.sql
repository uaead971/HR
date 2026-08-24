PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS organization (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  display_name TEXT NOT NULL,
  legal_name TEXT NOT NULL,
  license_no TEXT NOT NULL DEFAULT '',
  tax_no TEXT NOT NULL DEFAULT '',
  sector TEXT NOT NULL DEFAULT '',
  emirate TEXT NOT NULL DEFAULT 'دبي',
  address TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  website TEXT NOT NULL DEFAULT '',
  timezone TEXT NOT NULL DEFAULT 'Asia/Dubai',
  currency TEXT NOT NULL DEFAULT 'AED',
  primary_color TEXT NOT NULL DEFAULT '#123f35',
  accent_color TEXT NOT NULL DEFAULT '#c48a3a',
  document_template TEXT NOT NULL DEFAULT 'corporate',
  visual_identity_enabled INTEGER NOT NULL DEFAULT 0 CHECK (visual_identity_enabled IN (0,1)),
  visual_identity_mode TEXT NOT NULL DEFAULT 'static' CHECK (visual_identity_mode IN ('static','rotation')),
  visual_identity_surface TEXT NOT NULL DEFAULT 'both' CHECK (visual_identity_surface IN ('login','dashboard','both')),
  visual_identity_interval_seconds INTEGER NOT NULL DEFAULT 20 CHECK (visual_identity_interval_seconds BETWEEN 5 AND 300),
  visual_identity_overlay INTEGER NOT NULL DEFAULT 58 CHECK (visual_identity_overlay BETWEEN 20 AND 90),
  card_template TEXT NOT NULL DEFAULT 'portrait_orbit' CHECK (card_template IN ('portrait_orbit','executive_horizontal','minimal_vertical')),
  card_primary_color TEXT NOT NULL DEFAULT '#123d34',
  card_accent_color TEXT NOT NULL DEFAULT '#c6a15b',
  card_back_instructions TEXT NOT NULL DEFAULT 'البطاقة شخصية ولا يجوز استخدامها من غير صاحبها. عند العثور عليها يرجى التواصل مع المؤسسة.',
  card_contact_phone TEXT NOT NULL DEFAULT '',
  card_contact_email TEXT NOT NULL DEFAULT '',
  smtp_host TEXT NOT NULL DEFAULT '',
  smtp_port INTEGER NOT NULL DEFAULT 587,
  smtp_tls INTEGER NOT NULL DEFAULT 1 CHECK (smtp_tls IN (0,1)),
  smtp_ssl INTEGER NOT NULL DEFAULT 0 CHECK (smtp_ssl IN (0,1)),
  smtp_username TEXT NOT NULL DEFAULT '',
  smtp_password_encrypted TEXT NOT NULL DEFAULT '',
  smtp_from_name TEXT NOT NULL DEFAULT '',
  smtp_from_email TEXT NOT NULL DEFAULT '',
  logo_data TEXT,
  stamp_data TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS visual_identity_slides (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  organization_id INTEGER NOT NULL DEFAULT 1 CHECK (organization_id = 1),
  image_data TEXT,
  image_mime TEXT,
  title_ar TEXT NOT NULL DEFAULT '',
  title_en TEXT NOT NULL DEFAULT '',
  alt_ar TEXT NOT NULL DEFAULT '',
  alt_en TEXT NOT NULL DEFAULT '',
  focus_position TEXT NOT NULL DEFAULT 'center' CHECK (focus_position IN ('center','top','bottom','right','left')),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  sort_order INTEGER NOT NULL,
  created_by INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (organization_id) REFERENCES organization(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE (organization_id, sort_order)
);

CREATE TABLE IF NOT EXISTS departments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  branch_id INTEGER,
  manager_employee_id INTEGER,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT,
  FOREIGN KEY (manager_employee_id) REFERENCES employees(id) ON DELETE SET NULL,
  FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS job_grades (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  min_salary_cents INTEGER NOT NULL DEFAULT 0,
  max_salary_cents INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS job_titles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  department_id INTEGER,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS branches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  address TEXT NOT NULL DEFAULT '',
  manager_employee_id INTEGER,
  latitude REAL NOT NULL CHECK (latitude BETWEEN -90 AND 90),
  longitude REAL NOT NULL CHECK (longitude BETWEEN -180 AND 180),
  radius_m INTEGER NOT NULL CHECK (radius_m BETWEEN 50 AND 5000),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (manager_employee_id) REFERENCES employees(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS employees (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_no TEXT NOT NULL UNIQUE,
  full_name TEXT NOT NULL,
  email TEXT UNIQUE,
  phone TEXT NOT NULL DEFAULT '',
  job_title TEXT NOT NULL DEFAULT '',
  job_grade TEXT NOT NULL DEFAULT '',
  job_title_id INTEGER,
  job_grade_id INTEGER,
  department_id INTEGER,
  branch_id INTEGER,
  manager_id INTEGER,
  hire_date TEXT,
  qualification TEXT NOT NULL DEFAULT '',
  nationality TEXT NOT NULL DEFAULT '',
  birth_date TEXT,
  place_of_birth TEXT NOT NULL DEFAULT '',
  passport_no TEXT NOT NULL DEFAULT '',
  passport_expires_on TEXT,
  emirates_id_no TEXT NOT NULL DEFAULT '',
  emirates_id_expires_on TEXT,
  marital_status TEXT NOT NULL DEFAULT 'unspecified' CHECK (marital_status IN ('unspecified','single','married','divorced','widowed','separated')),
  address_country TEXT NOT NULL DEFAULT '',
  address_city TEXT NOT NULL DEFAULT '',
  address_area TEXT NOT NULL DEFAULT '',
  address_street TEXT NOT NULL DEFAULT '',
  address_building TEXT NOT NULL DEFAULT '',
  address_po_box TEXT NOT NULL DEFAULT '',
  address_notes TEXT NOT NULL DEFAULT '',
  salary REAL NOT NULL DEFAULT 0 CHECK (salary >= 0),
  basic_salary REAL NOT NULL DEFAULT 0 CHECK (basic_salary >= 0),
  housing_allowance REAL NOT NULL DEFAULT 0 CHECK (housing_allowance >= 0),
  transport_allowance REAL NOT NULL DEFAULT 0 CHECK (transport_allowance >= 0),
  profession_allowance REAL NOT NULL DEFAULT 0 CHECK (profession_allowance >= 0),
  other_allowance REAL NOT NULL DEFAULT 0 CHECK (other_allowance >= 0),
  manual_allowances_json TEXT NOT NULL DEFAULT '[]',
  photo_data TEXT,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE SET NULL,
  FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL,
  FOREIGN KEY (manager_id) REFERENCES employees(id) ON DELETE SET NULL,
  FOREIGN KEY (job_title_id) REFERENCES job_titles(id) ON DELETE SET NULL,
  FOREIGN KEY (job_grade_id) REFERENCES job_grades(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','hr','general_manager','manager','employee')),
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  employee_id INTEGER UNIQUE,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0,1)),
  is_super_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_super_admin IN (0,1)),
  last_password_change_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS employee_emergency_contacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL,
  full_name TEXT NOT NULL,
  relationship TEXT NOT NULL,
  phone TEXT NOT NULL,
  alternate_phone TEXT NOT NULL DEFAULT '',
  email TEXT,
  is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0,1)),
  notes TEXT NOT NULL DEFAULT '',
  archived INTEGER NOT NULL DEFAULT 0 CHECK (archived IN (0,1)),
  created_by INTEGER,
  archived_by INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  archived_at TEXT,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (archived_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_emergency_contacts_employee ON employee_emergency_contacts(employee_id,archived,is_primary DESC,id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_emergency_contacts_one_primary ON employee_emergency_contacts(employee_id) WHERE is_primary=1 AND archived=0;

CREATE TABLE IF NOT EXISTS employee_languages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL,
  code TEXT NOT NULL CHECK (code IN ('ar','en','ur','hi','zh','fil','bn','ne','ru','fr','es','other')),
  name TEXT NOT NULL,
  flag TEXT NOT NULL,
  flag_code TEXT NOT NULL,
  proficiency TEXT NOT NULL CHECK (proficiency IN ('native','excellent','very_good','good','basic')),
  display_order INTEGER NOT NULL DEFAULT 0 CHECK (display_order >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(employee_id, code),
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_employee_languages_order ON employee_languages(employee_id, display_order, id);

CREATE TABLE IF NOT EXISTS user_permissions (
  user_id INTEGER NOT NULL,
  permission TEXT NOT NULL,
  granted INTEGER NOT NULL DEFAULT 1 CHECK (granted IN (0,1)),
  PRIMARY KEY (user_id, permission),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  csrf_token TEXT NOT NULL DEFAULT '',
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS shifts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  break_minutes INTEGER NOT NULL DEFAULT 60 CHECK (break_minutes BETWEEN 0 AND 480),
  working_days TEXT NOT NULL DEFAULT '[0,1,2,3,4]',
  rest_days TEXT NOT NULL DEFAULT '[5,6]',
  grace_minutes INTEGER NOT NULL DEFAULT 10 CHECK (grace_minutes BETWEEN 0 AND 240),
  daily_limit_minutes INTEGER NOT NULL DEFAULT 480 CHECK (daily_limit_minutes BETWEEN 60 AND 1440),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS employee_shift_assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL,
  shift_id INTEGER NOT NULL,
  effective_from TEXT NOT NULL,
  effective_to TEXT,
  created_by INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (effective_to IS NULL OR effective_to >= effective_from),
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
  FOREIGN KEY (shift_id) REFERENCES shifts(id) ON DELETE RESTRICT,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_shift_employee_date ON employee_shift_assignments(employee_id, effective_from, effective_to);

CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL,
  work_date TEXT NOT NULL,
  branch_id INTEGER NOT NULL,
  check_in_at TEXT,
  check_out_at TEXT,
  check_in_lat REAL,
  check_in_lng REAL,
  check_in_accuracy REAL,
  check_in_distance_m REAL,
  check_out_lat REAL,
  check_out_lng REAL,
  check_out_accuracy REAL,
  check_out_distance_m REAL,
  decision TEXT NOT NULL DEFAULT 'accepted',
  rejection_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(employee_id, work_date),
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
  FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance(work_date, employee_id);

CREATE TABLE IF NOT EXISTS attendance_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL,
  branch_id INTEGER,
  action TEXT NOT NULL CHECK (action IN ('check_in','check_out')),
  latitude REAL NOT NULL,
  longitude REAL NOT NULL,
  accuracy REAL,
  distance_m REAL,
  accepted INTEGER NOT NULL CHECK (accepted IN (0,1)),
  reason TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
  FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS overtime_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL,
  work_date TEXT NOT NULL,
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  duration_minutes INTEGER NOT NULL CHECK (duration_minutes > 0),
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'submitted' CHECK (status IN ('draft','submitted','approved','rejected','cancelled')),
  rejection_reason TEXT,
  decided_by INTEGER,
  decided_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
  FOREIGN KEY (decided_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS overtime_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id INTEGER NOT NULL,
  actor_user_id INTEGER NOT NULL,
  from_status TEXT,
  to_status TEXT NOT NULL,
  comment TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY (request_id) REFERENCES overtime_requests(id) ON DELETE CASCADE,
  FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS leave_types (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  annual_entitlement REAL NOT NULL DEFAULT 0 CHECK (annual_entitlement >= 0),
  min_notice_days INTEGER NOT NULL DEFAULT 0 CHECK (min_notice_days >= 0),
  requires_attachment INTEGER NOT NULL DEFAULT 0 CHECK (requires_attachment IN (0,1)),
  paid INTEGER NOT NULL DEFAULT 1 CHECK (paid IN (0,1)),
  max_hours REAL NOT NULL DEFAULT 0 CHECK (max_hours >= 0),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1))
);

CREATE TABLE IF NOT EXISTS leave_balances (
  employee_id INTEGER NOT NULL,
  leave_type_id INTEGER NOT NULL,
  year INTEGER NOT NULL,
  entitlement REAL NOT NULL DEFAULT 0,
  carried REAL NOT NULL DEFAULT 0,
  used REAL NOT NULL DEFAULT 0,
  PRIMARY KEY (employee_id, leave_type_id, year),
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
  FOREIGN KEY (leave_type_id) REFERENCES leave_types(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS leave_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL,
  leave_type_id INTEGER NOT NULL,
  start_date TEXT NOT NULL,
  end_date TEXT NOT NULL,
  days REAL NOT NULL CHECK (days > 0),
  start_time TEXT,
  end_time TEXT,
  hours REAL NOT NULL DEFAULT 0 CHECK (hours >= 0),
  reason TEXT NOT NULL DEFAULT '',
  attachment_data TEXT,
  status TEXT NOT NULL DEFAULT 'submitted' CHECK (status IN ('draft','submitted','approved','rejected','cancelled')),
  manager_employee_id INTEGER,
  manager_decision TEXT NOT NULL DEFAULT 'pending' CHECK (manager_decision IN ('pending','approved','rejected')),
  manager_comment TEXT NOT NULL DEFAULT '',
  manager_decided_by INTEGER,
  manager_decided_at TEXT,
  rejection_reason TEXT,
  decided_by INTEGER,
  decided_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (end_date >= start_date),
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
  FOREIGN KEY (leave_type_id) REFERENCES leave_types(id) ON DELETE RESTRICT,
  FOREIGN KEY (manager_employee_id) REFERENCES employees(id) ON DELETE SET NULL,
  FOREIGN KEY (manager_decided_by) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (decided_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS leave_sale_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL,
  days REAL NOT NULL CHECK (days > 0),
  daily_rate_cents INTEGER NOT NULL DEFAULT 0 CHECK (daily_rate_cents >= 0),
  amount_cents INTEGER NOT NULL DEFAULT 0 CHECK (amount_cents >= 0),
  reason TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'submitted' CHECK (status IN ('submitted','approved','rejected')),
  decision_note TEXT NOT NULL DEFAULT '',
  decided_by INTEGER,
  decided_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
  FOREIGN KEY (decided_by) REFERENCES users(id) ON DELETE SET NULL
);

-- The calendar is intentionally data driven because UAE public-holiday dates
-- that follow the Hijri calendar change each year.  HR can maintain the
-- confirmed dates from the settings screen; annual-leave requests exclude
-- active dates in this table from their day count.
CREATE TABLE IF NOT EXISTS public_holidays (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  holiday_date TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_by INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evaluation_cycles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  year INTEGER NOT NULL UNIQUE,
  name TEXT NOT NULL,
  starts_on TEXT NOT NULL,
  ends_on TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  period_start TEXT,
  period_end TEXT,
  self_opens_on TEXT,
  self_due_on TEXT,
  manager_due_on TEXT,
  hr_due_on TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','announced','closed')),
  announcement_title TEXT NOT NULL DEFAULT '',
  announcement_body TEXT NOT NULL DEFAULT '',
  created_by INTEGER,
  announced_by INTEGER,
  announced_at TEXT,
  announcement_notification_id INTEGER,
  extension_reason TEXT NOT NULL DEFAULT '',
  created_at TEXT,
  updated_at TEXT,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (announced_by) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (announcement_notification_id) REFERENCES notifications(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evaluations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cycle_id INTEGER NOT NULL,
  employee_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','submitted','in_review','approved','rejected','returned')),
  weighted_score REAL,
  rating TEXT,
  current_step INTEGER NOT NULL DEFAULT 0,
  submitted_at TEXT,
  finalized_at TEXT,
  workflow_version INTEGER NOT NULL DEFAULT 2,
  manager_employee_id INTEGER,
  manager_report TEXT NOT NULL DEFAULT '',
  manager_submitted_at TEXT,
  hr_reviewed_by INTEGER,
  hr_comment TEXT NOT NULL DEFAULT '',
  disclosure_date TEXT,
  submitted_late INTEGER NOT NULL DEFAULT 0 CHECK (submitted_late IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(cycle_id, employee_id),
  FOREIGN KEY (cycle_id) REFERENCES evaluation_cycles(id) ON DELETE RESTRICT,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
  FOREIGN KEY (manager_employee_id) REFERENCES employees(id) ON DELETE SET NULL,
  FOREIGN KEY (hr_reviewed_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evaluation_goal_templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_title_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  measure TEXT NOT NULL DEFAULT '',
  default_weight REAL NOT NULL CHECK (default_weight > 0 AND default_weight <= 100),
  sort_order INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(job_title_id, title),
  FOREIGN KEY (job_title_id) REFERENCES job_titles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evaluation_goals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  evaluation_id INTEGER NOT NULL,
  source_template_id INTEGER,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  weight REAL NOT NULL CHECK (weight > 0 AND weight <= 100),
  measure TEXT NOT NULL DEFAULT '',
  achievement REAL NOT NULL DEFAULT 0 CHECK (achievement BETWEEN 0 AND 100),
  goal_type TEXT NOT NULL DEFAULT 'result' CHECK (goal_type IN ('result','behaviour','development')),
  start_date TEXT,
  end_date TEXT,
  progress_status TEXT NOT NULL DEFAULT 'not_completed' CHECK (progress_status IN ('completed','in_progress','not_completed')),
  evidence_note TEXT NOT NULL DEFAULT '',
  awarded_points REAL,
  employee_comment TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(evaluation_id, source_template_id),
  FOREIGN KEY (evaluation_id) REFERENCES evaluations(id) ON DELETE CASCADE,
  FOREIGN KEY (source_template_id) REFERENCES evaluation_goal_templates(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evaluation_grievances (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  evaluation_id INTEGER NOT NULL UNIQUE,
  employee_id INTEGER NOT NULL,
  reason TEXT NOT NULL,
  note TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'submitted' CHECK (status IN ('submitted','rejected','amended')),
  resolution_note TEXT,
  resolved_by INTEGER,
  score_before REAL,
  score_after REAL,
  submitted_at TEXT NOT NULL,
  resolved_at TEXT,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (evaluation_id) REFERENCES evaluations(id) ON DELETE CASCADE,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
  FOREIGN KEY (resolved_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evaluation_approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  evaluation_id INTEGER NOT NULL,
  step_no INTEGER NOT NULL,
  approver_employee_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','returned')),
  comment TEXT NOT NULL DEFAULT '',
  decided_at TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(evaluation_id, step_no),
  FOREIGN KEY (evaluation_id) REFERENCES evaluations(id) ON DELETE CASCADE,
  FOREIGN KEY (approver_employee_id) REFERENCES employees(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS evaluation_reminders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cycle_id INTEGER NOT NULL,
  employee_id INTEGER NOT NULL,
  reminder_type TEXT NOT NULL,
  notification_id INTEGER,
  created_by INTEGER,
  sent_at TEXT NOT NULL,
  UNIQUE(cycle_id, employee_id, reminder_type),
  FOREIGN KEY (cycle_id) REFERENCES evaluation_cycles(id) ON DELETE CASCADE,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
  FOREIGN KEY (notification_id) REFERENCES notifications(id) ON DELETE SET NULL,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evaluation_cycle_notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cycle_id INTEGER NOT NULL,
  employee_id INTEGER NOT NULL,
  notification_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(cycle_id, employee_id),
  UNIQUE(notification_id),
  FOREIGN KEY (cycle_id) REFERENCES evaluation_cycles(id) ON DELETE CASCADE,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
  FOREIGN KEY (notification_id) REFERENCES notifications(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  message_type TEXT NOT NULL CHECK (message_type IN ('law','notice','congratulation')),
  audience_type TEXT NOT NULL CHECK (audience_type IN ('all','department','branch','employees')),
  audience_ref TEXT,
  available_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (sender_user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS notification_recipients (
  notification_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  read_at TEXT,
  PRIMARY KEY (notification_id, user_id),
  FOREIGN KEY (notification_id) REFERENCES notifications(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS document_expiry_alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  document_id INTEGER NOT NULL,
  expires_on TEXT NOT NULL,
  notification_id INTEGER,
  created_at TEXT NOT NULL,
  UNIQUE(document_id, expires_on),
  FOREIGN KEY (document_id) REFERENCES employee_documents(id) ON DELETE CASCADE,
  FOREIGN KEY (notification_id) REFERENCES notifications(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_document_expiry_alerts_document ON document_expiry_alerts(document_id);

CREATE TABLE IF NOT EXISTS salary_certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  certificate_no TEXT NOT NULL UNIQUE,
  verification_code TEXT NOT NULL UNIQUE,
  integrity_hash TEXT NOT NULL,
  verification_status TEXT NOT NULL DEFAULT 'valid' CHECK (verification_status IN ('valid','revoked')),
  employee_id INTEGER NOT NULL,
  issued_by INTEGER NOT NULL,
  purpose TEXT NOT NULL DEFAULT '',
  salary_snapshot REAL NOT NULL,
  organization_snapshot TEXT NOT NULL,
  employee_snapshot TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  print_count INTEGER NOT NULL DEFAULT 0,
  last_printed_at TEXT,
  verification_count INTEGER NOT NULL DEFAULT 0,
  last_verified_at TEXT,
  request_status TEXT NOT NULL DEFAULT 'issued' CHECK (request_status IN ('requested','approved','rejected','issued')),
  requester_id INTEGER,
  requested_at TEXT,
  approved_by INTEGER,
  approved_at TEXT,
  decision_note TEXT NOT NULL DEFAULT '',
  email_outbox_id INTEGER,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE RESTRICT,
  FOREIGN KEY (issued_by) REFERENCES users(id) ON DELETE RESTRICT,
  FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS employee_documents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL,
  document_type TEXT NOT NULL CHECK (document_type IN ('passport','identity','residency','visa','work_permit','contract','job_offer','qualification','professional_certificate','marriage_certificate','birth_certificate','good_conduct','medical_exam','health_insurance','driving_license','personal_photo','employee_file','undertaking','violation','bank_document','other','general')),
  title TEXT NOT NULL,
  document_number TEXT NOT NULL DEFAULT '',
  issuer TEXT NOT NULL DEFAULT '',
  issued_on TEXT,
  expires_on TEXT,
  no_expiry INTEGER NOT NULL DEFAULT 0 CHECK (no_expiry IN (0,1)),
  file_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  data_url TEXT NOT NULL,
  notes TEXT NOT NULL DEFAULT '',
  archived INTEGER NOT NULL DEFAULT 0 CHECK (archived IN (0,1)),
  visible_to_employee INTEGER NOT NULL DEFAULT 1 CHECK (visible_to_employee IN (0,1)),
  uploaded_by INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
  FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS employee_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL,
  action_type TEXT NOT NULL CHECK (action_type IN ('violation','undertaking')),
  action_date TEXT NOT NULL,
  description TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed','cancelled')),
  penalty TEXT NOT NULL DEFAULT '',
  attachment_data TEXT,
  created_by INTEGER NOT NULL,
  closed_by INTEGER,
  closed_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT,
  FOREIGN KEY (closed_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS employee_custody (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL,
  asset_name TEXT NOT NULL,
  asset_type TEXT NOT NULL DEFAULT '',
  serial_number TEXT NOT NULL DEFAULT '',
  received_on TEXT NOT NULL,
  returned_on TEXT,
  received_condition TEXT NOT NULL CHECK (received_condition IN ('new','used_clean','used_average','used_damaged')),
  return_condition TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  created_by INTEGER NOT NULL,
  updated_by INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT,
  FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_employee_custody_employee ON employee_custody(employee_id, returned_on, received_on DESC, id DESC);

CREATE TABLE IF NOT EXISTS employee_custody_photos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  custody_id INTEGER NOT NULL,
  stage TEXT NOT NULL CHECK (stage IN ('received','returned')),
  file_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  data_url TEXT NOT NULL,
  caption TEXT NOT NULL DEFAULT '',
  uploaded_by INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (custody_id) REFERENCES employee_custody(id) ON DELETE CASCADE,
  FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_employee_custody_photos_stage ON employee_custody_photos(custody_id, stage, id);

CREATE TABLE IF NOT EXISTS payroll_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  payroll_month TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','review','approved','paid')),
  created_by INTEGER NOT NULL,
  approved_by INTEGER,
  paid_by INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  approved_at TEXT,
  paid_at TEXT,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT,
  FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (paid_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS payroll_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL,
  employee_id INTEGER NOT NULL,
  employee_no TEXT NOT NULL,
  employee_name TEXT NOT NULL,
  job_title TEXT NOT NULL DEFAULT '',
  job_grade TEXT NOT NULL DEFAULT '',
  basic_cents INTEGER NOT NULL,
  allowances_cents INTEGER NOT NULL DEFAULT 0,
  deductions_cents INTEGER NOT NULL DEFAULT 0,
  advance_cents INTEGER NOT NULL DEFAULT 0,
  net_cents INTEGER NOT NULL,
  UNIQUE(run_id, employee_id),
  FOREIGN KEY (run_id) REFERENCES payroll_runs(id) ON DELETE CASCADE,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS advances (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL,
  amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
  months INTEGER NOT NULL CHECK (months BETWEEN 1 AND 6),
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'submitted' CHECK (status IN ('submitted','approved','rejected','completed','cancelled')),
  decided_by INTEGER,
  decided_at TEXT,
  rejection_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
  FOREIGN KEY (decided_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS advance_installments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  advance_id INTEGER NOT NULL,
  installment_no INTEGER NOT NULL,
  due_month TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'scheduled' CHECK (status IN ('scheduled','paid','cancelled')),
  payroll_item_id INTEGER,
  UNIQUE(advance_id, installment_no),
  FOREIGN KEY (advance_id) REFERENCES advances(id) ON DELETE CASCADE,
  FOREIGN KEY (payroll_item_id) REFERENCES payroll_items(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS lifecycle_cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  module TEXT NOT NULL CHECK (module IN ('recruitment','onboarding','learning','benefits','offboarding')),
  title TEXT NOT NULL,
  employee_id INTEGER,
  candidate_name TEXT NOT NULL DEFAULT '',
  owner_user_id INTEGER,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','closed','cancelled')),
  due_date TEXT,
  notes TEXT NOT NULL DEFAULT '',
  created_by INTEGER NOT NULL,
  closed_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE SET NULL,
  FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_user_id INTEGER,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT,
  details TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  requested_ip TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_password_reset_user ON password_reset_tokens(user_id, created_at);

CREATE TABLE IF NOT EXISTS auth_rate_limits (
  rate_key TEXT NOT NULL,
  action TEXT NOT NULL,
  window_started TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (rate_key, action)
);

CREATE TABLE IF NOT EXISTS email_campaigns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_user_id INTEGER NOT NULL,
  audience_type TEXT NOT NULL CHECK (audience_type IN ('employee','department','branch','all')),
  audience_ref TEXT,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  template TEXT NOT NULL DEFAULT 'plain',
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','sending','sent','partial','failed')),
  recipient_count INTEGER NOT NULL DEFAULT 0,
  sent_count INTEGER NOT NULL DEFAULT 0,
  failed_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (sender_user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS email_deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id INTEGER NOT NULL,
  employee_id INTEGER NOT NULL,
  to_email TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','sent','failed')),
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  sent_at TEXT,
  UNIQUE(campaign_id, employee_id),
  FOREIGN KEY (campaign_id) REFERENCES email_campaigns(id) ON DELETE CASCADE,
  FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS email_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL CHECK (kind IN ('password_reset','campaign','smtp_test','salary_certificate')),
  to_email TEXT NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','sent','failed')),
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  campaign_id INTEGER,
  delivery_id INTEGER,
  user_id INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  sent_at TEXT,
  attachment_name TEXT,
  attachment_content_type TEXT,
  attachment_data TEXT,
  FOREIGN KEY (campaign_id) REFERENCES email_campaigns(id) ON DELETE CASCADE,
  FOREIGN KEY (delivery_id) REFERENCES email_deliveries(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_outbox_status ON email_outbox(status, created_at);
