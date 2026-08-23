# خيشة - Khaisha HR

نظام ويب ثنائي اللغة لإدارة الموارد البشرية. التطبيق الفعلي موجود في مجلد [`hr_platform`](hr_platform/).

## تشغيل محلي

```bash
cd hr_platform
python3 server.py --host 127.0.0.1 --port 8765
```

ثم افتح <http://localhost:8765/>. تُنشأ قاعدة البيانات المحلية داخل `hr_platform/data/` ولا تدخل في Git.

## قبل النشر أو الرفع إلى GitHub

- لا ترفع قاعدة البيانات أو ملفات `.env` أو كلمات المرور أو مفاتيح التشفير؛ قواعد التجاهل مضافة في الجذر وداخل `hr_platform`.
- انسخ [`hr_platform/.env.example`](hr_platform/.env.example) إلى `.env` في بيئة التشغيل، واستخدم قيمة عشوائية طويلة لـ `HR_SECRET_KEY` مع `HR_ENV=production`.
- استخدم HTTPS ونسخاً احتياطية مشفرة، وغيّر/احذف حسابات التجربة قبل أي نشر مشترك.
- راجع [`hr_platform/SECURITY.md`](hr_platform/SECURITY.md) و[`hr_platform/README.md`](hr_platform/README.md) للتشغيل والاختبار والتدقيق.

## اختبار

```bash
cd hr_platform
python3 -m unittest -v tests.test_api
```

هذا المستودع لا يحتوي على اتصال GitHub أو أسرار نشر؛ أضف remote والمصادقة من جهازك ثم نفّذ `git push` بعد مراجعة الملفات المرحّلة.
