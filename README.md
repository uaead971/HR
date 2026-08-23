# خيشة - Khaisha HR

نظام ويب ثنائي اللغة لإدارة الموارد البشرية، يعمل بخادم Python وSQLite.

## ملاحظة مهمة عن GitHub Pages

GitHub يستضيف ملفات المصدر فقط، وGitHub Pages لا يشغّل خادم Python أو SQLite؛ لذلك رفع المجلد إلى Pages وحده سيعرض الواجهة من دون API وتسجيل دخول. شغّل التطبيق على خادم يدعم Python/Docker، أو استخدم إعداد Render الموجود في [`render.yaml`](render.yaml). يبقى GitHub مستودعاً للكود والتكامل المستمر، وليس قاعدة بيانات التطبيق.

## تشغيل محلي

```bash
python3 server.py --host 127.0.0.1 --port 8765
```

ثم افتح <http://localhost:8765/>. تُنشأ قاعدة البيانات المحلية داخل `data/` ولا تدخل في Git.

## نشر Docker / Render

الملفات الجاهزة للنشر هي [`Dockerfile`](Dockerfile)، [`start.sh`](start.sh)، و[`render.yaml`](render.yaml). لبناء صورة محلياً:

```bash
docker build -t khaisha-hr .
docker run --rm -p 8765:8765 \
  -e HR_ENV=production \
  -e HR_SECRET_KEY="ضع-مفتاحاً-عشوائياً-طويلاً-هنا" \
  -e HR_BOOTSTRAP_ADMIN_EMAIL="admin@example.com" \
  -e HR_BOOTSTRAP_ADMIN_PASSWORD="ضع-كلمة-مرور-قوية-هنا" \
  khaisha-hr
```

في Render أنشئ **Blueprint** من هذا المستودع، ثم أدخل `HR_BOOTSTRAP_ADMIN_EMAIL` و`HR_BOOTSTRAP_ADMIN_PASSWORD` عند أول نشر. يتم إنشاء مدير النظام مرة واحدة فقط في قاعدة جديدة، ويجب إزالة متغير كلمة مرور التهيئة بعد تسجيل الدخول الأول. استخدم القرص الدائم المعرّف في `render.yaml` حتى لا تضيع قاعدة SQLite والوثائق عند إعادة التشغيل. تتطلب الخطة ذات القرص الدائم خطة Render مدفوعة أو بديلاً مماثلاً.

## قبل النشر أو الرفع إلى GitHub

- لا ترفع قاعدة البيانات أو ملفات `.env` أو كلمات المرور أو مفاتيح التشفير؛ استخدم إعدادات البيئة في منصة الاستضافة.
- استخدم [`.env.example`](.env.example) كمرجع فقط، واضبط قيمة عشوائية طويلة لـ `HR_SECRET_KEY` مع `HR_ENV=production`؛ التطبيق لا يقرأ `.env` تلقائياً.
- لا تُنشأ حسابات التجربة في قاعدة إنتاج جديدة. يلزم متغيرا التهيئة `HR_BOOTSTRAP_ADMIN_EMAIL` و`HR_BOOTSTRAP_ADMIN_PASSWORD` لأول تشغيل فقط، وإلا يتوقف الخادم برسالة واضحة.
- استخدم HTTPS ونسخاً احتياطية مشفرة، وغيّر/احذف حسابات التجربة الموجودة في قواعد قديمة قبل أي نشر مشترك.
- راجع [`SECURITY.md`](SECURITY.md) للتشغيل والاختبار والتدقيق.

## اختبار

```bash
python3 -m unittest -v tests.test_api
```

هذا المستودع لا يحتوي على اتصال GitHub أو أسرار نشر. بعد إنشاء مستودع فارغ على GitHub نفّذ من مجلد المشروع:

```bash
git remote add origin https://github.com/<owner>/<repository>.git
git branch -M main
git add -A
git commit -m "Prepare production deployment"
git push -u origin main
```

استخدم GitHub CLI أو SSH بدلاً من HTTPS إذا كان ذلك هو أسلوب المصادقة لديك، ولا تضع رمز الوصول داخل الملفات أو الأوامر المحفوظة.
