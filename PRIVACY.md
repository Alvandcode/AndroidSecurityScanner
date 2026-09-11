# Privacy Policy — Android Security Scanner (by alvandcode)

Last updated: 2026-09-10. Contact: https://github.com/Alvandcode

## FA — خلاصه فارسی
- لیست اپ‌ها، تاریخچه اسکن و نتایج فقط **روی گوشی شما** می‌ماند (Room + DataStore).
  هیچ سروری از ما چیزی دریافت نمی‌کند؛ ما اصلاً سرور نداریم.
- تنها ارسال شبکه، **اختیاری و خاموش به‌صورت پیش‌فرض** است: اگر خودتان در
  تنظیمات «بررسی آنلاین» را روشن کنید و کلید VirusTotal بچسبانید، فقط
  **SHA-256** فایل/اپ (یک رشته ۶۴ کاراکتری) به `virustotal.com` فرستاده می‌شود.
  خود فایل هرگز آپلود نمی‌شود. با خاموش کردن سوییچ، کلید ذخیره‌شده پاک می‌شود.
- بکاپ ابری/انتقال دستگاه برای دیتابیس و تنظیمات **غیرفعال** است
  (`allowBackup=false` + `data_extraction_rules`).
- دسترسی‌ها و دلیل‌شان:
  - `QUERY_ALL_PACKAGES`: فقط برای نمایش ریسک مجوزهای اپ‌های نصب‌شده، روی
    دستگاه، بدون ارسال به جایی. (برای انتشار در بازار توجیه لازم دارد — متن
    آماده در `STORE-LISTING.md`.)
  - `POST_NOTIFICATIONS`: فقط اعلان پایان اسکن/نصب جدید (اندروید ۱۳+ با اجازه شما).
  - `INTERNET`: فقط همان lookup اختیاری VirusTotal.
  - `READ_EXTERNAL_STORAGE` (تا اندروید ۱۲) / `READ_MEDIA_*` (۱۳+): فقط خواندن
    فایل‌های پوشه‌ای که خودتان با انتخاب‌گر سیستم (SAF) اجازه داده‌اید.
  - `RECEIVE_BOOT_COMPLETED`: باززمان‌بندی اسکن روزانه، فقط اگر خودتان روشن کنید.
- حذف: با حذف نصب اپ، همه داده‌های محلی (تاریخچه + تنظیمات) پاک می‌شود.

## EN — summary
- App list, scan history and results stay **on-device only** (Room + DataStore).
  We operate no server and receive nothing.
- The only network call is **opt-in, OFF by default**: if you enable Online
  reputation and paste a VirusTotal key, only the file's **SHA-256** hex is sent
  to `virustotal.com`. File content is never uploaded. Disabling the switch
  wipes the stored key.
- Cloud backup / device transfer for database and prefs is **disabled**.
- Permissions and why: `QUERY_ALL_PACKAGES` (on-device permission audit only),
  `POST_NOTIFICATIONS` (scan/install alerts), `INTERNET` (opt-in VT lookup only),
  `READ_EXTERNAL_STORAGE`/`READ_MEDIA_*` (read only the SAF-granted folder you pick),
  `RECEIVE_BOOT_COMPLETED` (reschedule daily scan only if you enabled it).
- Uninstalling wipes all local data.
