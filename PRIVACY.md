# Privacy Policy — Android Security Scanner (by alvandcode)

Last updated: 2026-11-27. Contact: https://github.com/Alvandcode

## FA — خلاصه فارسی
- لیست اپ‌ها، تاریخچه اسکن و نتایج فقط **روی گوشی شما** می‌ماند (Room + DataStore).
  هیچ سروری از ما چیزی دریافت نمی‌کند؛ ما اصلاً سرور نداریم.
- **کاتالوگ Idol (پیش‌فرض روشن، قابل خاموش‌کردن):** اپ یک فایل JSON عمومی از
  `github.com/Alvandcode/idol-store-catalog` **دانلود** می‌کند (گزارش اسکن
  ClamAV/YARA/OSV/Semgrep/Gitleaks آن کاتالوگ) و برنامه‌های نصب‌شده و هش
  فایل‌ها را فقط **به‌صورت محلی** با آن تطبیق می‌دهد. این ارتباط **فقط
  خواندنی** است: هیچ داده‌ای از دستگاه شما ارسال نمی‌شود — نه نام اپ، نه هش،
  نه هیچ شناسه‌ای. با سوییچ «اعتبار کاتالوگ Idol» در تنظیمات خاموش می‌شود.
- **تنها ارسال اختیاری دیگر، خاموش به‌صورت پیش‌فرض:** اگر «بررسی آنلاین» را
  روشن کنید و کلید VirusTotal بچسبانید، فقط **SHA-256** فایل/اپ (یک رشتهٔ
  ۶۴ کاراکتری) به `virustotal.com` فرستاده می‌شود. خود فایل هرگز آپلود
  نمی‌شود. با خاموش کردن سوییچ، کلید ذخیره‌شده پاک می‌شود.
- بکاپ ابری/انتقال دستگاه برای دیتابیس و تنظیمات **غیرفعال** است
  (`allowBackup=false` + `data_extraction_rules`).
- دسترسی‌ها و دلیل‌شان:
  - `QUERY_ALL_PACKAGES`: فقط برای نمایش ریسک مجوزهای اپ‌های نصب‌شده، روی
    دستگاه، بدون ارسال به جایی. (برای انتشار در یک استور توجیه لازم دارد —
    متن آماده در `STORE-LISTING.md`.)
  - `POST_NOTIFICATIONS`: فقط اعلان پایان اسکن/نصب جدید (اندروید ۱۳+ با اجازه شما).
  - `INTERNET`: دانلود گزارش کاتالوگ Idol (فقط خواندنی) + lookup اختیاری VirusTotal.
  - `RECEIVE_BOOT_COMPLETED`: باززمان‌بندی اسکن روزانه، فقط اگر خودتان روشن کنید.
  - **هیچ مجوز حافظه/رسانه نداریم:** اسکن فایل فقط از طریق SAF و پوشه‌ای است
    که خودتان صریحاً اجازه می‌دهید؛ هیچ کوئری MediaStore انجام نمی‌شود.
- حذف: با حذف نصب اپ، همه داده‌های محلی (تاریخچه + تنظیمات) پاک می‌شود.

## EN — summary
- App list, scan history and results stay **on-device only** (Room + DataStore).
  We operate no server and receive nothing.
- **Idol Catalog (on by default, toggle in Settings):** the app **downloads** a
  public JSON file from `github.com/Alvandcode/idol-store-catalog` (that
  catalog's ClamAV/YARA/OSV/Semgrep/Gitleaks security report) and matches your
  installed apps and file hashes against it **locally**. The request is
  **read-only**: nothing is sent from your device — no app names, no hashes,
  no identifiers of any kind.
- The only other network send is **opt-in, OFF by default**: if you enable
  Online reputation and paste a VirusTotal key, only the file's **SHA-256**
  hex is sent to `virustotal.com`. File content is never uploaded. Disabling
  the switch wipes the stored key.
- Cloud backup / device transfer for database and prefs is **disabled**.
- Permissions and why: `QUERY_ALL_PACKAGES` (on-device permission audit only),
  `POST_NOTIFICATIONS` (scan/install alerts), `INTERNET` (read-only Idol
  Catalog download + opt-in VT lookup), `RECEIVE_BOOT_COMPLETED` (reschedule
  daily scan only if you enabled it).
- **No storage/media permissions:** file scanning is SAF-based on folders you
  explicitly grant; no MediaStore query is performed.
- Uninstalling wipes all local data.
