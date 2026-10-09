# prscanm0r
Discover live proxies on Linux with both a graphical interface and CLI.
d
# PRSCANM0R — آموزش کامل

## نصب (دبیان / اوبونتو)
    sudo apt install ./prscanm0r_1.0.0_all.deb
وابستگی‌ها (python3-tk, python3-requests, python3-socks) خودکار نصب می‌شن.
حذف: `sudo apt remove prscanm0r`

## اجرا
- رابط گرافیکی: از منوی برنامه‌ها «PRSCANM0R» یا در ترمینال `prscanm0r`
- بدون GUI (سرور/SSH): `prscanm0r run`

## رابط گرافیکی
1. **Dashboard**: دکمه Start شروع، Stop توقف. کارت‌ها: تعداد کل، تست‌شده، سالم، سرعت، زمان باقی‌مانده.
   روی تیتر ستون‌ها کلیک کنید تا مرتب شود. کادر Filter برای جستجو (کشور، IP، نوع).
   خروجی با Export (JSON / CSV / URL list / TXT) و Copy selected برای کپی.
2. **Sources**: سه منبع پیش‌فرض همیشه هست (فقط می‌شه خاموش‌شون کرد). URL لیست خام (raw) رو بنویسید و Add بزنید.
3. **Settings**: workers، timeoutها، rate (سقف تست در ثانیه)، jitter، تأخیر بین منابع، کش منابع، سقف تعداد، پروتکل‌ها.
4. **Log**: گزارش لحظه‌ای.

## خط فرمان
    prscanm0r run                          # مثل اسکریپت قبلی → working-proxies.txt
    prscanm0r run -n 3000 -r 10 -w 100     # فقط 3000 پروکسی، حداکثر 10 تست/ثانیه
    prscanm0r run -p socks5 -f json -o out.json
    prscanm0r run -c "Germany,Iran" --max-latency 1500 --best 50
    prscanm0r run -q -f plain -o list.txt  # بی‌صدا، فقط http://ip:port

### مدیریت منابع
    prscanm0r source list
    prscanm0r source add https://example.com/proxies.txt
    prscanm0r source remove https://example.com/proxies.txt
    prscanm0r source disable URL   |   prscanm0r source enable URL
    prscanm0r source reset         # حذف سفارشی‌ها و فعال‌کردن همه

### تنظیمات
    prscanm0r config show
    prscanm0r config set rate 8
    prscanm0r config set protocols http,socks5
    prscanm0r config set test_urls https://ipwho.is/,https://api.ipify.org?format=json
    prscanm0r config reset
فایل تنظیمات: `~/.config/PRSCANM0R/config.json` ، کش: `~/.cache/PRSCANM0R/`

## چطور از لیمیت جلوگیری می‌شه
- **TCP pre-check**: اول فقط اتصال TCP تست می‌شه (سریع، بدون مصرف سهمیه). حدود ۹۰٪ پروکسی‌های مرده همین‌جا حذف می‌شن.
- **Rate limiter سراسری**: فقط پروکسی‌های زنده با سرعت `rate` در ثانیه + jitter تصادفی تست HTTP می‌شن.
- **چرخش سرویس تست**: ipwho.is / ipify / ip-api به‌صورت نوبتی؛ اگر 429 بگیره، خودکار می‌ره سراغ بعدی.
- **منابع**: بین دانلودها تأخیر هست، کش ۱۰ دقیقه‌ای، retry با backoff و احترام به Retry-After.
- اگر باز هم محدود شدید: `rate` رو کم (مثلاً 8) و `jitter_ms` رو زیاد کنید.

## نکات
- SOCKS فقط با python3-socks کار می‌کنه (همراه بسته نصب می‌شه).
- Ctrl+C در حالت CLI نتایج جزئی رو ذخیره می‌کنه.
- پروکسی‌های رایگان ناپایدارن؛ قبل از استفاده دوباره تست کنید و برای کار حساس ازشون استفاده نکنید.
                                                                                                   
