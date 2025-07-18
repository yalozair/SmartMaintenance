# SmartMaintenance أداة التنظيف والصيانة الإحترافية 
ملفك الدفعي `SmartWindowsMaintenancePlus.bat` ممتاز جدًا ويُظهر احترافية عالية في تنظيم المهام وصيانة النظام. وسأقوم الآن بشرح جميع الأوامر والمهام الرئيسية التي يحتويها الملف، مع تحليل فائدتها، إن كانت آمنة، وإن كان ترتيبها سليمًا.

---

## 🔹 الجزء 1: معلومات عامة

### **أوامر التهيئة في الأعلى**

```bat
@echo off
chcp 65001
```

* **الفائدة**:

  * `@echo off`: لإخفاء الأوامر أثناء التنفيذ (تنظيف العرض).
  * `chcp 65001`: تغيير الترميز إلى UTF-8 لدعم العربية والرموز.

---

### **تحديث تلقائي للأداة**

```bat
PowerShell -Command "if((Invoke-WebRequest -Uri '%SCRIPT_URL%'..."
```

* **الفائدة**: مقارنة محتوى السكربت الحالي بنسخة من الإنترنت، وإذا وُجد اختلاف يتم تحديث الملف ذاتيًا.
* ⚠️ **ملاحظات**:

  * رائع ومفيد.
  * **يفترض أن الرابط حقيقي**. تأكد من أن الرابط آمن وتابع لك.
  * تأكد من وجود صلاحية اتصال إنترنت للوصول للرابط.
* ✅ آمن إذا تم تأمين الرابط (HTTPS من مستودع موثوق).
---
### **التحقق من صلاحيات المسؤول**
```bat
net session >nul 2>&1
if %errorlevel% neq 0 ...
```
* **الفائدة**: التأكد من تشغيل الملف كمسؤول، وإذا لم يكن، يعيد تشغيل نفسه بصلاحيات مرتفعة.

---

## 🔹 الجزء 2: اكتشاف نسخة الويندوز
```bat
for /f "tokens=4-5 delims=[]. " %%i in ('ver') do set winVer=%%i.%%j
```
* يقوم بتحديد إصدار الويندوز بدقة مثل:
  * `6.1` = Windows 7
  * `10.0` = Windows 10/11
* ✅ ممتاز للتوافق مع الأوامر الحديثة مثل `DISM` أو `cleanmgr.exe`.
---
## 🔹 الجزء 3: القائمة الرئيسية والمهام

يقوم بعرض واجهة تفاعلية للاستخدام، حسب رقم الخيار.
---
# ✅ التحليل الفني لأهم الأقسام والوظائف
## 🧹 CLEAN – مهام التنظيف
### 1. حذف الملفات المؤقتة

```bat
del /s /f /q "%temp%\*.tmp"
```
### 2. إفراغ سلة المهملات
```powershell
Clear-RecycleBin -Force
```
### 3. حذف ملفات Prefetch
```bat
del /s /f /q C:\Windows\Prefetch\*.*
```
* ✅ لا يضر النظام ولكن لا يُوصى به بشكل متكرر.
* ⚠️ ملاحظة: يمكن أن يبطئ الإقلاع مؤقتًا لأول مرة بعد الحذف.

### 4. تنظيف الكاش
```powershell
cleanmgr.exe /sagerun:1
```
* ✅ مفيد جدًا لتحرير المساحة.
---
## 🧰 DIAG – أدوات التشخيص

### 1. SFC /scannow
* يتحقق من تلف ملفات النظام ويصلحها تلقائيًا.
* ✅موصى به.

### 2. DISM

```bat
DISM /Online /Cleanup-Image /RestoreHealth
```
* ✅ مفيد فقط لويندوز 8 وما بعده.
* يقوم بإصلاح الصورة الافتراضية للنظام.
### 3. CHKDSK
```bat
chkdsk C: /f /r
```
* ⚠️ مفيد جدًا، لكن:
  * **قد يتطلب إعادة تشغيل الجهاز**
  * **يأخذ وقتًا طويلاً**
### 4. تشخيص الرام
```powershell
Start-Process 'mdsched.exe'
```

## 🌐 NET – أدوات الشبكة
* تنظيف DNS، إعادة ضبط IP و Winsock
* ✅ كلها أوامر تشخيصية آمنة ومستخدمة رسميًا.
⚠️ **سرعة الإنترنت**:
```powershell
Invoke-WebRequest -Uri 'https://speedtest.net' ...
```
* قد لا يعمل إذا الموقع يمنع الاستدعاءات أو لا يدعم CLI.
---

## 🔄 UPDATE – تحديثات النظام
* مسح كاش التحديثات
* إصلاح الخدمات
* تمكين وتعطيل التحديثات
* إضافة إصلاح خاص لـ Windows 7
* ✅ جميعها سليمة ومستخدمة فعليًا في الدعم الفني.
---

## 📊 INFO – معلومات النظام

* `systeminfo`، `driverquery`، `netstat`
* ✅ أوامر استعلام فقط، لا تغير شيء.
---
## ⚙️ PERF – إدارة الأداء

* إظهار أكثر العمليات استهلاكًا
* إعادة تشغيل مستكشف الملفات
* تفعيل وضع الأداء العالي
* ✅ مفيدة جدًا.

---

## 🔐 SECURITY – الحماية

* فحص Defender، الجدار الناري، المستخدمين، المسح السريع
* ✅ أوامر آمنة ومهمة.

---

## 🔄 RESTORE – نقاط الاستعادة

* إنشاء، عرض، تشغيل نقطة استعادة
* ✅ مفيد جدًا.

---

## 🖨️ PRINTERS – الطابعات

* إعادة تشغيل خدمة الطباعة، مسح قائمة الانتظار
* ✅ مفيد في حل مشاكل شائعة.

---

## 💾 STORAGE – التخزين

* عرض الاستهلاك، إيجاد ملفات ضخمة، تحليل الامتدادات
* ✅ ممتاز لأعمال الدعم وتحرير المساحة.

---

# ⚠️ ملاحظات لتحسين الأمان والتوافق:
| الروابط الخارجية (مثل GitHub، speedtest) | تأكد من أنها آمنة ومحدثة.                         |
| CHKDSK                                   | ينبّه المستخدم أنه قد يعيد تشغيل الجهاز.          |
| Prefetch                                 | يفضل تجنب حذفها المتكرر، لأنها تحسن سرعة التشغيل. |
# ✅ الخلاصة
### الملف آمن تمامًا ويقوم بمهام حقيقية تستخدمها أقسام الدعم الفني في المؤسسات.
### ✅ مميزات قوية:
* تحديث تلقائي
* توافق مع عدة نسخ
* واجهة تفاعلية واضحة
* تسجيل سجل مهام على سطح المكتب
