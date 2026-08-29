# AI-Based Phishing Link Detection for Email and SOC

פרויקט בקורס **מבוא לאבטחת סייבר מבוססת בינה מלאכותית**: זיהוי קישורי פישינג המופיעים בהודעות דוא״ל באמצעות למידת מכונה, הסבר החלטות המודל ושילוב התוצאות בתהליך עבודה של SOC.

היקף הגרסה הראשונה מתמקד ברכיב הקישור שבהודעה: המודל מנתח מאפיינים שחולצו מה-URL ומהאתר המקושר. הרחבה עתידית תשלב גם מאפייני טקסט של גוף ההודעה ומודל NLP.

## מצב נוכחי

- נבחרה בעיית המחקר והוגדרו מטרות הפרויקט.
- נטען מאגר UCI Phishing Websites הכולל 11,055 דגימות ו-30 מאפיינים.
- אומן מודל Random Forest ונבדק על סט בדיקה נפרד.
- התקבלו Accuracy של 97.06%, ‏F1 לפישינג של 96.69% ו-ROC-AUC של 99.64%.
- הופקו מטריצת בלבול, עקומת ROC ו-Permutation Importance להסבר המודל.
- הוגדר מיפוי ל-MITRE ATT&CK ‏T1566.002 ופורמט התראה לדוגמה עבור SOC.
- הוכנו דוח ומצגת ראשוניים.
- נכתב מיפוי מפורש לדרישות הסילבוס ב-`docs/SYLLABUS_ALIGNMENT.md`.

## מבנה המאגר

| תיקייה | תוכן |
|---|---|
| `src/` | קוד Python לאימון, הערכה והפקת התראות |
| `notebooks/` | Notebook הדגמה להרצה ב-JupyterLab |
| `data/` | מאגר הנתונים והסבר מקור/רישיון |
| `results/` | מדדים, גרפים והתראות לדוגמה |
| `report/` | דוח הפרויקט |
| `presentation/` | מצגת קצרה להצגה |
| `docs/` | תוכנית עבודה ויומן התקדמות |
| `labs/` | סטטוס כן של ארבע המעבדות |

## הרצה

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python src/phishing_detection.py
```

אפשר גם לפתוח את `notebooks/phishing_detection_demo.ipynb` ב-JupyterLab ולהריץ את התאים לפי הסדר.

## תוצאות עיקריות

| מדד | תוצאה |
|---|---:|
| Accuracy | 97.06% |
| Precision — Phishing | 96.64% |
| Recall — Phishing | 96.73% |
| F1 — Phishing | 96.69% |
| ROC-AUC | 99.64% |

התוצאות הן ניסוי ראשוני על חלוקה אקראית משוכבת של אותו מאגר. הן אינן הוכחה לביצועים זהים בעולם האמיתי; נדרשת בהמשך בדיקה על נתונים עדכניים וחיצוניים.

## מקורות מרכזיים

- UCI Phishing Websites Dataset: https://doi.org/10.24432/C51W2X
- MITRE ATT&CK T1566.002: https://attack.mitre.org/techniques/T1566/002/
- NIST AI Risk Management Framework 1.0: https://doi.org/10.6028/NIST.AI.100-1
- Chio, C., & Freeman, D. (2018). *Machine Learning and Security*. O'Reilly Media.

## שימוש אחראי

הפרויקט הגנתי ולימודי בלבד. הקוד מנתח מאפיינים מספריים שכבר חולצו ואינו גולש לאתרים חשודים. אין להשתמש בתוצאה יחידה של המודל לחסימה אוטומטית ללא אימות, ניטור ושיקול דעת אנושי.
