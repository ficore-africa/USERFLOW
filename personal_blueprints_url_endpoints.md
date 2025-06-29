# Personal Blueprints URL Endpoints Analysis

## Overview
This document lists all URL endpoints that the personal finance blueprints are passing to their templates via `url_for()` calls.

## 1. Bill Blueprint (`personal/bill.py`)

### Routes Defined:
- `/BILL/main` → `bill.main`
- `/BILL/unsubscribe/<email>` → `bill.unsubscribe`

### URL Endpoints Passed to Templates:
- `bill.main` - Main bill management interface
- `bill.unsubscribe` - Unsubscribe from bill email notifications
- `users_blueprint.login` - Login page redirect
- `index` - Homepage redirect

### Template: `BILL/bill_main.html`

---

## 2. Budget Blueprint (`personal/budget.py`)

### Routes Defined:
- `/BUDGET/main` → `budget.main`

### URL Endpoints Passed to Templates:
- `budget.main` - Main budget management interface
- `users_blueprint.login` - Login page redirect

### Template: `BUDGET/budget_main.html`

---

## 3. Emergency Fund Blueprint (`personal/emergency_fund.py`)

### Routes Defined:
- `/EMERGENCYFUND/main` → `emergency_fund.main`
- `/EMERGENCYFUND/unsubscribe/<email>` → `emergency_fund.unsubscribe`

### URL Endpoints Passed to Templates:
- `emergency_fund.main` - Main emergency fund interface
- `emergency_fund.unsubscribe` - Unsubscribe from emergency fund emails
- `users_blueprint.login` - Login page redirect
- `index` - Homepage redirect

### Template: `EMERGENCYFUND/emergency_fund_main.html`

---

## 4. Financial Health Blueprint (`personal/financial_health.py`)

### Routes Defined:
- `/HEALTHSCORE/main` → `financial_health.main`

### URL Endpoints Passed to Templates:
- `financial_health.main` - Main financial health interface
- `users_blueprint.login` - Login page redirect

### Template: `HEALTHSCORE/health_score_main.html`

---

## 5. Learning Hub Blueprint (`personal/learning_hub.py`)

### Routes Defined:
- `/LEARNINGHUB/` → `learning_hub.main`
- `/LEARNINGHUB/main` → `learning_hub.main`
- `/LEARNINGHUB/api/course/<course_id>` → `learning_hub.get_course_data`
- `/LEARNINGHUB/api/lesson` → `learning_hub.get_lesson_data`
- `/LEARNINGHUB/api/quiz` → `learning_hub.get_quiz_data`
- `/LEARNINGHUB/api/lesson/action` → `learning_hub.lesson_action`
- `/LEARNINGHUB/api/quiz/action` → `learning_hub.quiz_action`
- `/LEARNINGHUB/profile` → `learning_hub.profile`
- `/LEARNINGHUB/unsubscribe/<email>` → `learning_hub.unsubscribe`
- `/LEARNINGHUB/static/uploads/<path:filename>` → `learning_hub.serve_uploaded_file`

### Legacy Redirects:
- `/LEARNINGHUB/courses` → redirects to `learning_hub.main`
- `/LEARNINGHUB/courses/<course_id>` → redirects to `learning_hub.main`
- `/LEARNINGHUB/courses/<course_id>/lesson/<lesson_id>` → redirects to `learning_hub.main`
- `/LEARNINGHUB/courses/<course_id>/quiz/<quiz_id>` → redirects to `learning_hub.main`
- `/LEARNINGHUB/dashboard` → redirects to `learning_hub.main`

### URL Endpoints Passed to Templates:
- `learning_hub.main` - Main learning hub interface
- `learning_hub.unsubscribe` - Unsubscribe from learning hub emails
- `users_blueprint.login` - Login page redirect

### Template: `learning_hub_main.html`

---

## 6. Net Worth Blueprint (`personal/net_worth.py`)

### Routes Defined:
- `/NETWORTH/main` → `net_worth.main`
- `/NETWORTH/unsubscribe/<email>` → `net_worth.unsubscribe`

### URL Endpoints Passed to Templates:
- `net_worth.main` - Main net worth interface
- `net_worth.unsubscribe` - Unsubscribe from net worth emails
- `users_blueprint.login` - Login page redirect
- `index` - Homepage redirect

### Template: `NETWORTH/net_worth_main.html`

---

## 7. Quiz Blueprint (`personal/quiz.py`)

### Routes Defined:
- `/QUIZ/main` → `quiz.main`

### URL Endpoints Passed to Templates:
- `quiz.main` - Main quiz interface
- `users_blueprint.login` - Login page redirect

### Template: `QUIZ/quiz_main.html`

---

## Summary of All URL Endpoints Used

### Internal Personal Finance Routes:
1. `bill.main`
2. `bill.unsubscribe`
3. `budget.main`
4. `emergency_fund.main`
5. `emergency_fund.unsubscribe`
6. `financial_health.main`
7. `learning_hub.main`
8. `learning_hub.unsubscribe`
9. `net_worth.main`
10. `net_worth.unsubscribe`
11. `quiz.main`

### External Routes Referenced:
1. `users_blueprint.login` - User authentication
2. `index` - Application homepage
3. `settings_blueprint.profile` - User profile settings

### API Endpoints (Learning Hub):
1. `learning_hub.get_course_data`
2. `learning_hub.get_lesson_data`
3. `learning_hub.get_quiz_data`
4. `learning_hub.lesson_action`
5. `learning_hub.quiz_action`
6. `learning_hub.profile`
7. `learning_hub.serve_uploaded_file`

## Template Structure
All personal finance blueprints follow a consistent pattern:
- Main route serves the primary interface
- Unsubscribe routes for email management
- Redirects to login for unauthenticated users
- Templates located in respective subdirectories under `templates/`

## Access Control
All routes use the `@requires_role(['personal', 'admin'])` decorator to ensure only personal users and admins can access these tools.