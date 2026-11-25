# Master Plan Phase 12 — React + TypeScript SOC SaaS Dashboard (`apps/web`)

## Executive Summary
Phase 12 delivers the production-ready Security Operations Center (SOC) Multi-Tenant Web Dashboard for the **Transformer-WAF** platform. Built under `apps/web/` using React 18, TypeScript, Vite, Tailwind CSS, TanStack React Query, and Recharts, the application provides enterprise security teams with real-time operational visibility, telemetry analytics, interactive WAF policy customization, scoped path exclusions, version rollbacks, human-governed false-positive feedback curation, and organization access control.

---

## 1. Architecture & Design System

### 1.1 Dark-First SOC Design System
- **Dark Mode Palette Tokens**: Canvas `#090D16`, Card/Sidebar `#111827`, Border `#1F2937`, High-contrast Text `#F8FAFC`, Muted Text `#94A3B8`.
- **Light Mode Palette Tokens**: Canvas `#F8FAFC`, Card/Sidebar `#FFFFFF`, Border `#E2E8F0`, Text `#0F172A`, Muted Text `#475569`.
- **Semantic Action Badges**:
  - `BLOCK`: Crimson (`bg-rose-500/10 text-rose-500 border-rose-500/20`)
  - `CHALLENGE`: Amber (`bg-amber-500/10 text-amber-500 border-amber-500/20`)
  - `MONITOR`: Blue (`bg-blue-500/10 text-blue-500 border-blue-500/20`)
  - `ALLOW`: Emerald (`bg-emerald-500/10 text-emerald-500 border-emerald-500/20`)
- **Risk Score Meter (`RiskMeter.tsx`)**: Visual 0.00–1.00 linear score meter color-coded across the active decision thresholds (`< 0.05` green, `0.05 - 0.50` blue, `0.50 - 0.85` amber, `>= 0.85` rose).
- **Monospace Formatting**: Strict `font-mono tabular-nums` applied to all HTTP methods, URL paths, risk scores, latencies, request IDs, and ISO timestamps.
- **Zero-Flash Theme Bootstrapping**: Embedded inline script inside `index.html` preventing theme flashing on initial DOM paint.

---

## 2. Implemented Pages & Features

### 2.1 Authentication & Workspace Onboarding (`Login.tsx`, `Register.tsx`)
- Secure authentication against `POST /api/v1/auth/login` and `POST /api/v1/auth/register`.
- HttpOnly cookie transport (`credentials: 'include'`) for `waf_access_token` and `waf_refresh_token`.
- Silent background session refresh on 401 Unauthorized (`POST /api/v1/auth/refresh`) with inflight subscriber queueing.
- Multi-tenant tenant creation on registration, establishing the owner membership and isolated tenant workspace.

### 2.2 Operational SOC Overview (`Overview.tsx`)
- **4 Key Performance Indicator (KPI) Cards**: Total Evaluated Requests, Blocked Threats with percentage rate, Active Protected Sites, and Average Decision Latency.
- **Threat Activity Stream**: Recharts stacked area chart displaying traffic volume over time partitioned into Allow, Monitor, Challenge, and Block bands across selectable time windows (`24h`, `7d`, `30d`).
- **Top Attacked Paths Table**: Ranked breakdown of endpoints with attack counts and high-risk percentages.
- **Recent Incident Log**: Live feed of the latest security events with 1-click drill-down.

### 2.3 Security Events & Threat Investigation (`Events.tsx`)
- Monospace query table supporting filtering by Action (`BLOCK`, `CHALLENGE`, `MONITOR`, `ALLOW`), path substring search, and minimum risk score.
- Slide-over Event Drawer:
  - Complete request metadata (IP hash, User-Agent, Referer, latency).
  - Risk breakdown and stage decision timeline (`Rule Match`, `Inference`, `Calibration`).
  - Redacted request payload JSON viewer.
  - Analyst False-Positive Feedback submission form.

### 2.4 Protected Sites Management (`Sites.tsx`)
- Inventory of provisioned tenant web properties with domain names, origin URLs, and health indicators (`ACTIVE`, `PAUSED`).
- Modal for provisioning new protected sites, automatically triggering backend default policy creation.
- 1-click site pause/resume toggle and safe deletion confirmation dialog.

### 2.5 WAF Policy Management, Versioning & Rollback (`Policies.tsx`)
- **Mode Selector Cards**: Visual radio selection between `MONITOR`, `BLOCKING`, and `LEARNING` modes.
- **Interactive 4-Band Threshold Bar**: Visual slider controls enforcing the strict invariant `0 < monitor < challenge < block <= 1.00`.
- **Attack Category Toggles**: Granular rule flags for SQL Injection (SQLi), Cross-Site Scripting (XSS), Command Injection (CMDi), and Path Traversal.
- **Scoped Exclusions Editor**: Modal and list editor for exempting trusted paths (e.g., `/api/v1/health`) while blocking broad wildcards (`*` or `/*`).
- **Policy Version History & 1-Click Rollback**: Version log displaying changelog comments, active indicators, and 1-click instant rollback creating a new immutable version.

### 2.6 False-Positive Feedback Queue (`Feedback.tsx`)
- **Human Governance Banner**: Explaining that feedback submissions do not mutate live production weights directly, but enter a curated corpus for offline validation.
- Status filter tabs: `Pending Review`, `Approved for Dataset`, `Rejected`, `All Submissions`.
- Inline Review Modals for `OWNER` and `ADMIN` users to approve or reject submissions with reviewer notes.

### 2.7 Team & RBAC Management (`Team.tsx`)
- Member roster displaying user full names, emails, joined dates, and semantic role badges.
- Member invitation modal allowing `OWNER` and `ADMIN` users to invite teammates with designated role tiers (`ADMIN`, `ANALYST`, `VIEWER`).

---

## 3. Test & Verification Matrix

| Suite | Category | Files | Total Tests | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Frontend Unit & Component** | Vitest + React Testing Library | 4 test suites | **18 passed** / 18 | **100% PASSED** |
| **Backend Domain & Unit** | NestJS + Jest | 7 test suites | **62 passed** / 62 | **100% PASSED** |
| **Backend Integration & E2E** | NestJS + Supertest | 5 test suites | **68 passed** / 68 | **100% PASSED** |
| **Python ML & WAF Data Plane** | PyTest | 6 test suites | **77 passed** / 77 | **100% PASSED** |
| **Production Build** | Vite Production Bundle | `apps/web/dist` | **746 kB minified / 207 kB gzip** | **0 Errors / 0 Warnings** |

### Vitest Frontend Test Breakdown:
1. `src/__tests__/theme.spec.tsx`: Verifies ThemeProvider dark mode default, class toggle on `<html>`, localStorage persistence, and hydration.
2. `src/__tests__/auth.spec.tsx`: Verifies Login and Register form rendering, input validation, and submission handler invocation.
3. `src/__tests__/rbac.spec.tsx`: Verifies ActionBadge rendering across all actions and RBAC permission helper logic across all 4 roles (`OWNER`, `ADMIN`, `ANALYST`, `VIEWER`).
4. `src/__tests__/policy-thresholds.spec.tsx`: Verifies 4-band threshold ordering invariant validation (`0 < monitor < challenge < block <= 1.00`).

---

## 4. Workstream Boundaries & Integrity
- **Python ML/WAF Data Plane**: `src/`, `models/`, `tests/`, and `nginx/` remained 100% untouched. All 77 PyTest tests pass cleanly in 25.35s.
- **Backend Modular Monolith**: `apps/api/` remained intact with zero architecture violations across all domain contexts. All 130 unit and E2E tests pass cleanly.
- **Cloud Spend**: Strictly **$0.00** across local Windows development environment.
