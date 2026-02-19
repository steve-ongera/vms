# 🏢 VMS — Professional Visitor Management System

> A scalable, production-ready **Visitor Management System** built with Django for gated estates, apartment complexes, and commercial buildings. Designed to match the feature depth of market-leading platforms like Envoy, Verkada, and ButterflyMX — while remaining fully self-hosted and extensible.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Database Models (60+)](#database-models)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [Running the Project](#running-the-project)
- [User Roles & Permissions](#user-roles--permissions)
- [Hardware Integration Guide](#hardware-integration-guide)
- [API Overview](#api-overview)
- [Admin Panel](#admin-panel)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

VMS is a comprehensive gate and visitor management platform for:

- 🏠 **Residential estates** and gated communities
- 🏗️ **Apartment complexes** with multiple blocks
- 🏢 **Commercial buildings** and office parks
- 🏭 **Industrial facilities** with contractor access control

It handles the full visitor lifecycle — from **pre-registration** and **invitation** through **biometric check-in**, **badge printing**, **parking**, **deliveries**, and **security incident logging** — with a clean audit trail throughout.

---

## Features

### Core Visitor Lifecycle
- ✅ Walk-in visitor registration with ID capture
- ✅ Pre-registration & invitation links (QR / OTP)
- ✅ Resident approval workflow (approve/deny from mobile)
- ✅ Self-service kiosk check-in
- ✅ Check-in / check-out with gate assignment
- ✅ Recurring visitor rules (house help, regular contractors)
- ✅ Multi-visitor group check-in

### Access Control
- ✅ Multi-zone, multi-gate architecture
- ✅ Time-based and day-based access rules
- ✅ Role-based access levels (6 levels)
- ✅ Card/RFID issuance with zone restrictions
- ✅ Temporary pass generation

### Hardware Integration (Plug-In Architecture)
- 🔌 Fingerprint reader SDK hooks
- 🔌 RFID / NFC / Smart card readers
- 🔌 Facial recognition cameras
- 🔌 QR code scanners
- 🔌 License plate recognition (LPR)
- 🔌 Video intercom / doorbell
- 🔌 Turnstile / barrier controllers
- 🔌 PIN keypad
- 🔌 Body temperature scanner

### Security & Operations
- ✅ Blacklist with severity levels (Low → Critical)
- ✅ Watchlist with security alerts
- ✅ Security incident reporting
- ✅ Emergency alerts with gate lockdown
- ✅ Muster/evacuation tracking
- ✅ CCTV snapshot capture on access events
- ✅ Police report reference tracking

### Vehicles & Parking
- ✅ Registered vehicle database per resident
- ✅ Visitor vehicle logging with LPR
- ✅ Parking slot assignment and session tracking

### Deliveries & Contractors
- ✅ Parcel/courier delivery tracking
- ✅ Resident notification on delivery arrival
- ✅ Contractor & work order management
- ✅ Resident approval for contractor unit access

### Notifications
- ✅ Multi-channel: SMS, Email, Push, WhatsApp, In-App
- ✅ Customisable templates per event type per estate
- ✅ Delivery status tracking

### Admin & Reporting
- ✅ Full-featured Django Admin with colour-coded status badges
- ✅ 14+ custom admin actions (approve, deny, export CSV, etc.)
- ✅ Daily pre-aggregated analytics reports
- ✅ Scheduled report subscriptions (PDF / Excel / CSV)
- ✅ Immutable audit trail on all system actions

### Enterprise / SaaS
- ✅ Multi-estate architecture (one platform, many clients)
- ✅ Subscription plan & billing model
- ✅ Webhook subscriptions for third-party integrations
- ✅ Third-party integration registry (Twilio, SendGrid, etc.)
- ✅ Soft delete across all core models
- ✅ UUID primary keys (safe for external APIs)

---

## System Architecture

```
┌───────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                        │
│  Web Dashboard │ Mobile App (Resident) │ Security Kiosk   │
└────────────────────────────┬──────────────────────────────┘
                             │ REST API / WebSocket
┌────────────────────────────▼──────────────────────────────┐
│                      DJANGO APPLICATION                    │
│                                                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐  │
│  │  Visits  │ │ Access   │ │Vehicles  │ │ Incidents   │  │
│  │  Module  │ │ Control  │ │ Parking  │ │ Emergency   │  │
│  └──────────┘ └──────────┘ └──────────┘ └─────────────┘  │
│                                                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐  │
│  │ Hardware │ │Notif     │ │Analytics │ │  Billing    │  │
│  │ Devices  │ │ Engine   │ │ Reports  │ │  & SaaS     │  │
│  └──────────┘ └──────────┘ └──────────┘ └─────────────┘  │
└──────┬─────────────────────────────────────────┬──────────┘
       │                                         │
┌──────▼──────┐                        ┌─────────▼────────┐
│  PostgreSQL  │                        │  Hardware Layer   │
│  Database   │                        │ Fingerprint/RFID  │
│             │                        │ Face/LPR/Intercom │
└─────────────┘                        └──────────────────┘
```

### Data Flow — Visitor Arrival

```
Visitor arrives at gate
        │
        ▼
Security scans ID / Visitor scans QR
        │
        ├── QR match? ──► Pre-registration found ──► Auto-approve
        │
        ├── Walk-in? ──► Check blacklist ──► Notify host ──► Await approval
        │
        ▼
Check-in confirmed
        │
        ├── Issue badge (printed / digital)
        ├── Log AccessEvent from device
        ├── Update Visit status → CHECKED_IN
        ├── Send notification to host
        ├── Trigger webhooks
        └── Start parking session (if vehicle)
```

---

## Database Models

| Module | Models | Description |
|--------|--------|-------------|
| Estate & Property | `Estate`, `Block`, `CommonArea` | Top-level property hierarchy |
| Users | `User`, `ResidentProfile`, `SecurityStaffProfile` | 9 built-in roles |
| Units | `Unit` | Individual flats/offices |
| Visits | `Visitor`, `Visit`, `RecurrenceRule` | Core transaction models |
| Pre-Registration | `PreRegistration` | QR/OTP invitation system |
| Access Control | `Zone`, `Gate`, `AccessPermission` | Multi-zone access rules |
| Hardware | `AccessDevice`, `BiometricTemplate`, `AccessCard`, `AccessEvent` | Device SDK integration |
| Badges | `VisitorBadge` | Printed/digital passes |
| Notifications | `NotificationTemplate`, `Notification` | Multi-channel messaging |
| Blacklist | `Blacklist`, `Watchlist` | Security screening |
| Vehicles | `RegisteredVehicle`, `VisitorVehicle`, `ParkingSlot`, `ParkingSession` | Parking management |
| Deliveries | `Delivery` | Parcel/courier tracking |
| Contractors | `Contractor`, `WorkOrder` | Service staff management |
| Incidents | `Incident` | Security event reporting |
| Audit | `AuditLog` | Immutable system log |
| Analytics | `DailyReport`, `SavedReport` | Reporting engine |
| Documents | `VisitorDocument` | NDA / form management |
| Emergency | `EmergencyAlert`, `EvacuationRecord` | Crisis management |
| Integrations | `WebhookEndpoint`, `WebhookDelivery`, `ThirdPartyIntegration` | External system hooks |
| Billing | `SubscriptionPlan`, `EstateSubscription` | SaaS monetisation |
| Config | `SystemSetting`, `VisitorFeedback` | Platform configuration |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Django 5.x, Django REST Framework |
| Database | PostgreSQL 15+ |
| Cache / Queue | Redis + Celery |
| Authentication | djangorestframework-simplejwt |
| File Storage | AWS S3 / MinIO (local dev) |
| SMS | Twilio / Africa's Talking |
| Email | SendGrid / Postfix |
| Push Notifications | Firebase Cloud Messaging (FCM) |
| WebSocket | Django Channels |
| Containerisation | Docker + Docker Compose |
| Task Scheduling | Celery Beat |
| Hardware SDKs | ZKTeco SDK, Suprema BioStar, HikVision API |

---

## Project Structure

```
vms/
├── config/                     # Django project settings
│   ├── settings/
│   │   ├── base.py
│   │   ├── development.py
│   │   └── production.py
│   ├── urls.py
│   ├── celery.py
│   └── wsgi.py
│
├── apps/
│   ├── estate/                 # Estate, Block, CommonArea
│   │   ├── models.py
│   │   ├── admin.py
│   │   ├── serializers.py
│   │   ├── views.py
│   │   └── urls.py
│   │
│   ├── users/                  # User, ResidentProfile, SecurityStaffProfile
│   ├── units/                  # Unit
│   ├── visits/                 # Visitor, Visit, PreRegistration, RecurrenceRule
│   ├── access_control/         # Zone, Gate, AccessPermission
│   ├── hardware/               # AccessDevice, BiometricTemplate, AccessCard, AccessEvent
│   ├── notifications/          # NotificationTemplate, Notification
│   ├── security/               # Blacklist, Watchlist, Incident
│   ├── vehicles/               # RegisteredVehicle, VisitorVehicle, ParkingSlot, ParkingSession
│   ├── deliveries/             # Delivery
│   ├── contractors/            # Contractor, WorkOrder
│   ├── analytics/              # DailyReport, SavedReport
│   ├── documents/              # VisitorDocument
│   ├── emergency/              # EmergencyAlert, EvacuationRecord
│   ├── integrations/           # WebhookEndpoint, WebhookDelivery, ThirdPartyIntegration
│   └── billing/                # SubscriptionPlan, EstateSubscription
│
├── shared/                     # Abstract models, mixins, utilities
│   ├── models.py               # TimeStampedModel, UUIDModel, SoftDeleteModel
│   ├── admin.py                # Shared admin utilities
│   └── utils.py
│
├── hardware_integrations/      # Device SDK adapters
│   ├── base.py                 # Abstract HardwareAdapter interface
│   ├── zkteco.py               # ZKTeco fingerprint/card reader
│   ├── suprema.py              # Suprema BioStar2 SDK
│   ├── hikvision.py            # HikVision camera / intercom
│   └── generic_wiegand.py      # Generic Wiegand card readers
│
├── tasks/                      # Celery tasks
│   ├── notifications.py
│   ├── analytics.py
│   ├── hardware_sync.py
│   └── reports.py
│
├── requirements/
│   ├── base.txt
│   ├── development.txt
│   └── production.txt
│
├── docker-compose.yml
├── Dockerfile
├── .env.example
└── manage.py
```

---

## Getting Started

### Prerequisites

- Python 3.11+
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose (recommended)

### 1. Clone the Repository

```bash
git clone https://github.com/yourorg/vms.git
cd vms
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements/development.txt
```

### 4. Set Up Environment Variables

```bash
cp .env.example .env
# Edit .env with your database, Redis, and API credentials
```

### 5. Create the Database

```bash
createdb vms_db
```

### 6. Run Migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

### 7. Create Superuser

```bash
python manage.py createsuperuser
```

### 8. Load Sample Data (Optional)

```bash
python manage.py loaddata fixtures/sample_estate.json
```

### 9. Start the Development Server

```bash
python manage.py runserver
```

Admin panel: [http://localhost:8000/admin](http://localhost:8000/admin)

---

## Environment Variables

```env
# Django
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DATABASE_URL=postgresql://postgres:password@localhost:5432/vms_db

# Redis
REDIS_URL=redis://localhost:6379/0

# File Storage
USE_S3=False
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_STORAGE_BUCKET_NAME=

# SMS (Africa's Talking or Twilio)
SMS_PROVIDER=africastalking
AFRICASTALKING_USERNAME=
AFRICASTALKING_API_KEY=

# Email
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.sendgrid.net
EMAIL_PORT=587
EMAIL_HOST_USER=apikey
EMAIL_HOST_PASSWORD=

# Firebase (Push Notifications)
FIREBASE_CREDENTIALS_PATH=firebase-credentials.json

# WhatsApp
WHATSAPP_API_URL=
WHATSAPP_ACCESS_TOKEN=

# Hardware
DEVICE_HEARTBEAT_TIMEOUT_SECONDS=60
```

---

## Running the Project

### With Docker (Recommended)

```bash
docker-compose up --build
```

This starts: Django, PostgreSQL, Redis, and Celery worker + beat.

### Celery Worker (Background Tasks)

```bash
# In a separate terminal
celery -A config worker --loglevel=info

# Celery Beat (scheduled tasks — daily reports, expired visits, etc.)
celery -A config beat --loglevel=info --scheduler django_celery_beat.schedulers:DatabaseScheduler
```

---

## User Roles & Permissions

| Role | Can Approve Visits | Can Check In | Manage Blacklist | View Reports | Manage Estate |
|------|--------------------|--------------|-----------------|--------------|---------------|
| **SuperAdmin** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Estate Admin** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Property Manager** | ✅ | ❌ | ✅ | ✅ | ⚠️ Partial |
| **Security** | ✅ | ✅ | ⚠️ Add only | ⚠️ Partial | ❌ |
| **Receptionist** | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Resident** | ✅ Own visitors | ❌ | ❌ | ❌ | ❌ |
| **Tenant** | ✅ Own visitors | ❌ | ❌ | ❌ | ❌ |
| **Contractor** | ❌ | ❌ | ❌ | ❌ | ❌ |

---

## Hardware Integration Guide

The system uses an **adapter pattern** to support any hardware vendor. Adding a new device type is straightforward.

### Step 1: Register the Device in Admin

Go to **Hardware → Access Devices** and create a new record:
- Set `device_type` (e.g. `FINGERPRINT_READER`)
- Enter `ip_address`, `api_endpoint`, `api_key`
- Save configuration in the `configuration` JSON field

### Step 2: Create an Adapter

```python
# hardware_integrations/my_device.py
from .base import HardwareAdapter

class MyFingerprintAdapter(HardwareAdapter):

    def enroll(self, user_id: str, template_data: bytes) -> bool:
        """Send template to device memory."""
        ...

    def verify(self, template_data: bytes) -> str | None:
        """Return matching user_id or None."""
        ...

    def delete(self, user_id: str) -> bool:
        """Remove user from device."""
        ...

    def get_events(self, since: datetime) -> list[dict]:
        """Pull raw access events from device."""
        ...
```

### Step 3: Map the Adapter

```python
# hardware_integrations/registry.py
ADAPTERS = {
    "FINGERPRINT_READER": {
        "ZKTeco": ZKTecoAdapter,
        "Suprema": SupremaAdapter,
        "MyDevice": MyFingerprintAdapter,    # ← add here
    },
    "RFID_READER": {...},
    "FACE_RECOGNITION": {...},
}
```

No model changes required. The `AccessDevice` and `BiometricTemplate` models are already built to store any manufacturer's data.

---

## API Overview

The REST API is built with **Django REST Framework**. All endpoints are JWT-authenticated.

| Resource | Endpoint | Methods |
|----------|----------|---------|
| Auth | `/api/auth/token/` | POST |
| Estates | `/api/estates/` | GET, POST |
| Units | `/api/units/` | GET, POST, PATCH |
| Visitors | `/api/visitors/` | GET, POST, PATCH |
| Visits | `/api/visits/` | GET, POST, PATCH |
| Pre-Registration | `/api/pre-registrations/` | GET, POST |
| Check-In | `/api/visits/{id}/checkin/` | POST |
| Check-Out | `/api/visits/{id}/checkout/` | POST |
| Approve Visit | `/api/visits/{id}/approve/` | POST |
| Gates | `/api/gates/` | GET |
| Devices | `/api/devices/` | GET, POST |
| Access Events | `/api/access-events/` | GET |
| Deliveries | `/api/deliveries/` | GET, POST, PATCH |
| Incidents | `/api/incidents/` | GET, POST |
| Blacklist | `/api/blacklist/` | GET, POST |
| Vehicles | `/api/vehicles/` | GET, POST |
| Emergency | `/api/emergency/alerts/` | GET, POST |

Full API documentation available at `/api/docs/` (Swagger UI) and `/api/redoc/` (ReDoc).

---

## Admin Panel

Access at `/admin/` with your superuser credentials.

Key features of the admin:
- **Colour-coded status badges** on all list views (green=active, red=denied, etc.)
- **Inline editing** of related models (e.g. BlockInline inside Estate)
- **Custom bulk actions**: approve visits, verify IDs, flag visitors, export CSV, open/close gates
- **Read-only AuditLog** — cannot be added, changed, or deleted
- **Date hierarchy navigation** on time-series models (Visits, Events, etc.)
- **Collapsible fieldsets** to keep long forms clean

---

## Roadmap

### Phase 1 — Core (Current)
- [x] Estate, Block, Unit hierarchy
- [x] Visitor & Visit lifecycle
- [x] Pre-registration & QR/OTP
- [x] Security blacklist & watchlist
- [x] Deliveries & parking
- [x] Incident reporting
- [x] Audit trail
- [x] Multi-estate SaaS architecture

### Phase 2 — Hardware Integration
- [ ] ZKTeco fingerprint reader adapter
- [ ] HikVision intercom/camera adapter
- [ ] Generic Wiegand card reader adapter
- [ ] License plate recognition (LPR) pipeline
- [ ] Real-time gate status via WebSocket

### Phase 3 — Mobile & Self-Service
- [ ] Resident mobile app (React Native)
- [ ] Security officer mobile app
- [ ] Self-service kiosk UI (Flutter / React)
- [ ] Visitor self-registration link
- [ ] WhatsApp approval bot

### Phase 4 — Intelligence
- [ ] AI-powered blacklist face matching
- [ ] Visit pattern anomaly detection
- [ ] Predictive parking availability
- [ ] Automated report generation

### Phase 5 — Enterprise
- [ ] Multi-tenant SaaS billing portal
- [ ] Custom branding per estate
- [ ] SAML / SSO integration
- [ ] ISO 27001 compliance audit export

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/fingerprint-integration`
3. Write tests for your changes
4. Run the test suite: `python manage.py test`
5. Submit a pull request with a clear description

Please follow PEP 8 and use `black` for formatting.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Support

For deployment support, hardware integration questions, or enterprise licensing, raise an issue or contact the maintainers.

---

*Built with ❤️ for safer, smarter communities.*