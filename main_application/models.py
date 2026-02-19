"""
=============================================================================
PROFESSIONAL VISITOR MANAGEMENT SYSTEM - DJANGO MODELS
Estate / Apartment / Gated Community
=============================================================================

ARCHITECTURE OVERVIEW:
  Core Modules:
    1.  Estate & Property Setup
    2.  Users, Residents & Staff
    3.  Units / Flats
    4.  Visitor & Visit Management
    5.  Pre-Registration & Invitations
    6.  Access Control (Gates, Doors, Zones)
    7.  Hardware Integration (Fingerprint, RFID/Card, Face, QR)
    8.  Badges & Passes
    9.  Notifications & Alerts
    10. Blacklist & Watchlist
    11. Vehicles & Parking
    12. Deliveries & Couriers
    13. Contractors & Service Staff
    14. Incidents & Security Logs
    15. Audit Trail
    16. Analytics & Reports
    17. Document & NDA Management
    18. Emergency Management
    19. API / Integration Webhooks
    20. Billing & Subscriptions (multi-estate SaaS-ready)

=============================================================================
"""

import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.core.validators import RegexValidator


# ---------------------------------------------------------------------------
# UTILITY MIXINS
# ---------------------------------------------------------------------------

class TimeStampedModel(models.Model):
    """Abstract base with created/updated timestamps."""
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class UUIDModel(models.Model):
    """Abstract base using UUID primary key for external-safe IDs."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        abstract = True


class SoftDeleteModel(models.Model):
    """Soft delete — records are never truly removed."""
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)

    def delete(self, *args, **kwargs):
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save()

    class Meta:
        abstract = True


# ---------------------------------------------------------------------------
# 1. ESTATE & PROPERTY SETUP
# ---------------------------------------------------------------------------

class Estate(UUIDModel, TimeStampedModel, SoftDeleteModel):
    """
    Top-level entity. One estate can have multiple blocks/buildings.
    Supports multi-estate SaaS deployment.
    """
    name = models.CharField(max_length=200)
    code = models.CharField(max_length=20, unique=True, help_text="Short code e.g. GRN01")
    address = models.TextField()
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    country = models.CharField(max_length=100, default="Kenya")
    postal_code = models.CharField(max_length=20, blank=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    logo = models.ImageField(upload_to="estate/logos/", null=True, blank=True)
    contact_phone = models.CharField(max_length=20, blank=True)
    contact_email = models.EmailField(blank=True)
    website = models.URLField(blank=True)
    is_active = models.BooleanField(default=True)
    timezone = models.CharField(max_length=50, default="Africa/Nairobi")
    # Settings JSON (visitor duration limits, OTP config, etc.)
    settings = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ["name"]


class Block(UUIDModel, TimeStampedModel):
    """A building / block within an estate (Block A, Tower 1, etc.)."""
    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="blocks")
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=10)
    floors = models.PositiveIntegerField(default=1)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.estate.name} – {self.name}"

    class Meta:
        unique_together = ("estate", "code")


class CommonArea(UUIDModel, TimeStampedModel):
    """Gym, pool, clubhouse, etc. — areas visitors/residents can access."""
    AREA_TYPES = [
        ("GYM", "Gymnasium"),
        ("POOL", "Swimming Pool"),
        ("CLUBHOUSE", "Clubhouse"),
        ("PARKING", "Parking"),
        ("LOBBY", "Lobby"),
        ("ROOFTOP", "Rooftop"),
        ("PLAYGROUND", "Playground"),
        ("OTHER", "Other"),
    ]
    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="common_areas")
    name = models.CharField(max_length=100)
    area_type = models.CharField(max_length=20, choices=AREA_TYPES)
    capacity = models.PositiveIntegerField(null=True, blank=True)
    access_controlled = models.BooleanField(default=False)
    description = models.TextField(blank=True)

    def __str__(self):
        return f"{self.name} ({self.estate.name})"


# ---------------------------------------------------------------------------
# 2. USERS, RESIDENTS & STAFF
# ---------------------------------------------------------------------------

class User(AbstractUser):
    """
    Extended user. Covers: SuperAdmin, EstateAdmin, SecurityStaff, Resident,
    Tenant, PropertyManager, Contractor, Visitor (self-service kiosk).
    """
    ROLE_CHOICES = [
        ("SUPERADMIN", "Super Admin"),         # Platform owner
        ("ESTATE_ADMIN", "Estate Admin"),       # Estate manager
        ("PROPERTY_MANAGER", "Property Manager"),
        ("SECURITY", "Security Staff"),
        ("RECEPTIONIST", "Receptionist"),
        ("RESIDENT", "Resident / Owner"),
        ("TENANT", "Tenant"),
        ("STAFF", "Support Staff"),             # Cleaners, maintenance
        ("CONTRACTOR", "Contractor"),
        ("VISITOR", "Visitor (self-service)"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="VISITOR")
    phone = models.CharField(max_length=20, blank=True)
    profile_photo = models.ImageField(upload_to="users/photos/", null=True, blank=True)
    national_id = models.CharField(max_length=50, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    estate = models.ForeignKey(
        Estate, on_delete=models.SET_NULL, null=True, blank=True, related_name="users"
    )
    is_verified = models.BooleanField(default=False)
    verification_method = models.CharField(
        max_length=20,
        choices=[("EMAIL", "Email"), ("SMS", "SMS"), ("MANUAL", "Manual")],
        blank=True,
    )
    push_token = models.TextField(blank=True, help_text="FCM / APNs push token")
    language = models.CharField(max_length=10, default="en")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["last_name", "first_name"]

    def __str__(self):
        return f"{self.get_full_name()} ({self.role})"


class ResidentProfile(UUIDModel, TimeStampedModel):
    """Extended profile for residents/tenants linked to a specific unit."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="resident_profile")
    # Unit FK defined after Unit model (see below — use string reference)
    unit = models.ForeignKey("Unit", on_delete=models.SET_NULL, null=True, related_name="residents")
    move_in_date = models.DateField(null=True, blank=True)
    move_out_date = models.DateField(null=True, blank=True)
    lease_expiry = models.DateField(null=True, blank=True)
    is_owner = models.BooleanField(default=False)
    is_primary_contact = models.BooleanField(default=True)
    emergency_contact_name = models.CharField(max_length=100, blank=True)
    emergency_contact_phone = models.CharField(max_length=20, blank=True)
    allow_visitor_self_checkin = models.BooleanField(
        default=True, help_text="Allow pre-registered visitors to self check-in via QR/kiosk"
    )
    max_active_visitors = models.PositiveIntegerField(
        default=5, help_text="Max simultaneous visitors allowed"
    )
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.get_full_name()} – {self.unit}"


class SecurityStaffProfile(UUIDModel, TimeStampedModel):
    """Extra details for security officers."""
    SHIFT_CHOICES = [
        ("MORNING", "Morning (06:00–14:00)"),
        ("AFTERNOON", "Afternoon (14:00–22:00)"),
        ("NIGHT", "Night (22:00–06:00)"),
        ("ROTATING", "Rotating"),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="security_profile")
    badge_number = models.CharField(max_length=30, unique=True)
    shift = models.CharField(max_length=20, choices=SHIFT_CHOICES, default="MORNING")
    assigned_gate = models.ForeignKey(
        "Gate", on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_staff"
    )
    is_supervisor = models.BooleanField(default=False)
    agency = models.CharField(max_length=100, blank=True, help_text="Outsourced security agency")

    def __str__(self):
        return f"{self.user.get_full_name()} – {self.badge_number}"


# ---------------------------------------------------------------------------
# 3. UNITS / FLATS
# ---------------------------------------------------------------------------

class Unit(UUIDModel, TimeStampedModel):
    """Individual flat / apartment / office within a block."""
    UNIT_TYPES = [
        ("APARTMENT", "Apartment"),
        ("PENTHOUSE", "Penthouse"),
        ("STUDIO", "Studio"),
        ("OFFICE", "Office"),
        ("RETAIL", "Retail"),
        ("WAREHOUSE", "Warehouse"),
        ("TOWNHOUSE", "Townhouse"),
    ]
    block = models.ForeignKey(Block, on_delete=models.CASCADE, related_name="units")
    unit_number = models.CharField(max_length=20, help_text="e.g. A101, 4B")
    floor = models.IntegerField(default=0)
    unit_type = models.CharField(max_length=20, choices=UNIT_TYPES, default="APARTMENT")
    bedrooms = models.PositiveIntegerField(null=True, blank=True)
    size_sqm = models.DecimalField(max_digits=8, decimal_places=2, null=True, blank=True)
    is_occupied = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"{self.block.estate.name} – {self.block.name} – Unit {self.unit_number}"

    class Meta:
        unique_together = ("block", "unit_number")
        ordering = ["block", "floor", "unit_number"]


# ---------------------------------------------------------------------------
# 4. VISITOR & VISIT MANAGEMENT  (Core)
# ---------------------------------------------------------------------------

class Visitor(UUIDModel, TimeStampedModel, SoftDeleteModel):
    """
    Persistent visitor record. Once created, reused across multiple visits.
    Links to biometric/card data for future hardware integration.
    """
    GENDER_CHOICES = [("M", "Male"), ("F", "Female"), ("O", "Other"), ("N", "Prefer not to say")]
    ID_TYPES = [
        ("NATIONAL_ID", "National ID"),
        ("PASSPORT", "Passport"),
        ("DRIVING_LICENSE", "Driving License"),
        ("WORK_PERMIT", "Work Permit"),
        ("STUDENT_ID", "Student ID"),
        ("OTHER", "Other"),
    ]

    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    phone = models.CharField(max_length=20)
    email = models.EmailField(blank=True)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES, blank=True)
    photo = models.ImageField(upload_to="visitors/photos/", null=True, blank=True)

    # ID Verification
    id_type = models.CharField(max_length=30, choices=ID_TYPES, blank=True)
    id_number = models.CharField(max_length=60, blank=True)
    id_scan_front = models.ImageField(upload_to="visitors/id_scans/", null=True, blank=True)
    id_scan_back = models.ImageField(upload_to="visitors/id_scans/", null=True, blank=True)
    id_verified = models.BooleanField(default=False)
    id_verified_at = models.DateTimeField(null=True, blank=True)
    id_verified_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="verified_visitors"
    )

    # Biometric/Hardware hooks (populated by AccessDevice integrations)
    fingerprint_template = models.BinaryField(null=True, blank=True)
    face_encoding = models.JSONField(null=True, blank=True, help_text="128-d face embedding vector")

    # Additional
    company = models.CharField(max_length=100, blank=True)
    nationality = models.CharField(max_length=60, blank=True)
    is_flagged = models.BooleanField(default=False)
    flag_reason = models.TextField(blank=True)

    # Consent / GDPR
    data_consent_given = models.BooleanField(default=False)
    data_consent_at = models.DateTimeField(null=True, blank=True)
    nda_signed = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.phone})"

    class Meta:
        ordering = ["last_name", "first_name"]
        indexes = [
            models.Index(fields=["phone"]),
            models.Index(fields=["id_number"]),
        ]


class Visit(UUIDModel, TimeStampedModel, SoftDeleteModel):
    """
    A single visit event. One visitor can have many visits over time.
    This is the central transaction record of the system.
    """
    STATUS_CHOICES = [
        ("PENDING", "Pending Approval"),
        ("APPROVED", "Approved"),
        ("CHECKED_IN", "Checked In"),
        ("CHECKED_OUT", "Checked Out"),
        ("DENIED", "Access Denied"),
        ("EXPIRED", "Expired"),
        ("CANCELLED", "Cancelled"),
        ("NO_SHOW", "No Show"),
    ]
    PURPOSE_CHOICES = [
        ("PERSONAL", "Personal Visit"),
        ("BUSINESS", "Business"),
        ("DELIVERY", "Delivery"),
        ("MAINTENANCE", "Maintenance/Repair"),
        ("CONTRACTOR", "Contractor"),
        ("EMERGENCY", "Emergency"),
        ("INTERVIEW", "Interview"),
        ("VIEWINGS", "Property Viewing"),
        ("EVENT", "Event/Party"),
        ("OTHER", "Other"),
    ]

    visitor = models.ForeignKey(Visitor, on_delete=models.CASCADE, related_name="visits")
    host = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="hosted_visits"
    )
    unit = models.ForeignKey(Unit, on_delete=models.SET_NULL, null=True, related_name="visits")
    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="visits")

    # Timing
    expected_arrival = models.DateTimeField(null=True, blank=True)
    expected_departure = models.DateTimeField(null=True, blank=True)
    actual_check_in = models.DateTimeField(null=True, blank=True)
    actual_check_out = models.DateTimeField(null=True, blank=True)

    # Gate/Access
    check_in_gate = models.ForeignKey(
        "Gate", on_delete=models.SET_NULL, null=True, blank=True, related_name="check_in_visits"
    )
    check_out_gate = models.ForeignKey(
        "Gate", on_delete=models.SET_NULL, null=True, blank=True, related_name="check_out_visits"
    )
    checked_in_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="checked_in_visits"
    )
    checked_out_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="checked_out_visits"
    )

    # Method of check-in
    CHECK_IN_METHODS = [
        ("MANUAL", "Manual by Security"),
        ("QR_CODE", "QR Code Scan"),
        ("FINGERPRINT", "Fingerprint"),
        ("FACE", "Facial Recognition"),
        ("CARD", "RFID Card"),
        ("OTP", "OTP / PIN"),
        ("INTERCOM", "Video Intercom"),
        ("KIOSK", "Self-Service Kiosk"),
        ("API", "API / Integration"),
    ]
    check_in_method = models.CharField(max_length=20, choices=CHECK_IN_METHODS, default="MANUAL")
    check_out_method = models.CharField(max_length=20, choices=CHECK_IN_METHODS, blank=True)

    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES, default="PERSONAL")
    purpose_detail = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="PENDING")

    # Pre-registration link
    pre_registration = models.ForeignKey(
        "PreRegistration", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="visits"
    )

    # Approval workflow
    approved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="approved_visits"
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    denial_reason = models.TextField(blank=True)

    # Extras
    number_of_visitors = models.PositiveIntegerField(default=1)
    accompanying_visitors = models.ManyToManyField(
        Visitor, blank=True, related_name="accompanying_visits"
    )
    notes = models.TextField(blank=True)
    is_recurring = models.BooleanField(default=False)
    recurrence_rule = models.ForeignKey(
        "RecurrenceRule", on_delete=models.SET_NULL, null=True, blank=True
    )

    # Photo evidence at check-in
    check_in_photo = models.ImageField(upload_to="visits/photos/", null=True, blank=True)
    check_out_photo = models.ImageField(upload_to="visits/photos/", null=True, blank=True)

    # Rating/feedback
    host_rating = models.PositiveSmallIntegerField(null=True, blank=True)
    visitor_rating = models.PositiveSmallIntegerField(null=True, blank=True)

    def duration_minutes(self):
        if self.actual_check_in and self.actual_check_out:
            return int((self.actual_check_out - self.actual_check_in).total_seconds() / 60)
        return None

    def __str__(self):
        return f"Visit: {self.visitor} → {self.unit} [{self.status}]"

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "estate"]),
            models.Index(fields=["actual_check_in"]),
            models.Index(fields=["visitor", "status"]),
        ]


class RecurrenceRule(UUIDModel, TimeStampedModel):
    """
    Defines repeating visit patterns (e.g. house cleaner every Monday).
    Based on iCal RRULE concepts.
    """
    FREQUENCY_CHOICES = [
        ("DAILY", "Daily"),
        ("WEEKLY", "Weekly"),
        ("BIWEEKLY", "Bi-Weekly"),
        ("MONTHLY", "Monthly"),
    ]
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES)
    days_of_week = models.JSONField(
        default=list, blank=True,
        help_text='e.g. ["MON","WED","FRI"]'
    )
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    start_time = models.TimeField()
    end_time = models.TimeField()
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.frequency} from {self.start_date}"


# ---------------------------------------------------------------------------
# 5. PRE-REGISTRATION & INVITATIONS
# ---------------------------------------------------------------------------

class PreRegistration(UUIDModel, TimeStampedModel, SoftDeleteModel):
    """
    A resident pre-registers an expected visitor.
    Generates a unique QR/OTP for self-check-in.
    """
    STATUS_CHOICES = [
        ("PENDING", "Pending"),
        ("USED", "Used"),
        ("EXPIRED", "Expired"),
        ("CANCELLED", "Cancelled"),
    ]

    host = models.ForeignKey(User, on_delete=models.CASCADE, related_name="pre_registrations")
    unit = models.ForeignKey(Unit, on_delete=models.SET_NULL, null=True, related_name="pre_registrations")
    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="pre_registrations")

    visitor_name = models.CharField(max_length=200)
    visitor_phone = models.CharField(max_length=20)
    visitor_email = models.EmailField(blank=True)
    visitor = models.ForeignKey(
        Visitor, on_delete=models.SET_NULL, null=True, blank=True,
        help_text="Linked once visitor is identified on arrival"
    )

    purpose = models.CharField(max_length=20, choices=Visit.PURPOSE_CHOICES, default="PERSONAL")
    expected_arrival = models.DateTimeField()
    expected_departure = models.DateTimeField(null=True, blank=True)

    # Access credentials
    qr_code_token = models.CharField(max_length=100, unique=True, blank=True)
    otp_code = models.CharField(max_length=10, blank=True)
    otp_expires_at = models.DateTimeField(null=True, blank=True)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="PENDING")
    allow_multiple_uses = models.BooleanField(default=False)
    max_uses = models.PositiveIntegerField(default=1)
    use_count = models.PositiveIntegerField(default=0)
    notes = models.TextField(blank=True)

    # Recurrence
    recurrence_rule = models.ForeignKey(
        RecurrenceRule, on_delete=models.SET_NULL, null=True, blank=True
    )

    def __str__(self):
        return f"PreReg: {self.visitor_name} → {self.unit} on {self.expected_arrival}"

    class Meta:
        ordering = ["-expected_arrival"]


# ---------------------------------------------------------------------------
# 6. ACCESS CONTROL (Gates, Doors, Zones)
# ---------------------------------------------------------------------------

class Zone(UUIDModel, TimeStampedModel):
    """
    Security zones within an estate (e.g. Perimeter, Lobby, Pool, Parking).
    Used for granular access control.
    """
    ACCESS_LEVEL_CHOICES = [
        (1, "Public"),
        (2, "Visitor (escorted)"),
        (3, "Resident"),
        (4, "Staff"),
        (5, "Security"),
        (6, "Admin"),
    ]
    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="zones")
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    minimum_access_level = models.PositiveSmallIntegerField(choices=ACCESS_LEVEL_CHOICES, default=3)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.estate.name} – Zone: {self.name}"


class Gate(UUIDModel, TimeStampedModel):
    """
    A physical gate or entry/exit point.
    Can have multiple access devices attached.
    """
    GATE_TYPES = [
        ("MAIN_ENTRY", "Main Entry"),
        ("MAIN_EXIT", "Main Exit"),
        ("PEDESTRIAN", "Pedestrian"),
        ("VEHICLE", "Vehicle"),
        ("EMERGENCY", "Emergency"),
        ("DELIVERY", "Delivery"),
        ("SERVICE", "Service/Staff"),
    ]
    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="gates")
    block = models.ForeignKey(Block, on_delete=models.SET_NULL, null=True, blank=True, related_name="gates")
    zone = models.ForeignKey(Zone, on_delete=models.SET_NULL, null=True, blank=True)
    name = models.CharField(max_length=100)
    gate_type = models.CharField(max_length=20, choices=GATE_TYPES)
    is_active = models.BooleanField(default=True)
    is_open = models.BooleanField(default=False, help_text="Real-time open/closed state")
    is_24h = models.BooleanField(default=True)
    operating_hours_start = models.TimeField(null=True, blank=True)
    operating_hours_end = models.TimeField(null=True, blank=True)
    requires_escort = models.BooleanField(default=False)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"{self.estate.name} – {self.name}"


class AccessPermission(UUIDModel, TimeStampedModel):
    """
    Grants specific user/visitor access to a zone or gate.
    Used for residents, staff, contractors with standing access.
    """
    PERMISSION_TYPES = [
        ("PERMANENT", "Permanent"),
        ("TEMPORARY", "Temporary"),
        ("SCHEDULED", "Scheduled"),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="access_permissions")
    gate = models.ForeignKey(Gate, on_delete=models.SET_NULL, null=True, blank=True)
    zone = models.ForeignKey(Zone, on_delete=models.SET_NULL, null=True, blank=True)
    permission_type = models.CharField(max_length=20, choices=PERMISSION_TYPES, default="PERMANENT")
    valid_from = models.DateTimeField(default=timezone.now)
    valid_until = models.DateTimeField(null=True, blank=True)
    allowed_days = models.JSONField(
        default=list, help_text='e.g. ["MON","TUE","WED","THU","FRI"]'
    )
    allowed_time_start = models.TimeField(null=True, blank=True)
    allowed_time_end = models.TimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    granted_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="granted_permissions"
    )
    reason = models.TextField(blank=True)

    def __str__(self):
        return f"{self.user} → {self.gate or self.zone}"


# ---------------------------------------------------------------------------
# 7. HARDWARE INTEGRATION
# Scalable device registry — add fingerprint readers, RFID, face cams, etc.
# ---------------------------------------------------------------------------

class AccessDevice(UUIDModel, TimeStampedModel):
    """
    Represents a physical hardware device at a gate/door.
    Each device type has its own integration handler.
    """
    DEVICE_TYPES = [
        ("FINGERPRINT_READER", "Fingerprint Reader"),
        ("RFID_READER", "RFID / Card Reader"),
        ("FACE_RECOGNITION", "Face Recognition Camera"),
        ("QR_SCANNER", "QR Code Scanner"),
        ("INTERCOM", "Video Intercom"),
        ("KIOSK", "Self-Service Kiosk"),
        ("BARRIER_CONTROLLER", "Barrier/Gate Controller"),
        ("DOOR_CONTROLLER", "Door Access Controller"),
        ("NFC_READER", "NFC Reader"),
        ("PIN_PAD", "PIN Keypad"),
        ("LICENSE_PLATE", "License Plate Recognition"),
        ("BODY_TEMP", "Body Temperature Scanner"),
    ]
    STATUS_CHOICES = [
        ("ONLINE", "Online"),
        ("OFFLINE", "Offline"),
        ("MAINTENANCE", "Under Maintenance"),
        ("FAULT", "Fault"),
    ]

    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="devices")
    gate = models.ForeignKey(Gate, on_delete=models.SET_NULL, null=True, blank=True, related_name="devices")
    device_type = models.CharField(max_length=30, choices=DEVICE_TYPES)
    name = models.CharField(max_length=100)
    serial_number = models.CharField(max_length=100, blank=True, unique=True)
    manufacturer = models.CharField(max_length=100, blank=True)
    model = models.CharField(max_length=100, blank=True)
    firmware_version = models.CharField(max_length=50, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    mac_address = models.CharField(max_length=17, blank=True)
    api_endpoint = models.URLField(blank=True, help_text="Device API URL")
    api_key = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="OFFLINE")
    last_heartbeat = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    configuration = models.JSONField(
        default=dict, blank=True,
        help_text="Device-specific config (thresholds, sensitivity, etc.)"
    )
    installed_at = models.DateTimeField(null=True, blank=True)
    last_maintenance = models.DateTimeField(null=True, blank=True)
    next_maintenance = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"{self.name} [{self.device_type}] @ {self.gate}"


class BiometricTemplate(UUIDModel, TimeStampedModel):
    """
    Stores biometric enrollments for users AND visitors.
    Separated from main models to keep sensitive data isolated.
    """
    BIOMETRIC_TYPES = [
        ("FINGERPRINT", "Fingerprint"),
        ("FACE", "Face"),
        ("IRIS", "Iris"),
        ("PALM", "Palm Vein"),
    ]

    # Can belong to a user (resident/staff) or a visitor
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name="biometrics")
    visitor = models.ForeignKey(Visitor, on_delete=models.CASCADE, null=True, blank=True, related_name="biometrics")

    biometric_type = models.CharField(max_length=20, choices=BIOMETRIC_TYPES)
    device = models.ForeignKey(AccessDevice, on_delete=models.SET_NULL, null=True)
    template_data = models.BinaryField(help_text="Encrypted biometric template blob")
    quality_score = models.FloatField(null=True, blank=True, help_text="0.0 – 1.0 quality score")
    finger_index = models.PositiveSmallIntegerField(
        null=True, blank=True, help_text="0=right thumb, 1=right index, ..., 9=left pinky"
    )
    is_active = models.BooleanField(default=True)
    enrolled_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="enrolled_biometrics"
    )

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=models.Q(user__isnull=False) | models.Q(visitor__isnull=False),
                name="biometric_must_have_owner"
            )
        ]

    def __str__(self):
        owner = self.user or self.visitor
        return f"{self.biometric_type} for {owner}"


class AccessCard(UUIDModel, TimeStampedModel):
    """
    RFID / NFC / Smart cards issued to residents, staff, or temporary visitors.
    """
    CARD_TYPES = [
        ("RFID_125KHZ", "RFID 125kHz (EM4100)"),
        ("RFID_13MHZ", "RFID 13.56MHz (Mifare)"),
        ("NFC", "NFC"),
        ("SMART_CARD", "Smart Card (Contact)"),
        ("BARCODE", "Barcode Card"),
        ("QR_PHYSICAL", "Physical QR Card"),
    ]
    STATUS_CHOICES = [
        ("ACTIVE", "Active"),
        ("SUSPENDED", "Suspended"),
        ("LOST", "Reported Lost"),
        ("EXPIRED", "Expired"),
        ("RETURNED", "Returned"),
    ]

    card_number = models.CharField(max_length=100, unique=True)
    card_type = models.CharField(max_length=20, choices=CARD_TYPES, default="RFID_13MHZ")
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="cards")
    visitor = models.ForeignKey(Visitor, on_delete=models.SET_NULL, null=True, blank=True, related_name="cards")
    visit = models.ForeignKey(Visit, on_delete=models.SET_NULL, null=True, blank=True, related_name="cards")
    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="cards")

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="ACTIVE")
    issued_at = models.DateTimeField(auto_now_add=True)
    issued_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="issued_cards"
    )
    valid_from = models.DateTimeField(default=timezone.now)
    valid_until = models.DateTimeField(null=True, blank=True)
    is_temporary = models.BooleanField(default=False)

    # Access permission scope
    allowed_zones = models.ManyToManyField(Zone, blank=True)
    allowed_gates = models.ManyToManyField(Gate, blank=True)

    notes = models.TextField(blank=True)

    def __str__(self):
        return f"Card {self.card_number} [{self.status}]"


class AccessEvent(UUIDModel, TimeStampedModel):
    """
    Raw event log from any access device.
    Every tap, scan, or denied entry is recorded here.
    This is the immutable hardware event log.
    """
    EVENT_TYPES = [
        ("GRANTED", "Access Granted"),
        ("DENIED", "Access Denied"),
        ("TAILGATE", "Tailgate Detected"),
        ("DOOR_FORCED", "Door Forced Open"),
        ("DOOR_HELD", "Door Held Open"),
        ("ALARM", "Alarm Triggered"),
        ("CARD_UNKNOWN", "Unknown Card"),
        ("BIOMETRIC_FAIL", "Biometric Failure"),
        ("OFFLINE_GRANT", "Offline Grant"),
    ]

    device = models.ForeignKey(AccessDevice, on_delete=models.CASCADE, related_name="events")
    gate = models.ForeignKey(Gate, on_delete=models.SET_NULL, null=True)
    visit = models.ForeignKey(Visit, on_delete=models.SET_NULL, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    visitor = models.ForeignKey(Visitor, on_delete=models.SET_NULL, null=True, blank=True)
    card = models.ForeignKey(AccessCard, on_delete=models.SET_NULL, null=True, blank=True)

    event_type = models.CharField(max_length=20, choices=EVENT_TYPES)
    event_time = models.DateTimeField(default=timezone.now)
    direction = models.CharField(
        max_length=3, choices=[("IN", "Entry"), ("OUT", "Exit")], blank=True
    )
    raw_data = models.JSONField(
        default=dict, blank=True, help_text="Raw payload from device SDK"
    )
    snapshot = models.ImageField(upload_to="events/snapshots/", null=True, blank=True)
    is_acknowledged = models.BooleanField(default=False)

    class Meta:
        ordering = ["-event_time"]
        indexes = [
            models.Index(fields=["event_time", "gate"]),
            models.Index(fields=["event_type"]),
        ]

    def __str__(self):
        return f"{self.event_type} @ {self.gate} [{self.event_time}]"


# ---------------------------------------------------------------------------
# 8. BADGES & PASSES
# ---------------------------------------------------------------------------

class VisitorBadge(UUIDModel, TimeStampedModel):
    """
    Printed or digital badge issued at check-in.
    """
    BADGE_TYPES = [
        ("PRINTED", "Printed Badge"),
        ("DIGITAL", "Digital / QR Badge"),
        ("STICKER", "Sticker"),
    ]
    visit = models.OneToOneField(Visit, on_delete=models.CASCADE, related_name="badge")
    badge_type = models.CharField(max_length=20, choices=BADGE_TYPES, default="PRINTED")
    badge_number = models.CharField(max_length=30, unique=True)
    printed_at = models.DateTimeField(null=True, blank=True)
    printed_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="printed_badges"
    )
    qr_data = models.TextField(blank=True)
    color_code = models.CharField(
        max_length=7, blank=True,
        help_text="Color to indicate visitor type (hex e.g. #FF0000)"
    )
    is_returned = models.BooleanField(default=False)
    returned_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Badge {self.badge_number} for {self.visit.visitor}"


# ---------------------------------------------------------------------------
# 9. NOTIFICATIONS & ALERTS
# ---------------------------------------------------------------------------

class NotificationTemplate(UUIDModel, TimeStampedModel):
    """
    Customizable message templates for different events.
    Supports SMS, Email, Push, WhatsApp.
    """
    CHANNEL_CHOICES = [
        ("SMS", "SMS"),
        ("EMAIL", "Email"),
        ("PUSH", "Push Notification"),
        ("WHATSAPP", "WhatsApp"),
        ("IN_APP", "In-App"),
    ]
    EVENT_TRIGGERS = [
        ("VISITOR_ARRIVING", "Visitor Arriving"),
        ("VISITOR_CHECKED_IN", "Visitor Checked In"),
        ("VISITOR_CHECKED_OUT", "Visitor Checked Out"),
        ("PRE_REG_CREATED", "Pre-Registration Created"),
        ("ACCESS_DENIED", "Access Denied"),
        ("BLACKLIST_MATCH", "Blacklist Match"),
        ("VISIT_APPROVED", "Visit Approved"),
        ("VISIT_EXPIRED", "Visit Expired"),
        ("EMERGENCY", "Emergency Alert"),
        ("DELIVERY", "Delivery Arrived"),
    ]

    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="notification_templates")
    event_trigger = models.CharField(max_length=30, choices=EVENT_TRIGGERS)
    channel = models.CharField(max_length=20, choices=CHANNEL_CHOICES)
    subject = models.CharField(max_length=200, blank=True, help_text="For email")
    body = models.TextField(help_text="Supports {visitor_name}, {host_name}, {unit}, {time} placeholders")
    is_active = models.BooleanField(default=True)
    send_to_host = models.BooleanField(default=True)
    send_to_visitor = models.BooleanField(default=False)
    send_to_security = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.event_trigger} via {self.channel}"


class Notification(UUIDModel, TimeStampedModel):
    """
    Log of all notifications sent by the system.
    """
    STATUS_CHOICES = [
        ("PENDING", "Pending"),
        ("SENT", "Sent"),
        ("DELIVERED", "Delivered"),
        ("FAILED", "Failed"),
        ("READ", "Read"),
    ]

    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name="notifications")
    template = models.ForeignKey(
        NotificationTemplate, on_delete=models.SET_NULL, null=True, blank=True
    )
    visit = models.ForeignKey(Visit, on_delete=models.SET_NULL, null=True, blank=True)
    channel = models.CharField(max_length=20)
    subject = models.CharField(max_length=200, blank=True)
    message = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="PENDING")
    sent_at = models.DateTimeField(null=True, blank=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    read_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    external_id = models.CharField(max_length=200, blank=True, help_text="Provider message ID")

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Notification to {self.recipient} [{self.status}]"


# ---------------------------------------------------------------------------
# 10. BLACKLIST & WATCHLIST
# ---------------------------------------------------------------------------

class Blacklist(UUIDModel, TimeStampedModel):
    """
    Persons banned from entering the estate.
    """
    SEVERITY_CHOICES = [
        ("LOW", "Low – Monitor Only"),
        ("MEDIUM", "Medium – Alert Security"),
        ("HIGH", "High – Deny Access"),
        ("CRITICAL", "Critical – Alert Police"),
    ]

    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="blacklists")
    visitor = models.ForeignKey(
        Visitor, on_delete=models.SET_NULL, null=True, blank=True, related_name="blacklist_entries"
    )
    # Can also blacklist by ID number or phone without a visitor record
    id_number = models.CharField(max_length=60, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    name = models.CharField(max_length=200, blank=True)
    photo = models.ImageField(upload_to="blacklist/photos/", null=True, blank=True)

    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="HIGH")
    reason = models.TextField()
    incident_date = models.DateField(null=True, blank=True)
    valid_until = models.DateField(null=True, blank=True, help_text="Null = permanent ban")
    added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"Blacklist: {self.visitor or self.name} [{self.severity}]"


class Watchlist(UUIDModel, TimeStampedModel):
    """
    Persons of interest — don't deny access but alert security on arrival.
    """
    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="watchlists")
    visitor = models.ForeignKey(Visitor, on_delete=models.SET_NULL, null=True, blank=True)
    name = models.CharField(max_length=200, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    reason = models.TextField()
    alert_message = models.TextField(help_text="Message shown to security on match")
    added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"Watchlist: {self.visitor or self.name}"


# ---------------------------------------------------------------------------
# 11. VEHICLES & PARKING
# ---------------------------------------------------------------------------

class RegisteredVehicle(UUIDModel, TimeStampedModel):
    """
    Vehicles registered to residents or staff.
    """
    VEHICLE_TYPES = [
        ("CAR", "Car"),
        ("SUV", "SUV"),
        ("MOTORCYCLE", "Motorcycle"),
        ("TRUCK", "Truck"),
        ("VAN", "Van"),
        ("BICYCLE", "Bicycle"),
        ("OTHER", "Other"),
    ]

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="vehicles")
    unit = models.ForeignKey(Unit, on_delete=models.SET_NULL, null=True, blank=True)
    vehicle_type = models.CharField(max_length=15, choices=VEHICLE_TYPES, default="CAR")
    make = models.CharField(max_length=60, blank=True)
    model = models.CharField(max_length=60, blank=True)
    color = models.CharField(max_length=30, blank=True)
    license_plate = models.CharField(max_length=20)
    sticker_number = models.CharField(max_length=30, blank=True)
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"{self.license_plate} ({self.make} {self.model}) – {self.owner}"

    class Meta:
        unique_together = ("license_plate", "owner")


class VisitorVehicle(UUIDModel, TimeStampedModel):
    """Vehicle details of a visitor for a specific visit."""
    visit = models.OneToOneField(Visit, on_delete=models.CASCADE, related_name="vehicle")
    license_plate = models.CharField(max_length=20)
    vehicle_type = models.CharField(max_length=15, choices=RegisteredVehicle.VEHICLE_TYPES, default="CAR")
    make = models.CharField(max_length=60, blank=True)
    model = models.CharField(max_length=60, blank=True)
    color = models.CharField(max_length=30, blank=True)
    lpr_captured = models.BooleanField(
        default=False, help_text="Captured by License Plate Recognition camera"
    )
    lpr_image = models.ImageField(upload_to="vehicles/lpr/", null=True, blank=True)

    def __str__(self):
        return f"{self.license_plate} for {self.visit}"


class ParkingSlot(UUIDModel, TimeStampedModel):
    """Individual parking spaces in the estate."""
    SLOT_TYPES = [
        ("RESIDENT", "Resident"),
        ("VISITOR", "Visitor"),
        ("DISABLED", "Disabled"),
        ("VIP", "VIP"),
        ("DELIVERY", "Delivery"),
    ]
    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="parking_slots")
    block = models.ForeignKey(Block, on_delete=models.SET_NULL, null=True, blank=True)
    slot_number = models.CharField(max_length=20)
    slot_type = models.CharField(max_length=20, choices=SLOT_TYPES, default="RESIDENT")
    assigned_to = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="parking_slots"
    )
    is_occupied = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"Slot {self.slot_number} [{self.slot_type}]"


class ParkingSession(UUIDModel, TimeStampedModel):
    """Tracks a vehicle occupying a parking slot."""
    slot = models.ForeignKey(ParkingSlot, on_delete=models.CASCADE, related_name="sessions")
    vehicle_plate = models.CharField(max_length=20)
    vehicle = models.ForeignKey(
        RegisteredVehicle, on_delete=models.SET_NULL, null=True, blank=True
    )
    visit = models.ForeignKey(Visit, on_delete=models.SET_NULL, null=True, blank=True)
    entry_time = models.DateTimeField(default=timezone.now)
    exit_time = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.vehicle_plate} in {self.slot}"


# ---------------------------------------------------------------------------
# 12. DELIVERIES & COURIERS
# ---------------------------------------------------------------------------

class Delivery(UUIDModel, TimeStampedModel):
    """
    Tracks parcels, food, and courier deliveries to units.
    """
    STATUS_CHOICES = [
        ("EXPECTED", "Expected"),
        ("ARRIVED", "Arrived at Gate"),
        ("NOTIFIED", "Resident Notified"),
        ("COLLECTING", "Being Collected"),
        ("COLLECTED", "Collected"),
        ("RETURNED", "Returned to Sender"),
        ("STORED", "In Storage"),
    ]
    DELIVERY_TYPES = [
        ("PARCEL", "Parcel/Package"),
        ("FOOD", "Food Delivery"),
        ("GROCERY", "Grocery"),
        ("DOCUMENT", "Document"),
        ("FURNITURE", "Furniture/Large Item"),
        ("OTHER", "Other"),
    ]

    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="deliveries")
    unit = models.ForeignKey(Unit, on_delete=models.CASCADE, related_name="deliveries")
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name="deliveries")

    delivery_type = models.CharField(max_length=20, choices=DELIVERY_TYPES, default="PARCEL")
    courier_name = models.CharField(max_length=100, blank=True)
    courier_company = models.CharField(max_length=100, blank=True)
    courier_phone = models.CharField(max_length=20, blank=True)
    tracking_number = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="ARRIVED")

    arrived_at = models.DateTimeField(default=timezone.now)
    collected_at = models.DateTimeField(null=True, blank=True)
    collected_by_signature = models.ImageField(
        upload_to="deliveries/signatures/", null=True, blank=True
    )
    photo = models.ImageField(upload_to="deliveries/photos/", null=True, blank=True)
    storage_location = models.CharField(max_length=100, blank=True)
    received_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="received_deliveries"
    )
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"Delivery to {self.unit} [{self.status}]"


# ---------------------------------------------------------------------------
# 13. CONTRACTORS & SERVICE STAFF
# ---------------------------------------------------------------------------

class Contractor(UUIDModel, TimeStampedModel):
    """
    External companies/individuals that regularly service the estate.
    """
    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="contractors")
    company_name = models.CharField(max_length=200)
    contact_person = models.CharField(max_length=100)
    phone = models.CharField(max_length=20)
    email = models.EmailField(blank=True)
    service_type = models.CharField(
        max_length=100, help_text="e.g. Plumbing, Electrical, Cleaning, Landscaping"
    )
    contract_start = models.DateField(null=True, blank=True)
    contract_end = models.DateField(null=True, blank=True)
    is_approved = models.BooleanField(default=False)
    approved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="approved_contractors"
    )
    documents = models.JSONField(
        default=list, blank=True,
        help_text="List of document URLs (certificates, insurance, etc.)"
    )
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"{self.company_name} ({self.service_type})"


class WorkOrder(UUIDModel, TimeStampedModel):
    """A specific maintenance job assigned to a contractor."""
    STATUS_CHOICES = [
        ("SCHEDULED", "Scheduled"),
        ("IN_PROGRESS", "In Progress"),
        ("COMPLETED", "Completed"),
        ("CANCELLED", "Cancelled"),
        ("ON_HOLD", "On Hold"),
    ]

    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="work_orders")
    unit = models.ForeignKey(Unit, on_delete=models.SET_NULL, null=True, blank=True)
    contractor = models.ForeignKey(Contractor, on_delete=models.CASCADE, related_name="work_orders")
    assigned_workers = models.ManyToManyField(User, blank=True, related_name="work_orders")
    title = models.CharField(max_length=200)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="SCHEDULED")
    scheduled_start = models.DateTimeField()
    scheduled_end = models.DateTimeField()
    actual_start = models.DateTimeField(null=True, blank=True)
    actual_end = models.DateTimeField(null=True, blank=True)
    requires_unit_access = models.BooleanField(default=False)
    resident_approved = models.BooleanField(default=False)
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"WorkOrder: {self.title} [{self.status}]"


# ---------------------------------------------------------------------------
# 14. INCIDENTS & SECURITY LOGS
# ---------------------------------------------------------------------------

class Incident(UUIDModel, TimeStampedModel):
    """
    Security incident reports filed by staff.
    """
    SEVERITY_CHOICES = [
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]
    INCIDENT_TYPES = [
        ("UNAUTHORIZED_ACCESS", "Unauthorized Access"),
        ("TAILGATE", "Tailgating"),
        ("THEFT", "Theft"),
        ("VANDALISM", "Vandalism"),
        ("ASSAULT", "Assault"),
        ("SUSPICIOUS_PERSON", "Suspicious Person"),
        ("FIRE", "Fire"),
        ("MEDICAL", "Medical Emergency"),
        ("NOISE", "Noise Complaint"),
        ("PARKING", "Parking Violation"),
        ("OTHER", "Other"),
    ]
    STATUS_CHOICES = [
        ("OPEN", "Open"),
        ("INVESTIGATING", "Investigating"),
        ("RESOLVED", "Resolved"),
        ("ESCALATED", "Escalated"),
        ("CLOSED", "Closed"),
    ]

    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="incidents")
    gate = models.ForeignKey(Gate, on_delete=models.SET_NULL, null=True, blank=True)
    unit = models.ForeignKey(Unit, on_delete=models.SET_NULL, null=True, blank=True)
    visit = models.ForeignKey(Visit, on_delete=models.SET_NULL, null=True, blank=True)
    visitor = models.ForeignKey(Visitor, on_delete=models.SET_NULL, null=True, blank=True)

    incident_type = models.CharField(max_length=30, choices=INCIDENT_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="MEDIUM")
    title = models.CharField(max_length=200)
    description = models.TextField()
    occurred_at = models.DateTimeField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="OPEN")

    reported_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="reported_incidents"
    )
    assigned_to = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_incidents"
    )
    resolution_notes = models.TextField(blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    # Evidence
    photos = models.JSONField(default=list, blank=True)
    cctv_reference = models.CharField(max_length=200, blank=True)

    police_report_number = models.CharField(max_length=100, blank=True)
    is_police_notified = models.BooleanField(default=False)

    def __str__(self):
        return f"Incident: {self.title} [{self.severity}] – {self.status}"

    class Meta:
        ordering = ["-occurred_at"]


# ---------------------------------------------------------------------------
# 15. AUDIT TRAIL
# ---------------------------------------------------------------------------

class AuditLog(UUIDModel, TimeStampedModel):
    """
    Immutable log of every significant action in the system.
    Used for compliance, forensics, and accountability.
    """
    ACTION_TYPES = [
        ("CREATE", "Created"),
        ("UPDATE", "Updated"),
        ("DELETE", "Deleted"),
        ("LOGIN", "Login"),
        ("LOGOUT", "Logout"),
        ("APPROVE", "Approved"),
        ("DENY", "Denied"),
        ("CHECKIN", "Checked In"),
        ("CHECKOUT", "Checked Out"),
        ("CARD_ISSUED", "Card Issued"),
        ("CARD_REVOKED", "Card Revoked"),
        ("BLACKLIST_ADD", "Added to Blacklist"),
        ("EXPORT", "Data Exported"),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=30, choices=ACTION_TYPES)
    model_name = models.CharField(max_length=100, help_text="Django model name")
    object_id = models.CharField(max_length=100, blank=True)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    before_state = models.JSONField(null=True, blank=True)
    after_state = models.JSONField(null=True, blank=True)
    estate = models.ForeignKey(Estate, on_delete=models.SET_NULL, null=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["model_name", "object_id"])]

    def __str__(self):
        return f"{self.action} by {self.user} on {self.model_name}:{self.object_id}"


# ---------------------------------------------------------------------------
# 16. ANALYTICS & REPORTING
# ---------------------------------------------------------------------------

class DailyReport(UUIDModel, TimeStampedModel):
    """
    Pre-aggregated daily stats per estate (updated by a nightly task).
    """
    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="daily_reports")
    date = models.DateField()
    total_visitors = models.PositiveIntegerField(default=0)
    total_check_ins = models.PositiveIntegerField(default=0)
    total_check_outs = models.PositiveIntegerField(default=0)
    denied_access = models.PositiveIntegerField(default=0)
    blacklist_alerts = models.PositiveIntegerField(default=0)
    avg_visit_duration_minutes = models.FloatField(null=True, blank=True)
    peak_hour = models.PositiveSmallIntegerField(null=True, blank=True)
    total_deliveries = models.PositiveIntegerField(default=0)
    total_incidents = models.PositiveIntegerField(default=0)
    stats_json = models.JSONField(default=dict, blank=True, help_text="Flexible extra stats")

    class Meta:
        unique_together = ("estate", "date")

    def __str__(self):
        return f"Report: {self.estate.name} – {self.date}"


class SavedReport(UUIDModel, TimeStampedModel):
    """User-defined scheduled reports."""
    FREQUENCY_CHOICES = [
        ("DAILY", "Daily"),
        ("WEEKLY", "Weekly"),
        ("MONTHLY", "Monthly"),
    ]
    FORMAT_CHOICES = [("PDF", "PDF"), ("EXCEL", "Excel"), ("CSV", "CSV")]

    estate = models.ForeignKey(Estate, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    filters = models.JSONField(default=dict, blank=True)
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES)
    format = models.CharField(max_length=10, choices=FORMAT_CHOICES, default="PDF")
    recipients = models.ManyToManyField(User, blank=True, related_name="subscribed_reports")
    last_sent = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.name} ({self.frequency})"


# ---------------------------------------------------------------------------
# 17. DOCUMENT & NDA MANAGEMENT
# ---------------------------------------------------------------------------

class VisitorDocument(UUIDModel, TimeStampedModel):
    """
    Documents that visitors may be required to sign (NDA, health forms, etc.)
    """
    DOC_TYPES = [
        ("NDA", "Non-Disclosure Agreement"),
        ("HEALTH_DECLARATION", "Health Declaration"),
        ("TERMS", "Terms & Conditions"),
        ("INDEMNITY", "Indemnity Form"),
        ("CUSTOM", "Custom"),
    ]
    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="visitor_documents")
    visit = models.ForeignKey(Visit, on_delete=models.CASCADE, related_name="documents")
    document_type = models.CharField(max_length=30, choices=DOC_TYPES)
    template_url = models.URLField(blank=True)
    signed_document = models.FileField(upload_to="documents/signed/", null=True, blank=True)
    is_signed = models.BooleanField(default=False)
    signed_at = models.DateTimeField(null=True, blank=True)
    signature_image = models.ImageField(upload_to="documents/signatures/", null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    def __str__(self):
        return f"{self.document_type} – {self.visit}"


# ---------------------------------------------------------------------------
# 18. EMERGENCY MANAGEMENT
# ---------------------------------------------------------------------------

class EmergencyAlert(UUIDModel, TimeStampedModel):
    """
    Estate-wide emergency broadcasts.
    """
    ALERT_TYPES = [
        ("FIRE", "Fire"),
        ("EVACUATION", "Evacuation"),
        ("LOCKDOWN", "Lockdown"),
        ("MEDICAL", "Medical Emergency"),
        ("SECURITY", "Security Threat"),
        ("NATURAL_DISASTER", "Natural Disaster"),
        ("GENERAL", "General Announcement"),
    ]
    STATUS_CHOICES = [
        ("ACTIVE", "Active"),
        ("RESOLVED", "Resolved"),
        ("DRILL", "Drill / Test"),
    ]

    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="emergency_alerts")
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPES)
    title = models.CharField(max_length=200)
    message = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="ACTIVE")
    initiated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    initiated_at = models.DateTimeField(default=timezone.now)
    resolved_at = models.DateTimeField(null=True, blank=True)
    gate_lockdown = models.BooleanField(default=False, help_text="Lock all gates on alert")
    mustering_point = models.CharField(max_length=200, blank=True)

    def __str__(self):
        return f"EMERGENCY: {self.alert_type} – {self.estate.name} [{self.status}]"


class EvacuationRecord(UUIDModel, TimeStampedModel):
    """Tracks who has been accounted for during an evacuation."""
    alert = models.ForeignKey(EmergencyAlert, on_delete=models.CASCADE, related_name="evacuations")
    person = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    visitor = models.ForeignKey(Visitor, on_delete=models.SET_NULL, null=True, blank=True)
    is_accounted = models.BooleanField(default=False)
    accounted_at = models.DateTimeField(null=True, blank=True)
    mustering_point = models.CharField(max_length=200, blank=True)
    notes = models.TextField(blank=True)


# ---------------------------------------------------------------------------
# 19. API / INTEGRATION & WEBHOOKS
# ---------------------------------------------------------------------------

class WebhookEndpoint(UUIDModel, TimeStampedModel):
    """
    External systems can subscribe to VMS events via webhooks.
    e.g. Property management software, ERP, CCTV system.
    """
    EVENTS = [
        ("visit.checkin", "Visit Check-In"),
        ("visit.checkout", "Visit Check-Out"),
        ("visit.denied", "Access Denied"),
        ("blacklist.match", "Blacklist Match"),
        ("incident.created", "Incident Created"),
        ("emergency.alert", "Emergency Alert"),
        ("delivery.arrived", "Delivery Arrived"),
    ]

    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="webhooks")
    url = models.URLField()
    secret_key = models.CharField(max_length=200, help_text="HMAC secret for payload signing")
    subscribed_events = models.JSONField(default=list)
    is_active = models.BooleanField(default=True)
    timeout_seconds = models.PositiveSmallIntegerField(default=10)
    retry_attempts = models.PositiveSmallIntegerField(default=3)
    description = models.TextField(blank=True)

    def __str__(self):
        return f"Webhook → {self.url}"


class WebhookDelivery(UUIDModel, TimeStampedModel):
    """Log of webhook deliveries for debugging."""
    endpoint = models.ForeignKey(WebhookEndpoint, on_delete=models.CASCADE, related_name="deliveries")
    event = models.CharField(max_length=50)
    payload = models.JSONField()
    response_status = models.PositiveSmallIntegerField(null=True, blank=True)
    response_body = models.TextField(blank=True)
    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    success = models.BooleanField(default=False)
    attempt_number = models.PositiveSmallIntegerField(default=1)

    class Meta:
        ordering = ["-created_at"]


class ThirdPartyIntegration(UUIDModel, TimeStampedModel):
    """
    Tracks connected third-party systems (Slack, Mailchimp, Twilio, etc.)
    """
    INTEGRATION_TYPES = [
        ("SMS_GATEWAY", "SMS Gateway"),
        ("EMAIL_PROVIDER", "Email Provider"),
        ("PUSH_SERVICE", "Push Notification Service"),
        ("WHATSAPP", "WhatsApp Business"),
        ("CCTV", "CCTV System"),
        ("ACCESS_CONTROL", "Access Control System"),
        ("PROPERTY_MGMT", "Property Management Software"),
        ("PAYMENT", "Payment Gateway"),
        ("HR_SYSTEM", "HR System"),
    ]

    estate = models.ForeignKey(Estate, on_delete=models.CASCADE, related_name="integrations")
    integration_type = models.CharField(max_length=30, choices=INTEGRATION_TYPES)
    provider_name = models.CharField(max_length=100, help_text="e.g. Twilio, SendGrid, Paytm")
    config = models.JSONField(
        default=dict, help_text="Provider-specific config (store API keys encrypted)"
    )
    is_active = models.BooleanField(default=True)
    last_tested = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.provider_name} [{self.integration_type}] – {self.estate.name}"


# ---------------------------------------------------------------------------
# 20. BILLING & SUBSCRIPTIONS (SaaS-Ready, Multi-Estate)
# ---------------------------------------------------------------------------

class SubscriptionPlan(UUIDModel, TimeStampedModel):
    """
    Plans for multi-estate SaaS billing.
    """
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=20, unique=True)
    max_units = models.PositiveIntegerField(null=True, blank=True, help_text="Null = unlimited")
    max_users = models.PositiveIntegerField(null=True, blank=True)
    max_devices = models.PositiveIntegerField(null=True, blank=True)
    monthly_price = models.DecimalField(max_digits=10, decimal_places=2)
    annual_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    features = models.JSONField(
        default=list, help_text="List of enabled feature flags"
    )
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.name} – KES {self.monthly_price}/mo"


class EstateSubscription(UUIDModel, TimeStampedModel):
    """Links an estate to a subscription plan."""
    STATUS_CHOICES = [
        ("TRIAL", "Trial"),
        ("ACTIVE", "Active"),
        ("SUSPENDED", "Suspended"),
        ("CANCELLED", "Cancelled"),
        ("EXPIRED", "Expired"),
    ]

    estate = models.OneToOneField(Estate, on_delete=models.CASCADE, related_name="subscription")
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.PROTECT)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="TRIAL")
    trial_ends = models.DateTimeField(null=True, blank=True)
    billing_cycle_start = models.DateField(null=True, blank=True)
    billing_cycle_end = models.DateField(null=True, blank=True)
    auto_renew = models.BooleanField(default=True)
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"{self.estate.name} – {self.plan.name} [{self.status}]"


# ---------------------------------------------------------------------------
# SYSTEM CONFIGURATION
# ---------------------------------------------------------------------------

class SystemSetting(UUIDModel, TimeStampedModel):
    """
    Key-value store for estate-level or global system configuration.
    """
    estate = models.ForeignKey(
        Estate, on_delete=models.CASCADE, null=True, blank=True,
        help_text="Null = global platform setting"
    )
    key = models.CharField(max_length=100)
    value = models.TextField()
    data_type = models.CharField(
        max_length=20,
        choices=[("str", "String"), ("int", "Integer"), ("bool", "Boolean"), ("json", "JSON")],
        default="str"
    )
    description = models.TextField(blank=True)
    is_public = models.BooleanField(default=False)

    class Meta:
        unique_together = ("estate", "key")

    def __str__(self):
        return f"{self.key} = {self.value}"


class VisitorFeedback(UUIDModel, TimeStampedModel):
    """Post-visit feedback from visitor or resident."""
    visit = models.OneToOneField(Visit, on_delete=models.CASCADE, related_name="feedback")
    submitted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    rating = models.PositiveSmallIntegerField(help_text="1–5 stars")
    comment = models.TextField(blank=True)
    is_anonymous = models.BooleanField(default=False)

    def __str__(self):
        return f"Feedback for {self.visit} – {self.rating}⭐"


# ---------------------------------------------------------------------------
# SIGNAL HOOKS (for extensibility)
# ---------------------------------------------------------------------------
"""
Register Django signals in apps.py or signals.py:

from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=Visit)
def on_visit_checked_in(sender, instance, **kwargs):
    if instance.status == 'CHECKED_IN':
        # → Send notification
        # → Trigger webhook
        # → Update analytics
        pass
"""