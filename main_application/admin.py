"""
=============================================================================
VISITOR MANAGEMENT SYSTEM — admin.py
=============================================================================
Comprehensive Django Admin configuration for all 60+ models.
Features:
  - Custom list_display, list_filter, search_fields for every model
  - Inline admins for related objects
  - Custom actions (approve visits, blacklist, export CSV)
  - Read-only audit trail
  - Colour-coded status badges via custom methods
  - Collapsible fieldsets for long forms
  - Date hierarchy for time-series models
=============================================================================
"""

import csv
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.utils import timezone
from django.http import HttpResponse
from django.urls import reverse
from django.utils.safestring import mark_safe

from .models import (
    # Property
    Estate, Block, CommonArea,
    # Users
    User, ResidentProfile, SecurityStaffProfile,
    # Units
    Unit,
    # Visits
    Visitor, Visit, RecurrenceRule,
    # Pre-registration
    PreRegistration,
    # Access Control
    Zone, Gate, AccessPermission,
    # Hardware
    AccessDevice, BiometricTemplate, AccessCard, AccessEvent,
    # Badges
    VisitorBadge,
    # Notifications
    NotificationTemplate, Notification,
    # Blacklist
    Blacklist, Watchlist,
    # Vehicles
    RegisteredVehicle, VisitorVehicle, ParkingSlot, ParkingSession,
    # Deliveries
    Delivery,
    # Contractors
    Contractor, WorkOrder,
    # Incidents
    Incident,
    # Audit
    AuditLog,
    # Analytics
    DailyReport, SavedReport,
    # Documents
    VisitorDocument,
    # Emergency
    EmergencyAlert, EvacuationRecord,
    # Webhooks
    WebhookEndpoint, WebhookDelivery, ThirdPartyIntegration,
    # Billing
    SubscriptionPlan, EstateSubscription,
    # Config
    SystemSetting, VisitorFeedback,
)


# =============================================================================
# UTILITY: CSV EXPORT ACTION
# =============================================================================

def export_as_csv(modeladmin, request, queryset):
    """Generic action to export selected records as CSV."""
    meta = modeladmin.model._meta
    field_names = [field.name for field in meta.fields]

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = f"attachment; filename={meta.model_name}_export.csv"

    writer = csv.writer(response)
    writer.writerow(field_names)
    for obj in queryset:
        writer.writerow([getattr(obj, field) for field in field_names])
    return response

export_as_csv.short_description = "Export selected records as CSV"


# =============================================================================
# UTILITY: STATUS BADGE HELPERS
# =============================================================================

STATUS_COLORS = {
    # Visit statuses
    "PENDING":      "#f59e0b",
    "APPROVED":     "#3b82f6",
    "CHECKED_IN":   "#10b981",
    "CHECKED_OUT":  "#6b7280",
    "DENIED":       "#ef4444",
    "EXPIRED":      "#9ca3af",
    "CANCELLED":    "#9ca3af",
    "NO_SHOW":      "#f97316",
    # Device
    "ONLINE":       "#10b981",
    "OFFLINE":      "#ef4444",
    "MAINTENANCE":  "#f59e0b",
    "FAULT":        "#dc2626",
    # Severity
    "LOW":          "#10b981",
    "MEDIUM":       "#f59e0b",
    "HIGH":         "#ef4444",
    "CRITICAL":     "#7c3aed",
    # Subscription
    "TRIAL":        "#f59e0b",
    "ACTIVE":       "#10b981",
    "SUSPENDED":    "#ef4444",
    "EXPIRED":      "#9ca3af",
}


def colored_status(status):
    color = STATUS_COLORS.get(status, "#6b7280")
    return format_html(
        '<span style="background:{};color:#fff;padding:2px 8px;border-radius:4px;'
        'font-size:11px;font-weight:600;">{}</span>',
        color, status,
    )


# =============================================================================
# 1. ESTATE & PROPERTY
# =============================================================================

class BlockInline(admin.TabularInline):
    model = Block
    extra = 1
    fields = ("name", "code", "floors", "is_active")
    show_change_link = True


class CommonAreaInline(admin.TabularInline):
    model = CommonArea
    extra = 1
    fields = ("name", "area_type", "capacity", "access_controlled")


@admin.register(Estate)
class EstateAdmin(admin.ModelAdmin):
    list_display = ("name", "code", "city", "country", "is_active", "created_at")
    list_filter = ("is_active", "country", "city")
    search_fields = ("name", "code", "address", "contact_email")
    readonly_fields = ("id", "created_at", "updated_at")
    inlines = [BlockInline, CommonAreaInline]
    actions = [export_as_csv]
    fieldsets = (
        ("Identity", {
            "fields": ("id", "name", "code", "logo")
        }),
        ("Location", {
            "fields": ("address", "city", "state", "country", "postal_code", "latitude", "longitude", "timezone")
        }),
        ("Contact", {
            "fields": ("contact_phone", "contact_email", "website")
        }),
        ("Settings", {
            "classes": ("collapse",),
            "fields": ("settings", "is_active")
        }),
        ("Timestamps", {
            "classes": ("collapse",),
            "fields": ("created_at", "updated_at", "is_deleted", "deleted_at")
        }),
    )


@admin.register(Block)
class BlockAdmin(admin.ModelAdmin):
    list_display = ("name", "code", "estate", "floors", "is_active")
    list_filter = ("estate", "is_active")
    search_fields = ("name", "code", "estate__name")
    readonly_fields = ("id", "created_at", "updated_at")


@admin.register(CommonArea)
class CommonAreaAdmin(admin.ModelAdmin):
    list_display = ("name", "area_type", "estate", "capacity", "access_controlled")
    list_filter = ("area_type", "access_controlled", "estate")
    search_fields = ("name", "estate__name")
    readonly_fields = ("id",)


# =============================================================================
# 2. USERS, RESIDENTS & STAFF
# =============================================================================

class ResidentProfileInline(admin.StackedInline):
    model = ResidentProfile
    can_delete = False
    extra = 0
    verbose_name = "Resident Profile"
    fieldsets = (
        (None, {
            "fields": ("unit", "is_owner", "is_primary_contact", "is_active",
                       "move_in_date", "move_out_date", "lease_expiry",
                       "allow_visitor_self_checkin", "max_active_visitors",
                       "emergency_contact_name", "emergency_contact_phone")
        }),
    )


class SecurityProfileInline(admin.StackedInline):
    model = SecurityStaffProfile
    can_delete = False
    extra = 0
    verbose_name = "Security Profile"


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ("get_full_name", "email", "phone", "role", "estate", "is_verified", "is_active")
    list_filter = ("role", "is_verified", "is_active", "estate")
    search_fields = ("first_name", "last_name", "email", "phone", "national_id", "username")
    readonly_fields = ("id", "created_at", "updated_at", "last_login", "date_joined")
    ordering = ("last_name", "first_name")
    inlines = [ResidentProfileInline, SecurityProfileInline]
    actions = [export_as_csv]

    fieldsets = BaseUserAdmin.fieldsets + (
        ("VMS Profile", {
            "fields": ("role", "phone", "profile_photo", "national_id",
                       "date_of_birth", "estate", "is_verified",
                       "verification_method", "push_token", "language")
        }),
    )
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ("VMS Profile", {
            "fields": ("role", "phone", "estate")
        }),
    )

    def get_full_name(self, obj):
        return obj.get_full_name() or obj.username
    get_full_name.short_description = "Name"


@admin.register(ResidentProfile)
class ResidentProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "unit", "is_owner", "is_primary_contact", "move_in_date", "is_active")
    list_filter = ("is_owner", "is_active", "unit__block__estate")
    search_fields = ("user__first_name", "user__last_name", "user__email", "unit__unit_number")
    readonly_fields = ("id", "created_at", "updated_at")
    actions = [export_as_csv]


@admin.register(SecurityStaffProfile)
class SecurityStaffProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "badge_number", "shift", "assigned_gate", "is_supervisor")
    list_filter = ("shift", "is_supervisor")
    search_fields = ("user__first_name", "user__last_name", "badge_number")
    readonly_fields = ("id",)


# =============================================================================
# 3. UNITS
# =============================================================================

class UnitInline(admin.TabularInline):
    model = Unit
    extra = 0
    fields = ("unit_number", "floor", "unit_type", "is_occupied", "is_active")
    show_change_link = True


@admin.register(Unit)
class UnitAdmin(admin.ModelAdmin):
    list_display = ("unit_number", "block", "floor", "unit_type", "is_occupied", "is_active")
    list_filter = ("unit_type", "is_occupied", "is_active", "block__estate", "block")
    search_fields = ("unit_number", "block__name", "block__estate__name")
    readonly_fields = ("id", "created_at", "updated_at")
    ordering = ("block", "floor", "unit_number")
    actions = [export_as_csv]


# =============================================================================
# 4. VISITOR & VISIT MANAGEMENT
# =============================================================================

class VisitInline(admin.TabularInline):
    model = Visit
    extra = 0
    fields = ("unit", "host", "status", "actual_check_in", "actual_check_out", "purpose")
    readonly_fields = ("actual_check_in", "actual_check_out", "status")
    show_change_link = True
    max_num = 20


@admin.register(Visitor)
class VisitorAdmin(admin.ModelAdmin):
    list_display = ("get_full_name", "phone", "email", "id_type", "id_verified",
                    "is_flagged", "data_consent_given", "created_at")
    list_filter = ("id_type", "id_verified", "is_flagged", "data_consent_given", "gender")
    search_fields = ("first_name", "last_name", "phone", "email", "id_number", "company")
    readonly_fields = ("id", "created_at", "updated_at", "id_verified_at")
    inlines = [VisitInline]
    actions = [export_as_csv, "flag_visitors", "verify_ids"]
    date_hierarchy = "created_at"

    fieldsets = (
        ("Personal Info", {
            "fields": ("first_name", "last_name", "phone", "email", "gender",
                       "nationality", "company", "photo")
        }),
        ("ID Verification", {
            "fields": ("id_type", "id_number", "id_scan_front", "id_scan_back",
                       "id_verified", "id_verified_at", "id_verified_by")
        }),
        ("Biometrics", {
            "classes": ("collapse",),
            "fields": ("fingerprint_template", "face_encoding")
        }),
        ("Flags & Consent", {
            "fields": ("is_flagged", "flag_reason", "data_consent_given",
                       "data_consent_at", "nda_signed")
        }),
        ("Timestamps", {
            "classes": ("collapse",),
            "fields": ("id", "created_at", "updated_at")
        }),
    )

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}"
    get_full_name.short_description = "Name"

    @admin.action(description="Flag selected visitors")
    def flag_visitors(self, request, queryset):
        updated = queryset.update(is_flagged=True)
        self.message_user(request, f"{updated} visitor(s) flagged.")

    @admin.action(description="Mark IDs as verified")
    def verify_ids(self, request, queryset):
        updated = queryset.update(id_verified=True, id_verified_at=timezone.now())
        self.message_user(request, f"{updated} visitor ID(s) verified.")


class VisitorVehicleInline(admin.StackedInline):
    model = VisitorVehicle
    can_delete = False
    extra = 0
    fields = ("license_plate", "vehicle_type", "make", "model", "color", "lpr_captured", "lpr_image")


class VisitorBadgeInline(admin.StackedInline):
    model = VisitorBadge
    can_delete = False
    extra = 0
    fields = ("badge_type", "badge_number", "printed_at", "color_code", "is_returned")
    readonly_fields = ("printed_at",)


class VisitorDocumentInline(admin.TabularInline):
    model = VisitorDocument
    extra = 0
    fields = ("document_type", "is_signed", "signed_at")
    readonly_fields = ("signed_at",)


@admin.register(Visit)
class VisitAdmin(admin.ModelAdmin):
    list_display = ("visitor_link", "unit", "host", "purpose", "colored_status_badge",
                    "check_in_method", "actual_check_in", "actual_check_out",
                    "check_in_gate", "created_at")
    list_filter = ("status", "purpose", "check_in_method", "estate",
                   "check_in_gate", "is_recurring")
    search_fields = ("visitor__first_name", "visitor__last_name", "visitor__phone",
                     "unit__unit_number", "host__first_name", "host__last_name")
    readonly_fields = ("id", "created_at", "updated_at", "duration_minutes")
    date_hierarchy = "created_at"
    inlines = [VisitorVehicleInline, VisitorBadgeInline, VisitorDocumentInline]
    actions = [export_as_csv, "approve_visits", "deny_visits", "mark_no_show"]

    fieldsets = (
        ("Core", {
            "fields": ("id", "visitor", "host", "unit", "estate", "purpose",
                       "purpose_detail", "status", "number_of_visitors",
                       "accompanying_visitors")
        }),
        ("Timing", {
            "fields": ("expected_arrival", "expected_departure",
                       "actual_check_in", "actual_check_out", "duration_minutes")
        }),
        ("Gate & Method", {
            "fields": ("check_in_gate", "check_out_gate", "check_in_method",
                       "check_out_method", "checked_in_by", "checked_out_by")
        }),
        ("Approval", {
            "fields": ("approved_by", "approved_at", "denial_reason",
                       "pre_registration")
        }),
        ("Recurrence", {
            "classes": ("collapse",),
            "fields": ("is_recurring", "recurrence_rule")
        }),
        ("Photos & Ratings", {
            "classes": ("collapse",),
            "fields": ("check_in_photo", "check_out_photo",
                       "host_rating", "visitor_rating", "notes")
        }),
        ("Timestamps", {
            "classes": ("collapse",),
            "fields": ("created_at", "updated_at")
        }),
    )

    def visitor_link(self, obj):
        url = reverse("admin:vms_visitor_change", args=[obj.visitor.pk])
        return format_html('<a href="{}">{}</a>', url, obj.visitor)
    visitor_link.short_description = "Visitor"

    def colored_status_badge(self, obj):
        return colored_status(obj.status)
    colored_status_badge.short_description = "Status"
    colored_status_badge.allow_tags = True

    @admin.action(description="Approve selected visits")
    def approve_visits(self, request, queryset):
        updated = queryset.filter(status="PENDING").update(
            status="APPROVED", approved_by=request.user, approved_at=timezone.now()
        )
        self.message_user(request, f"{updated} visit(s) approved.")

    @admin.action(description="Deny selected visits")
    def deny_visits(self, request, queryset):
        updated = queryset.filter(status__in=["PENDING", "APPROVED"]).update(status="DENIED")
        self.message_user(request, f"{updated} visit(s) denied.")

    @admin.action(description="Mark selected as No Show")
    def mark_no_show(self, request, queryset):
        updated = queryset.filter(status="APPROVED").update(status="NO_SHOW")
        self.message_user(request, f"{updated} visit(s) marked as no-show.")


@admin.register(RecurrenceRule)
class RecurrenceRuleAdmin(admin.ModelAdmin):
    list_display = ("frequency", "start_date", "end_date", "start_time", "end_time", "is_active")
    list_filter = ("frequency", "is_active")
    readonly_fields = ("id",)


# =============================================================================
# 5. PRE-REGISTRATION
# =============================================================================

@admin.register(PreRegistration)
class PreRegistrationAdmin(admin.ModelAdmin):
    list_display = ("visitor_name", "visitor_phone", "unit", "host", "expected_arrival",
                    "status", "use_count", "max_uses", "created_at")
    list_filter = ("status", "purpose", "allow_multiple_uses", "estate")
    search_fields = ("visitor_name", "visitor_phone", "visitor_email",
                     "unit__unit_number", "host__first_name", "host__last_name",
                     "qr_code_token", "otp_code")
    readonly_fields = ("id", "created_at", "updated_at", "use_count")
    date_hierarchy = "expected_arrival"
    actions = [export_as_csv, "cancel_preregistrations"]

    fieldsets = (
        ("Host & Unit", {
            "fields": ("host", "unit", "estate", "purpose")
        }),
        ("Visitor Details", {
            "fields": ("visitor_name", "visitor_phone", "visitor_email", "visitor")
        }),
        ("Timing", {
            "fields": ("expected_arrival", "expected_departure")
        }),
        ("Access Credentials", {
            "fields": ("qr_code_token", "otp_code", "otp_expires_at",
                       "status", "allow_multiple_uses", "max_uses", "use_count")
        }),
        ("Recurrence", {
            "classes": ("collapse",),
            "fields": ("recurrence_rule",)
        }),
        ("Timestamps", {
            "classes": ("collapse",),
            "fields": ("id", "created_at", "updated_at")
        }),
    )

    @admin.action(description="Cancel selected pre-registrations")
    def cancel_preregistrations(self, request, queryset):
        updated = queryset.filter(status="PENDING").update(status="CANCELLED")
        self.message_user(request, f"{updated} pre-registration(s) cancelled.")


# =============================================================================
# 6. ACCESS CONTROL
# =============================================================================

class AccessDeviceInline(admin.TabularInline):
    model = AccessDevice
    extra = 0
    fields = ("name", "device_type", "status", "ip_address", "is_active")
    show_change_link = True


@admin.register(Zone)
class ZoneAdmin(admin.ModelAdmin):
    list_display = ("name", "estate", "minimum_access_level", "is_active")
    list_filter = ("estate", "minimum_access_level", "is_active")
    search_fields = ("name", "estate__name")
    readonly_fields = ("id",)


@admin.register(Gate)
class GateAdmin(admin.ModelAdmin):
    list_display = ("name", "estate", "gate_type", "zone", "is_active",
                    "is_open", "is_24h", "requires_escort")
    list_filter = ("gate_type", "is_active", "is_open", "is_24h", "requires_escort", "estate")
    search_fields = ("name", "estate__name", "zone__name")
    readonly_fields = ("id", "created_at", "updated_at")
    inlines = [AccessDeviceInline]
    actions = ["open_gates", "close_gates"]

    @admin.action(description="Mark selected gates as OPEN")
    def open_gates(self, request, queryset):
        queryset.update(is_open=True)
        self.message_user(request, "Selected gates marked as open.")

    @admin.action(description="Mark selected gates as CLOSED")
    def close_gates(self, request, queryset):
        queryset.update(is_open=False)
        self.message_user(request, "Selected gates marked as closed.")


@admin.register(AccessPermission)
class AccessPermissionAdmin(admin.ModelAdmin):
    list_display = ("user", "gate", "zone", "permission_type", "valid_from",
                    "valid_until", "is_active")
    list_filter = ("permission_type", "is_active")
    search_fields = ("user__first_name", "user__last_name", "user__email")
    readonly_fields = ("id", "created_at", "updated_at")
    date_hierarchy = "valid_from"


# =============================================================================
# 7. HARDWARE / DEVICES
# =============================================================================

@admin.register(AccessDevice)
class AccessDeviceAdmin(admin.ModelAdmin):
    list_display = ("name", "device_type", "gate", "estate", "colored_device_status",
                    "ip_address", "last_heartbeat", "is_active")
    list_filter = ("device_type", "status", "is_active", "estate")
    search_fields = ("name", "serial_number", "ip_address", "mac_address", "manufacturer")
    readonly_fields = ("id", "created_at", "updated_at", "last_heartbeat")
    actions = [export_as_csv, "set_online", "set_offline"]

    fieldsets = (
        ("Identity", {
            "fields": ("id", "name", "device_type", "estate", "gate",
                       "manufacturer", "model", "serial_number", "firmware_version")
        }),
        ("Network", {
            "fields": ("ip_address", "mac_address", "api_endpoint", "api_key")
        }),
        ("Status", {
            "fields": ("status", "last_heartbeat", "is_active")
        }),
        ("Maintenance", {
            "classes": ("collapse",),
            "fields": ("installed_at", "last_maintenance", "next_maintenance", "notes")
        }),
        ("Configuration", {
            "classes": ("collapse",),
            "fields": ("configuration",)
        }),
    )

    def colored_device_status(self, obj):
        return colored_status(obj.status)
    colored_device_status.short_description = "Status"

    @admin.action(description="Set selected devices ONLINE")
    def set_online(self, request, queryset):
        queryset.update(status="ONLINE", last_heartbeat=timezone.now())

    @admin.action(description="Set selected devices OFFLINE")
    def set_offline(self, request, queryset):
        queryset.update(status="OFFLINE")


@admin.register(BiometricTemplate)
class BiometricTemplateAdmin(admin.ModelAdmin):
    list_display = ("biometric_type", "user", "visitor", "device", "quality_score",
                    "finger_index", "is_active", "created_at")
    list_filter = ("biometric_type", "is_active")
    search_fields = ("user__first_name", "user__last_name", "visitor__first_name",
                     "visitor__last_name")
    readonly_fields = ("id", "created_at", "updated_at")


@admin.register(AccessCard)
class AccessCardAdmin(admin.ModelAdmin):
    list_display = ("card_number", "card_type", "user", "visitor", "estate",
                    "status", "valid_from", "valid_until", "is_temporary")
    list_filter = ("card_type", "status", "is_temporary", "estate")
    search_fields = ("card_number", "user__first_name", "user__last_name",
                     "visitor__first_name", "visitor__last_name")
    readonly_fields = ("id", "issued_at")
    filter_horizontal = ("allowed_zones", "allowed_gates")
    actions = [export_as_csv, "suspend_cards", "revoke_cards"]

    @admin.action(description="Suspend selected cards")
    def suspend_cards(self, request, queryset):
        queryset.update(status="SUSPENDED")

    @admin.action(description="Mark selected cards as LOST")
    def revoke_cards(self, request, queryset):
        queryset.update(status="LOST")


@admin.register(AccessEvent)
class AccessEventAdmin(admin.ModelAdmin):
    list_display = ("event_type", "gate", "direction", "user", "visitor",
                    "colored_event_type", "event_time", "is_acknowledged")
    list_filter = ("event_type", "direction", "is_acknowledged", "gate")
    search_fields = ("user__first_name", "visitor__first_name", "visitor__last_name",
                     "gate__name")
    readonly_fields = ("id", "created_at", "updated_at", "event_time", "raw_data")
    date_hierarchy = "event_time"
    actions = [export_as_csv, "acknowledge_events"]

    def colored_event_type(self, obj):
        color = "#10b981" if obj.event_type == "GRANTED" else "#ef4444"
        return format_html(
            '<span style="color:{};font-weight:bold;">{}</span>', color, obj.event_type
        )
    colored_event_type.short_description = "Type"

    @admin.action(description="Acknowledge selected events")
    def acknowledge_events(self, request, queryset):
        queryset.update(is_acknowledged=True)


# =============================================================================
# 8. BADGES
# =============================================================================

@admin.register(VisitorBadge)
class VisitorBadgeAdmin(admin.ModelAdmin):
    list_display = ("badge_number", "visit", "badge_type", "printed_at",
                    "color_code", "is_returned")
    list_filter = ("badge_type", "is_returned")
    search_fields = ("badge_number", "visit__visitor__first_name", "visit__visitor__last_name")
    readonly_fields = ("id", "created_at", "updated_at")
    actions = [export_as_csv]


# =============================================================================
# 9. NOTIFICATIONS
# =============================================================================

@admin.register(NotificationTemplate)
class NotificationTemplateAdmin(admin.ModelAdmin):
    list_display = ("event_trigger", "channel", "estate", "send_to_host",
                    "send_to_visitor", "send_to_security", "is_active")
    list_filter = ("event_trigger", "channel", "is_active", "estate")
    search_fields = ("event_trigger", "subject", "body")
    readonly_fields = ("id",)


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ("recipient", "channel", "status", "sent_at", "delivered_at")
    list_filter = ("channel", "status")
    search_fields = ("recipient__first_name", "recipient__last_name", "subject", "message")
    readonly_fields = ("id", "created_at", "updated_at", "sent_at", "delivered_at", "read_at")
    date_hierarchy = "created_at"


# =============================================================================
# 10. BLACKLIST & WATCHLIST
# =============================================================================

@admin.register(Blacklist)
class BlacklistAdmin(admin.ModelAdmin):
    list_display = ("get_name", "severity_badge", "estate", "is_active",
                    "valid_until", "added_by", "created_at")
    list_filter = ("severity", "is_active", "estate")
    search_fields = ("visitor__first_name", "visitor__last_name", "name",
                     "id_number", "phone", "reason")
    readonly_fields = ("id", "created_at", "updated_at")
    date_hierarchy = "created_at"
    actions = [export_as_csv]

    def get_name(self, obj):
        return str(obj.visitor) if obj.visitor else obj.name or obj.phone or obj.id_number
    get_name.short_description = "Person"

    def severity_badge(self, obj):
        return colored_status(obj.severity)
    severity_badge.short_description = "Severity"


@admin.register(Watchlist)
class WatchlistAdmin(admin.ModelAdmin):
    list_display = ("get_name", "estate", "reason", "is_active", "added_by", "created_at")
    list_filter = ("is_active", "estate")
    search_fields = ("visitor__first_name", "visitor__last_name", "name", "phone", "reason")
    readonly_fields = ("id",)

    def get_name(self, obj):
        return str(obj.visitor) if obj.visitor else obj.name or obj.phone
    get_name.short_description = "Person"


# =============================================================================
# 11. VEHICLES & PARKING
# =============================================================================

@admin.register(RegisteredVehicle)
class RegisteredVehicleAdmin(admin.ModelAdmin):
    list_display = ("license_plate", "owner", "unit", "vehicle_type",
                    "make", "model", "color", "sticker_number", "is_active")
    list_filter = ("vehicle_type", "is_active")
    search_fields = ("license_plate", "make", "model", "sticker_number",
                     "owner__first_name", "owner__last_name")
    readonly_fields = ("id",)
    actions = [export_as_csv]


@admin.register(ParkingSlot)
class ParkingSlotAdmin(admin.ModelAdmin):
    list_display = ("slot_number", "estate", "block", "slot_type",
                    "assigned_to", "is_occupied", "is_active")
    list_filter = ("slot_type", "is_occupied", "is_active", "estate")
    search_fields = ("slot_number", "assigned_to__first_name", "assigned_to__last_name")
    readonly_fields = ("id",)


@admin.register(ParkingSession)
class ParkingSessionAdmin(admin.ModelAdmin):
    list_display = ("vehicle_plate", "slot", "entry_time", "exit_time", "is_active")
    list_filter = ("is_active",)
    search_fields = ("vehicle_plate", "slot__slot_number")
    readonly_fields = ("id", "created_at", "updated_at")
    date_hierarchy = "entry_time"


# =============================================================================
# 12. DELIVERIES
# =============================================================================

@admin.register(Delivery)
class DeliveryAdmin(admin.ModelAdmin):
    list_display = ("unit", "recipient", "delivery_type", "courier_company",
                    "status_badge", "arrived_at", "collected_at")
    list_filter = ("delivery_type", "status", "estate")
    search_fields = ("tracking_number", "courier_name", "courier_company",
                     "unit__unit_number", "recipient__first_name", "recipient__last_name")
    readonly_fields = ("id", "created_at", "updated_at")
    date_hierarchy = "arrived_at"
    actions = [export_as_csv]

    def status_badge(self, obj):
        colors = {
            "ARRIVED": "#f59e0b", "COLLECTED": "#10b981",
            "RETURNED": "#ef4444", "STORED": "#3b82f6"
        }
        color = colors.get(obj.status, "#6b7280")
        return format_html(
            '<span style="background:{};color:#fff;padding:2px 8px;border-radius:4px;">{}</span>',
            color, obj.status
        )
    status_badge.short_description = "Status"


# =============================================================================
# 13. CONTRACTORS & WORK ORDERS
# =============================================================================

class WorkOrderInline(admin.TabularInline):
    model = WorkOrder
    extra = 0
    fields = ("title", "status", "scheduled_start", "scheduled_end", "requires_unit_access")
    show_change_link = True


@admin.register(Contractor)
class ContractorAdmin(admin.ModelAdmin):
    list_display = ("company_name", "contact_person", "phone", "service_type",
                    "estate", "is_approved", "is_active", "contract_end")
    list_filter = ("is_approved", "is_active", "estate")
    search_fields = ("company_name", "contact_person", "phone", "email", "service_type")
    readonly_fields = ("id",)
    inlines = [WorkOrderInline]
    actions = [export_as_csv, "approve_contractors"]

    @admin.action(description="Approve selected contractors")
    def approve_contractors(self, request, queryset):
        updated = queryset.update(is_approved=True, approved_by=request.user)
        self.message_user(request, f"{updated} contractor(s) approved.")


@admin.register(WorkOrder)
class WorkOrderAdmin(admin.ModelAdmin):
    list_display = ("title", "contractor", "unit", "status", "scheduled_start",
                    "scheduled_end", "requires_unit_access", "resident_approved")
    list_filter = ("status", "requires_unit_access", "resident_approved", "estate")
    search_fields = ("title", "description", "contractor__company_name",
                     "unit__unit_number")
    readonly_fields = ("id", "created_at", "updated_at")
    filter_horizontal = ("assigned_workers",)
    date_hierarchy = "scheduled_start"


# =============================================================================
# 14. INCIDENTS
# =============================================================================

@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ("title", "incident_type", "severity_badge", "status_badge",
                    "estate", "gate", "occurred_at", "reported_by")
    list_filter = ("incident_type", "severity", "status", "is_police_notified", "estate")
    search_fields = ("title", "description", "police_report_number",
                     "reported_by__first_name", "reported_by__last_name")
    readonly_fields = ("id", "created_at", "updated_at")
    date_hierarchy = "occurred_at"
    actions = [export_as_csv]

    fieldsets = (
        ("Details", {
            "fields": ("id", "estate", "gate", "unit", "visit", "visitor",
                       "incident_type", "severity", "title", "description", "occurred_at")
        }),
        ("Assignment", {
            "fields": ("reported_by", "assigned_to", "status",
                       "resolution_notes", "resolved_at")
        }),
        ("Police", {
            "classes": ("collapse",),
            "fields": ("is_police_notified", "police_report_number")
        }),
        ("Evidence", {
            "classes": ("collapse",),
            "fields": ("photos", "cctv_reference")
        }),
    )

    def severity_badge(self, obj):
        return colored_status(obj.severity)
    severity_badge.short_description = "Severity"

    def status_badge(self, obj):
        return colored_status(obj.status)
    status_badge.short_description = "Status"


# =============================================================================
# 15. AUDIT TRAIL (Read-Only)
# =============================================================================

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("action", "model_name", "object_id", "user", "ip_address",
                    "estate", "created_at")
    list_filter = ("action", "model_name", "estate")
    search_fields = ("description", "model_name", "object_id",
                     "user__first_name", "user__last_name", "ip_address")
    readonly_fields = ("id", "created_at", "updated_at", "user", "action",
                       "model_name", "object_id", "description", "ip_address",
                       "user_agent", "before_state", "after_state", "estate")
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False  # Audit logs are system-generated only

    def has_change_permission(self, request, obj=None):
        return False  # Immutable

    def has_delete_permission(self, request, obj=None):
        return False  # Never delete audit logs


# =============================================================================
# 16. ANALYTICS & REPORTS
# =============================================================================

@admin.register(DailyReport)
class DailyReportAdmin(admin.ModelAdmin):
    list_display = ("date", "estate", "total_visitors", "total_check_ins",
                    "total_check_outs", "denied_access", "blacklist_alerts",
                    "total_incidents", "avg_visit_duration_minutes")
    list_filter = ("estate",)
    search_fields = ("estate__name",)
    readonly_fields = ("id", "created_at", "updated_at")
    date_hierarchy = "date"
    actions = [export_as_csv]


@admin.register(SavedReport)
class SavedReportAdmin(admin.ModelAdmin):
    list_display = ("name", "estate", "frequency", "format", "last_sent",
                    "created_by", "is_active")
    list_filter = ("frequency", "format", "is_active", "estate")
    search_fields = ("name", "estate__name")
    readonly_fields = ("id",)
    filter_horizontal = ("recipients",)


# =============================================================================
# 17. DOCUMENTS
# =============================================================================

@admin.register(VisitorDocument)
class VisitorDocumentAdmin(admin.ModelAdmin):
    list_display = ("document_type", "visit", "estate", "is_signed", "signed_at")
    list_filter = ("document_type", "is_signed", "estate")
    search_fields = ("visit__visitor__first_name", "visit__visitor__last_name")
    readonly_fields = ("id", "created_at", "updated_at", "signed_at")


# =============================================================================
# 18. EMERGENCY
# =============================================================================

class EvacuationRecordInline(admin.TabularInline):
    model = EvacuationRecord
    extra = 0
    fields = ("person", "visitor", "is_accounted", "accounted_at", "mustering_point")
    readonly_fields = ("accounted_at",)


@admin.register(EmergencyAlert)
class EmergencyAlertAdmin(admin.ModelAdmin):
    list_display = ("alert_type", "title", "estate", "status", "gate_lockdown",
                    "initiated_by", "initiated_at", "resolved_at")
    list_filter = ("alert_type", "status", "gate_lockdown", "estate")
    search_fields = ("title", "message", "estate__name")
    readonly_fields = ("id", "created_at", "updated_at")
    date_hierarchy = "initiated_at"
    inlines = [EvacuationRecordInline]
    actions = ["resolve_alerts"]

    @admin.action(description="Mark selected alerts as RESOLVED")
    def resolve_alerts(self, request, queryset):
        queryset.filter(status="ACTIVE").update(
            status="RESOLVED", resolved_at=timezone.now()
        )


@admin.register(EvacuationRecord)
class EvacuationRecordAdmin(admin.ModelAdmin):
    list_display = ("alert", "person", "visitor", "is_accounted",
                    "accounted_at", "mustering_point")
    list_filter = ("is_accounted",)
    readonly_fields = ("id",)


# =============================================================================
# 19. WEBHOOKS & INTEGRATIONS
# =============================================================================

class WebhookDeliveryInline(admin.TabularInline):
    model = WebhookDelivery
    extra = 0
    fields = ("event", "response_status", "success", "attempt_number", "created_at")
    readonly_fields = ("event", "response_status", "success", "attempt_number", "created_at")
    show_change_link = True
    max_num = 20


@admin.register(WebhookEndpoint)
class WebhookEndpointAdmin(admin.ModelAdmin):
    list_display = ("url", "estate", "is_active", "timeout_seconds",
                    "retry_attempts", "created_at")
    list_filter = ("is_active", "estate")
    search_fields = ("url", "description", "estate__name")
    readonly_fields = ("id",)
    inlines = [WebhookDeliveryInline]


@admin.register(WebhookDelivery)
class WebhookDeliveryAdmin(admin.ModelAdmin):
    list_display = ("endpoint", "event", "response_status", "success",
                    "duration_ms", "attempt_number", "created_at")
    list_filter = ("success", "event")
    search_fields = ("event",)
    readonly_fields = ("id", "created_at", "updated_at")
    date_hierarchy = "created_at"


@admin.register(ThirdPartyIntegration)
class ThirdPartyIntegrationAdmin(admin.ModelAdmin):
    list_display = ("provider_name", "integration_type", "estate",
                    "is_active", "last_tested")
    list_filter = ("integration_type", "is_active", "estate")
    search_fields = ("provider_name", "estate__name")
    readonly_fields = ("id",)


# =============================================================================
# 20. BILLING
# =============================================================================

@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    list_display = ("name", "code", "monthly_price", "annual_price",
                    "max_units", "max_users", "max_devices", "is_active")
    list_filter = ("is_active",)
    search_fields = ("name", "code")
    readonly_fields = ("id",)


@admin.register(EstateSubscription)
class EstateSubscriptionAdmin(admin.ModelAdmin):
    list_display = ("estate", "plan", "status_badge", "trial_ends",
                    "billing_cycle_end", "auto_renew")
    list_filter = ("status", "auto_renew", "plan")
    search_fields = ("estate__name", "plan__name")
    readonly_fields = ("id",)

    def status_badge(self, obj):
        return colored_status(obj.status)
    status_badge.short_description = "Status"


# =============================================================================
# SYSTEM CONFIG
# =============================================================================

@admin.register(SystemSetting)
class SystemSettingAdmin(admin.ModelAdmin):
    list_display = ("key", "value", "data_type", "estate", "is_public", "created_at")
    list_filter = ("data_type", "is_public", "estate")
    search_fields = ("key", "value", "description")
    readonly_fields = ("id",)


@admin.register(VisitorFeedback)
class VisitorFeedbackAdmin(admin.ModelAdmin):
    list_display = ("visit", "rating", "submitted_by", "is_anonymous", "created_at")
    list_filter = ("rating", "is_anonymous")
    search_fields = ("visit__visitor__first_name", "visit__visitor__last_name", "comment")
    readonly_fields = ("id", "created_at", "updated_at")
    date_hierarchy = "created_at"
    actions = [export_as_csv]


# =============================================================================
# ADMIN SITE CUSTOMISATION
# =============================================================================

admin.site.site_header = "🏢 VMS – Visitor Management System"
admin.site.site_title = "VMS Admin"
admin.site.index_title = "Estate Operations Dashboard"