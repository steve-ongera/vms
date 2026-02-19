"""
=============================================================================
VISITOR MANAGEMENT SYSTEM — views.py  (Function-Based Views)
=============================================================================
Every endpoint is a plain @api_view FBV using DRF.
Pattern per resource:
    list_create   → GET (list + filters) | POST (create)
    detail        → GET (single) | PUT/PATCH (update) | DELETE (soft delete)
    action views  → POST-only custom business logic

Permissions helpers used throughout:
    is_admin()   → SUPERADMIN or ESTATE_ADMIN
    is_security()→ SECURITY or RECEPTIONIST
    is_resident()→ RESIDENT or TENANT
    same_estate()→ request.user.estate == obj.estate

Return format (all endpoints):
    Success → {"success": True, "data": {...}, "message": "..."}
    Error   → {"success": False, "error": "...", "details": {...}}
=============================================================================
"""

import uuid
import secrets
import string
from datetime import timedelta

from django.utils import timezone
from django.db.models import Q, Count, Avg
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import get_object_or_404

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from .models import (
    Estate, Block, CommonArea,
    User, ResidentProfile, SecurityStaffProfile,
    Unit,
    Visitor, Visit, RecurrenceRule,
    PreRegistration,
    Zone, Gate, AccessPermission,
    AccessDevice, BiometricTemplate, AccessCard, AccessEvent,
    VisitorBadge,
    NotificationTemplate, Notification,
    Blacklist, Watchlist,
    RegisteredVehicle, VisitorVehicle, ParkingSlot, ParkingSession,
    Delivery,
    Contractor, WorkOrder,
    Incident,
    AuditLog,
    DailyReport, SavedReport,
    VisitorDocument,
    EmergencyAlert, EvacuationRecord,
    WebhookEndpoint, WebhookDelivery, ThirdPartyIntegration,
    SubscriptionPlan, EstateSubscription,
    SystemSetting, VisitorFeedback,
)


# =============================================================================
# HELPERS
# =============================================================================

def ok(data=None, message="Success", status_code=status.HTTP_200_OK):
    return Response({"success": True, "message": message, "data": data}, status=status_code)


def err(error, details=None, status_code=status.HTTP_400_BAD_REQUEST):
    return Response({"success": False, "error": error, "details": details}, status=status_code)


def paginate(queryset, request, serializer_class, per_page=20):
    """Simple cursor-style pagination via ?page= and ?per_page=."""
    try:
        page = max(1, int(request.GET.get("page", 1)))
        per_page = min(100, int(request.GET.get("per_page", per_page)))
    except ValueError:
        page, per_page = 1, 20
    start = (page - 1) * per_page
    end = start + per_page
    total = queryset.count()
    items = queryset[start:end]
    return {
        "results": serializer_class(items, many=True, context={"request": request}).data,
        "pagination": {
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
            "has_next": end < total,
            "has_prev": page > 1,
        },
    }


def is_admin(user):
    return user.role in ("SUPERADMIN", "ESTATE_ADMIN", "PROPERTY_MANAGER")


def is_security(user):
    return user.role in ("SECURITY", "RECEPTIONIST")


def is_resident(user):
    return user.role in ("RESIDENT", "TENANT")


def same_estate(user, estate):
    return user.role == "SUPERADMIN" or user.estate == estate


def log_action(user, action, model_name, object_id, description, request=None):
    """Write to immutable AuditLog."""
    AuditLog.objects.create(
        user=user,
        action=action,
        model_name=model_name,
        object_id=str(object_id),
        description=description,
        ip_address=request.META.get("REMOTE_ADDR") if request else None,
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:500] if request else "",
        estate=getattr(user, "estate", None),
    )


def gen_otp(length=6):
    return "".join(secrets.choice(string.digits) for _ in range(length))


def gen_token(length=32):
    return secrets.token_urlsafe(length)


# =============================================================================
# Inline serialiser helpers (lightweight dicts – no separate serializers.py needed)
# =============================================================================

def _user_dict(u):
    if not u:
        return None
    return {
        "id": str(u.id), "username": u.username,
        "full_name": u.get_full_name(), "email": u.email,
        "phone": u.phone, "role": u.role,
    }


def _estate_dict(e):
    if not e:
        return None
    return {"id": str(e.id), "name": e.name, "code": e.code, "city": e.city}


def _unit_dict(u):
    if not u:
        return None
    return {
        "id": str(u.id), "unit_number": u.unit_number,
        "floor": u.floor, "block": u.block.name,
        "estate": u.block.estate.name,
    }


def _visitor_dict(v):
    if not v:
        return None
    return {
        "id": str(v.id),
        "full_name": f"{v.first_name} {v.last_name}",
        "phone": v.phone, "email": v.email,
        "id_type": v.id_type, "id_number": v.id_number,
        "id_verified": v.id_verified, "is_flagged": v.is_flagged,
        "company": v.company,
        "photo": v.photo.url if v.photo else None,
    }


def _visit_dict(v, detail=False):
    d = {
        "id": str(v.id),
        "visitor": _visitor_dict(v.visitor),
        "host": _user_dict(v.host),
        "unit": _unit_dict(v.unit),
        "estate": _estate_dict(v.estate),
        "status": v.status,
        "purpose": v.purpose,
        "check_in_method": v.check_in_method,
        "expected_arrival": v.expected_arrival,
        "expected_departure": v.expected_departure,
        "actual_check_in": v.actual_check_in,
        "actual_check_out": v.actual_check_out,
        "check_in_gate": v.check_in_gate.name if v.check_in_gate else None,
        "number_of_visitors": v.number_of_visitors,
        "created_at": v.created_at,
    }
    if detail:
        d.update({
            "purpose_detail": v.purpose_detail,
            "notes": v.notes,
            "denial_reason": v.denial_reason,
            "approved_by": _user_dict(v.approved_by),
            "approved_at": v.approved_at,
            "checked_in_by": _user_dict(v.checked_in_by),
            "checked_out_by": _user_dict(v.checked_out_by),
            "check_in_photo": v.check_in_photo.url if v.check_in_photo else None,
            "check_out_photo": v.check_out_photo.url if v.check_out_photo else None,
            "is_recurring": v.is_recurring,
            "duration_minutes": v.duration_minutes(),
            "host_rating": v.host_rating,
            "visitor_rating": v.visitor_rating,
        })
    return d


# =============================================================================
# 1. AUTHENTICATION
# =============================================================================

@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    """
    POST /api/auth/login/
    Body: { "username": "...", "password": "..." }
    Returns: access + refresh JWT tokens + user profile.
    """
    username = request.data.get("username", "").strip()
    password = request.data.get("password", "")

    if not username or not password:
        return err("Username and password are required.")

    try:
        user = User.objects.get(
            Q(username=username) | Q(email=username) | Q(phone=username)
        )
    except User.DoesNotExist:
        return err("Invalid credentials.", status_code=status.HTTP_401_UNAUTHORIZED)

    if not user.check_password(password):
        return err("Invalid credentials.", status_code=status.HTTP_401_UNAUTHORIZED)

    if not user.is_active:
        return err("Account is disabled. Contact your estate administrator.",
                   status_code=status.HTTP_403_FORBIDDEN)

    refresh = RefreshToken.for_user(user)
    log_action(user, "LOGIN", "User", user.id, f"Login from {request.META.get('REMOTE_ADDR')}", request)

    return ok({
        "access": str(refresh.access_token),
        "refresh": str(refresh),
        "user": {
            **_user_dict(user),
            "is_verified": user.is_verified,
            "estate": _estate_dict(user.estate),
            "language": user.language,
        },
    }, message="Login successful.")


@api_view(["POST"])
@permission_classes([AllowAny])
def token_refresh_view(request):
    """
    POST /api/auth/token/refresh/
    Body: { "refresh": "<token>" }
    """
    refresh_token = request.data.get("refresh")
    if not refresh_token:
        return err("Refresh token required.")
    try:
        token = RefreshToken(refresh_token)
        return ok({"access": str(token.access_token)})
    except TokenError as e:
        return err(str(e), status_code=status.HTTP_401_UNAUTHORIZED)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """
    POST /api/auth/logout/
    Body: { "refresh": "<token>" }
    Blacklists the refresh token.
    """
    refresh_token = request.data.get("refresh")
    if not refresh_token:
        return err("Refresh token required.")
    try:
        token = RefreshToken(refresh_token)
        token.blacklist()
        log_action(request.user, "LOGOUT", "User", request.user.id, "User logged out", request)
        return ok(message="Logged out successfully.")
    except TokenError as e:
        return err(str(e))


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def change_password_view(request):
    """
    POST /api/auth/change-password/
    Body: { "old_password", "new_password", "confirm_password" }
    """
    user = request.user
    old = request.data.get("old_password")
    new = request.data.get("new_password")
    confirm = request.data.get("confirm_password")

    if not user.check_password(old):
        return err("Current password is incorrect.")
    if new != confirm:
        return err("New passwords do not match.")
    if len(new) < 8:
        return err("Password must be at least 8 characters.")

    user.set_password(new)
    user.save()
    update_session_auth_hash(request, user)
    log_action(user, "UPDATE", "User", user.id, "Password changed", request)
    return ok(message="Password changed successfully.")


@api_view(["GET", "PATCH"])
@permission_classes([IsAuthenticated])
def me_view(request):
    """
    GET  /api/auth/me/    → current user profile
    PATCH /api/auth/me/   → update profile (name, phone, language, photo)
    """
    user = request.user
    if request.method == "GET":
        data = {
            **_user_dict(user),
            "national_id": user.national_id,
            "date_of_birth": user.date_of_birth,
            "is_verified": user.is_verified,
            "estate": _estate_dict(user.estate),
            "language": user.language,
            "push_token": user.push_token,
            "profile_photo": user.profile_photo.url if user.profile_photo else None,
            "last_login": user.last_login,
            "date_joined": user.date_joined,
        }
        return ok(data)

    # PATCH
    allowed = ["first_name", "last_name", "phone", "language",
               "national_id", "date_of_birth", "profile_photo"]
    for field in allowed:
        if field in request.data:
            setattr(user, field, request.data[field])
    user.save()
    return ok(_user_dict(user), message="Profile updated.")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def update_push_token_view(request):
    """POST /api/auth/push-token/ — store FCM/APNs device token."""
    token = request.data.get("push_token", "").strip()
    if not token:
        return err("push_token is required.")
    request.user.push_token = token
    request.user.save(update_fields=["push_token"])
    return ok(message="Push token updated.")


# =============================================================================
# 2. USER MANAGEMENT
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def user_list_create(request):
    """
    GET  /api/users/        → list users (admin: all in estate; resident: self only)
    POST /api/users/        → create new user (admin only)

    Query params: ?role=SECURITY&search=john&is_active=true
    """
    if request.method == "GET":
        if not is_admin(request.user) and not is_security(request.user):
            return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)

        qs = User.objects.filter(is_deleted=False) if hasattr(User, 'is_deleted') else User.objects.all()

        if request.user.role != "SUPERADMIN":
            qs = qs.filter(estate=request.user.estate)

        # Filters
        role = request.GET.get("role")
        search = request.GET.get("search")
        is_active = request.GET.get("is_active")
        is_verified = request.GET.get("is_verified")

        if role:
            qs = qs.filter(role=role)
        if search:
            qs = qs.filter(
                Q(first_name__icontains=search) | Q(last_name__icontains=search) |
                Q(email__icontains=search) | Q(phone__icontains=search)
            )
        if is_active is not None:
            qs = qs.filter(is_active=is_active.lower() == "true")
        if is_verified is not None:
            qs = qs.filter(is_verified=is_verified.lower() == "true")

        data = [_user_dict(u) for u in qs.order_by("last_name", "first_name")]
        return ok(data)

    # POST
    if not is_admin(request.user):
        return err("Only admins can create users.", status_code=status.HTTP_403_FORBIDDEN)

    required = ["username", "password", "role", "first_name", "last_name"]
    for f in required:
        if not request.data.get(f):
            return err(f"Field '{f}' is required.")

    if User.objects.filter(username=request.data["username"]).exists():
        return err("Username already taken.")

    user = User(
        username=request.data["username"],
        first_name=request.data["first_name"],
        last_name=request.data["last_name"],
        email=request.data.get("email", ""),
        phone=request.data.get("phone", ""),
        role=request.data["role"],
        estate=request.user.estate if request.user.role != "SUPERADMIN"
               else Estate.objects.filter(id=request.data.get("estate")).first(),
        national_id=request.data.get("national_id", ""),
        language=request.data.get("language", "en"),
    )
    user.set_password(request.data["password"])
    user.save()
    log_action(request.user, "CREATE", "User", user.id, f"Created user {user.username}", request)
    return ok(_user_dict(user), message="User created.", status_code=status.HTTP_201_CREATED)


@api_view(["GET", "PUT", "PATCH", "DELETE"])
@permission_classes([IsAuthenticated])
def user_detail(request, user_id):
    """
    GET    /api/users/<id>/
    PUT    /api/users/<id>/   → full update (admin only)
    PATCH  /api/users/<id>/   → partial update
    DELETE /api/users/<id>/   → deactivate (admin only)
    """
    user = get_object_or_404(User, id=user_id)

    # Permission: admin or self
    if not is_admin(request.user) and request.user.id != user.id:
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)

    if request.method == "GET":
        data = {
            **_user_dict(user),
            "national_id": user.national_id,
            "date_of_birth": user.date_of_birth,
            "is_verified": user.is_verified,
            "verification_method": user.verification_method,
            "is_active": user.is_active,
            "estate": _estate_dict(user.estate),
            "profile_photo": user.profile_photo.url if user.profile_photo else None,
            "last_login": user.last_login,
            "date_joined": user.date_joined,
        }
        return ok(data)

    if request.method in ("PUT", "PATCH"):
        if not is_admin(request.user) and request.user.id != user.id:
            return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
        updatable = ["first_name", "last_name", "email", "phone", "role",
                     "national_id", "date_of_birth", "language", "is_active",
                     "is_verified", "verification_method"]
        for f in updatable:
            if f in request.data:
                setattr(user, f, request.data[f])
        user.save()
        log_action(request.user, "UPDATE", "User", user.id, f"Updated user {user.username}", request)
        return ok(_user_dict(user), message="User updated.")

    # DELETE → deactivate
    if not is_admin(request.user):
        return err("Only admins can deactivate users.", status_code=status.HTTP_403_FORBIDDEN)
    user.is_active = False
    user.save()
    log_action(request.user, "DELETE", "User", user.id, f"Deactivated user {user.username}", request)
    return ok(message="User deactivated.")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verify_user_view(request, user_id):
    """POST /api/users/<id>/verify/ — mark user as verified."""
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    user = get_object_or_404(User, id=user_id)
    user.is_verified = True
    user.verification_method = request.data.get("method", "MANUAL")
    user.save()
    log_action(request.user, "UPDATE", "User", user.id, f"Verified user {user.username}", request)
    return ok(message=f"User {user.get_full_name()} verified.")


# =============================================================================
# 3. RESIDENT PROFILE
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def resident_profile_list_create(request):
    """
    GET  /api/residents/        → list all residents in estate
    POST /api/residents/        → create resident profile
    """
    if request.method == "GET":
        if not (is_admin(request.user) or is_security(request.user)):
            return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
        qs = ResidentProfile.objects.select_related("user", "unit__block__estate")
        if request.user.role != "SUPERADMIN":
            qs = qs.filter(unit__block__estate=request.user.estate)
        unit_id = request.GET.get("unit")
        is_active = request.GET.get("is_active")
        if unit_id:
            qs = qs.filter(unit_id=unit_id)
        if is_active is not None:
            qs = qs.filter(is_active=is_active.lower() == "true")
        data = [{
            "id": str(r.id),
            "user": _user_dict(r.user),
            "unit": _unit_dict(r.unit),
            "is_owner": r.is_owner,
            "is_primary_contact": r.is_primary_contact,
            "move_in_date": r.move_in_date,
            "move_out_date": r.move_out_date,
            "lease_expiry": r.lease_expiry,
            "is_active": r.is_active,
            "allow_visitor_self_checkin": r.allow_visitor_self_checkin,
            "max_active_visitors": r.max_active_visitors,
        } for r in qs]
        return ok(data)

    # POST
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    user = get_object_or_404(User, id=request.data.get("user_id"))
    unit = get_object_or_404(Unit, id=request.data.get("unit_id"))
    if ResidentProfile.objects.filter(user=user).exists():
        return err("Resident profile already exists for this user.")
    profile = ResidentProfile.objects.create(
        user=user, unit=unit,
        is_owner=request.data.get("is_owner", False),
        is_primary_contact=request.data.get("is_primary_contact", True),
        move_in_date=request.data.get("move_in_date"),
        lease_expiry=request.data.get("lease_expiry"),
        emergency_contact_name=request.data.get("emergency_contact_name", ""),
        emergency_contact_phone=request.data.get("emergency_contact_phone", ""),
        allow_visitor_self_checkin=request.data.get("allow_visitor_self_checkin", True),
        max_active_visitors=request.data.get("max_active_visitors", 5),
    )
    unit.is_occupied = True
    unit.save(update_fields=["is_occupied"])
    return ok({"id": str(profile.id)}, message="Resident profile created.", status_code=status.HTTP_201_CREATED)


@api_view(["GET", "PATCH", "DELETE"])
@permission_classes([IsAuthenticated])
def resident_profile_detail(request, profile_id):
    """GET/PATCH/DELETE /api/residents/<id>/"""
    profile = get_object_or_404(ResidentProfile, id=profile_id)
    if not is_admin(request.user) and request.user.id != profile.user.id:
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)

    if request.method == "GET":
        return ok({
            "id": str(profile.id),
            "user": _user_dict(profile.user),
            "unit": _unit_dict(profile.unit),
            "is_owner": profile.is_owner,
            "is_primary_contact": profile.is_primary_contact,
            "move_in_date": profile.move_in_date,
            "move_out_date": profile.move_out_date,
            "lease_expiry": profile.lease_expiry,
            "is_active": profile.is_active,
            "emergency_contact_name": profile.emergency_contact_name,
            "emergency_contact_phone": profile.emergency_contact_phone,
            "allow_visitor_self_checkin": profile.allow_visitor_self_checkin,
            "max_active_visitors": profile.max_active_visitors,
        })

    if request.method == "PATCH":
        fields = ["is_owner", "is_primary_contact", "move_in_date", "move_out_date",
                  "lease_expiry", "emergency_contact_name", "emergency_contact_phone",
                  "allow_visitor_self_checkin", "max_active_visitors", "is_active"]
        for f in fields:
            if f in request.data:
                setattr(profile, f, request.data[f])
        if "unit_id" in request.data:
            profile.unit = get_object_or_404(Unit, id=request.data["unit_id"])
        profile.save()
        return ok(message="Resident profile updated.")

    # DELETE
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    profile.is_active = False
    profile.move_out_date = timezone.now().date()
    profile.save()
    return ok(message="Resident profile deactivated.")


# =============================================================================
# 4. ESTATE
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def estate_list_create(request):
    """
    GET  /api/estates/   → list (superadmin: all | others: own estate)
    POST /api/estates/   → create (superadmin only)
    """
    if request.method == "GET":
        if request.user.role == "SUPERADMIN":
            qs = Estate.objects.filter(is_deleted=False)
        else:
            qs = Estate.objects.filter(id=request.user.estate_id, is_deleted=False)
        data = [{
            "id": str(e.id), "name": e.name, "code": e.code,
            "city": e.city, "country": e.country,
            "is_active": e.is_active, "contact_phone": e.contact_phone,
            "contact_email": e.contact_email,
            "logo": e.logo.url if e.logo else None,
            "created_at": e.created_at,
        } for e in qs]
        return ok(data)

    if request.user.role != "SUPERADMIN":
        return err("Only superadmin can create estates.", status_code=status.HTTP_403_FORBIDDEN)
    required = ["name", "code", "address", "city", "state"]
    for f in required:
        if not request.data.get(f):
            return err(f"Field '{f}' is required.")
    if Estate.objects.filter(code=request.data["code"]).exists():
        return err("Estate code already exists.")
    estate = Estate.objects.create(
        name=request.data["name"], code=request.data["code"].upper(),
        address=request.data["address"], city=request.data["city"],
        state=request.data["state"],
        country=request.data.get("country", "Kenya"),
        contact_phone=request.data.get("contact_phone", ""),
        contact_email=request.data.get("contact_email", ""),
        website=request.data.get("website", ""),
        timezone=request.data.get("timezone", "Africa/Nairobi"),
    )
    log_action(request.user, "CREATE", "Estate", estate.id, f"Estate '{estate.name}' created", request)
    return ok(_estate_dict(estate), message="Estate created.", status_code=status.HTTP_201_CREATED)


@api_view(["GET", "PUT", "PATCH", "DELETE"])
@permission_classes([IsAuthenticated])
def estate_detail(request, estate_id):
    """GET/PUT/PATCH/DELETE /api/estates/<id>/"""
    estate = get_object_or_404(Estate, id=estate_id, is_deleted=False)
    if not same_estate(request.user, estate):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)

    if request.method == "GET":
        blocks = [{
            "id": str(b.id), "name": b.name, "code": b.code,
            "floors": b.floors, "unit_count": b.units.count(),
        } for b in estate.blocks.filter(is_active=True)]
        return ok({
            "id": str(estate.id), "name": estate.name, "code": estate.code,
            "address": estate.address, "city": estate.city, "state": estate.state,
            "country": estate.country, "timezone": estate.timezone,
            "contact_phone": estate.contact_phone, "contact_email": estate.contact_email,
            "website": estate.website, "is_active": estate.is_active,
            "logo": estate.logo.url if estate.logo else None,
            "settings": estate.settings, "blocks": blocks,
            "created_at": estate.created_at,
        })

    if request.method in ("PUT", "PATCH"):
        if not is_admin(request.user):
            return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
        fields = ["name", "address", "city", "state", "country", "contact_phone",
                  "contact_email", "website", "timezone", "is_active", "settings"]
        for f in fields:
            if f in request.data:
                setattr(estate, f, request.data[f])
        estate.save()
        log_action(request.user, "UPDATE", "Estate", estate.id, "Estate updated", request)
        return ok(message="Estate updated.")

    if not request.user.role == "SUPERADMIN":
        return err("Only superadmin can delete estates.", status_code=status.HTTP_403_FORBIDDEN)
    estate.is_deleted = True
    estate.deleted_at = timezone.now()
    estate.save()
    return ok(message="Estate deleted.")


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def estate_stats(request, estate_id):
    """GET /api/estates/<id>/stats/ — dashboard overview numbers."""
    estate = get_object_or_404(Estate, id=estate_id)
    if not same_estate(request.user, estate):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    today = timezone.now().date()
    now = timezone.now()
    return ok({
        "total_units": Unit.objects.filter(block__estate=estate).count(),
        "occupied_units": Unit.objects.filter(block__estate=estate, is_occupied=True).count(),
        "total_residents": User.objects.filter(estate=estate, role__in=["RESIDENT", "TENANT"]).count(),
        "total_staff": User.objects.filter(estate=estate, role="SECURITY").count(),
        "active_visits": Visit.objects.filter(estate=estate, status="CHECKED_IN").count(),
        "visits_today": Visit.objects.filter(estate=estate, actual_check_in__date=today).count(),
        "pending_visits": Visit.objects.filter(estate=estate, status="PENDING").count(),
        "pending_deliveries": Delivery.objects.filter(estate=estate, status__in=["ARRIVED", "NOTIFIED"]).count(),
        "open_incidents": Incident.objects.filter(estate=estate, status__in=["OPEN", "INVESTIGATING"]).count(),
        "blacklisted_persons": Blacklist.objects.filter(estate=estate, is_active=True).count(),
        "devices_online": AccessDevice.objects.filter(estate=estate, status="ONLINE").count(),
        "devices_total": AccessDevice.objects.filter(estate=estate).count(),
        "active_emergency": EmergencyAlert.objects.filter(estate=estate, status="ACTIVE").exists(),
    })


# =============================================================================
# 5. BLOCKS
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def block_list_create(request):
    """GET /api/blocks/?estate=<id> | POST /api/blocks/"""
    if request.method == "GET":
        estate_id = request.GET.get("estate")
        qs = Block.objects.select_related("estate")
        if request.user.role != "SUPERADMIN":
            qs = qs.filter(estate=request.user.estate)
        elif estate_id:
            qs = qs.filter(estate_id=estate_id)
        data = [{
            "id": str(b.id), "name": b.name, "code": b.code,
            "estate": _estate_dict(b.estate), "floors": b.floors,
            "is_active": b.is_active, "description": b.description,
            "unit_count": b.units.filter(is_active=True).count(),
        } for b in qs]
        return ok(data)

    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    estate = get_object_or_404(Estate, id=request.data.get("estate_id"))
    block = Block.objects.create(
        estate=estate,
        name=request.data.get("name"),
        code=request.data.get("code", "").upper(),
        floors=request.data.get("floors", 1),
        description=request.data.get("description", ""),
    )
    return ok({"id": str(block.id), "name": block.name}, message="Block created.", status_code=status.HTTP_201_CREATED)


@api_view(["GET", "PATCH", "DELETE"])
@permission_classes([IsAuthenticated])
def block_detail(request, block_id):
    """GET/PATCH/DELETE /api/blocks/<id>/"""
    block = get_object_or_404(Block, id=block_id)
    if request.method == "GET":
        units = [{
            "id": str(u.id), "unit_number": u.unit_number,
            "floor": u.floor, "unit_type": u.unit_type, "is_occupied": u.is_occupied,
        } for u in block.units.filter(is_active=True).order_by("floor", "unit_number")]
        return ok({
            "id": str(block.id), "name": block.name, "code": block.code,
            "estate": _estate_dict(block.estate), "floors": block.floors,
            "is_active": block.is_active, "description": block.description,
            "units": units,
        })
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    if request.method == "PATCH":
        for f in ["name", "code", "floors", "description", "is_active"]:
            if f in request.data:
                setattr(block, f, request.data[f])
        block.save()
        return ok(message="Block updated.")
    block.is_active = False
    block.save()
    return ok(message="Block deactivated.")


# =============================================================================
# 6. UNITS
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def unit_list_create(request):
    """
    GET  /api/units/?block=&estate=&is_occupied=&unit_type=&search=
    POST /api/units/
    """
    if request.method == "GET":
        qs = Unit.objects.select_related("block__estate").filter(is_active=True)
        if request.user.role != "SUPERADMIN":
            qs = qs.filter(block__estate=request.user.estate)

        block_id = request.GET.get("block")
        estate_id = request.GET.get("estate")
        is_occupied = request.GET.get("is_occupied")
        unit_type = request.GET.get("unit_type")
        search = request.GET.get("search")

        if block_id:
            qs = qs.filter(block_id=block_id)
        if estate_id:
            qs = qs.filter(block__estate_id=estate_id)
        if is_occupied is not None:
            qs = qs.filter(is_occupied=is_occupied.lower() == "true")
        if unit_type:
            qs = qs.filter(unit_type=unit_type)
        if search:
            qs = qs.filter(unit_number__icontains=search)

        data = [_unit_dict(u) for u in qs.order_by("block", "floor", "unit_number")]
        return ok(data)

    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    block = get_object_or_404(Block, id=request.data.get("block_id"))
    unit = Unit.objects.create(
        block=block,
        unit_number=request.data.get("unit_number"),
        floor=request.data.get("floor", 0),
        unit_type=request.data.get("unit_type", "APARTMENT"),
        bedrooms=request.data.get("bedrooms"),
        size_sqm=request.data.get("size_sqm"),
        notes=request.data.get("notes", ""),
    )
    return ok(_unit_dict(unit), message="Unit created.", status_code=status.HTTP_201_CREATED)


@api_view(["GET", "PATCH", "DELETE"])
@permission_classes([IsAuthenticated])
def unit_detail(request, unit_id):
    """GET/PATCH/DELETE /api/units/<id>/"""
    unit = get_object_or_404(Unit, id=unit_id, is_active=True)
    if request.method == "GET":
        residents = [{
            "id": str(r.id),
            "full_name": r.user.get_full_name(),
            "phone": r.user.phone,
            "is_owner": r.is_owner,
            "move_in_date": r.move_in_date,
        } for r in unit.residents.filter(is_active=True)]
        active_visits = [_visit_dict(v) for v in unit.visits.filter(status="CHECKED_IN")]
        return ok({
            **_unit_dict(unit),
            "bedrooms": unit.bedrooms,
            "size_sqm": str(unit.size_sqm) if unit.size_sqm else None,
            "notes": unit.notes,
            "residents": residents,
            "active_visits": active_visits,
            "created_at": unit.created_at,
        })
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    if request.method == "PATCH":
        for f in ["unit_number", "floor", "unit_type", "bedrooms", "size_sqm",
                  "is_occupied", "notes", "is_active"]:
            if f in request.data:
                setattr(unit, f, request.data[f])
        unit.save()
        return ok(message="Unit updated.")
    unit.is_active = False
    unit.save()
    return ok(message="Unit deactivated.")


# =============================================================================
# 7. VISITOR
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def visitor_list_create(request):
    """
    GET  /api/visitors/?search=&is_flagged=&id_verified=
    POST /api/visitors/   → register a new visitor
    """
    if request.method == "GET":
        if not (is_admin(request.user) or is_security(request.user)):
            return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
        qs = Visitor.objects.filter(is_deleted=False)
        search = request.GET.get("search")
        is_flagged = request.GET.get("is_flagged")
        id_verified = request.GET.get("id_verified")
        phone = request.GET.get("phone")
        id_number = request.GET.get("id_number")

        if search:
            qs = qs.filter(
                Q(first_name__icontains=search) | Q(last_name__icontains=search) |
                Q(phone__icontains=search) | Q(email__icontains=search) |
                Q(company__icontains=search) | Q(id_number__icontains=search)
            )
        if is_flagged is not None:
            qs = qs.filter(is_flagged=is_flagged.lower() == "true")
        if id_verified is not None:
            qs = qs.filter(id_verified=id_verified.lower() == "true")
        if phone:
            qs = qs.filter(phone__icontains=phone)
        if id_number:
            qs = qs.filter(id_number__icontains=id_number)

        return ok([_visitor_dict(v) for v in qs.order_by("last_name", "first_name")])

    # POST – create visitor (security staff or admin)
    required = ["first_name", "last_name", "phone"]
    for f in required:
        if not request.data.get(f):
            return err(f"Field '{f}' is required.")

    # Check blacklist before creating
    phone = request.data.get("phone")
    id_number = request.data.get("id_number", "")
    blacklisted = Blacklist.objects.filter(
        Q(phone=phone) | Q(id_number=id_number) if id_number else Q(phone=phone),
        estate=request.user.estate, is_active=True
    ).first()
    if blacklisted and blacklisted.severity in ("HIGH", "CRITICAL"):
        return err("This person is blacklisted and cannot be registered.",
                   details={"severity": blacklisted.severity, "reason": blacklisted.reason},
                   status_code=status.HTTP_403_FORBIDDEN)

    visitor = Visitor.objects.create(
        first_name=request.data["first_name"],
        last_name=request.data["last_name"],
        phone=phone,
        email=request.data.get("email", ""),
        gender=request.data.get("gender", ""),
        id_type=request.data.get("id_type", ""),
        id_number=id_number,
        company=request.data.get("company", ""),
        nationality=request.data.get("nationality", ""),
        data_consent_given=request.data.get("data_consent_given", False),
        data_consent_at=timezone.now() if request.data.get("data_consent_given") else None,
    )
    log_action(request.user, "CREATE", "Visitor", visitor.id,
               f"Visitor {visitor} registered", request)
    return ok(_visitor_dict(visitor), message="Visitor registered.", status_code=status.HTTP_201_CREATED)


@api_view(["GET", "PATCH", "DELETE"])
@permission_classes([IsAuthenticated])
def visitor_detail(request, visitor_id):
    """GET/PATCH/DELETE /api/visitors/<id>/"""
    visitor = get_object_or_404(Visitor, id=visitor_id, is_deleted=False)

    if request.method == "GET":
        recent = [_visit_dict(v) for v in visitor.visits.order_by("-created_at")[:10]]
        return ok({
            **_visitor_dict(visitor),
            "id_scan_front": visitor.id_scan_front.url if visitor.id_scan_front else None,
            "id_scan_back": visitor.id_scan_back.url if visitor.id_scan_back else None,
            "id_verified_at": visitor.id_verified_at,
            "id_verified_by": _user_dict(visitor.id_verified_by),
            "flag_reason": visitor.flag_reason,
            "data_consent_at": visitor.data_consent_at,
            "nda_signed": visitor.nda_signed,
            "recent_visits": recent,
            "total_visits": visitor.visits.count(),
            "created_at": visitor.created_at,
        })

    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)

    if request.method == "PATCH":
        for f in ["first_name", "last_name", "phone", "email", "gender",
                  "id_type", "id_number", "company", "nationality",
                  "is_flagged", "flag_reason", "data_consent_given", "nda_signed"]:
            if f in request.data:
                setattr(visitor, f, request.data[f])
        visitor.save()
        log_action(request.user, "UPDATE", "Visitor", visitor.id, "Visitor updated", request)
        return ok(_visitor_dict(visitor), message="Visitor updated.")

    # DELETE → soft delete
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    visitor.delete()
    return ok(message="Visitor deleted.")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verify_visitor_id(request, visitor_id):
    """POST /api/visitors/<id>/verify-id/ — mark ID as verified."""
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    visitor = get_object_or_404(Visitor, id=visitor_id)
    visitor.id_verified = True
    visitor.id_verified_at = timezone.now()
    visitor.id_verified_by = request.user
    visitor.save()
    return ok(message="Visitor ID verified.")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def flag_visitor(request, visitor_id):
    """POST /api/visitors/<id>/flag/ — flag/unflag a visitor."""
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    visitor = get_object_or_404(Visitor, id=visitor_id)
    visitor.is_flagged = not visitor.is_flagged
    visitor.flag_reason = request.data.get("reason", "")
    visitor.save()
    action = "flagged" if visitor.is_flagged else "unflagged"
    log_action(request.user, "UPDATE", "Visitor", visitor.id, f"Visitor {action}", request)
    return ok({"is_flagged": visitor.is_flagged}, message=f"Visitor {action}.")


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def visitor_visit_history(request, visitor_id):
    """GET /api/visitors/<id>/visits/ — full visit history for a visitor."""
    visitor = get_object_or_404(Visitor, id=visitor_id)
    qs = visitor.visits.order_by("-created_at")
    status_filter = request.GET.get("status")
    if status_filter:
        qs = qs.filter(status=status_filter)
    return ok([_visit_dict(v) for v in qs])


# =============================================================================
# 8. VISITS  (Core Transaction)
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def visit_list_create(request):
    """
    GET  /api/visits/?status=&estate=&date=&gate=&purpose=&search=
    POST /api/visits/    → create / walk-in visit
    """
    if request.method == "GET":
        qs = Visit.objects.select_related(
            "visitor", "host", "unit__block__estate", "estate", "check_in_gate"
        ).filter(is_deleted=False)

        if request.user.role != "SUPERADMIN":
            qs = qs.filter(estate=request.user.estate)

        # If resident, show only their hosted visits
        if is_resident(request.user):
            qs = qs.filter(host=request.user)

        # Filters
        visit_status = request.GET.get("status")
        date = request.GET.get("date")
        gate_id = request.GET.get("gate")
        purpose = request.GET.get("purpose")
        search = request.GET.get("search")
        unit_id = request.GET.get("unit")
        host_id = request.GET.get("host")
        today_only = request.GET.get("today")

        if visit_status:
            qs = qs.filter(status=visit_status)
        if date:
            qs = qs.filter(actual_check_in__date=date)
        if today_only == "true":
            qs = qs.filter(actual_check_in__date=timezone.now().date())
        if gate_id:
            qs = qs.filter(check_in_gate_id=gate_id)
        if purpose:
            qs = qs.filter(purpose=purpose)
        if unit_id:
            qs = qs.filter(unit_id=unit_id)
        if host_id:
            qs = qs.filter(host_id=host_id)
        if search:
            qs = qs.filter(
                Q(visitor__first_name__icontains=search) |
                Q(visitor__last_name__icontains=search) |
                Q(visitor__phone__icontains=search) |
                Q(unit__unit_number__icontains=search)
            )

        return ok([_visit_dict(v) for v in qs.order_by("-created_at")])

    # POST — create a new walk-in visit
    required = ["visitor_id", "unit_id", "purpose"]
    for f in required:
        if not request.data.get(f):
            return err(f"Field '{f}' is required.")

    visitor = get_object_or_404(Visitor, id=request.data["visitor_id"], is_deleted=False)
    unit = get_object_or_404(Unit, id=request.data["unit_id"])

    # Blacklist check
    blacklisted = Blacklist.objects.filter(
        Q(visitor=visitor) | Q(phone=visitor.phone),
        estate=unit.block.estate, is_active=True
    ).first()
    if blacklisted and blacklisted.severity in ("HIGH", "CRITICAL"):
        log_action(request.user, "DENY", "Visit", "N/A",
                   f"Blacklisted visitor {visitor} denied entry", request)
        return err("Visitor is blacklisted.", details={"severity": blacklisted.severity},
                   status_code=status.HTTP_403_FORBIDDEN)

    # Watchlist check — log but allow
    watchlisted = Watchlist.objects.filter(
        Q(visitor=visitor) | Q(phone=visitor.phone),
        estate=unit.block.estate, is_active=True
    ).first()

    host = None
    if request.data.get("host_id"):
        host = get_object_or_404(User, id=request.data["host_id"])

    visit = Visit.objects.create(
        visitor=visitor, host=host, unit=unit, estate=unit.block.estate,
        purpose=request.data["purpose"],
        purpose_detail=request.data.get("purpose_detail", ""),
        expected_arrival=request.data.get("expected_arrival"),
        expected_departure=request.data.get("expected_departure"),
        number_of_visitors=request.data.get("number_of_visitors", 1),
        notes=request.data.get("notes", ""),
        check_in_method=request.data.get("check_in_method", "MANUAL"),
        status="PENDING",
    )
    log_action(request.user, "CREATE", "Visit", visit.id,
               f"Visit created for {visitor} to {unit}", request)

    response_data = _visit_dict(visit, detail=True)
    if watchlisted:
        response_data["watchlist_alert"] = watchlisted.alert_message

    return ok(response_data, message="Visit created.", status_code=status.HTTP_201_CREATED)


@api_view(["GET", "PATCH", "DELETE"])
@permission_classes([IsAuthenticated])
def visit_detail(request, visit_id):
    """GET/PATCH/DELETE /api/visits/<id>/"""
    visit = get_object_or_404(Visit, id=visit_id, is_deleted=False)

    if request.method == "GET":
        data = _visit_dict(visit, detail=True)
        # Attach badge if exists
        if hasattr(visit, "badge"):
            data["badge"] = {
                "badge_number": visit.badge.badge_number,
                "badge_type": visit.badge.badge_type,
                "is_returned": visit.badge.is_returned,
                "color_code": visit.badge.color_code,
            }
        # Attach vehicle if exists
        if hasattr(visit, "vehicle"):
            data["vehicle"] = {
                "license_plate": visit.vehicle.license_plate,
                "vehicle_type": visit.vehicle.vehicle_type,
                "make": visit.vehicle.make, "color": visit.vehicle.color,
            }
        return ok(data)

    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)

    if request.method == "PATCH":
        for f in ["purpose", "purpose_detail", "notes", "expected_departure",
                  "number_of_visitors", "check_in_method"]:
            if f in request.data:
                setattr(visit, f, request.data[f])
        visit.save()
        return ok(message="Visit updated.")

    # Soft delete
    visit.delete()
    log_action(request.user, "DELETE", "Visit", visit.id, "Visit deleted", request)
    return ok(message="Visit deleted.")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def visit_approve(request, visit_id):
    """
    POST /api/visits/<id>/approve/
    Body: {} (empty is fine)
    Host or admin approves a pending visit.
    """
    visit = get_object_or_404(Visit, id=visit_id)
    if visit.status != "PENDING":
        return err(f"Cannot approve a visit with status '{visit.status}'.")

    # Only host or admin can approve
    if not (is_admin(request.user) or is_security(request.user) or
            request.user == visit.host):
        return err("Only the host or an admin can approve this visit.",
                   status_code=status.HTTP_403_FORBIDDEN)

    visit.status = "APPROVED"
    visit.approved_by = request.user
    visit.approved_at = timezone.now()
    visit.save()
    log_action(request.user, "APPROVE", "Visit", visit.id, "Visit approved", request)
    return ok(_visit_dict(visit), message="Visit approved.")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def visit_deny(request, visit_id):
    """
    POST /api/visits/<id>/deny/
    Body: { "reason": "..." }
    """
    visit = get_object_or_404(Visit, id=visit_id)
    if visit.status not in ("PENDING", "APPROVED"):
        return err(f"Cannot deny a visit with status '{visit.status}'.")
    visit.status = "DENIED"
    visit.denial_reason = request.data.get("reason", "No reason provided.")
    visit.save()
    log_action(request.user, "DENY", "Visit", visit.id,
               f"Visit denied: {visit.denial_reason}", request)
    return ok(message="Visit denied.")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def visit_checkin(request, visit_id):
    """
    POST /api/visits/<id>/checkin/
    Body: { "gate_id", "method", "check_in_photo" (optional) }
    Security checks-in a visitor at the gate.
    """
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Only security staff can perform check-in.",
                   status_code=status.HTTP_403_FORBIDDEN)

    visit = get_object_or_404(Visit, id=visit_id)

    if visit.status not in ("APPROVED", "PENDING"):
        return err(f"Cannot check in a visit with status '{visit.status}'.")

    gate = None
    if request.data.get("gate_id"):
        gate = get_object_or_404(Gate, id=request.data["gate_id"])

    visit.status = "CHECKED_IN"
    visit.actual_check_in = timezone.now()
    visit.check_in_gate = gate
    visit.checked_in_by = request.user
    visit.check_in_method = request.data.get("method", "MANUAL")
    if "check_in_photo" in request.FILES:
        visit.check_in_photo = request.FILES["check_in_photo"]
    visit.save()

    # Log access event
    AccessEvent.objects.create(
        device=gate.devices.filter(is_active=True).first() if gate else None,
        gate=gate, visit=visit, visitor=visit.visitor,
        event_type="GRANTED", direction="IN",
        event_time=visit.actual_check_in,
    ) if gate else None

    log_action(request.user, "CHECKIN", "Visit", visit.id,
               f"Visitor {visit.visitor} checked in at {gate}", request)
    return ok(_visit_dict(visit, detail=True), message="Visitor checked in.")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def visit_checkout(request, visit_id):
    """
    POST /api/visits/<id>/checkout/
    Body: { "gate_id" (optional), "method" (optional) }
    """
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Only security staff can perform check-out.",
                   status_code=status.HTTP_403_FORBIDDEN)

    visit = get_object_or_404(Visit, id=visit_id)
    if visit.status != "CHECKED_IN":
        return err(f"Cannot check out a visit with status '{visit.status}'.")

    gate = None
    if request.data.get("gate_id"):
        gate = get_object_or_404(Gate, id=request.data["gate_id"])

    visit.status = "CHECKED_OUT"
    visit.actual_check_out = timezone.now()
    visit.check_out_gate = gate
    visit.checked_out_by = request.user
    visit.check_out_method = request.data.get("method", "MANUAL")
    if "check_out_photo" in request.FILES:
        visit.check_out_photo = request.FILES["check_out_photo"]
    visit.save()

    AccessEvent.objects.create(
        gate=gate, visit=visit, visitor=visit.visitor,
        event_type="GRANTED", direction="OUT",
        event_time=visit.actual_check_out,
    ) if gate else None

    log_action(request.user, "CHECKOUT", "Visit", visit.id,
               f"Visitor {visit.visitor} checked out", request)
    return ok(_visit_dict(visit, detail=True), message="Visitor checked out.")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def visit_cancel(request, visit_id):
    """POST /api/visits/<id>/cancel/"""
    visit = get_object_or_404(Visit, id=visit_id)
    if visit.status in ("CHECKED_OUT", "CANCELLED"):
        return err("Visit is already closed.")
    if not (is_admin(request.user) or request.user == visit.host):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    visit.status = "CANCELLED"
    visit.save()
    return ok(message="Visit cancelled.")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def qr_checkin(request):
    """
    POST /api/visits/qr-checkin/
    Body: { "token": "<qr_code_token>", "gate_id" }
    Self-service QR check-in at kiosk or gate scanner.
    """
    token = request.data.get("token", "").strip()
    if not token:
        return err("QR token required.")

    pre_reg = PreRegistration.objects.filter(
        qr_code_token=token, status="PENDING"
    ).first()
    if not pre_reg:
        return err("Invalid or expired QR code.", status_code=status.HTTP_404_NOT_FOUND)

    if timezone.now() > pre_reg.expected_arrival + timedelta(hours=2):
        pre_reg.status = "EXPIRED"
        pre_reg.save()
        return err("QR code has expired.")

    # Create or find visitor
    visitor = pre_reg.visitor
    if not visitor:
        visitor, _ = Visitor.objects.get_or_create(
            phone=pre_reg.visitor_phone,
            defaults={
                "first_name": pre_reg.visitor_name.split()[0],
                "last_name": " ".join(pre_reg.visitor_name.split()[1:]) or ".",
                "email": pre_reg.visitor_email,
            }
        )
        pre_reg.visitor = visitor
        pre_reg.save(update_fields=["visitor"])

    gate = None
    if request.data.get("gate_id"):
        gate = get_object_or_404(Gate, id=request.data["gate_id"])

    # Create visit
    visit = Visit.objects.create(
        visitor=visitor, host=pre_reg.host,
        unit=pre_reg.unit, estate=pre_reg.estate,
        purpose=pre_reg.purpose,
        pre_registration=pre_reg,
        status="CHECKED_IN",
        actual_check_in=timezone.now(),
        check_in_gate=gate,
        check_in_method="QR_CODE",
    )

    # Update pre_reg use count
    pre_reg.use_count += 1
    if not pre_reg.allow_multiple_uses or pre_reg.use_count >= pre_reg.max_uses:
        pre_reg.status = "USED"
    pre_reg.save()

    return ok(_visit_dict(visit, detail=True), message="QR check-in successful.")


@api_view(["POST"])
@permission_classes([AllowAny])
def otp_checkin(request):
    """
    POST /api/visits/otp-checkin/
    Body: { "otp_code": "123456", "phone": "0712..." }
    Kiosk or gate: visitor enters OTP to check in.
    """
    otp = request.data.get("otp_code", "").strip()
    phone = request.data.get("phone", "").strip()
    if not otp or not phone:
        return err("otp_code and phone are required.")

    pre_reg = PreRegistration.objects.filter(
        otp_code=otp, visitor_phone=phone, status="PENDING"
    ).first()
    if not pre_reg:
        return err("Invalid OTP or phone number.", status_code=status.HTTP_404_NOT_FOUND)
    if pre_reg.otp_expires_at and timezone.now() > pre_reg.otp_expires_at:
        return err("OTP has expired. Please request a new one.")

    visitor, _ = Visitor.objects.get_or_create(
        phone=phone,
        defaults={
            "first_name": pre_reg.visitor_name.split()[0],
            "last_name": " ".join(pre_reg.visitor_name.split()[1:]) or ".",
            "email": pre_reg.visitor_email,
        }
    )

    visit = Visit.objects.create(
        visitor=visitor, host=pre_reg.host,
        unit=pre_reg.unit, estate=pre_reg.estate,
        purpose=pre_reg.purpose, pre_registration=pre_reg,
        status="CHECKED_IN", actual_check_in=timezone.now(),
        check_in_method="OTP",
    )
    pre_reg.use_count += 1
    pre_reg.status = "USED"
    pre_reg.save()
    return ok(_visit_dict(visit), message="OTP check-in successful.")


# =============================================================================
# 9. PRE-REGISTRATION
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def pre_registration_list_create(request):
    """
    GET  /api/pre-registrations/?status=&date=
    POST /api/pre-registrations/   → resident pre-registers a visitor
    """
    if request.method == "GET":
        if is_resident(request.user):
            qs = PreRegistration.objects.filter(host=request.user, is_deleted=False)
        elif is_admin(request.user) or is_security(request.user):
            qs = PreRegistration.objects.filter(
                estate=request.user.estate, is_deleted=False
            )
        else:
            return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)

        status_filter = request.GET.get("status")
        date = request.GET.get("date")
        if status_filter:
            qs = qs.filter(status=status_filter)
        if date:
            qs = qs.filter(expected_arrival__date=date)

        data = [{
            "id": str(p.id), "visitor_name": p.visitor_name,
            "visitor_phone": p.visitor_phone, "visitor_email": p.visitor_email,
            "unit": _unit_dict(p.unit), "purpose": p.purpose,
            "expected_arrival": p.expected_arrival,
            "expected_departure": p.expected_departure,
            "status": p.status, "qr_code_token": p.qr_code_token,
            "otp_code": p.otp_code, "use_count": p.use_count,
            "max_uses": p.max_uses, "allow_multiple_uses": p.allow_multiple_uses,
            "created_at": p.created_at,
        } for p in qs.order_by("-expected_arrival")]
        return ok(data)

    # POST
    required = ["visitor_name", "visitor_phone", "unit_id", "expected_arrival", "purpose"]
    for f in required:
        if not request.data.get(f):
            return err(f"Field '{f}' is required.")

    unit = get_object_or_404(Unit, id=request.data["unit_id"])

    # Resident can only pre-register for their own unit
    if is_resident(request.user):
        try:
            profile = request.user.resident_profile
            if profile.unit != unit:
                return err("You can only pre-register visitors for your own unit.")
        except ResidentProfile.DoesNotExist:
            return err("No resident profile found for your account.")

    # Generate QR token and OTP
    qr_token = gen_token()
    otp = gen_otp()
    otp_expiry = timezone.now() + timedelta(hours=24)

    host = request.user if is_resident(request.user) else \
        User.objects.filter(id=request.data.get("host_id")).first() or request.user

    pre_reg = PreRegistration.objects.create(
        host=host, unit=unit, estate=unit.block.estate,
        visitor_name=request.data["visitor_name"],
        visitor_phone=request.data["visitor_phone"],
        visitor_email=request.data.get("visitor_email", ""),
        purpose=request.data["purpose"],
        expected_arrival=request.data["expected_arrival"],
        expected_departure=request.data.get("expected_departure"),
        qr_code_token=qr_token,
        otp_code=otp,
        otp_expires_at=otp_expiry,
        allow_multiple_uses=request.data.get("allow_multiple_uses", False),
        max_uses=request.data.get("max_uses", 1),
        notes=request.data.get("notes", ""),
    )
    log_action(request.user, "CREATE", "PreRegistration", pre_reg.id,
               f"Pre-reg created for {pre_reg.visitor_name}", request)
    return ok({
        "id": str(pre_reg.id),
        "qr_code_token": qr_token,
        "otp_code": otp,
        "otp_expires_at": otp_expiry,
        "visitor_name": pre_reg.visitor_name,
        "expected_arrival": pre_reg.expected_arrival,
    }, message="Pre-registration created.", status_code=status.HTTP_201_CREATED)


@api_view(["GET", "PATCH", "DELETE"])
@permission_classes([IsAuthenticated])
def pre_registration_detail(request, prereg_id):
    """GET/PATCH/DELETE /api/pre-registrations/<id>/"""
    pre_reg = get_object_or_404(PreRegistration, id=prereg_id, is_deleted=False)

    if not (is_admin(request.user) or is_security(request.user) or
            request.user == pre_reg.host):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)

    if request.method == "GET":
        return ok({
            "id": str(pre_reg.id),
            "host": _user_dict(pre_reg.host),
            "unit": _unit_dict(pre_reg.unit),
            "visitor_name": pre_reg.visitor_name,
            "visitor_phone": pre_reg.visitor_phone,
            "visitor_email": pre_reg.visitor_email,
            "purpose": pre_reg.purpose,
            "expected_arrival": pre_reg.expected_arrival,
            "expected_departure": pre_reg.expected_departure,
            "status": pre_reg.status,
            "qr_code_token": pre_reg.qr_code_token,
            "otp_code": pre_reg.otp_code,
            "otp_expires_at": pre_reg.otp_expires_at,
            "use_count": pre_reg.use_count,
            "max_uses": pre_reg.max_uses,
            "notes": pre_reg.notes,
            "created_at": pre_reg.created_at,
        })

    if request.method == "PATCH":
        for f in ["visitor_name", "visitor_phone", "visitor_email",
                  "expected_arrival", "expected_departure", "notes",
                  "allow_multiple_uses", "max_uses"]:
            if f in request.data:
                setattr(pre_reg, f, request.data[f])
        pre_reg.save()
        return ok(message="Pre-registration updated.")

    pre_reg.status = "CANCELLED"
    pre_reg.save()
    return ok(message="Pre-registration cancelled.")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def regenerate_otp(request, prereg_id):
    """POST /api/pre-registrations/<id>/regenerate-otp/ — send fresh OTP."""
    pre_reg = get_object_or_404(PreRegistration, id=prereg_id)
    if request.user != pre_reg.host and not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    pre_reg.otp_code = gen_otp()
    pre_reg.otp_expires_at = timezone.now() + timedelta(hours=24)
    pre_reg.status = "PENDING"
    pre_reg.save()
    return ok({"otp_code": pre_reg.otp_code, "expires_at": pre_reg.otp_expires_at},
              message="New OTP generated.")


# =============================================================================
# 10. ZONES
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def zone_list_create(request):
    """GET /api/zones/?estate= | POST /api/zones/"""
    if request.method == "GET":
        qs = Zone.objects.all()
        if request.user.role != "SUPERADMIN":
            qs = qs.filter(estate=request.user.estate)
        data = [{
            "id": str(z.id), "name": z.name,
            "estate": _estate_dict(z.estate),
            "minimum_access_level": z.minimum_access_level,
            "is_active": z.is_active, "description": z.description,
        } for z in qs]
        return ok(data)
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    estate = get_object_or_404(Estate, id=request.data.get("estate_id", str(request.user.estate_id)))
    zone = Zone.objects.create(
        estate=estate, name=request.data.get("name"),
        description=request.data.get("description", ""),
        minimum_access_level=request.data.get("minimum_access_level", 3),
    )
    return ok({"id": str(zone.id), "name": zone.name}, message="Zone created.", status_code=status.HTTP_201_CREATED)


@api_view(["GET", "PATCH", "DELETE"])
@permission_classes([IsAuthenticated])
def zone_detail(request, zone_id):
    """GET/PATCH/DELETE /api/zones/<id>/"""
    zone = get_object_or_404(Zone, id=zone_id)
    if request.method == "GET":
        return ok({
            "id": str(zone.id), "name": zone.name,
            "estate": _estate_dict(zone.estate),
            "minimum_access_level": zone.minimum_access_level,
            "is_active": zone.is_active, "description": zone.description,
            "gates": [{"id": str(g.id), "name": g.name} for g in zone.gate_set.all()],
        })
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    if request.method == "PATCH":
        for f in ["name", "description", "minimum_access_level", "is_active"]:
            if f in request.data:
                setattr(zone, f, request.data[f])
        zone.save()
        return ok(message="Zone updated.")
    zone.is_active = False
    zone.save()
    return ok(message="Zone deactivated.")


# =============================================================================
# 11. GATES
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def gate_list_create(request):
    """GET /api/gates/?estate= | POST /api/gates/"""
    if request.method == "GET":
        qs = Gate.objects.select_related("estate", "zone")
        if request.user.role != "SUPERADMIN":
            qs = qs.filter(estate=request.user.estate)
        if request.GET.get("is_active"):
            qs = qs.filter(is_active=request.GET["is_active"].lower() == "true")
        data = [{
            "id": str(g.id), "name": g.name, "gate_type": g.gate_type,
            "estate": _estate_dict(g.estate),
            "zone": {"id": str(g.zone.id), "name": g.zone.name} if g.zone else None,
            "is_active": g.is_active, "is_open": g.is_open,
            "is_24h": g.is_24h, "requires_escort": g.requires_escort,
            "device_count": g.devices.filter(is_active=True).count(),
        } for g in qs]
        return ok(data)

    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    estate = get_object_or_404(Estate, id=request.data.get("estate_id", str(request.user.estate_id)))
    zone = Zone.objects.filter(id=request.data.get("zone_id")).first()
    gate = Gate.objects.create(
        estate=estate, zone=zone,
        name=request.data.get("name"),
        gate_type=request.data.get("gate_type", "MAIN_ENTRY"),
        is_24h=request.data.get("is_24h", True),
        requires_escort=request.data.get("requires_escort", False),
        notes=request.data.get("notes", ""),
    )
    return ok({"id": str(gate.id), "name": gate.name}, message="Gate created.", status_code=status.HTTP_201_CREATED)


@api_view(["GET", "PATCH"])
@permission_classes([IsAuthenticated])
def gate_detail(request, gate_id):
    """GET/PATCH /api/gates/<id>/"""
    gate = get_object_or_404(Gate, id=gate_id)
    if request.method == "GET":
        return ok({
            "id": str(gate.id), "name": gate.name, "gate_type": gate.gate_type,
            "estate": _estate_dict(gate.estate), "is_active": gate.is_active,
            "is_open": gate.is_open, "is_24h": gate.is_24h,
            "requires_escort": gate.requires_escort,
            "operating_hours_start": gate.operating_hours_start,
            "operating_hours_end": gate.operating_hours_end,
            "latitude": str(gate.latitude) if gate.latitude else None,
            "longitude": str(gate.longitude) if gate.longitude else None,
            "notes": gate.notes,
            "devices": [{
                "id": str(d.id), "name": d.name, "device_type": d.device_type,
                "status": d.status,
            } for d in gate.devices.filter(is_active=True)],
            "assigned_staff": [{
                "id": str(s.user.id), "name": s.user.get_full_name(),
                "badge": s.badge_number, "shift": s.shift,
            } for s in gate.assigned_staff.all()],
        })
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    for f in ["name", "gate_type", "is_active", "is_open", "is_24h",
              "requires_escort", "operating_hours_start", "operating_hours_end", "notes"]:
        if f in request.data:
            setattr(gate, f, request.data[f])
    gate.save()
    return ok(message="Gate updated.")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def gate_toggle(request, gate_id):
    """POST /api/gates/<id>/toggle/ — open or close a gate remotely."""
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    gate = get_object_or_404(Gate, id=gate_id)
    gate.is_open = not gate.is_open
    gate.save(update_fields=["is_open"])
    state = "opened" if gate.is_open else "closed"
    log_action(request.user, "UPDATE", "Gate", gate.id, f"Gate {state}", request)
    return ok({"is_open": gate.is_open}, message=f"Gate {state}.")


# =============================================================================
# 12. ACCESS PERMISSIONS
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def access_permission_list_create(request):
    """GET /api/access-permissions/?user= | POST /api/access-permissions/"""
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    if request.method == "GET":
        qs = AccessPermission.objects.select_related("user", "gate", "zone")
        if request.user.role != "SUPERADMIN":
            qs = qs.filter(user__estate=request.user.estate)
        user_id = request.GET.get("user")
        if user_id:
            qs = qs.filter(user_id=user_id)
        data = [{
            "id": str(p.id), "user": _user_dict(p.user),
            "gate": {"id": str(p.gate.id), "name": p.gate.name} if p.gate else None,
            "zone": {"id": str(p.zone.id), "name": p.zone.name} if p.zone else None,
            "permission_type": p.permission_type, "valid_from": p.valid_from,
            "valid_until": p.valid_until, "is_active": p.is_active,
            "allowed_days": p.allowed_days,
        } for p in qs]
        return ok(data)
    user = get_object_or_404(User, id=request.data.get("user_id"))
    gate = Gate.objects.filter(id=request.data.get("gate_id")).first()
    zone = Zone.objects.filter(id=request.data.get("zone_id")).first()
    perm = AccessPermission.objects.create(
        user=user, gate=gate, zone=zone,
        permission_type=request.data.get("permission_type", "PERMANENT"),
        valid_from=request.data.get("valid_from", timezone.now()),
        valid_until=request.data.get("valid_until"),
        allowed_days=request.data.get("allowed_days", []),
        allowed_time_start=request.data.get("allowed_time_start"),
        allowed_time_end=request.data.get("allowed_time_end"),
        granted_by=request.user,
        reason=request.data.get("reason", ""),
    )
    log_action(request.user, "CREATE", "AccessPermission", perm.id,
               f"Access permission granted to {user}", request)
    return ok({"id": str(perm.id)}, message="Access permission granted.", status_code=status.HTTP_201_CREATED)


@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def access_permission_revoke(request, perm_id):
    """DELETE /api/access-permissions/<id>/revoke/"""
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    perm = get_object_or_404(AccessPermission, id=perm_id)
    perm.is_active = False
    perm.save()
    log_action(request.user, "UPDATE", "AccessPermission", perm.id, "Permission revoked", request)
    return ok(message="Access permission revoked.")


# =============================================================================
# 13. ACCESS DEVICES
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def device_list_create(request):
    """GET /api/devices/?estate=&gate=&device_type= | POST /api/devices/"""
    if request.method == "GET":
        if not (is_admin(request.user) or is_security(request.user)):
            return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
        qs = AccessDevice.objects.select_related("estate", "gate")
        if request.user.role != "SUPERADMIN":
            qs = qs.filter(estate=request.user.estate)
        gate_id = request.GET.get("gate")
        device_type = request.GET.get("device_type")
        status_filter = request.GET.get("status")
        if gate_id:
            qs = qs.filter(gate_id=gate_id)
        if device_type:
            qs = qs.filter(device_type=device_type)
        if status_filter:
            qs = qs.filter(status=status_filter)
        data = [{
            "id": str(d.id), "name": d.name, "device_type": d.device_type,
            "status": d.status, "ip_address": d.ip_address,
            "gate": {"id": str(d.gate.id), "name": d.gate.name} if d.gate else None,
            "serial_number": d.serial_number, "manufacturer": d.manufacturer,
            "model": d.model, "last_heartbeat": d.last_heartbeat, "is_active": d.is_active,
        } for d in qs]
        return ok(data)
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    estate = get_object_or_404(Estate, id=request.data.get("estate_id", str(request.user.estate_id)))
    gate = Gate.objects.filter(id=request.data.get("gate_id")).first()
    device = AccessDevice.objects.create(
        estate=estate, gate=gate,
        device_type=request.data.get("device_type"),
        name=request.data.get("name"),
        serial_number=request.data.get("serial_number", ""),
        manufacturer=request.data.get("manufacturer", ""),
        model=request.data.get("model", ""),
        ip_address=request.data.get("ip_address"),
        mac_address=request.data.get("mac_address", ""),
        api_endpoint=request.data.get("api_endpoint", ""),
        configuration=request.data.get("configuration", {}),
    )
    return ok({"id": str(device.id)}, message="Device registered.", status_code=status.HTTP_201_CREATED)


@api_view(["GET", "PATCH"])
@permission_classes([IsAuthenticated])
def device_detail(request, device_id):
    """GET/PATCH /api/devices/<id>/"""
    device = get_object_or_404(AccessDevice, id=device_id)
    if request.method == "GET":
        return ok({
            "id": str(device.id), "name": device.name, "device_type": device.device_type,
            "status": device.status, "ip_address": device.ip_address,
            "mac_address": device.mac_address, "serial_number": device.serial_number,
            "manufacturer": device.manufacturer, "model": device.model,
            "firmware_version": device.firmware_version, "api_endpoint": device.api_endpoint,
            "last_heartbeat": device.last_heartbeat, "is_active": device.is_active,
            "installed_at": device.installed_at, "last_maintenance": device.last_maintenance,
            "next_maintenance": device.next_maintenance, "notes": device.notes,
            "configuration": device.configuration,
            "gate": {"id": str(device.gate.id), "name": device.gate.name} if device.gate else None,
        })
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    for f in ["name", "ip_address", "mac_address", "firmware_version", "api_endpoint",
              "status", "is_active", "configuration", "notes", "next_maintenance"]:
        if f in request.data:
            setattr(device, f, request.data[f])
    device.save()
    return ok(message="Device updated.")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def device_heartbeat(request, device_id):
    """
    POST /api/devices/<id>/heartbeat/
    Called by device firmware to report it is alive.
    Body: { "status": "ONLINE", "firmware_version": "..." (optional) }
    No auth required in practice — secured by API key in header.
    """
    device = get_object_or_404(AccessDevice, id=device_id)
    device.last_heartbeat = timezone.now()
    device.status = request.data.get("status", "ONLINE")
    if "firmware_version" in request.data:
        device.firmware_version = request.data["firmware_version"]
    device.save(update_fields=["last_heartbeat", "status", "firmware_version"])
    return ok({"last_heartbeat": device.last_heartbeat}, message="Heartbeat received.")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def device_push_event(request, device_id):
    """
    POST /api/devices/<id>/push-event/
    Hardware device pushes a raw access event (card tap, fingerprint match, etc.)
    Body: { "event_type", "card_number"/"user_id"/"visitor_id", "direction", "raw_data" }
    """
    device = get_object_or_404(AccessDevice, id=device_id)
    event_type = request.data.get("event_type", "GRANTED")
    direction = request.data.get("direction", "IN")
    raw_data = request.data.get("raw_data", {})

    user = None
    visitor = None
    visit = None
    card = None

    if request.data.get("card_number"):
        card = AccessCard.objects.filter(card_number=request.data["card_number"]).first()
        if card:
            user = card.user
            visitor = card.visitor
            visit = card.visit

    if request.data.get("user_id"):
        user = User.objects.filter(id=request.data["user_id"]).first()

    if request.data.get("visitor_id"):
        visitor = Visitor.objects.filter(id=request.data["visitor_id"]).first()

    event = AccessEvent.objects.create(
        device=device, gate=device.gate,
        user=user, visitor=visitor, visit=visit, card=card,
        event_type=event_type, direction=direction,
        raw_data=raw_data, event_time=timezone.now(),
    )

    # If GRANTED + IN + visitor → auto check-in
    if event_type == "GRANTED" and direction == "IN" and visit:
        visit.status = "CHECKED_IN"
        visit.actual_check_in = event.event_time
        visit.check_in_gate = device.gate
        visit.check_in_method = "CARD" if card else "FINGERPRINT"
        visit.save()

    return ok({"event_id": str(event.id)}, message="Event recorded.", status_code=status.HTTP_201_CREATED)


# =============================================================================
# 14. ACCESS CARDS
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def card_list_create(request):
    """GET /api/cards/?user=&status= | POST /api/cards/ — issue a card."""
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    if request.method == "GET":
        qs = AccessCard.objects.select_related("user", "visitor")
        if request.user.role != "SUPERADMIN":
            qs = qs.filter(estate=request.user.estate)
        user_id = request.GET.get("user")
        card_status = request.GET.get("status")
        if user_id:
            qs = qs.filter(user_id=user_id)
        if card_status:
            qs = qs.filter(status=card_status)
        data = [{
            "id": str(c.id), "card_number": c.card_number, "card_type": c.card_type,
            "user": _user_dict(c.user), "visitor": _visitor_dict(c.visitor),
            "status": c.status, "valid_from": c.valid_from, "valid_until": c.valid_until,
            "is_temporary": c.is_temporary, "issued_at": c.issued_at,
        } for c in qs]
        return ok(data)

    user = User.objects.filter(id=request.data.get("user_id")).first()
    visitor = Visitor.objects.filter(id=request.data.get("visitor_id")).first()
    if not user and not visitor:
        return err("Either user_id or visitor_id is required.")

    card = AccessCard.objects.create(
        card_number=request.data.get("card_number"),
        card_type=request.data.get("card_type", "RFID_13MHZ"),
        user=user, visitor=visitor,
        estate=request.user.estate,
        issued_by=request.user,
        valid_from=request.data.get("valid_from", timezone.now()),
        valid_until=request.data.get("valid_until"),
        is_temporary=request.data.get("is_temporary", False),
    )
    log_action(request.user, "CARD_ISSUED", "AccessCard", card.id,
               f"Card {card.card_number} issued", request)
    return ok({"id": str(card.id), "card_number": card.card_number},
              message="Card issued.", status_code=status.HTTP_201_CREATED)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def card_revoke(request, card_id):
    """POST /api/cards/<id>/revoke/"""
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    card = get_object_or_404(AccessCard, id=card_id)
    reason = request.data.get("reason", "LOST")
    card.status = reason if reason in ("SUSPENDED", "LOST") else "SUSPENDED"
    card.save()
    log_action(request.user, "CARD_REVOKED", "AccessCard", card.id,
               f"Card {card.card_number} revoked: {reason}", request)
    return ok(message=f"Card {card.card_number} revoked.")


# =============================================================================
# 15. ACCESS EVENTS
# =============================================================================

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def access_event_list(request):
    """
    GET /api/access-events/?gate=&event_type=&date=&direction=&unacknowledged=
    """
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    qs = AccessEvent.objects.select_related("gate", "user", "visitor", "device")
    if request.user.role != "SUPERADMIN":
        qs = qs.filter(gate__estate=request.user.estate)

    gate_id = request.GET.get("gate")
    event_type = request.GET.get("event_type")
    date = request.GET.get("date")
    direction = request.GET.get("direction")
    unacknowledged = request.GET.get("unacknowledged")

    if gate_id:
        qs = qs.filter(gate_id=gate_id)
    if event_type:
        qs = qs.filter(event_type=event_type)
    if date:
        qs = qs.filter(event_time__date=date)
    if direction:
        qs = qs.filter(direction=direction)
    if unacknowledged == "true":
        qs = qs.filter(is_acknowledged=False)

    data = [{
        "id": str(e.id), "event_type": e.event_type, "direction": e.direction,
        "gate": e.gate.name if e.gate else None,
        "device": e.device.name if e.device else None,
        "user": _user_dict(e.user), "visitor": _visitor_dict(e.visitor),
        "event_time": e.event_time, "is_acknowledged": e.is_acknowledged,
        "snapshot": e.snapshot.url if e.snapshot else None,
    } for e in qs.order_by("-event_time")[:200]]
    return ok(data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def access_event_acknowledge(request, event_id):
    """POST /api/access-events/<id>/acknowledge/"""
    event = get_object_or_404(AccessEvent, id=event_id)
    event.is_acknowledged = True
    event.save(update_fields=["is_acknowledged"])
    return ok(message="Event acknowledged.")


# =============================================================================
# 16. VISITOR BADGES
# =============================================================================

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def issue_badge(request, visit_id):
    """
    POST /api/visits/<id>/issue-badge/
    Body: { "badge_type": "PRINTED", "color_code": "#00FF00" }
    """
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    visit = get_object_or_404(Visit, id=visit_id)
    if hasattr(visit, "badge"):
        return err("A badge has already been issued for this visit.")
    if visit.status != "CHECKED_IN":
        return err("Badges can only be issued for checked-in visitors.")
    badge = VisitorBadge.objects.create(
        visit=visit,
        badge_type=request.data.get("badge_type", "PRINTED"),
        badge_number=f"VMS-{timezone.now().strftime('%Y%m%d')}-{str(visit.id)[:8].upper()}",
        printed_at=timezone.now(),
        printed_by=request.user,
        color_code=request.data.get("color_code", "#3b82f6"),
        qr_data=str(visit.id),
    )
    return ok({
        "badge_number": badge.badge_number, "badge_type": badge.badge_type,
        "color_code": badge.color_code, "printed_at": badge.printed_at,
    }, message="Badge issued.", status_code=status.HTTP_201_CREATED)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def return_badge(request, visit_id):
    """POST /api/visits/<id>/return-badge/"""
    visit = get_object_or_404(Visit, id=visit_id)
    if not hasattr(visit, "badge"):
        return err("No badge found for this visit.")
    visit.badge.is_returned = True
    visit.badge.returned_at = timezone.now()
    visit.badge.save()
    return ok(message="Badge returned.")


# =============================================================================
# 17. NOTIFICATIONS
# =============================================================================

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def my_notifications(request):
    """GET /api/notifications/ — inbox for current user."""
    qs = Notification.objects.filter(recipient=request.user).order_by("-created_at")
    unread_only = request.GET.get("unread")
    if unread_only == "true":
        qs = qs.exclude(status="READ")
    data = [{
        "id": str(n.id), "channel": n.channel, "subject": n.subject,
        "message": n.message, "status": n.status, "sent_at": n.sent_at,
        "read_at": n.read_at,
        "visit": {"id": str(n.visit.id)} if n.visit else None,
    } for n in qs[:50]]
    return ok(data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def mark_notification_read(request, notif_id):
    """POST /api/notifications/<id>/read/"""
    notif = get_object_or_404(Notification, id=notif_id, recipient=request.user)
    notif.status = "READ"
    notif.read_at = timezone.now()
    notif.save()
    return ok(message="Notification marked as read.")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def mark_all_notifications_read(request):
    """POST /api/notifications/read-all/"""
    Notification.objects.filter(
        recipient=request.user
    ).exclude(status="READ").update(status="READ", read_at=timezone.now())
    return ok(message="All notifications marked as read.")


@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def notification_template_list_create(request):
    """GET /api/notification-templates/ | POST /api/notification-templates/"""
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    if request.method == "GET":
        qs = NotificationTemplate.objects.filter(estate=request.user.estate)
        return ok([{
            "id": str(t.id), "event_trigger": t.event_trigger,
            "channel": t.channel, "subject": t.subject,
            "is_active": t.is_active, "send_to_host": t.send_to_host,
        } for t in qs])
    tmpl = NotificationTemplate.objects.create(
        estate=request.user.estate,
        event_trigger=request.data.get("event_trigger"),
        channel=request.data.get("channel"),
        subject=request.data.get("subject", ""),
        body=request.data.get("body"),
        is_active=request.data.get("is_active", True),
        send_to_host=request.data.get("send_to_host", True),
        send_to_visitor=request.data.get("send_to_visitor", False),
        send_to_security=request.data.get("send_to_security", False),
    )
    return ok({"id": str(tmpl.id)}, message="Template created.", status_code=status.HTTP_201_CREATED)


# =============================================================================
# 18. BLACKLIST
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def blacklist_list_create(request):
    """GET /api/blacklist/?severity=&search= | POST /api/blacklist/"""
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)

    if request.method == "GET":
        qs = Blacklist.objects.filter(estate=request.user.estate, is_active=True)
        severity = request.GET.get("severity")
        search = request.GET.get("search")
        if severity:
            qs = qs.filter(severity=severity)
        if search:
            qs = qs.filter(
                Q(name__icontains=search) | Q(phone__icontains=search) |
                Q(id_number__icontains=search) |
                Q(visitor__first_name__icontains=search) |
                Q(visitor__last_name__icontains=search)
            )
        data = [{
            "id": str(b.id),
            "person": str(b.visitor) if b.visitor else b.name or b.phone,
            "severity": b.severity, "reason": b.reason,
            "is_active": b.is_active, "valid_until": b.valid_until,
            "added_by": _user_dict(b.added_by), "created_at": b.created_at,
            "phone": b.phone, "id_number": b.id_number,
        } for b in qs]
        return ok(data)

    # POST — add to blacklist
    visitor = Visitor.objects.filter(id=request.data.get("visitor_id")).first()
    entry = Blacklist.objects.create(
        estate=request.user.estate,
        visitor=visitor,
        name=request.data.get("name", ""),
        phone=request.data.get("phone", visitor.phone if visitor else ""),
        id_number=request.data.get("id_number", visitor.id_number if visitor else ""),
        severity=request.data.get("severity", "HIGH"),
        reason=request.data.get("reason", ""),
        incident_date=request.data.get("incident_date"),
        valid_until=request.data.get("valid_until"),
        added_by=request.user,
        notes=request.data.get("notes", ""),
    )
    if visitor:
        visitor.is_flagged = True
        visitor.flag_reason = request.data.get("reason", "Added to blacklist")
        visitor.save()
    log_action(request.user, "BLACKLIST_ADD", "Blacklist", entry.id,
               f"Person added to blacklist: {entry.severity}", request)
    return ok({"id": str(entry.id)}, message="Person added to blacklist.", status_code=status.HTTP_201_CREATED)


@api_view(["GET", "PATCH", "DELETE"])
@permission_classes([IsAuthenticated])
def blacklist_detail(request, blacklist_id):
    """GET/PATCH/DELETE /api/blacklist/<id>/"""
    entry = get_object_or_404(Blacklist, id=blacklist_id)
    if request.method == "GET":
        return ok({
            "id": str(entry.id),
            "visitor": _visitor_dict(entry.visitor),
            "name": entry.name, "phone": entry.phone, "id_number": entry.id_number,
            "severity": entry.severity, "reason": entry.reason,
            "incident_date": entry.incident_date, "valid_until": entry.valid_until,
            "is_active": entry.is_active, "notes": entry.notes,
            "added_by": _user_dict(entry.added_by), "created_at": entry.created_at,
        })
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    if request.method == "PATCH":
        for f in ["severity", "reason", "valid_until", "is_active", "notes"]:
            if f in request.data:
                setattr(entry, f, request.data[f])
        entry.save()
        return ok(message="Blacklist entry updated.")
    entry.is_active = False
    entry.save()
    return ok(message="Blacklist entry removed.")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def blacklist_check(request):
    """
    POST /api/blacklist/check/
    Body: { "phone": "..." } or { "id_number": "..." } or { "visitor_id": "..." }
    Quick check whether someone is blacklisted — used at gate.
    """
    phone = request.data.get("phone")
    id_number = request.data.get("id_number")
    visitor_id = request.data.get("visitor_id")

    q = Q(estate=request.user.estate, is_active=True)
    if phone:
        q &= Q(phone=phone)
    elif id_number:
        q &= Q(id_number=id_number)
    elif visitor_id:
        q &= Q(visitor_id=visitor_id)
    else:
        return err("Provide phone, id_number, or visitor_id.")

    entry = Blacklist.objects.filter(q).first()
    if entry:
        return ok({
            "blacklisted": True, "severity": entry.severity,
            "reason": entry.reason, "valid_until": entry.valid_until,
        }, message="Person is blacklisted.")
    return ok({"blacklisted": False}, message="No blacklist entry found.")


# =============================================================================
# 19. WATCHLIST
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def watchlist_list_create(request):
    """GET /api/watchlist/ | POST /api/watchlist/"""
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    if request.method == "GET":
        qs = Watchlist.objects.filter(estate=request.user.estate, is_active=True)
        return ok([{
            "id": str(w.id),
            "person": str(w.visitor) if w.visitor else w.name,
            "phone": w.phone, "reason": w.reason,
            "alert_message": w.alert_message, "is_active": w.is_active,
            "added_by": _user_dict(w.added_by),
        } for w in qs])
    visitor = Visitor.objects.filter(id=request.data.get("visitor_id")).first()
    entry = Watchlist.objects.create(
        estate=request.user.estate, visitor=visitor,
        name=request.data.get("name", ""),
        phone=request.data.get("phone", ""),
        reason=request.data.get("reason", ""),
        alert_message=request.data.get("alert_message", "Proceed with caution."),
        added_by=request.user,
    )
    return ok({"id": str(entry.id)}, message="Added to watchlist.", status_code=status.HTTP_201_CREATED)


@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def watchlist_remove(request, watchlist_id):
    """DELETE /api/watchlist/<id>/"""
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    entry = get_object_or_404(Watchlist, id=watchlist_id)
    entry.is_active = False
    entry.save()
    return ok(message="Removed from watchlist.")


# =============================================================================
# 20. VEHICLES & PARKING
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def vehicle_list_create(request):
    """GET /api/vehicles/?owner= | POST /api/vehicles/"""
    if request.method == "GET":
        if is_resident(request.user):
            qs = RegisteredVehicle.objects.filter(owner=request.user)
        elif is_admin(request.user) or is_security(request.user):
            qs = RegisteredVehicle.objects.filter(owner__estate=request.user.estate)
        else:
            return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
        data = [{
            "id": str(v.id), "license_plate": v.license_plate,
            "vehicle_type": v.vehicle_type, "make": v.make,
            "model": v.model, "color": v.color,
            "sticker_number": v.sticker_number, "is_active": v.is_active,
            "owner": _user_dict(v.owner),
        } for v in qs]
        return ok(data)

    owner = User.objects.filter(id=request.data.get("owner_id", str(request.user.id))).first() or request.user
    vehicle = RegisteredVehicle.objects.create(
        owner=owner,
        unit=Unit.objects.filter(id=request.data.get("unit_id")).first(),
        vehicle_type=request.data.get("vehicle_type", "CAR"),
        make=request.data.get("make", ""),
        model=request.data.get("model", ""),
        color=request.data.get("color", ""),
        license_plate=request.data.get("license_plate"),
        sticker_number=request.data.get("sticker_number", ""),
    )
    return ok({"id": str(vehicle.id), "license_plate": vehicle.license_plate},
              message="Vehicle registered.", status_code=status.HTTP_201_CREATED)


@api_view(["PATCH", "DELETE"])
@permission_classes([IsAuthenticated])
def vehicle_detail(request, vehicle_id):
    """PATCH/DELETE /api/vehicles/<id>/"""
    vehicle = get_object_or_404(RegisteredVehicle, id=vehicle_id)
    if not (is_admin(request.user) or request.user == vehicle.owner):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    if request.method == "PATCH":
        for f in ["vehicle_type", "make", "model", "color", "license_plate",
                  "sticker_number", "is_active"]:
            if f in request.data:
                setattr(vehicle, f, request.data[f])
        vehicle.save()
        return ok(message="Vehicle updated.")
    vehicle.is_active = False
    vehicle.save()
    return ok(message="Vehicle removed.")


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def parking_slot_list(request):
    """GET /api/parking/slots/?slot_type=&is_occupied="""
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    qs = ParkingSlot.objects.filter(estate=request.user.estate, is_active=True)
    slot_type = request.GET.get("slot_type")
    is_occupied = request.GET.get("is_occupied")
    if slot_type:
        qs = qs.filter(slot_type=slot_type)
    if is_occupied is not None:
        qs = qs.filter(is_occupied=is_occupied.lower() == "true")
    data = [{
        "id": str(s.id), "slot_number": s.slot_number, "slot_type": s.slot_type,
        "is_occupied": s.is_occupied,
        "assigned_to": _user_dict(s.assigned_to) if s.assigned_to else None,
    } for s in qs]
    return ok(data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def parking_session_start(request):
    """
    POST /api/parking/sessions/start/
    Body: { "slot_id", "vehicle_plate", "visit_id" (optional) }
    """
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    slot = get_object_or_404(ParkingSlot, id=request.data.get("slot_id"))
    if slot.is_occupied:
        return err(f"Slot {slot.slot_number} is already occupied.")
    session = ParkingSession.objects.create(
        slot=slot,
        vehicle_plate=request.data.get("vehicle_plate"),
        visit=Visit.objects.filter(id=request.data.get("visit_id")).first(),
        entry_time=timezone.now(),
    )
    slot.is_occupied = True
    slot.save(update_fields=["is_occupied"])
    return ok({"session_id": str(session.id), "slot": slot.slot_number},
              message="Parking session started.", status_code=status.HTTP_201_CREATED)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def parking_session_end(request, session_id):
    """POST /api/parking/sessions/<id>/end/"""
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    session = get_object_or_404(ParkingSession, id=session_id, is_active=True)
    session.exit_time = timezone.now()
    session.is_active = False
    session.save()
    session.slot.is_occupied = False
    session.slot.save(update_fields=["is_occupied"])
    duration = int((session.exit_time - session.entry_time).total_seconds() / 60)
    return ok({"duration_minutes": duration}, message="Parking session ended.")


# =============================================================================
# 21. DELIVERIES
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def delivery_list_create(request):
    """GET /api/deliveries/?status=&unit= | POST /api/deliveries/"""
    if request.method == "GET":
        if is_resident(request.user):
            qs = Delivery.objects.filter(recipient=request.user)
        elif is_admin(request.user) or is_security(request.user):
            qs = Delivery.objects.filter(estate=request.user.estate)
        else:
            return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
        delivery_status = request.GET.get("status")
        unit_id = request.GET.get("unit")
        if delivery_status:
            qs = qs.filter(status=delivery_status)
        if unit_id:
            qs = qs.filter(unit_id=unit_id)
        data = [{
            "id": str(d.id), "delivery_type": d.delivery_type,
            "courier_name": d.courier_name, "courier_company": d.courier_company,
            "tracking_number": d.tracking_number, "status": d.status,
            "arrived_at": d.arrived_at, "collected_at": d.collected_at,
            "unit": _unit_dict(d.unit), "recipient": _user_dict(d.recipient),
            "storage_location": d.storage_location,
        } for d in qs.order_by("-arrived_at")]
        return ok(data)

    # POST — security logs a new delivery arrival
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    unit = get_object_or_404(Unit, id=request.data.get("unit_id"))
    recipient = get_object_or_404(User, id=request.data.get("recipient_id"))
    delivery = Delivery.objects.create(
        estate=unit.block.estate, unit=unit, recipient=recipient,
        delivery_type=request.data.get("delivery_type", "PARCEL"),
        courier_name=request.data.get("courier_name", ""),
        courier_company=request.data.get("courier_company", ""),
        courier_phone=request.data.get("courier_phone", ""),
        tracking_number=request.data.get("tracking_number", ""),
        status="ARRIVED", arrived_at=timezone.now(),
        storage_location=request.data.get("storage_location", ""),
        received_by=request.user,
        notes=request.data.get("notes", ""),
    )
    return ok({"id": str(delivery.id)}, message="Delivery logged.", status_code=status.HTTP_201_CREATED)


@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def delivery_update_status(request, delivery_id):
    """PATCH /api/deliveries/<id>/status/ — collected, returned, etc."""
    delivery = get_object_or_404(Delivery, id=delivery_id)
    new_status = request.data.get("status")
    if new_status not in dict(Delivery.STATUS_CHOICES):
        return err(f"Invalid status: {new_status}")
    delivery.status = new_status
    if new_status == "COLLECTED":
        delivery.collected_at = timezone.now()
    delivery.save()
    return ok({"status": delivery.status}, message="Delivery status updated.")


# =============================================================================
# 22. CONTRACTORS & WORK ORDERS
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def contractor_list_create(request):
    """GET /api/contractors/ | POST /api/contractors/"""
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    if request.method == "GET":
        qs = Contractor.objects.filter(estate=request.user.estate)
        is_approved = request.GET.get("is_approved")
        if is_approved is not None:
            qs = qs.filter(is_approved=is_approved.lower() == "true")
        data = [{
            "id": str(c.id), "company_name": c.company_name,
            "contact_person": c.contact_person, "phone": c.phone,
            "service_type": c.service_type, "is_approved": c.is_approved,
            "is_active": c.is_active, "contract_end": c.contract_end,
        } for c in qs]
        return ok(data)
    contractor = Contractor.objects.create(
        estate=request.user.estate,
        company_name=request.data.get("company_name"),
        contact_person=request.data.get("contact_person"),
        phone=request.data.get("phone"),
        email=request.data.get("email", ""),
        service_type=request.data.get("service_type"),
        contract_start=request.data.get("contract_start"),
        contract_end=request.data.get("contract_end"),
        notes=request.data.get("notes", ""),
    )
    return ok({"id": str(contractor.id)}, message="Contractor added.", status_code=status.HTTP_201_CREATED)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def contractor_approve(request, contractor_id):
    """POST /api/contractors/<id>/approve/"""
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    contractor = get_object_or_404(Contractor, id=contractor_id)
    contractor.is_approved = True
    contractor.approved_by = request.user
    contractor.save()
    return ok(message=f"Contractor '{contractor.company_name}' approved.")


@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def work_order_list_create(request):
    """GET /api/work-orders/?contractor=&status= | POST /api/work-orders/"""
    if request.method == "GET":
        qs = WorkOrder.objects.filter(estate=request.user.estate)
        contractor_id = request.GET.get("contractor")
        wo_status = request.GET.get("status")
        if contractor_id:
            qs = qs.filter(contractor_id=contractor_id)
        if wo_status:
            qs = qs.filter(status=wo_status)
        data = [{
            "id": str(w.id), "title": w.title,
            "contractor": w.contractor.company_name,
            "status": w.status, "scheduled_start": w.scheduled_start,
            "unit": _unit_dict(w.unit), "requires_unit_access": w.requires_unit_access,
            "resident_approved": w.resident_approved,
        } for w in qs.order_by("-scheduled_start")]
        return ok(data)
    contractor = get_object_or_404(Contractor, id=request.data.get("contractor_id"))
    wo = WorkOrder.objects.create(
        estate=request.user.estate,
        contractor=contractor,
        unit=Unit.objects.filter(id=request.data.get("unit_id")).first(),
        title=request.data.get("title"),
        description=request.data.get("description", ""),
        scheduled_start=request.data.get("scheduled_start"),
        scheduled_end=request.data.get("scheduled_end"),
        requires_unit_access=request.data.get("requires_unit_access", False),
    )
    return ok({"id": str(wo.id)}, message="Work order created.", status_code=status.HTTP_201_CREATED)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def work_order_approve(request, wo_id):
    """POST /api/work-orders/<id>/approve/ — resident approves contractor unit entry."""
    wo = get_object_or_404(WorkOrder, id=wo_id)
    if not (is_resident(request.user) and
            wo.unit and hasattr(request.user, "resident_profile") and
            request.user.resident_profile.unit == wo.unit):
        return err("Only the unit resident can approve this work order.")
    wo.resident_approved = True
    wo.save(update_fields=["resident_approved"])
    return ok(message="Work order approved for unit entry.")


# =============================================================================
# 23. INCIDENTS
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def incident_list_create(request):
    """GET /api/incidents/?severity=&status=&type= | POST /api/incidents/"""
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    if request.method == "GET":
        qs = Incident.objects.filter(estate=request.user.estate)
        severity = request.GET.get("severity")
        inc_status = request.GET.get("status")
        inc_type = request.GET.get("incident_type")
        if severity:
            qs = qs.filter(severity=severity)
        if inc_status:
            qs = qs.filter(status=inc_status)
        if inc_type:
            qs = qs.filter(incident_type=inc_type)
        data = [{
            "id": str(i.id), "title": i.title, "incident_type": i.incident_type,
            "severity": i.severity, "status": i.status,
            "occurred_at": i.occurred_at, "gate": i.gate.name if i.gate else None,
            "reported_by": _user_dict(i.reported_by),
            "is_police_notified": i.is_police_notified,
        } for i in qs.order_by("-occurred_at")]
        return ok(data)

    incident = Incident.objects.create(
        estate=request.user.estate,
        gate=Gate.objects.filter(id=request.data.get("gate_id")).first(),
        unit=Unit.objects.filter(id=request.data.get("unit_id")).first(),
        visit=Visit.objects.filter(id=request.data.get("visit_id")).first(),
        visitor=Visitor.objects.filter(id=request.data.get("visitor_id")).first(),
        incident_type=request.data.get("incident_type"),
        severity=request.data.get("severity", "MEDIUM"),
        title=request.data.get("title"),
        description=request.data.get("description"),
        occurred_at=request.data.get("occurred_at", timezone.now()),
        reported_by=request.user,
        is_police_notified=request.data.get("is_police_notified", False),
        police_report_number=request.data.get("police_report_number", ""),
    )
    return ok({"id": str(incident.id)}, message="Incident reported.", status_code=status.HTTP_201_CREATED)


@api_view(["GET", "PATCH"])
@permission_classes([IsAuthenticated])
def incident_detail(request, incident_id):
    """GET/PATCH /api/incidents/<id>/"""
    incident = get_object_or_404(Incident, id=incident_id)
    if request.method == "GET":
        return ok({
            "id": str(incident.id), "title": incident.title,
            "incident_type": incident.incident_type, "severity": incident.severity,
            "description": incident.description, "status": incident.status,
            "occurred_at": incident.occurred_at,
            "reported_by": _user_dict(incident.reported_by),
            "assigned_to": _user_dict(incident.assigned_to),
            "resolution_notes": incident.resolution_notes,
            "resolved_at": incident.resolved_at,
            "is_police_notified": incident.is_police_notified,
            "police_report_number": incident.police_report_number,
            "gate": incident.gate.name if incident.gate else None,
            "visitor": _visitor_dict(incident.visitor),
            "cctv_reference": incident.cctv_reference,
        })
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    for f in ["status", "severity", "resolution_notes", "resolved_at",
              "is_police_notified", "police_report_number", "cctv_reference"]:
        if f in request.data:
            setattr(incident, f, request.data[f])
    if request.data.get("assigned_to_id"):
        incident.assigned_to = get_object_or_404(User, id=request.data["assigned_to_id"])
    if request.data.get("status") == "RESOLVED" and not incident.resolved_at:
        incident.resolved_at = timezone.now()
    incident.save()
    return ok(message="Incident updated.")


# =============================================================================
# 24. AUDIT LOGS
# =============================================================================

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def audit_log_list(request):
    """
    GET /api/audit-logs/?action=&model=&user=&date=
    Read-only. Admin only.
    """
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    qs = AuditLog.objects.select_related("user")
    if request.user.role != "SUPERADMIN":
        qs = qs.filter(estate=request.user.estate)
    action = request.GET.get("action")
    model = request.GET.get("model")
    user_id = request.GET.get("user")
    date = request.GET.get("date")
    if action:
        qs = qs.filter(action=action)
    if model:
        qs = qs.filter(model_name__icontains=model)
    if user_id:
        qs = qs.filter(user_id=user_id)
    if date:
        qs = qs.filter(created_at__date=date)
    data = [{
        "id": str(a.id), "action": a.action, "model_name": a.model_name,
        "object_id": a.object_id, "description": a.description,
        "user": _user_dict(a.user), "ip_address": a.ip_address,
        "created_at": a.created_at,
    } for a in qs.order_by("-created_at")[:500]]
    return ok(data)


# =============================================================================
# 25. ANALYTICS & REPORTS
# =============================================================================

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def dashboard_stats(request):
    """GET /api/analytics/dashboard/ — real-time dashboard numbers."""
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    estate = request.user.estate
    today = timezone.now().date()
    now = timezone.now()
    last_30 = now - timedelta(days=30)

    hourly = []
    for h in range(24):
        count = Visit.objects.filter(
            estate=estate, actual_check_in__date=today,
            actual_check_in__hour=h
        ).count()
        hourly.append({"hour": h, "count": count})

    return ok({
        "today": {
            "total_visits": Visit.objects.filter(estate=estate, actual_check_in__date=today).count(),
            "checked_in": Visit.objects.filter(estate=estate, status="CHECKED_IN").count(),
            "checked_out": Visit.objects.filter(estate=estate, actual_check_out__date=today).count(),
            "denied": Visit.objects.filter(estate=estate, status="DENIED", created_at__date=today).count(),
            "deliveries": Delivery.objects.filter(estate=estate, arrived_at__date=today).count(),
        },
        "pending": {
            "visits": Visit.objects.filter(estate=estate, status="PENDING").count(),
            "deliveries": Delivery.objects.filter(estate=estate, status__in=["ARRIVED", "NOTIFIED"]).count(),
            "incidents": Incident.objects.filter(estate=estate, status__in=["OPEN", "INVESTIGATING"]).count(),
            "work_orders": WorkOrder.objects.filter(estate=estate, status="SCHEDULED").count(),
        },
        "last_30_days": {
            "total_visits": Visit.objects.filter(estate=estate, created_at__gte=last_30).count(),
            "unique_visitors": Visit.objects.filter(
                estate=estate, created_at__gte=last_30
            ).values("visitor").distinct().count(),
            "avg_daily_visits": Visit.objects.filter(
                estate=estate, created_at__gte=last_30
            ).count() / 30,
        },
        "security": {
            "blacklisted": Blacklist.objects.filter(estate=estate, is_active=True).count(),
            "watchlisted": Watchlist.objects.filter(estate=estate, is_active=True).count(),
            "open_incidents": Incident.objects.filter(estate=estate, status="OPEN").count(),
            "devices_offline": AccessDevice.objects.filter(estate=estate, status="OFFLINE").count(),
        },
        "hourly_traffic_today": hourly,
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def daily_report_list(request):
    """GET /api/analytics/daily/?start=&end="""
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    qs = DailyReport.objects.filter(estate=request.user.estate)
    start = request.GET.get("start")
    end = request.GET.get("end")
    if start:
        qs = qs.filter(date__gte=start)
    if end:
        qs = qs.filter(date__lte=end)
    data = [{
        "date": str(r.date), "total_visitors": r.total_visitors,
        "total_check_ins": r.total_check_ins, "total_check_outs": r.total_check_outs,
        "denied_access": r.denied_access, "blacklist_alerts": r.blacklist_alerts,
        "avg_visit_duration_minutes": r.avg_visit_duration_minutes,
        "peak_hour": r.peak_hour, "total_deliveries": r.total_deliveries,
        "total_incidents": r.total_incidents,
    } for r in qs.order_by("-date")]
    return ok(data)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def visit_trends(request):
    """
    GET /api/analytics/visits/trends/?days=30
    Returns daily visit counts for trending chart.
    """
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    days = min(int(request.GET.get("days", 30)), 365)
    since = timezone.now() - timedelta(days=days)
    estate = request.user.estate

    from django.db.models.functions import TruncDate
    trends = (
        Visit.objects.filter(estate=estate, created_at__gte=since)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(count=Count("id"))
        .order_by("day")
    )
    return ok([{"date": str(t["day"]), "count": t["count"]} for t in trends])


# =============================================================================
# 26. EMERGENCY ALERTS
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def emergency_alert_list_create(request):
    """GET /api/emergency/ | POST /api/emergency/"""
    if request.method == "GET":
        qs = EmergencyAlert.objects.filter(estate=request.user.estate)
        if request.GET.get("active_only") == "true":
            qs = qs.filter(status="ACTIVE")
        data = [{
            "id": str(a.id), "alert_type": a.alert_type, "title": a.title,
            "status": a.status, "gate_lockdown": a.gate_lockdown,
            "initiated_by": _user_dict(a.initiated_by),
            "initiated_at": a.initiated_at, "resolved_at": a.resolved_at,
            "mustering_point": a.mustering_point,
        } for a in qs.order_by("-initiated_at")]
        return ok(data)

    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)

    alert = EmergencyAlert.objects.create(
        estate=request.user.estate,
        alert_type=request.data.get("alert_type", "GENERAL"),
        title=request.data.get("title"),
        message=request.data.get("message"),
        initiated_by=request.user,
        gate_lockdown=request.data.get("gate_lockdown", False),
        mustering_point=request.data.get("mustering_point", ""),
    )

    # Trigger gate lockdown if requested
    if alert.gate_lockdown:
        Gate.objects.filter(estate=request.user.estate).update(is_open=False)

    log_action(request.user, "CREATE", "EmergencyAlert", alert.id,
               f"Emergency alert issued: {alert.alert_type}", request)
    return ok({"id": str(alert.id)}, message="Emergency alert issued!", status_code=status.HTTP_201_CREATED)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def emergency_resolve(request, alert_id):
    """POST /api/emergency/<id>/resolve/"""
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    alert = get_object_or_404(EmergencyAlert, id=alert_id)
    alert.status = "RESOLVED"
    alert.resolved_at = timezone.now()
    alert.save()
    log_action(request.user, "UPDATE", "EmergencyAlert", alert.id, "Emergency resolved", request)
    return ok(message="Emergency alert resolved.")


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def active_emergency(request):
    """GET /api/emergency/active/ — quick check for any active alerts."""
    alert = EmergencyAlert.objects.filter(
        estate=request.user.estate, status="ACTIVE"
    ).first()
    if alert:
        return ok({
            "active": True, "alert_type": alert.alert_type,
            "title": alert.title, "message": alert.message,
            "gate_lockdown": alert.gate_lockdown,
            "mustering_point": alert.mustering_point,
            "initiated_at": alert.initiated_at,
        })
    return ok({"active": False})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def muster_record(request, alert_id):
    """
    POST /api/emergency/<id>/muster/
    Body: { "person_id" or "visitor_id", "mustering_point", "is_accounted" }
    """
    alert = get_object_or_404(EmergencyAlert, id=alert_id)
    person = User.objects.filter(id=request.data.get("person_id")).first()
    visitor = Visitor.objects.filter(id=request.data.get("visitor_id")).first()
    record, _ = EvacuationRecord.objects.get_or_create(
        alert=alert, person=person, visitor=visitor,
        defaults={"mustering_point": request.data.get("mustering_point", "")}
    )
    record.is_accounted = request.data.get("is_accounted", True)
    record.accounted_at = timezone.now()
    record.mustering_point = request.data.get("mustering_point", record.mustering_point)
    record.save()
    return ok({"id": str(record.id), "is_accounted": record.is_accounted},
              message="Muster record updated.")


# =============================================================================
# 27. WEBHOOKS
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def webhook_list_create(request):
    """GET /api/webhooks/ | POST /api/webhooks/"""
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    if request.method == "GET":
        qs = WebhookEndpoint.objects.filter(estate=request.user.estate)
        return ok([{
            "id": str(w.id), "url": w.url, "is_active": w.is_active,
            "subscribed_events": w.subscribed_events, "description": w.description,
            "created_at": w.created_at,
        } for w in qs])
    webhook = WebhookEndpoint.objects.create(
        estate=request.user.estate,
        url=request.data.get("url"),
        secret_key=request.data.get("secret_key", gen_token(32)),
        subscribed_events=request.data.get("subscribed_events", []),
        description=request.data.get("description", ""),
        timeout_seconds=request.data.get("timeout_seconds", 10),
        retry_attempts=request.data.get("retry_attempts", 3),
    )
    return ok({"id": str(webhook.id), "secret_key": webhook.secret_key},
              message="Webhook registered.", status_code=status.HTTP_201_CREATED)


@api_view(["PATCH", "DELETE"])
@permission_classes([IsAuthenticated])
def webhook_detail(request, webhook_id):
    """PATCH/DELETE /api/webhooks/<id>/"""
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    webhook = get_object_or_404(WebhookEndpoint, id=webhook_id)
    if request.method == "PATCH":
        for f in ["url", "subscribed_events", "is_active", "description",
                  "timeout_seconds", "retry_attempts"]:
            if f in request.data:
                setattr(webhook, f, request.data[f])
        webhook.save()
        return ok(message="Webhook updated.")
    webhook.delete()
    return ok(message="Webhook deleted.")


# =============================================================================
# 28. INTEGRATIONS
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def integration_list_create(request):
    """GET /api/integrations/ | POST /api/integrations/"""
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    if request.method == "GET":
        qs = ThirdPartyIntegration.objects.filter(estate=request.user.estate)
        return ok([{
            "id": str(i.id), "integration_type": i.integration_type,
            "provider_name": i.provider_name, "is_active": i.is_active,
            "last_tested": i.last_tested,
        } for i in qs])
    integration = ThirdPartyIntegration.objects.create(
        estate=request.user.estate,
        integration_type=request.data.get("integration_type"),
        provider_name=request.data.get("provider_name"),
        config=request.data.get("config", {}),
        is_active=request.data.get("is_active", True),
    )
    return ok({"id": str(integration.id)}, message="Integration configured.", status_code=status.HTTP_201_CREATED)


# =============================================================================
# 29. BILLING & SUBSCRIPTIONS
# =============================================================================

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def subscription_plan_list(request):
    """GET /api/billing/plans/ — list all available plans."""
    plans = SubscriptionPlan.objects.filter(is_active=True)
    return ok([{
        "id": str(p.id), "name": p.name, "code": p.code,
        "monthly_price": str(p.monthly_price),
        "annual_price": str(p.annual_price) if p.annual_price else None,
        "max_units": p.max_units, "max_users": p.max_users,
        "max_devices": p.max_devices, "features": p.features,
    } for p in plans])


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def my_subscription(request):
    """GET /api/billing/my-subscription/ — current estate subscription."""
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    try:
        sub = request.user.estate.subscription
        return ok({
            "plan": sub.plan.name, "status": sub.status,
            "trial_ends": sub.trial_ends,
            "billing_cycle_start": sub.billing_cycle_start,
            "billing_cycle_end": sub.billing_cycle_end,
            "auto_renew": sub.auto_renew,
        })
    except EstateSubscription.DoesNotExist:
        return ok({"plan": None, "status": "NONE"})


# =============================================================================
# 30. SYSTEM SETTINGS
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def system_settings_list_create(request):
    """GET /api/settings/ | POST /api/settings/"""
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    if request.method == "GET":
        qs = SystemSetting.objects.filter(
            Q(estate=request.user.estate) | Q(estate__isnull=True, is_public=True)
        )
        return ok([{
            "id": str(s.id), "key": s.key, "value": s.value,
            "data_type": s.data_type, "description": s.description,
        } for s in qs])
    setting, created = SystemSetting.objects.update_or_create(
        estate=request.user.estate, key=request.data.get("key"),
        defaults={
            "value": request.data.get("value", ""),
            "data_type": request.data.get("data_type", "str"),
            "description": request.data.get("description", ""),
        }
    )
    return ok({"id": str(setting.id)}, message="Setting saved.",
              status_code=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


# =============================================================================
# 31. VISITOR FEEDBACK
# =============================================================================

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def submit_feedback(request, visit_id):
    """
    POST /api/visits/<id>/feedback/
    Body: { "rating": 5, "comment": "...", "is_anonymous": false }
    """
    visit = get_object_or_404(Visit, id=visit_id)
    if visit.status != "CHECKED_OUT":
        return err("Feedback can only be submitted after check-out.")
    if VisitorFeedback.objects.filter(visit=visit).exists():
        return err("Feedback already submitted for this visit.")
    rating = request.data.get("rating")
    if not rating or int(rating) not in range(1, 6):
        return err("Rating must be between 1 and 5.")
    feedback = VisitorFeedback.objects.create(
        visit=visit,
        submitted_by=request.user if not request.data.get("is_anonymous") else None,
        rating=int(rating),
        comment=request.data.get("comment", ""),
        is_anonymous=request.data.get("is_anonymous", False),
    )
    return ok({"id": str(feedback.id)}, message="Feedback submitted.", status_code=status.HTTP_201_CREATED)


# =============================================================================
# 32. BIOMETRIC TEMPLATES
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def biometric_list_create(request):
    """GET /api/biometrics/?user= | POST /api/biometrics/ — enroll biometric."""
    if not (is_admin(request.user) or is_security(request.user)):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    if request.method == "GET":
        qs = BiometricTemplate.objects.filter(is_active=True)
        user_id = request.GET.get("user")
        visitor_id = request.GET.get("visitor")
        if user_id:
            qs = qs.filter(user_id=user_id)
        if visitor_id:
            qs = qs.filter(visitor_id=visitor_id)
        data = [{
            "id": str(b.id), "biometric_type": b.biometric_type,
            "user": _user_dict(b.user), "visitor": _visitor_dict(b.visitor),
            "quality_score": b.quality_score, "finger_index": b.finger_index,
            "is_active": b.is_active, "created_at": b.created_at,
        } for b in qs]
        return ok(data)

    device = get_object_or_404(AccessDevice, id=request.data.get("device_id"))
    user = User.objects.filter(id=request.data.get("user_id")).first()
    visitor = Visitor.objects.filter(id=request.data.get("visitor_id")).first()
    if not user and not visitor:
        return err("Either user_id or visitor_id required.")

    template = BiometricTemplate.objects.create(
        user=user, visitor=visitor, device=device,
        biometric_type=request.data.get("biometric_type", "FINGERPRINT"),
        template_data=request.data.get("template_data", b""),
        quality_score=request.data.get("quality_score"),
        finger_index=request.data.get("finger_index"),
        enrolled_by=request.user,
    )
    log_action(request.user, "CREATE", "BiometricTemplate", template.id,
               f"Biometric enrolled: {template.biometric_type}", request)
    return ok({"id": str(template.id)}, message="Biometric enrolled.", status_code=status.HTTP_201_CREATED)


@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def biometric_revoke(request, biometric_id):
    """DELETE /api/biometrics/<id>/revoke/ — deactivate a biometric template."""
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    template = get_object_or_404(BiometricTemplate, id=biometric_id)
    template.is_active = False
    template.save(update_fields=["is_active"])
    return ok(message="Biometric template deactivated.")


# =============================================================================
# 33. VISITOR DOCUMENTS
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def visitor_document_list_create(request):
    """GET /api/visits/<id>/documents/ | POST — upload signed document."""
    visit_id = request.data.get("visit_id") or request.GET.get("visit_id")
    visit = get_object_or_404(Visit, id=visit_id)
    if request.method == "GET":
        docs = VisitorDocument.objects.filter(visit=visit)
        return ok([{
            "id": str(d.id), "document_type": d.document_type,
            "is_signed": d.is_signed, "signed_at": d.signed_at,
            "signed_document": d.signed_document.url if d.signed_document else None,
        } for d in docs])
    doc = VisitorDocument.objects.create(
        estate=visit.estate, visit=visit,
        document_type=request.data.get("document_type", "NDA"),
        is_signed=request.data.get("is_signed", False),
        signed_at=timezone.now() if request.data.get("is_signed") else None,
        ip_address=request.META.get("REMOTE_ADDR"),
    )
    if "signed_document" in request.FILES:
        doc.signed_document = request.FILES["signed_document"]
        doc.save()
    if "signature_image" in request.FILES:
        doc.signature_image = request.FILES["signature_image"]
        doc.save()
    return ok({"id": str(doc.id)}, message="Document recorded.", status_code=status.HTTP_201_CREATED)


# =============================================================================
# 34. COMMON AREAS
# =============================================================================

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def common_area_list_create(request):
    """GET /api/common-areas/?estate= | POST /api/common-areas/"""
    if request.method == "GET":
        qs = CommonArea.objects.filter(estate=request.user.estate)
        return ok([{
            "id": str(a.id), "name": a.name, "area_type": a.area_type,
            "capacity": a.capacity, "access_controlled": a.access_controlled,
            "description": a.description,
        } for a in qs])
    if not is_admin(request.user):
        return err("Permission denied.", status_code=status.HTTP_403_FORBIDDEN)
    area = CommonArea.objects.create(
        estate=request.user.estate,
        name=request.data.get("name"),
        area_type=request.data.get("area_type", "OTHER"),
        capacity=request.data.get("capacity"),
        access_controlled=request.data.get("access_controlled", False),
        description=request.data.get("description", ""),
    )
    return ok({"id": str(area.id)}, message="Common area created.", status_code=status.HTTP_201_CREATED)


# =============================================================================
# 35. HEALTH CHECK
# =============================================================================

@api_view(["GET"])
@permission_classes([AllowAny])
def health_check(request):
    """GET /api/health/ — basic liveness probe."""
    return ok({"status": "ok", "timestamp": timezone.now()}, message="VMS API is running.")


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def api_info(request):
    """GET /api/info/ — API meta info for authenticated user."""
    return ok({
        "version": "1.0.0",
        "user": _user_dict(request.user),
        "estate": _estate_dict(request.user.estate),
        "server_time": timezone.now(),
        "features": {
            "biometrics": True,
            "qr_checkin": True,
            "otp_checkin": True,
            "card_access": True,
            "parking": True,
            "deliveries": True,
            "emergency": True,
            "webhooks": True,
        },
    })