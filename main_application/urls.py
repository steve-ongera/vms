
from django.urls import path
from . import views

app_name = "vms"

urlpatterns = [

    # =========================================================================
    # SYSTEM / HEALTH
    # =========================================================================
    path("health/",                     views.health_check,                  name="health-check"),
    path("info/",                       views.api_info,                      name="api-info"),

    # =========================================================================
    # AUTHENTICATION
    # =========================================================================
    path("auth/login/",                 views.login_view,                    name="auth-login"),
    path("auth/logout/",                views.logout_view,                   name="auth-logout"),
    path("auth/token/refresh/",         views.token_refresh_view,            name="auth-token-refresh"),
    path("auth/change-password/",       views.change_password_view,          name="auth-change-password"),
    path("auth/me/",                    views.me_view,                       name="auth-me"),
    path("auth/push-token/",            views.update_push_token_view,        name="auth-push-token"),

    # =========================================================================
    # USERS
    # =========================================================================
    path("users/",                      views.user_list_create,              name="user-list"),
    path("users/<uuid:user_id>/",       views.user_detail,                   name="user-detail"),
    path("users/<uuid:user_id>/verify/",views.verify_user_view,              name="user-verify"),

    # =========================================================================
    # RESIDENT PROFILES
    # =========================================================================
    path("residents/",                              views.resident_profile_list_create,  name="resident-list"),
    path("residents/<uuid:profile_id>/",            views.resident_profile_detail,       name="resident-detail"),

    # =========================================================================
    # ESTATES
    # =========================================================================
    path("estates/",                    views.estate_list_create,            name="estate-list"),
    path("estates/<uuid:estate_id>/",   views.estate_detail,                 name="estate-detail"),
    path("estates/<uuid:estate_id>/stats/", views.estate_stats,              name="estate-stats"),

    # =========================================================================
    # BLOCKS
    # =========================================================================
    path("blocks/",                     views.block_list_create,             name="block-list"),
    path("blocks/<uuid:block_id>/",     views.block_detail,                  name="block-detail"),

    # =========================================================================
    # UNITS / FLATS
    # =========================================================================
    path("units/",                      views.unit_list_create,              name="unit-list"),
    path("units/<uuid:unit_id>/",       views.unit_detail,                   name="unit-detail"),

    # =========================================================================
    # VISITORS
    # =========================================================================
    path("visitors/",                               views.visitor_list_create,       name="visitor-list"),
    path("visitors/<uuid:visitor_id>/",             views.visitor_detail,            name="visitor-detail"),
    path("visitors/<uuid:visitor_id>/verify-id/",   views.verify_visitor_id,         name="visitor-verify-id"),
    path("visitors/<uuid:visitor_id>/flag/",        views.flag_visitor,              name="visitor-flag"),
    path("visitors/<uuid:visitor_id>/visits/",      views.visitor_visit_history,     name="visitor-visits"),

    # =========================================================================
    # VISITS  (CORE)
    # =========================================================================
    # Action endpoints BEFORE parameterised detail to avoid UUID conflicts
    path("visits/qr-checkin/",                      views.qr_checkin,                name="visit-qr-checkin"),
    path("visits/otp-checkin/",                     views.otp_checkin,               name="visit-otp-checkin"),

    path("visits/",                                 views.visit_list_create,         name="visit-list"),
    path("visits/<uuid:visit_id>/",                 views.visit_detail,              name="visit-detail"),
    path("visits/<uuid:visit_id>/approve/",         views.visit_approve,             name="visit-approve"),
    path("visits/<uuid:visit_id>/deny/",            views.visit_deny,                name="visit-deny"),
    path("visits/<uuid:visit_id>/checkin/",         views.visit_checkin,             name="visit-checkin"),
    path("visits/<uuid:visit_id>/checkout/",        views.visit_checkout,            name="visit-checkout"),
    path("visits/<uuid:visit_id>/cancel/",          views.visit_cancel,              name="visit-cancel"),
    path("visits/<uuid:visit_id>/issue-badge/",     views.issue_badge,               name="visit-issue-badge"),
    path("visits/<uuid:visit_id>/return-badge/",    views.return_badge,              name="visit-return-badge"),
    path("visits/<uuid:visit_id>/feedback/",        views.submit_feedback,           name="visit-feedback"),
    path("visits/<uuid:visit_id>/documents/",       views.visitor_document_list_create, name="visit-documents"),

    # =========================================================================
    # PRE-REGISTRATIONS
    # =========================================================================
    path("pre-registrations/",                              views.pre_registration_list_create,  name="prereg-list"),
    path("pre-registrations/<uuid:prereg_id>/",             views.pre_registration_detail,       name="prereg-detail"),
    path("pre-registrations/<uuid:prereg_id>/regenerate-otp/", views.regenerate_otp,            name="prereg-regen-otp"),

    # =========================================================================
    # ZONES
    # =========================================================================
    path("zones/",                      views.zone_list_create,              name="zone-list"),
    path("zones/<uuid:zone_id>/",       views.zone_detail,                   name="zone-detail"),

    # =========================================================================
    # GATES
    # =========================================================================
    path("gates/",                              views.gate_list_create,      name="gate-list"),
    path("gates/<uuid:gate_id>/",               views.gate_detail,           name="gate-detail"),
    path("gates/<uuid:gate_id>/toggle/",        views.gate_toggle,           name="gate-toggle"),

    # =========================================================================
    # ACCESS PERMISSIONS
    # =========================================================================
    path("access-permissions/",                         views.access_permission_list_create,  name="access-perm-list"),
    path("access-permissions/<uuid:perm_id>/revoke/",   views.access_permission_revoke,       name="access-perm-revoke"),

    # =========================================================================
    # HARDWARE DEVICES
    # =========================================================================
    path("devices/",                                views.device_list_create,        name="device-list"),
    path("devices/<uuid:device_id>/",               views.device_detail,             name="device-detail"),
    path("devices/<uuid:device_id>/heartbeat/",     views.device_heartbeat,          name="device-heartbeat"),
    path("devices/<uuid:device_id>/push-event/",    views.device_push_event,         name="device-push-event"),

    # =========================================================================
    # BIOMETRIC TEMPLATES
    # =========================================================================
    path("biometrics/",                             views.biometric_list_create,     name="biometric-list"),
    path("biometrics/<uuid:biometric_id>/revoke/",  views.biometric_revoke,          name="biometric-revoke"),

    # =========================================================================
    # ACCESS CARDS
    # =========================================================================
    path("cards/",                              views.card_list_create,      name="card-list"),
    path("cards/<uuid:card_id>/revoke/",        views.card_revoke,           name="card-revoke"),

    # =========================================================================
    # ACCESS EVENTS (Hardware Log)
    # =========================================================================
    path("access-events/",                              views.access_event_list,         name="access-event-list"),
    path("access-events/<uuid:event_id>/acknowledge/",  views.access_event_acknowledge,  name="access-event-ack"),

    # =========================================================================
    # NOTIFICATIONS
    # =========================================================================
    path("notifications/",                          views.my_notifications,              name="notification-list"),
    path("notifications/read-all/",                 views.mark_all_notifications_read,   name="notification-read-all"),
    path("notifications/<uuid:notif_id>/read/",     views.mark_notification_read,        name="notification-read"),
    path("notification-templates/",                 views.notification_template_list_create, name="notif-template-list"),

    # =========================================================================
    # BLACKLIST
    # =========================================================================
    path("blacklist/",                          views.blacklist_list_create,     name="blacklist-list"),
    path("blacklist/check/",                    views.blacklist_check,           name="blacklist-check"),
    path("blacklist/<uuid:blacklist_id>/",       views.blacklist_detail,          name="blacklist-detail"),

    # =========================================================================
    # WATCHLIST
    # =========================================================================
    path("watchlist/",                          views.watchlist_list_create,     name="watchlist-list"),
    path("watchlist/<uuid:watchlist_id>/",       views.watchlist_remove,          name="watchlist-remove"),

    # =========================================================================
    # VEHICLES
    # =========================================================================
    path("vehicles/",                           views.vehicle_list_create,       name="vehicle-list"),
    path("vehicles/<uuid:vehicle_id>/",         views.vehicle_detail,            name="vehicle-detail"),

    # =========================================================================
    # PARKING
    # =========================================================================
    path("parking/slots/",                          views.parking_slot_list,         name="parking-slots"),
    path("parking/sessions/start/",                 views.parking_session_start,     name="parking-session-start"),
    path("parking/sessions/<uuid:session_id>/end/", views.parking_session_end,       name="parking-session-end"),

    # =========================================================================
    # DELIVERIES
    # =========================================================================
    path("deliveries/",                             views.delivery_list_create,      name="delivery-list"),
    path("deliveries/<uuid:delivery_id>/status/",   views.delivery_update_status,    name="delivery-status"),

    # =========================================================================
    # CONTRACTORS
    # =========================================================================
    path("contractors/",                                views.contractor_list_create,    name="contractor-list"),
    path("contractors/<uuid:contractor_id>/approve/",   views.contractor_approve,        name="contractor-approve"),

    # =========================================================================
    # WORK ORDERS
    # =========================================================================
    path("work-orders/",                            views.work_order_list_create,    name="work-order-list"),
    path("work-orders/<uuid:wo_id>/approve/",       views.work_order_approve,        name="work-order-approve"),

    # =========================================================================
    # INCIDENTS
    # =========================================================================
    path("incidents/",                          views.incident_list_create,      name="incident-list"),
    path("incidents/<uuid:incident_id>/",       views.incident_detail,           name="incident-detail"),

    # =========================================================================
    # AUDIT LOGS  (read-only)
    # =========================================================================
    path("audit-logs/",                         views.audit_log_list,            name="audit-log-list"),

    # =========================================================================
    # ANALYTICS & REPORTS
    # =========================================================================
    path("analytics/dashboard/",                views.dashboard_stats,           name="analytics-dashboard"),
    path("analytics/daily/",                    views.daily_report_list,         name="analytics-daily"),
    path("analytics/visits/trends/",            views.visit_trends,              name="analytics-trends"),

    # =========================================================================
    # EMERGENCY
    # =========================================================================
    path("emergency/",                          views.emergency_alert_list_create,   name="emergency-list"),
    path("emergency/active/",                   views.active_emergency,              name="emergency-active"),
    path("emergency/<uuid:alert_id>/resolve/",  views.emergency_resolve,             name="emergency-resolve"),
    path("emergency/<uuid:alert_id>/muster/",   views.muster_record,                 name="emergency-muster"),

    # =========================================================================
    # WEBHOOKS
    # =========================================================================
    path("webhooks/",                           views.webhook_list_create,       name="webhook-list"),
    path("webhooks/<uuid:webhook_id>/",         views.webhook_detail,            name="webhook-detail"),

    # =========================================================================
    # THIRD-PARTY INTEGRATIONS
    # =========================================================================
    path("integrations/",                       views.integration_list_create,   name="integration-list"),

    # =========================================================================
    # BILLING & SUBSCRIPTIONS
    # =========================================================================
    path("billing/plans/",                      views.subscription_plan_list,    name="billing-plans"),
    path("billing/my-subscription/",            views.my_subscription,           name="billing-subscription"),

    # =========================================================================
    # SYSTEM SETTINGS
    # =========================================================================
    path("settings/",                           views.system_settings_list_create, name="settings-list"),

    # =========================================================================
    # COMMON AREAS
    # =========================================================================
    path("common-areas/",                       views.common_area_list_create,   name="common-area-list"),
]