#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// User role enum
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "varchar")]
pub enum UserRole {
    #[serde(rename = "guard")]
    Guard,
    #[serde(rename = "supervisor")]
    Supervisor,
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "superadmin")]
    Superadmin,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::Guard => write!(f, "guard"),
            UserRole::Supervisor => write!(f, "supervisor"),
            UserRole::Admin => write!(f, "admin"),
            UserRole::Superadmin => write!(f, "superadmin"),
        }
    }
}

impl std::str::FromStr for UserRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" | "guard" => Ok(UserRole::Guard),
            "supervisor" => Ok(UserRole::Supervisor),
            "admin" => Ok(UserRole::Admin),
            "superadmin" => Ok(UserRole::Superadmin),
            _ => Err(format!("Unknown role: {}", s)),
        }
    }
}

// User model
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password: String,
    pub role: String,
    pub full_name: String,
    pub phone_number: String,
    pub license_number: Option<String>,
    pub license_issued_date: Option<DateTime<Utc>>,
    pub license_expiry_date: Option<DateTime<Utc>>,
    pub address: Option<String>,
    pub profile_photo: Option<String>,
    pub verified: bool,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// User creation request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub username: String,
    pub role: String,
    pub full_name: String,
    pub phone_number: String,
    pub license_number: Option<String>,
    #[serde(default, with = "option_date_format")]
    pub license_issued_date: Option<DateTime<Utc>>,
    #[serde(default, with = "option_date_format")]
    pub license_expiry_date: Option<DateTime<Utc>>,
    pub address: Option<String>,
    pub admin_code: Option<String>,
}

// User response (without password)
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub username: String,
    pub role: String,
    pub full_name: String,
    pub phone_number: String,
    pub profile_photo: Option<String>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        UserResponse {
            id: user.id,
            email: user.email,
            username: user.username,
            role: user.role,
            full_name: user.full_name,
            phone_number: user.phone_number,
            profile_photo: user.profile_photo,
            last_seen_at: user.last_seen_at,
        }
    }
}

// Verification model
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Verification {
    pub id: String,
    pub user_id: String,
    pub code: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

// Audit log API models
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AuditLogEntry {
    pub id: String,
    pub actor_user_id: Option<String>,
    pub actor_name: Option<String>,
    pub actor_email: Option<String>,
    pub actor_role: Option<String>,
    pub action_key: String,
    pub entity_type: String,
    pub entity_id: Option<String>,
    pub result: String,
    pub reason: Option<String>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Option<Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct AuditLogPageMeta {
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
pub struct AuditLogListResponse {
    pub items: Vec<AuditLogEntry>,
    pub meta: AuditLogPageMeta,
}

// Firearm status enum
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FirearmStatus {
    Available,
    Allocated,
    Maintenance,
}

impl std::fmt::Display for FirearmStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirearmStatus::Available => write!(f, "available"),
            FirearmStatus::Allocated => write!(f, "allocated"),
            FirearmStatus::Maintenance => write!(f, "maintenance"),
        }
    }
}

// Firearm model
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Firearm {
    pub id: String,
    pub name: String,
    pub serial_number: String,
    pub model: String,
    pub caliber: String,
    pub status: String,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateFirearmRequest {
    pub serial_number: String,
    pub model: String,
    pub caliber: String,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFirearmRequest {
    pub status: Option<String>,
    pub caliber: Option<String>,
}

// Firearm Allocation model
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FirearmAllocation {
    pub id: String,
    pub guard_id: String,
    pub firearm_id: String,
    pub allocation_date: DateTime<Utc>,
    pub return_date: Option<DateTime<Utc>>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueFirearmRequest {
    pub firearm_id: String,
    pub guard_id: String,
    pub shift_id: Option<String>,
    pub issued_by: Option<String>,
    pub expected_return_date: Option<DateTime<Utc>>,
    pub notes: Option<String>,
    /// If true, skip permit/training checks (for admin override)
    pub force: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReturnFirearmRequest {
    pub allocation_id: String,
}

// Attendance model
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Attendance {
    pub id: String,
    pub guard_id: String,
    pub shift_id: String,
    pub check_in_time: DateTime<Utc>,
    pub check_out_time: Option<DateTime<Utc>>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Authentication requests
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub identifier: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyEmailRequest {
    pub email: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResendCodeRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyResetCodeRequest {
    pub email: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetPasswordRequest {
    pub email: String,
    pub code: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

// Guard Replacement related models
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Shift {
    pub id: String,
    pub guard_id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub client_site: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateShiftRequest {
    pub guard_id: String,
    pub start_time: String,
    pub end_time: String,
    pub client_site: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckInRequest {
    pub guard_id: String,
    pub shift_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckOutRequest {
    pub attendance_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestReplacementRequest {
    pub original_guard_id: String,
    pub replacement_guard_id: String,
    pub shift_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetAvailabilityRequest {
    pub guard_id: String,
    pub available: Option<bool>,
    pub available_from: Option<DateTime<Utc>>,
    pub available_to: Option<DateTime<Utc>>,
    pub notes: Option<String>,
}
// Armored Car models
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ArmoredCar {
    pub id: String,
    pub license_plate: String,
    pub vin: String,
    pub model: String,
    pub manufacturer: String,
    pub capacity_kg: i32,
    pub passenger_capacity: Option<i32>,
    pub status: String,
    pub registration_expiry: Option<DateTime<Utc>>,
    pub insurance_expiry: Option<DateTime<Utc>>,
    pub last_maintenance_date: Option<DateTime<Utc>>,
    pub mileage: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateArmoredCarRequest {
    pub license_plate: String,
    pub vin: String,
    pub model: String,
    pub manufacturer: String,
    pub capacity_kg: i32,
    pub passenger_capacity: Option<i32>,
    pub registration_expiry: Option<DateTime<Utc>>,
    pub insurance_expiry: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateArmoredCarRequest {
    pub status: Option<String>,
    pub mileage: Option<i32>,
    pub registration_expiry: Option<DateTime<Utc>>,
    pub insurance_expiry: Option<DateTime<Utc>>,
}

// Car Allocation model
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CarAllocation {
    pub id: String,
    pub car_id: String,
    pub client_id: String,
    pub allocation_date: DateTime<Utc>,
    pub return_date: Option<DateTime<Utc>>,
    pub expected_return_date: Option<DateTime<Utc>>,
    pub status: String,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCarRequest {
    pub car_id: String,
    pub client_id: String,
    pub expected_return_date: Option<DateTime<Utc>>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReturnCarRequest {
    pub allocation_id: String,
}

// Car Maintenance model
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CarMaintenance {
    pub id: String,
    pub car_id: Option<String>,
    pub maintenance_type: Option<String>,
    pub description: Option<String>,
    pub cost: Option<f64>, // DB column is NUMERIC; queried with ::FLOAT8 cast
    pub scheduled_date: Option<DateTime<Utc>>,
    pub completion_date: Option<DateTime<Utc>>,
    pub status: Option<String>,
    pub notes: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateMaintenanceRequest {
    pub car_id: String,
    pub maintenance_type: String,
    pub description: String,
    pub scheduled_date: Option<DateTime<Utc>>,
    /// Accepts a numeric string (e.g. "5000") or null — stored as text in car_maintenance.cost
    pub cost: Option<String>,
}

// Driver Assignment model
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DriverAssignment {
    pub id: String,
    pub car_id: String,
    pub guard_id: String,
    pub assignment_date: DateTime<Utc>,
    pub end_date: Option<DateTime<Utc>>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignDriverRequest {
    pub car_id: String,
    pub guard_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Incident {
    pub id: String,
    pub title: String,
    pub description: String,
    pub location: String,
    pub reported_by: String,
    pub reported_by_name: Option<String>,
    pub status: String,
    pub priority: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateIncidentRequest {
    pub title: String,
    pub description: String,
    pub location: String,
    pub priority: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateIncidentStatusRequest {
    pub status: String,
}

// Trip model
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Trip {
    pub id: String,
    pub car_id: Option<String>,
    pub driver_id: Option<String>,
    pub allocation_id: Option<String>,
    pub start_location: Option<String>,
    pub end_location: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub distance_km: Option<f64>, // DB column is NUMERIC; EndTripRequest uses Option<String> for parsing
    pub status: Option<String>,
    pub mission_details: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTripRequest {
    pub car_id: String,
    pub driver_id: String,
    pub allocation_id: Option<String>,
    pub start_location: String,
    pub mission_details: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndTripRequest {
    pub trip_id: String,
    pub end_location: String,
    /// Accepts a string (e.g. "8.5") so frontend/scripts don't need to cast to float.
    /// The column type is DECIMAL but sqlx will coerce the string.
    pub distance_km: Option<String>,
}

// Guard permit model
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GuardFirearmPermit {
    pub id: String,
    pub guard_id: String,
    pub firearm_id: Option<String>,
    pub permit_type: String,
    pub issued_date: DateTime<Utc>,
    pub expiry_date: DateTime<Utc>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateGuardFirearmPermitRequest {
    pub guard_id: String,
    pub firearm_id: Option<String>,
    pub permit_type: String,
    pub issued_date: DateTime<Utc>,
    pub expiry_date: DateTime<Utc>,
    pub status: Option<String>,
}

// Guard allocation view with firearm details
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GuardAllocationView {
    pub id: String,
    pub guard_id: String,
    pub firearm_id: String,
    pub allocation_date: DateTime<Utc>,
    pub return_date: Option<DateTime<Utc>>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub firearm_model: String,
    pub firearm_caliber: String,
    pub firearm_serial_number: String,
}

// Support ticket model
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SupportTicket {
    pub id: String,
    pub guard_id: String,
    pub subject: String,
    pub message: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSupportTicketRequest {
    #[serde(alias = "guardId")]
    pub guard_id: String,
    pub subject: String,
    pub message: String,
}

// Notification model for web-based notification system
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Notification {
    pub id: String,
    pub user_id: String,
    pub title: String,
    pub message: String,
    #[serde(rename = "type")]
    pub notification_type: String,
    pub related_shift_id: Option<String>,
    pub read: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateNotificationRequest {
    pub user_id: String,
    pub title: String,
    pub message: String,
    #[serde(rename = "type")]
    pub notification_type: String,
    pub related_shift_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkNotificationReadRequest {
    pub notification_id: String,
}

// Guard availability model
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct GuardAvailability {
    pub id: String,
    pub guard_id: String,
    pub available: bool,
    pub available_from: Option<DateTime<Utc>>,
    pub available_to: Option<DateTime<Utc>>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateGuardAvailabilityRequest {
    pub guard_id: String,
    pub available: bool,
    pub available_from: Option<DateTime<Utc>>,
    pub available_to: Option<DateTime<Utc>>,
    pub notes: Option<String>,
}

// Merit Score System Models (Requirement 2)

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct GuardMeritScore {
    pub id: String,
    pub guard_id: String,
    pub attendance_score: f64,
    pub punctuality_score: f64,
    pub client_rating: f64,
    pub overall_score: f64,
    pub rank: Option<String>,
    pub total_shifts_completed: Option<i32>,
    pub on_time_count: Option<i32>,
    pub late_count: Option<i32>,
    pub no_show_count: Option<i32>,
    pub average_client_rating: Option<f64>,
    pub evaluation_count: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_calculated_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CalculateMeritScoreRequest {
    pub guard_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct ClientEvaluation {
    pub id: String,
    pub guard_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shift_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mission_id: Option<String>,
    pub evaluator_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluator_role: Option<String>,
    pub rating: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateClientEvaluationRequest {
    pub guard_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shift_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mission_id: Option<String>,
    pub evaluator_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluator_role: Option<String>,
    pub rating: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct PunctualityRecord {
    pub id: String,
    pub guard_id: String,
    pub shift_id: String,
    pub scheduled_start_time: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_check_in_time: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minutes_late: Option<i32>,
    pub is_on_time: bool,
    pub status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeritScoreResponse {
    pub guard_id: String,
    pub guard_name: Option<String>,
    pub overall_score: f64,
    pub rank: Option<String>,
    pub attendance_score: f64,
    pub punctuality_score: f64,
    pub client_rating: f64,
    pub stats: MeritStats,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeritStats {
    pub total_shifts: i32,
    pub on_time_count: i32,
    pub late_count: i32,
    pub no_show_count: i32,
    pub evaluations: i32,
    pub average_rating: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RankedGuardResponse {
    pub rank: i32,
    pub guard_id: String,
    pub guard_name: Option<String>,
    pub overall_score: f64,
    pub merit_rank: Option<String>,
    pub on_time_percentage: f64,
    pub client_rating: f64,
}

// ── Requirement 3: Firearm Maintenance ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct FirearmMaintenance {
    pub id: String,
    pub firearm_id: String,
    pub maintenance_type: String,
    pub description: String,
    pub scheduled_date: DateTime<Utc>,
    pub completion_date: Option<DateTime<Utc>>,
    pub performed_by: Option<String>,
    pub cost: Option<String>,
    pub status: String,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateFirearmMaintenanceRequest {
    pub firearm_id: String,
    pub maintenance_type: String,
    pub description: String,
    pub scheduled_date: DateTime<Utc>,
    pub performed_by: Option<String>,
    pub cost: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteFirearmMaintenanceRequest {
    pub performed_by: Option<String>,
    pub cost: Option<String>,
    pub notes: Option<String>,
}

// ── Requirement 3: Training Records ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct TrainingRecord {
    pub id: String,
    pub guard_id: String,
    pub training_type: String,
    pub completed_date: DateTime<Utc>,
    pub expiry_date: Option<DateTime<Utc>>,
    pub certificate_number: Option<String>,
    pub status: String,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTrainingRecordRequest {
    pub guard_id: String,
    pub training_type: String,
    pub completed_date: DateTime<Utc>,
    pub expiry_date: Option<DateTime<Utc>>,
    pub certificate_number: Option<String>,
    pub notes: Option<String>,
}

// Phase 1: AI-assisted operational intelligence models.

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct GuardAbsencePrediction {
    pub id: String,
    pub guard_id: String,
    pub prediction_window_hours: i32,
    pub risk_score: f64,
    pub risk_level: String,
    pub confidence_score: f64,
    pub explanation: Value,
    pub contributing_factors: Value,
    pub source_snapshot: Value,
    pub generated_at: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub feature_version: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct SmartGuardReplacement {
    pub id: String,
    pub shift_id: String,
    pub absent_guard_id: Option<String>,
    pub recommended_guard_id: Option<String>,
    pub recommendation_rank: i32,
    pub compatibility_score: f64,
    pub confidence_score: f64,
    pub rationale: String,
    pub scoring_breakdown: Value,
    pub candidate_pool: Value,
    pub recommendation_status: String,
    pub generated_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub feature_version: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct IncidentSeverityClassification {
    pub id: String,
    pub incident_id: String,
    pub predicted_severity: String,
    pub confidence_score: f64,
    pub requires_human_review: bool,
    pub rationale: String,
    pub feature_scores: Value,
    pub supporting_signals: Value,
    pub classified_at: DateTime<Utc>,
    pub classifier_version: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct PredictiveVehicleMaintenance {
    pub id: String,
    pub car_id: String,
    pub risk_score: f64,
    pub risk_level: String,
    pub days_to_service: Option<i32>,
    pub predicted_failure_window_days: Option<i32>,
    pub recommended_action: String,
    pub rationale: String,
    pub signal_snapshot: Value,
    pub maintenance_type_suggestion: Option<String>,
    pub generated_at: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub feature_version: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct AiIncidentSummary {
    pub id: String,
    pub incident_id: String,
    pub summary_kind: String,
    pub summary_text: String,
    pub concise_headline: Option<String>,
    pub key_points: Value,
    pub action_items: Value,
    pub entities: Value,
    pub confidence_score: f64,
    pub explainability: Value,
    pub source_event_count: i32,
    pub generated_at: DateTime<Utc>,
    pub summarizer_version: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Custom serde module for parsing date strings (YYYY-MM-DD) into DateTime<Utc>
mod option_date_format {
    use chrono::{DateTime, NaiveDate, Utc};
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            None => Ok(None),
            Some(date_str) => {
                // Handle empty strings as None
                if date_str.trim().is_empty() {
                    return Ok(None);
                }

                // Parse YYYY-MM-DD format
                let naive_date = NaiveDate::parse_from_str(&date_str, "%Y-%m-%d")
                    .map_err(serde::de::Error::custom)?;

                // Convert to NaiveDateTime with time 00:00:00
                let naive_datetime = naive_date
                    .and_hms_opt(0, 0, 0)
                    .ok_or_else(|| serde::de::Error::custom("Invalid datetime"))?;

                // Convert to DateTime<Utc>
                Ok(Some(DateTime::<Utc>::from_naive_utc_and_offset(
                    naive_datetime,
                    Utc,
                )))
            }
        }
    }
}

// ═══ MDR Integration Models ═══

// Client entity (first-class business client)
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Client {
    pub id: String,
    pub name: String,
    pub address: Option<String>,
    pub phone: Option<String>,
    pub client_number: Option<i32>,
    pub branch: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Guard assignment (guard-to-client posting)
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GuardAssignment {
    pub id: String,
    pub guard_id: String,
    pub client_id: String,
    pub client_site_id: Option<String>,
    pub post_label: Option<String>,
    pub guard_number: Option<i32>,
    pub assignment_start: Option<DateTime<Utc>>,
    pub assignment_end: Option<DateTime<Utc>>,
    pub status: String,
    pub mdr_batch_id: Option<String>,
    pub mdr_row_ref: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Guard status transition (pull-out history)
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GuardStatusTransition {
    pub id: String,
    pub guard_id: String,
    pub transition_type: String,
    pub reason: Option<String>,
    pub previous_client_id: Option<String>,
    pub effective_date: Option<DateTime<Utc>>,
    pub mdr_batch_id: Option<String>,
    pub mdr_row_ref: Option<String>,
    pub recorded_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

// Equipment (non-firearm gear)
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Equipment {
    pub id: String,
    pub equipment_type: String,
    pub description: Option<String>,
    pub serial_number: Option<String>,
    pub assigned_to_client_id: Option<String>,
    pub assigned_to_guard_id: Option<String>,
    pub quantity: i32,
    pub status: String,
    pub mdr_batch_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// MDR import batch audit trail
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MdrImportBatch {
    pub id: String,
    pub filename: String,
    pub report_month: String,
    pub branch: Option<String>,
    pub uploaded_by: String,
    pub status: String,
    pub total_rows: Option<i32>,
    pub matched_rows: Option<i32>,
    pub new_rows: Option<i32>,
    pub ambiguous_rows: Option<i32>,
    pub error_rows: Option<i32>,
    pub pending_rows: Option<i32>,
    pub committed_at: Option<DateTime<Utc>>,
    pub committed_by: Option<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

// MDR staging row (raw parsed Excel data)
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MdrStagingRow {
    pub id: String,
    pub batch_id: String,
    pub sheet_name: String,
    pub row_number: i32,
    pub section: Option<String>,
    pub client_number: Option<i32>,
    pub client_name: Option<String>,
    pub client_address: Option<String>,
    pub guard_number: Option<i32>,
    pub guard_name: Option<String>,
    pub contact_number: Option<String>,
    pub license_number: Option<String>,
    pub license_expiry: Option<String>,
    pub firearm_kind: Option<String>,
    pub firearm_make: Option<String>,
    pub caliber: Option<String>,
    pub serial_number: Option<String>,
    pub firearm_validity: Option<String>,
    pub actual_ammo: Option<String>,
    pub ammo_count: Option<String>,
    pub lic_reg_name: Option<String>,
    pub pullout_status: Option<String>,
    pub fa_remarks: Option<String>,
    pub match_status: String,
    pub matched_guard_id: Option<String>,
    pub matched_firearm_id: Option<String>,
    pub matched_client_id: Option<String>,
    pub validation_errors: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}
