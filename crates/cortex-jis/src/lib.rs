//! TIBET Cortex JIS — Multi-dimensional Joint Identity Sectors
//!
//! JIS is not a single number. It's a multi-dimensional identity claim:
//! - **Role**: partner, analyst, intern
//! - **Department**: strategy, finance, engineering
//! - **Clearance**: numeric level 0-255
//! - **Time**: valid_from / valid_until
//! - **Geo**: country/region restrictions
//!
//! All dimensions must match for access. A partner in strategy with
//! clearance 3 in the EU can access different data than a partner
//! in finance with clearance 3 in the US.

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

/// A JIS identity claim — multi-dimensional access credential
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JisClaim {
    /// Who is making this claim
    pub actor: String,

    /// Numeric clearance level (0 = public, 255 = max)
    pub clearance: u8,

    /// Role within organization
    pub role: Option<String>,

    /// Department / business unit
    pub department: Option<String>,

    /// Geographic restriction (ISO 3166-1 alpha-2)
    pub geo: Option<Vec<String>>,

    /// Claim valid from
    pub valid_from: Option<DateTime<Utc>>,

    /// Claim valid until
    pub valid_until: Option<DateTime<Utc>>,

    /// Ed25519 signature over the claim (proves authenticity)
    pub signature: Option<Vec<u8>>,
}

/// A JIS policy attached to data — defines who can access it
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JisPolicy {
    /// Minimum clearance level required
    pub min_clearance: u8,

    /// Required roles (any of these, empty = any role)
    pub allowed_roles: Vec<String>,

    /// Required departments (any of these, empty = any dept)
    pub allowed_departments: Vec<String>,

    /// Allowed geos (empty = worldwide)
    pub allowed_geos: Vec<String>,

    /// Time-based: data available from
    pub available_from: Option<DateTime<Utc>>,

    /// Time-based: data available until (expiry)
    pub available_until: Option<DateTime<Utc>>,
}

/// Result of a JIS evaluation — detailed access decision
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JisVerdict {
    pub allowed: bool,
    pub claim_actor: String,
    pub denials: Vec<JisDenialReason>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum JisDenialReason {
    ClearanceTooLow { required: u8, actual: u8 },
    RoleNotAllowed { actor_role: String, allowed: Vec<String> },
    DepartmentNotAllowed { actor_dept: String, allowed: Vec<String> },
    GeoRestricted { actor_geo: Vec<String>, allowed: Vec<String> },
    ClaimExpired { expired_at: DateTime<Utc> },
    ClaimNotYetValid { valid_from: DateTime<Utc> },
    DataNotYetAvailable { available_from: DateTime<Utc> },
    DataExpired { expired_at: DateTime<Utc> },
}

/// The JIS Gate — evaluates claims against policies
pub struct JisGate;

impl JisGate {
    /// Evaluate a claim against a policy. Returns a detailed verdict.
    pub fn evaluate(claim: &JisClaim, policy: &JisPolicy) -> JisVerdict {
        let mut denials = Vec::new();
        let now = Utc::now();

        // 1. Clearance level check
        if claim.clearance < policy.min_clearance {
            denials.push(JisDenialReason::ClearanceTooLow {
                required: policy.min_clearance,
                actual: claim.clearance,
            });
        }

        // 2. Role check
        if !policy.allowed_roles.is_empty() {
            if let Some(ref role) = claim.role {
                if !policy.allowed_roles.iter().any(|r| r == role) {
                    denials.push(JisDenialReason::RoleNotAllowed {
                        actor_role: role.clone(),
                        allowed: policy.allowed_roles.clone(),
                    });
                }
            } else {
                denials.push(JisDenialReason::RoleNotAllowed {
                    actor_role: "<none>".into(),
                    allowed: policy.allowed_roles.clone(),
                });
            }
        }

        // 3. Department check
        if !policy.allowed_departments.is_empty() {
            if let Some(ref dept) = claim.department {
                if !policy.allowed_departments.iter().any(|d| d == dept) {
                    denials.push(JisDenialReason::DepartmentNotAllowed {
                        actor_dept: dept.clone(),
                        allowed: policy.allowed_departments.clone(),
                    });
                }
            } else {
                denials.push(JisDenialReason::DepartmentNotAllowed {
                    actor_dept: "<none>".into(),
                    allowed: policy.allowed_departments.clone(),
                });
            }
        }

        // 4. Geo check
        if !policy.allowed_geos.is_empty() {
            if let Some(ref geos) = claim.geo {
                if !geos.iter().any(|g| policy.allowed_geos.contains(g)) {
                    denials.push(JisDenialReason::GeoRestricted {
                        actor_geo: geos.clone(),
                        allowed: policy.allowed_geos.clone(),
                    });
                }
            } else {
                denials.push(JisDenialReason::GeoRestricted {
                    actor_geo: vec![],
                    allowed: policy.allowed_geos.clone(),
                });
            }
        }

        // 5. Claim time validity
        if let Some(valid_until) = claim.valid_until {
            if now > valid_until {
                denials.push(JisDenialReason::ClaimExpired {
                    expired_at: valid_until,
                });
            }
        }
        if let Some(valid_from) = claim.valid_from {
            if now < valid_from {
                denials.push(JisDenialReason::ClaimNotYetValid { valid_from });
            }
        }

        // 6. Data time availability
        if let Some(available_from) = policy.available_from {
            if now < available_from {
                denials.push(JisDenialReason::DataNotYetAvailable { available_from });
            }
        }
        if let Some(available_until) = policy.available_until {
            if now > available_until {
                denials.push(JisDenialReason::DataExpired {
                    expired_at: available_until,
                });
            }
        }

        JisVerdict {
            allowed: denials.is_empty(),
            claim_actor: claim.actor.clone(),
            denials,
        }
    }

    /// Simple check: is access allowed?
    pub fn is_allowed(claim: &JisClaim, policy: &JisPolicy) -> bool {
        Self::evaluate(claim, policy).allowed
    }
}

impl JisClaim {
    pub fn new(actor: impl Into<String>, clearance: u8) -> Self {
        Self {
            actor: actor.into(),
            clearance,
            role: None,
            department: None,
            geo: None,
            valid_from: None,
            valid_until: None,
            signature: None,
        }
    }

    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    pub fn with_department(mut self, dept: impl Into<String>) -> Self {
        self.department = Some(dept.into());
        self
    }

    pub fn with_geo(mut self, geos: Vec<String>) -> Self {
        self.geo = Some(geos);
        self
    }

    pub fn with_validity(mut self, from: DateTime<Utc>, until: DateTime<Utc>) -> Self {
        self.valid_from = Some(from);
        self.valid_until = Some(until);
        self
    }
}

impl JisPolicy {
    pub fn public() -> Self {
        Self {
            min_clearance: 0,
            allowed_roles: vec![],
            allowed_departments: vec![],
            allowed_geos: vec![],
            available_from: None,
            available_until: None,
        }
    }

    pub fn clearance(level: u8) -> Self {
        Self {
            min_clearance: level,
            ..Self::public()
        }
    }

    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.allowed_roles = roles;
        self
    }

    pub fn with_departments(mut self, depts: Vec<String>) -> Self {
        self.allowed_departments = depts;
        self
    }

    pub fn with_geos(mut self, geos: Vec<String>) -> Self {
        self.allowed_geos = geos;
        self
    }

    pub fn with_availability(
        mut self,
        from: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
    ) -> Self {
        self.available_from = from;
        self.available_until = until;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_public_access() {
        let claim = JisClaim::new("anyone@company.com", 0);
        let policy = JisPolicy::public();
        assert!(JisGate::is_allowed(&claim, &policy));
    }

    #[test]
    fn test_clearance_denied() {
        let claim = JisClaim::new("intern@company.com", 1);
        let policy = JisPolicy::clearance(3);

        let verdict = JisGate::evaluate(&claim, &policy);
        assert!(!verdict.allowed);
        assert!(matches!(
            verdict.denials[0],
            JisDenialReason::ClearanceTooLow { required: 3, actual: 1 }
        ));
    }

    #[test]
    fn test_role_gated() {
        let claim = JisClaim::new("analyst@company.com", 2)
            .with_role("analyst");
        let policy = JisPolicy::clearance(2)
            .with_roles(vec!["partner".into(), "director".into()]);

        let verdict = JisGate::evaluate(&claim, &policy);
        assert!(!verdict.allowed);
        assert!(matches!(
            verdict.denials[0],
            JisDenialReason::RoleNotAllowed { .. }
        ));
    }

    #[test]
    fn test_multi_dimensional_access() {
        // Partner, strategy, EU, clearance 3
        let claim = JisClaim::new("partner@mckinsey.com", 3)
            .with_role("partner")
            .with_department("strategy")
            .with_geo(vec!["NL".into(), "DE".into()]);

        // M&A doc: needs clearance 3, strategy dept, partner role, EU only
        let policy = JisPolicy::clearance(3)
            .with_roles(vec!["partner".into()])
            .with_departments(vec!["strategy".into()])
            .with_geos(vec!["NL".into(), "DE".into(), "FR".into()]);

        assert!(JisGate::is_allowed(&claim, &policy));
    }

    #[test]
    fn test_geo_restricted() {
        let claim = JisClaim::new("partner@mckinsey.com", 3)
            .with_role("partner")
            .with_geo(vec!["US".into()]);

        // EU-only document
        let policy = JisPolicy::clearance(2)
            .with_geos(vec!["NL".into(), "DE".into(), "FR".into()]);

        let verdict = JisGate::evaluate(&claim, &policy);
        assert!(!verdict.allowed);
        assert!(matches!(
            verdict.denials[0],
            JisDenialReason::GeoRestricted { .. }
        ));
    }

    #[test]
    fn test_expired_claim() {
        let yesterday = Utc::now() - Duration::days(1);
        let last_week = Utc::now() - Duration::days(7);

        let claim = JisClaim::new("temp@company.com", 2)
            .with_validity(last_week, yesterday); // Expired yesterday

        let policy = JisPolicy::clearance(1);

        let verdict = JisGate::evaluate(&claim, &policy);
        assert!(!verdict.allowed);
        assert!(matches!(
            verdict.denials[0],
            JisDenialReason::ClaimExpired { .. }
        ));
    }

    #[test]
    fn test_time_locked_data() {
        let next_week = Utc::now() + Duration::days(7);

        let claim = JisClaim::new("analyst@company.com", 3);
        let policy = JisPolicy::clearance(0)
            .with_availability(Some(next_week), None);

        let verdict = JisGate::evaluate(&claim, &policy);
        assert!(!verdict.allowed);
        assert!(matches!(
            verdict.denials[0],
            JisDenialReason::DataNotYetAvailable { .. }
        ));
    }

    #[test]
    fn test_multiple_denial_reasons() {
        let claim = JisClaim::new("intern@company.com", 0)
            .with_role("intern")
            .with_geo(vec!["US".into()]);

        let policy = JisPolicy::clearance(3)
            .with_roles(vec!["partner".into()])
            .with_geos(vec!["NL".into()]);

        let verdict = JisGate::evaluate(&claim, &policy);
        assert!(!verdict.allowed);
        assert_eq!(verdict.denials.len(), 3); // clearance + role + geo
    }
}
