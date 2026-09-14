// @jumo generated
// @jumo hash=91638372490551d3

use insight_control::SubmitEnrollmentRequest;

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "interface", domain = "Control", module = "Control.AgentApp.FacingInterface")]
pub struct WpAgentOnlineRegistrationInterface;

impl WpAgentOnlineRegistrationInterface {
    pub fn route() -> (&'static str, &'static str) {
        ("POST", "/api/v1/agent/enroll")
    }
}

pub fn handler(_input: SubmitEnrollmentRequest) -> Result<(), crate::AppError> {
    todo!()
}
