// @jumo generated
// @jumo hash=8c5f4e01d1ad3c4e

use insight_control::AdminGetAgentInstallCode;

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "interface", domain = "Control", module = "Control.GatewayApp.UserFacingInterface")]
pub struct WarpGateWayPublicInstallInterface;

impl WarpGateWayPublicInstallInterface {
    pub fn route() -> (&'static str, &'static str) {
        ("GET", "/api/v1/agent/install-code")
    }
}

pub fn handler(_input: AdminGetAgentInstallCode) -> Result<(), crate::AppError> {
    todo!()
}
