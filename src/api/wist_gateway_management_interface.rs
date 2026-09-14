// @jumo generated
// @jumo hash=5cd0b68d5b14ca27

use insight_control::AdminShowAgentRuntimeStatus;

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "interface", domain = "Control", module = "Control.GatewayApp.UserFacingInterface")]
pub struct WarpGateWayManagementInterface;

impl WarpGateWayManagementInterface {
    pub fn route() -> (&'static str, &'static str) {
        ("GET", "/api/v1/admin/agents/{agent_id}/runtime-status")
    }
}

pub fn handler(_input: AdminShowAgentRuntimeStatus) -> Result<(), crate::AppError> {
    todo!()
}
