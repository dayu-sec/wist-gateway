use wist_control::AdminShowAgentRuntimeStatus;

pub struct WarpGatewayManagementInterface;

impl WarpGatewayManagementInterface {
    pub fn route() -> (&'static str, &'static str) {
        ("GET", "/api/v1/admin/agents/{agent_id}/runtime-status")
    }
}

pub fn handler(_input: AdminShowAgentRuntimeStatus) -> Result<(), crate::AppError> {
    todo!()
}
