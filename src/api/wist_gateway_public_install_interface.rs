use wist_control::AdminGetAgentInstallCode;

pub struct WarpGatewayPublicInstallInterface;

impl WarpGatewayPublicInstallInterface {
    pub fn route() -> (&'static str, &'static str) {
        ("GET", "/api/v1/agent/install-code")
    }
}

pub fn handler(_input: AdminGetAgentInstallCode) -> Result<(), crate::AppError> {
    todo!()
}
