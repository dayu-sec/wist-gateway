// @jumo generated
// @jumo hash=91638372490551d3

// seam 报文只有一份定义：`wist-api::enrollment`（独立 seam crate，两侧共依赖）。
// 模型里的 `SubmitEnrollmentRequest` 在 control 侧的生成骨架已删除，避免同一条 seam 两份定义。
use wist_api::enrollment::EnrollmentRequest as SubmitEnrollmentRequest;

#[derive(::jumo_derive::Jumo)]
#[jumo(
    kind = "interface",
    domain = "Control",
    module = "Control.AgentApp.FacingInterface"
)]
pub struct WistAgentdOnlineRegistrationInterface;

impl WistAgentdOnlineRegistrationInterface {
    pub fn route() -> (&'static str, &'static str) {
        ("POST", "/api/v1/agent/enroll")
    }
}

pub fn handler(_input: SubmitEnrollmentRequest) -> Result<(), crate::AppError> {
    todo!()
}
