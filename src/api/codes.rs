//! 管理面 API 错误的**稳定 code 词表**（设计 `foundation/error-handling-system.md` §6.3）。
//!
//! 这里是所有 `{ "error": { "code": … } }` 响应里 `code` 的**唯一来源**：调用点只引用本模块常量，
//! 不再各写字符串字面量，避免改名时漏改、或两处漂移。`code` 是对外契约（前端按它分支），因此
//! **重命名 / 删除属破坏性变更**，需同步前端与文档；新增则向后兼容。
//!
//! 命名约定：`snake_case`，按**域**加前缀（`agent_` / `rollout_` / `work_` / `install_package_` …），
//! 便于按域检索。词表之外的字符串不应出现在 `ApiError` 的 `code` 位置。
//!
//! 相关：`wist_shared::protocol` 里的 `ProtocolErrorEnvelope` 是承载它跨进程的 wire 类型。

// 词表按字母序排列，便于查找与去重。用宏声明：常量与测试用的 `ALL` 出自同一份清单，不会漂移。
macro_rules! codes {
    ($($name:ident => $value:literal),* $(,)?) => {
        $(pub const $name: &str = $value;)*

        /// 词表全部取值（仅测试用；供唯一性 / 命名校验）。
        #[cfg(test)]
        pub(crate) const ALL: &[&str] = &[$($value),*];
    };
}

codes! {
    ADVERTISE_URL_INVALID => "advertise_url_invalid",
    ADVERTISE_URL_STORE_FAILED => "advertise_url_store_failed",
    ADVERTISE_URL_UNAVAILABLE => "advertise_url_unavailable",
    AGENT_CERTIFICATE_AUTHORITY_UNCONFIGURED => "agent_certificate_authority_unconfigured",
    AGENT_CERTIFICATE_INVALID => "agent_certificate_invalid",
    AGENT_CLASSIFICATION_STORE_FAILED => "agent_classification_store_failed",
    AGENT_CLASSIFICATION_UNAVAILABLE => "agent_classification_unavailable",
    AGENT_CREDENTIAL_NOT_FOUND => "agent_credential_not_found",
    AGENT_CREDENTIAL_REVOKE_FAILED => "agent_credential_revoke_failed",
    AGENT_DELETE_FAILED => "agent_delete_failed",
    AGENT_FACT_SUMMARY_LOAD_FAILED => "agent_fact_summary_load_failed",
    AGENT_FACT_SUMMARY_STORE_FAILED => "agent_fact_summary_store_failed",
    AGENT_FACT_SUMMARY_UNAVAILABLE => "agent_fact_summary_unavailable",
    AGENT_NOT_FOUND => "agent_not_found",
    AGENT_ONLINE => "agent_online",
    AGENT_PACKAGE_COPY_MISSING => "agent_package_copy_missing",
    AGENT_PACKAGE_HISTORY_LOAD_FAILED => "agent_package_history_load_failed",
    AGENT_PACKAGE_LOOPBACK_ONLY => "agent_package_loopback_only",
    AGENT_PACKAGE_NOT_CONFIGURED => "agent_package_not_configured",
    AGENT_PACKAGE_NOT_FOUND => "agent_package_not_found",
    AGENT_PACKAGE_READ_FAILED => "agent_package_read_failed",
    AGENT_REGISTRATION_MISSING_AFTER_REBUILD => "agent_registration_missing_after_rebuild",
    AGENT_REVOCATION_LIFT_FAILED => "agent_revocation_lift_failed",
    AGENT_REVOCATION_LIST_FAILED => "agent_revocation_list_failed",
    AGENT_REVOCATION_NOT_FOUND => "agent_revocation_not_found",
    AGENT_REVOCATION_UNAVAILABLE => "agent_revocation_unavailable",
    AGENT_REVOKE_FAILED => "agent_revoke_failed",
    AGENT_STATUS_UPDATE_FAILED => "agent_status_update_failed",
    AGENT_STORE_UNAVAILABLE => "agent_store_unavailable",
    AGENT_UPLINK_GRANT_BUILD_FAILED => "agent_uplink_grant_build_failed",
    AGENT_UPLINK_INVALID => "agent_uplink_invalid",
    AGENT_UPLINK_STORE_FAILED => "agent_uplink_store_failed",
    AGENT_UPLINK_UNAVAILABLE => "agent_uplink_unavailable",
    BOOTSTRAP_TOKEN_INVALID => "bootstrap_token_invalid",
    BOOTSTRAP_TOKEN_REQUIRED => "bootstrap_token_required",
    CERTIFICATE_MISMATCH => "certificate_mismatch",
    CERTIFICATE_REQUIRED => "certificate_required",
    CERTIFICATE_REVOKED => "certificate_revoked",
    CLASSIFICATION_REQUIRES_FACT_SUMMARY => "classification_requires_fact_summary",
    COLLECTION_CONTENT_UNAVAILABLE => "collection_content_unavailable",
    CREDENTIAL_ID_GENERATION_FAILED => "credential_id_generation_failed",
    CREDENTIAL_RENEWAL_FAILED => "credential_renewal_failed",
    CREDENTIAL_REQUIRED => "credential_required",
    DIR => "dir",
    DISCOVERY_POLICY_TABLE_UNCONFIGURED => "discovery_policy_table_unconfigured",
    GITHUB_RELEASE_RESOLVE_FAILED => "github_release_resolve_failed",
    HOST_METRICS_UNAVAILABLE => "host_metrics_unavailable",
    INGEST_LOGS_TOO_MANY_RECORDS => "ingest_logs_too_many_records",
    INSTALL_CODE_ISSUE_FAILED => "install_code_issue_failed",
    INSTALL_PACKAGE_ADDRESS_INVALID => "install_package_address_invalid",
    INSTALL_PACKAGE_ADDRESS_STORE_FAILED => "install_package_address_store_failed",
    INSTALL_PACKAGE_ADDRESS_UNAVAILABLE => "install_package_address_unavailable",
    INSTALL_PACKAGE_ARTIFACTS_EMPTY => "install_package_artifacts_empty",
    INSTALL_PACKAGE_DIGEST_MISMATCH => "install_package_digest_mismatch",
    INSTALL_PACKAGE_HISTORY_STORE_FAILED => "install_package_history_store_failed",
    INSTALL_PACKAGE_HISTORY_UNAVAILABLE => "install_package_history_unavailable",
    INSTALL_PACKAGE_ORIGIN_INVALID => "install_package_origin_invalid",
    INSTALL_PACKAGE_PLATFORM_DUPLICATE => "install_package_platform_duplicate",
    INSTALL_PACKAGE_PLATFORM_MISMATCH => "install_package_platform_mismatch",
    INSTALL_PACKAGE_PLATFORM_REQUIRED => "install_package_platform_required",
    INSTALL_PACKAGE_SOURCE_UNAVAILABLE => "install_package_source_unavailable",
    INSTALL_PACKAGE_UNAVAILABLE => "install_package_unavailable",
    INSTALL_SCRIPT_SIGN_FAILED => "install_script_sign_failed",
    INVALID_ADMIN_BEARER_TOKEN => "invalid_admin_bearer_token",
    INVALID_AGENT_CREDENTIAL => "invalid_agent_credential",
    INVALID_CERTIFICATE_SIGNING_REQUEST => "invalid_certificate_signing_request",
    INVALID_CREDENTIAL_RENEWAL_REQUEST => "invalid_credential_renewal_request",
    INVALID_DISCOVERY_POLICIES_POLL => "invalid_discovery_policies_poll",
    INVALID_FACT_SUMMARY => "invalid_fact_summary",
    INVALID_FACT_SUMMARY_REPORT => "invalid_fact_summary_report",
    INVALID_TOKEN => "invalid_token",
    INVALID_UPLINK_POLL => "invalid_uplink_poll",
    INVALID_WORK_ACK => "invalid_work_ack",
    INVALID_WORK_POLL => "invalid_work_poll",
    INVALID_WORK_RESULT => "invalid_work_result",
    INVALID_WORK_RESULT_STATUS => "invalid_work_result_status",
    LINK_REQUEST_INVALID => "link_request_invalid",
    LINK_REQUEST_LOOPBACK_ONLY => "link_request_loopback_only",
    LINK_REQUEST_MISSING_TRUST_ANCHOR => "link_request_missing_trust_anchor",
    LINK_REQUEST_NOT_FOUND => "link_request_not_found",
    LINK_RESULT_INVALID_STATUS => "link_result_invalid_status",
    LINK_RESULT_LOOPBACK_ONLY => "link_result_loopback_only",
    LINKD_STATUS_APPEND_FAILED => "linkd_status_append_failed",
    LINKD_STATUS_HISTORY_READ_FAILED => "linkd_status_history_read_failed",
    LINKD_STATUS_LOOPBACK_ONLY => "linkd_status_loopback_only",
    LINKD_STATUS_READ_FAILED => "linkd_status_read_failed",
    LOG_INGEST_APPEND_FAILED => "log_ingest_append_failed",
    LOGS_READ_FAILED => "logs_read_failed",
    MACHINE_CLASS_NO_PLATFORM => "machine_class_no_platform",
    MACHINE_CLASS_PLATFORM_MISMATCH => "machine_class_platform_mismatch",
    MISSING_ADMIN_BEARER_TOKEN => "missing_admin_bearer_token",
    MISSING_CERTIFICATE_SIGNING_REQUEST => "missing_certificate_signing_request",
    MISSING_CREDENTIAL => "missing_credential",
    MISSING_PLATFORM => "missing_platform",
    NONE => "none",
    ONE_SHOT_WORK_LOAD_FAILED => "one_shot_work_load_failed",
    ONE_SHOT_WORK_STORE_FAILED => "one_shot_work_store_failed",
    ONE_SHOT_WORK_UNAVAILABLE => "one_shot_work_unavailable",
    PACKAGE => "package",
    PACKAGE_CONTENT_INVALID => "package_content_invalid",
    PACKAGE_MANIFEST_INCONSISTENT => "package_manifest_inconsistent",
    PACKAGE_NOT_FOUND => "package_not_found",
    PACKAGE_SHA256_MISMATCH => "package_sha256_mismatch",
    PACKAGE_SIGNATURE_INVALID => "package_signature_invalid",
    PACKAGE_SOURCE_INVALID => "package_source_invalid",
    PACKAGE_SOURCE_UNAVAILABLE => "package_source_unavailable",
    PACKAGE_STORE_FAILED => "package_store_failed",
    PURPOSE_COVERAGE_UNAVAILABLE => "purpose_coverage_unavailable",
    PURPOSE_SUGGESTION_UNAVAILABLE => "purpose_suggestion_unavailable",
    RELEASE_URL_REQUIRED => "release_url_required",
    ROLLOUT_ACTION_REQUIRED => "rollout_action_required",
    ROLLOUT_ADVANCE_BLOCKED => "rollout_advance_blocked",
    ROLLOUT_AGENT_LIST_FAILED => "rollout_agent_list_failed",
    ROLLOUT_DEADLINE_INVALID => "rollout_deadline_invalid",
    ROLLOUT_ENTRY_LIST_FAILED => "rollout_entry_list_failed",
    ROLLOUT_NO_FAILED_TARGET => "rollout_no_failed_target",
    ROLLOUT_PACKAGE_LIST_FAILED => "rollout_package_list_failed",
    ROLLOUT_PACKAGE_NOT_FOUND => "rollout_package_not_found",
    ROLLOUT_PHASES_INVALID => "rollout_phases_invalid",
    ROLLOUT_PLAN_CONFLICT => "rollout_plan_conflict",
    ROLLOUT_PLAN_ENTRY_STORE_FAILED => "rollout_plan_entry_store_failed",
    ROLLOUT_PLAN_LIST_FAILED => "rollout_plan_list_failed",
    ROLLOUT_PLAN_LOAD_FAILED => "rollout_plan_load_failed",
    ROLLOUT_PLAN_NOT_FOUND => "rollout_plan_not_found",
    ROLLOUT_PLAN_SPEC_INVALID => "rollout_plan_spec_invalid",
    ROLLOUT_PLAN_STORE_FAILED => "rollout_plan_store_failed",
    ROLLOUT_PLATFORM_STORE_FAILED => "rollout_platform_store_failed",
    ROLLOUT_PLATFORM_UNAVAILABLE => "rollout_platform_unavailable",
    ROLLOUT_SPEC_REQUIRED => "rollout_spec_required",
    ROLLOUT_TIMEOUT_INVALID => "rollout_timeout_invalid",
    ROLLOUT_UNKNOWN_TARGETS => "rollout_unknown_targets",
    ROLLOUT_UPGRADE_SPEC_INVALID => "rollout_upgrade_spec_invalid",
    ROLLOUT_VERSION_INCOMPLETE => "rollout_version_incomplete",
    ROLLOUT_WORK_SEQUENCE_FAILED => "rollout_work_sequence_failed",
    ROLLOUT_WORK_STORE_FAILED => "rollout_work_store_failed",
    SELF_STATE_LOOPBACK_ONLY => "self_state_loopback_only",
    SELF_STATE_MISSING_GATEWAY_ID => "self_state_missing_gateway_id",
    SHA256_REQUIRED => "sha256_required",
    SOFTWARE_AGENT_NOT_FOUND => "software_agent_not_found",
    SOFTWARE_AGENT_STORE_FAILED => "software_agent_store_failed",
    SOFTWARE_HOLDINGS_LOAD_FAILED => "software_holdings_load_failed",
    SOFTWARE_INVENTORY_LOAD_FAILED => "software_inventory_load_failed",
    SOFTWARE_KEYS_COUNT_FAILED => "software_keys_count_failed",
    SOFTWARE_SUMMARY_FAILED => "software_summary_failed",
    STANDING_WORK_LOAD_FAILED => "standing_work_load_failed",
    STANDING_WORK_STORE_FAILED => "standing_work_store_failed",
    STANDING_WORK_UNAVAILABLE => "standing_work_unavailable",
    UNKNOWN_MACHINE_CLASS => "unknown_machine_class",
    UNKNOWN_PLATFORM => "unknown_platform",
    UNKNOWN_WORK_KIND => "unknown_work_kind",
    UNSUPPORTED_CREDENTIAL_REQUEST => "unsupported_credential_request",
    WORK_ACK_STORE_FAILED => "work_ack_store_failed",
    WORK_ACK_UNAVAILABLE => "work_ack_unavailable",
    WORK_ACTION_REQUIRED => "work_action_required",
    WORK_AGENT_UNCLASSIFIED => "work_agent_unclassified",
    WORK_ALREADY_REVOKED => "work_already_revoked",
    WORK_ALREADY_TERMINAL => "work_already_terminal",
    WORK_BAD_REQUEST => "work_bad_request",
    WORK_CONFLICT => "work_conflict",
    WORK_DEADLINE_INVALID => "work_deadline_invalid",
    WORK_DEADLINE_REQUIRED => "work_deadline_required",
    WORK_FAMILY_REQUIRED => "work_family_required",
    WORK_GRANT_BUILD_FAILED => "work_grant_build_failed",
    WORK_NOT_ACTIVE => "work_not_active",
    WORK_NOT_FOUND => "work_not_found",
    WORK_NOT_PAUSED => "work_not_paused",
    WORK_RESULT_STORE_FAILED => "work_result_store_failed",
    WORK_RESULT_UNAVAILABLE => "work_result_unavailable",
    WORK_SCHEDULED_AT_INVALID => "work_scheduled_at_invalid",
    WORK_SEQUENCE_BUMP_FAILED => "work_sequence_bump_failed",
    WORK_SEQUENCE_UNAVAILABLE => "work_sequence_unavailable",
    WORK_SPEC_REQUIRED => "work_spec_required",
    WORK_SPEC_UNDERIVABLE => "work_spec_underivable",
    WORK_TIMEOUT_INVALID => "work_timeout_invalid",
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::knowledge::KnowledgeRecordError;

    /// 契约关键码：钉住取值（前端 / gwlinkd / agentd 按它分支，改名即破坏）。
    #[test]
    fn contract_critical_codes_are_stable() {
        assert_eq!(AGENT_NOT_FOUND, "agent_not_found");
        assert_eq!(AGENT_ONLINE, "agent_online");
        assert_eq!(CERTIFICATE_REQUIRED, "certificate_required");
        assert_eq!(INSTALL_PACKAGE_UNAVAILABLE, "install_package_unavailable");
        assert_eq!(INVALID_UPLINK_POLL, "invalid_uplink_poll");
        assert_eq!(PACKAGE_SOURCE_INVALID, "package_source_invalid");
        assert_eq!(PACKAGE_NOT_FOUND, "package_not_found");
    }

    /// 词表自身：全是非空 `snake_case`，且取值互不重复。
    #[test]
    fn every_code_is_nonempty_snake_case_and_unique() {
        assert!(!ALL.is_empty());
        let mut seen = std::collections::BTreeSet::new();
        for code in ALL {
            assert!(!code.is_empty(), "empty code");
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "not snake_case: {code}"
            );
            assert!(!code.starts_with('_'), "leading underscore: {code}");
            assert!(!code.ends_with('_'), "trailing underscore: {code}");
            assert!(seen.insert(*code), "duplicate code value: {code}");
        }
    }

    /// 知识库录入错误的 `code()` 必须与词表一致（词表是唯一来源，防两处漂移）。
    #[test]
    fn knowledge_record_codes_match_the_registry() {
        let cases: [(KnowledgeRecordError, &str); 7] = [
            (
                KnowledgeRecordError::SourceInvalid(String::new()),
                PACKAGE_SOURCE_INVALID,
            ),
            (
                KnowledgeRecordError::SourceUnavailable(String::new()),
                PACKAGE_SOURCE_UNAVAILABLE,
            ),
            (
                KnowledgeRecordError::DigestMismatch(String::new()),
                PACKAGE_SHA256_MISMATCH,
            ),
            (
                KnowledgeRecordError::ManifestInconsistent(String::new()),
                PACKAGE_MANIFEST_INCONSISTENT,
            ),
            (
                KnowledgeRecordError::ContentInvalid(String::new()),
                PACKAGE_CONTENT_INVALID,
            ),
            (
                KnowledgeRecordError::SignatureInvalid(String::new()),
                PACKAGE_SIGNATURE_INVALID,
            ),
            (
                KnowledgeRecordError::Store(String::new()),
                PACKAGE_STORE_FAILED,
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.code(), expected);
        }
    }
}
