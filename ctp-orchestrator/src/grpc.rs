//! The orchestrator's external tonic surface: `Evaluate` and `Health`.
//! Translates the proto envelope to/from the core pipeline and is
//! fail-closed at the boundary (an UNSPECIFIED direction is a BLOCK).

use std::sync::Arc;

use ctp_core::{Decision, Direction, Verdict};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::orchestrator_proto::orchestrator_service_server::OrchestratorService;
use crate::orchestrator_proto::{
    self, EvaluateRequest, EvaluateResponse, Finding as ProtoFinding, HealthRequest, HealthResponse,
};
use crate::pipeline::Orchestrator;

pub struct GrpcGateway {
    orchestrator: Arc<Orchestrator>,
}

impl GrpcGateway {
    pub fn new(orchestrator: Arc<Orchestrator>) -> Self {
        GrpcGateway { orchestrator }
    }
}

fn to_proto_finding(f: &ctp_core::Finding) -> ProtoFinding {
    ProtoFinding {
        source: f.source.clone(),
        reason: f.reason.clone(),
        severity: f.severity.to_string(),
        disposition: match f.disposition {
            ctp_core::FindingDisposition::Blocking => "blocking",
            ctp_core::FindingDisposition::Advisory => "advisory",
        }
        .to_string(),
    }
}

fn to_proto_response(decision: &Decision, session_id: Uuid) -> EvaluateResponse {
    let verdict = match decision.verdict {
        Verdict::Pass => orchestrator_proto::Verdict::Pass,
        Verdict::Block => orchestrator_proto::Verdict::Block,
    };
    EvaluateResponse {
        verdict: verdict as i32,
        layer: decision.layer.to_string(),
        findings: decision.findings.iter().map(to_proto_finding).collect(),
        elapsed_micros: decision.elapsed.as_micros() as u64,
        session_id: session_id.to_string(),
    }
}

/// A fail-closed BLOCK response for requests rejected at the boundary, before
/// the pipeline runs (e.g. an invalid direction).
fn boundary_block(session_id: Uuid, reason: &str) -> EvaluateResponse {
    EvaluateResponse {
        verdict: orchestrator_proto::Verdict::Block as i32,
        layer: "orchestrator".into(),
        findings: vec![ProtoFinding {
            source: "request_validation".into(),
            reason: reason.into(),
            severity: "high".into(),
            disposition: "blocking".into(),
        }],
        elapsed_micros: 0,
        session_id: session_id.to_string(),
    }
}

#[tonic::async_trait]
impl OrchestratorService for GrpcGateway {
    async fn evaluate(
        &self,
        request: Request<EvaluateRequest>,
    ) -> Result<Response<EvaluateResponse>, Status> {
        let req = request.into_inner();

        // Session id: empty or unparseable → a fresh session (correlation
        // only; never a reason to reject).
        let session_id = if req.session_id.is_empty() {
            Uuid::new_v4()
        } else {
            Uuid::parse_str(&req.session_id).unwrap_or_else(|_| Uuid::new_v4())
        };

        // SECURITY: an UNSPECIFIED/unknown direction is off-contract → BLOCK at
        // the boundary, before the pipeline runs. A malformed request from an
        // external caller fails closed rather than defaulting to a direction.
        let direction = match orchestrator_proto::Direction::try_from(req.direction) {
            Ok(orchestrator_proto::Direction::Inbound) => Direction::Inbound,
            Ok(orchestrator_proto::Direction::Outbound) => Direction::Outbound,
            _ => {
                tracing::warn!(
                    direction = req.direction,
                    "evaluate rejected: invalid direction"
                );
                return Ok(Response::new(boundary_block(
                    session_id,
                    "invalid direction",
                )));
            }
        };

        let tool_name = (!req.tool_name.is_empty()).then_some(req.tool_name);
        let decision = self
            .orchestrator
            .evaluate(req.payload, direction, tool_name, session_id)
            .await;
        Ok(Response::new(to_proto_response(&decision, session_id)))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            ready: true,
            active_rules: self.orchestrator.active_rules() as u32,
        }))
    }
}
