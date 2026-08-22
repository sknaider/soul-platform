"""SOUL Platform — contained agency and multi-agent coordination for SOUL Core."""

from soul_platform.agency import (
    AgencyModule,
    CapabilityDenied,
    InMemoryAuditSink,
    InMemoryBudgetStore,
    IndeterminateEffect,
    Limit,
    SqliteAuditSink,
    SqliteBudgetStore,
    ToolSpec,
    load_capability,
)
from soul_platform.coordination import (
    ChannelService,
    Coordinator,
    CoordinatorStore,
    MessageRecord,
    TaskRecord,
)
from soul_platform.autonomy import AutonomyController
from soul_platform.auth import (
    AuthenticationDenied, PrincipalTokenIssuer, PrincipalTokenVerifier, VerifiedPrincipal,
)
from soul_platform.receipts import (
    ReceiptCheckpointStore,
    ReceiptSigner,
    ReceiptVerifier,
    SignedReceipt,
)
from soul_platform.runtime import AgentRuntime, ProtocolViolation, SubprocessLLMProvider
from soul_platform.sandbox import DockerSandbox, DockerTool, ImageTrustStore, SandboxPolicy

__version__ = "0.7.0.dev1"

__all__ = [
    "AgencyModule",
    "AgentRuntime",
    "AutonomyController",
    "AuthenticationDenied",
    "CapabilityDenied",
    "ChannelService",
    "Coordinator",
    "CoordinatorStore",
    "DockerSandbox",
    "DockerTool",
    "InMemoryAuditSink",
    "InMemoryBudgetStore",
    "ImageTrustStore",
    "IndeterminateEffect",
    "Limit",
    "MessageRecord",
    "ProtocolViolation",
    "PrincipalTokenIssuer",
    "PrincipalTokenVerifier",
    "ReceiptSigner",
    "ReceiptCheckpointStore",
    "ReceiptVerifier",
    "SandboxPolicy",
    "SqliteBudgetStore",
    "SubprocessLLMProvider",
    "SqliteAuditSink",
    "SignedReceipt",
    "TaskRecord",
    "ToolSpec",
    "VerifiedPrincipal",
    "load_capability",
]
