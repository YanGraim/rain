//! Container engines through the Docker CLI (ADR 0004). Bytes live inside
//! the engine's virtual disk, so only the tool reports them (FR-020, FR-021).
//! `act` is `None` everywhere until the M2 spec.

use crate::model::{Category, Risk, RuleId};
use crate::providers::docker::{parse_dangling_images, parse_system_df, SystemDf};
use crate::rule::{ProviderRule, Rule, RuleKind, RuleMeta};
use crate::tools::{ParseError, ProviderItem, ToolCall, ToolId, ToolOutput};
use rain_platform::Os;

const SYSTEM_DF: ToolCall =
    ToolCall::read(ToolId::Docker, &["system", "df", "--format", "{{json .}}"]);
const DANGLING: ToolCall = ToolCall::read(
    ToolId::Docker,
    &[
        "images",
        "--filter",
        "dangling=true",
        "--format",
        "{{json .}}",
    ],
);

pub(super) static RULES: &[&dyn Rule] = &[
    &BUILD_CACHE,
    &DANGLING_IMAGES,
    &STOPPED,
    &UNUSED_IMAGES,
    &VOLUMES,
];

const fn meta(
    id: &'static str,
    name: &'static str,
    consequence: &'static str,
    risk: Risk,
) -> RuleMeta {
    RuleMeta {
        id: RuleId::new(id),
        category: Category::Containers,
        risk,
        name_key: name,
        consequence_key: consequence,
        // FR-014: no container rule is ever preselected.
        default_selected: false,
        requires_app_closed: None,
        os: &[Os::Macos],
    }
}

/// One `docker system df` row as a single item; 0 reclaimable = no item.
struct DfRow {
    meta: RuleMeta,
    key: &'static str,
    pick: fn(&SystemDf) -> u64,
}

impl Rule for DfRow {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Provider(self)
    }
}

impl ProviderRule for DfRow {
    fn probe(&self) -> ToolCall {
        SYSTEM_DF
    }
    fn parse(&self, out: &ToolOutput) -> Result<Vec<ProviderItem>, ParseError> {
        let bytes = (self.pick)(&parse_system_df(&out.stdout)?);
        Ok((bytes > 0)
            .then(|| ProviderItem {
                key: self.key.to_owned(),
                label: self.key.to_owned(),
                reported_bytes: bytes,
                paths: Vec::new(),
            })
            .into_iter()
            .collect())
    }
    fn act(&self, _: &ProviderItem) -> Option<ToolCall> {
        None
    }
}

/// FR-021: build cache.
static BUILD_CACHE: DfRow = DfRow {
    meta: meta(
        "containers.build-cache",
        "rule.containers.build-cache",
        "rule.containers.build-cache.consequence",
        Risk::Medium,
    ),
    key: "build-cache",
    pick: |df| df.build_cache,
};

/// FR-021: Docker counts only stopped containers as reclaimable, so a
/// running container never adds bytes here.
static STOPPED: DfRow = DfRow {
    meta: meta(
        "containers.stopped",
        "rule.containers.stopped",
        "rule.containers.stopped.consequence",
        Risk::Medium,
    ),
    key: "stopped",
    pick: |df| df.containers,
};

/// FR-021: images no container uses (dangling ones included, so the two
/// image rules may overlap in `tool_total_bytes`).
static UNUSED_IMAGES: DfRow = DfRow {
    meta: meta(
        "containers.unused-images",
        "rule.containers.unused-images",
        "rule.containers.unused-images.consequence",
        Risk::Medium,
    ),
    key: "unused-images",
    pick: |df| df.images,
};

/// FR-014: volumes may hold databases: high, never preselected.
static VOLUMES: DfRow = DfRow {
    meta: meta(
        "containers.volumes",
        "rule.containers.volumes",
        "rule.containers.volumes.consequence",
        Risk::High,
    ),
    key: "unused-volumes",
    pick: |df| df.volumes,
};

/// FR-021: one item per unused dangling image.
struct DanglingImages {
    meta: RuleMeta,
}

static DANGLING_IMAGES: DanglingImages = DanglingImages {
    meta: meta(
        "containers.dangling-images",
        "rule.containers.dangling-images",
        "rule.containers.dangling-images.consequence",
        Risk::Medium,
    ),
};

impl Rule for DanglingImages {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Provider(self)
    }
}

impl ProviderRule for DanglingImages {
    fn probe(&self) -> ToolCall {
        DANGLING
    }
    fn parse(&self, out: &ToolOutput) -> Result<Vec<ProviderItem>, ParseError> {
        parse_dangling_images(&out.stdout)
    }
    fn act(&self, _: &ProviderItem) -> Option<ToolCall> {
        None
    }
    /// `containers.unused-images` already counts dangling images.
    fn counted_elsewhere(&self) -> bool {
        true
    }
}
