//! Local AI models (catalogue 6.3): Hugging Face, PyTorch Hub, Whisper,
//! LM Studio and GPT4All.
//!
//! Every rule is high risk and never selected: a model is a download of
//! gigabytes, and some cannot be fetched again. Each lists only what its
//! tool's documentation names, one item per model; the rest of each folder
//! (tokens, chats, local documents, tool state) is never listed.

use crate::fs::Fs;
use crate::model::{Category, Risk, RuleId};
use crate::rule::{EntryInfo, FileRule, RootedPath, Rule, RuleContext, RuleKind, RuleMeta, Visit};
use rain_platform::{Os, Root};

pub(super) static RULES: &[&dyn Rule] = &[&HUGGINGFACE, &TORCH_HUB, &WHISPER, &LMSTUDIO, &GPT4ALL];

/// What an entry at the item depth has to be to count as a model.
enum Pick {
    /// A real folder named `<prefix><something>`.
    DirPrefixed(&'static [&'static str]),
    /// Any real folder.
    Dir,
    /// A regular file with this exact (lowercase) extension.
    FileExt(&'static str),
    /// Any regular file.
    File,
}

/// A rule whose items are the entries `depth` levels below each folder,
/// when they are what `pick` asks for. Links are never items.
pub struct ModelItems {
    meta: RuleMeta,
    /// Folders below the home.
    rels: &'static [&'static str],
    depth: usize,
    pick: Pick,
}

const fn meta(id: &'static str, name_key: &'static str, consequence_key: &'static str) -> RuleMeta {
    RuleMeta {
        id: RuleId::new(id),
        category: Category::AiModels,
        risk: Risk::High,
        name_key,
        consequence_key,
        // FR-014: only low risk items are preselected.
        default_selected: false,
        requires_app_closed: None,
        os: &[Os::Macos],
    }
}

impl Rule for ModelItems {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Files(self)
    }
}

impl FileRule for ModelItems {
    fn roots(&self, _: &RuleContext) -> Vec<RootedPath> {
        self.rels
            .iter()
            .map(|rel| RootedPath::Under(Root::Home, rel))
            .collect()
    }

    fn visit(&self, entry: &EntryInfo, depth: usize, _: &RuleContext, _: &dyn Fs) -> Visit {
        if depth == 0 {
            return Visit::Descend;
        }
        if depth < self.depth {
            return if entry.meta.is_dir && !entry.meta.is_symlink {
                Visit::Descend
            } else {
                Visit::Skip
            };
        }
        let name = entry
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let real = !entry.meta.is_symlink;
        let is_model = match self.pick {
            Pick::DirPrefixed(prefixes) => {
                real && entry.meta.is_dir
                    && prefixes
                        .iter()
                        .any(|p| name.strip_prefix(p).is_some_and(|rest| !rest.is_empty()))
            }
            Pick::Dir => real && entry.meta.is_dir,
            Pick::FileExt(ext) => {
                real && !entry.meta.is_dir
                    && name.strip_suffix(ext).is_some_and(|stem| !stem.is_empty())
            }
            Pick::File => real && !entry.meta.is_dir,
        };
        if is_model {
            Visit::Candidate
        } else {
            Visit::Skip
        }
    }
}

/// `~/.cache/huggingface/hub`, one folder per repository: the hub cache page
/// shows models, datasets and spaces as `models--<org>--<name>`,
/// `datasets--<name>` and `spaces--<org>--<name>`. The rest of the folder and
/// the token one level up are never listed.
pub static HUGGINGFACE: ModelItems = ModelItems {
    meta: meta(
        "models.huggingface",
        "rule.models.huggingface",
        "rule.models.huggingface.consequence",
    ),
    rels: &[".cache/huggingface/hub"],
    depth: 1,
    pick: Pick::DirPrefixed(&["models--", "datasets--", "spaces--"]),
};

/// PyTorch Hub: the files it downloads to `~/.cache/torch/hub/checkpoints`
/// (the default `model_dir` of `load_state_dict_from_url`). The repositories
/// it clones into the hub folder have no documented layout and stay out.
pub static TORCH_HUB: ModelItems = ModelItems {
    meta: meta(
        "models.torch-hub",
        "rule.models.torch-hub",
        "rule.models.torch-hub.consequence",
    ),
    rels: &[".cache/torch/hub/checkpoints"],
    depth: 1,
    pick: Pick::File,
};

/// Whisper: the `.pt` files in `~/.cache/whisper` (`download_root` in
/// `whisper/__init__.py`, named after the last part of the model URL).
pub static WHISPER: ModelItems = ModelItems {
    meta: meta(
        "models.whisper",
        "rule.models.whisper",
        "rule.models.whisper.consequence",
    ),
    rels: &[".cache/whisper"],
    depth: 1,
    pick: Pick::FileExt(".pt"),
};

/// LM Studio: `<publisher>/<model>` below `~/.lmstudio/models` (its import
/// page shows that layout) and below the old `~/.cache/lm-studio/models`.
/// The old root comes from the catalogue spec: LM Studio's pages do not
/// mention it, and it is not on this Mac.
pub static LMSTUDIO: ModelItems = ModelItems {
    meta: meta(
        "models.lmstudio",
        "rule.models.lmstudio",
        "rule.models.lmstudio.consequence",
    ),
    rels: &[".lmstudio/models", ".cache/lm-studio/models"],
    depth: 2,
    pick: Pick::Dir,
};

/// GPT4All: the `.gguf` files in its macOS folder (the "Download Path"
/// default). Chats and local documents live in the same folder and are never
/// listed.
pub static GPT4ALL: ModelItems = ModelItems {
    meta: meta(
        "models.gpt4all",
        "rule.models.gpt4all",
        "rule.models.gpt4all.consequence",
    ),
    rels: &["Library/Application Support/nomic.ai/GPT4All"],
    depth: 1,
    pick: Pick::FileExt(".gguf"),
};

#[cfg(test)]
mod tests {
    use crate::fs::{FakeFs, Metadata};
    use crate::model::{Risk, ScanReport};
    use crate::planner::{scan, ResolvedRoots, ScanContext};
    use crate::protect::ProtectList;
    use crate::rule::RuleContext;
    use rain_platform::{Os, Platform, PlatformError, Root};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;
    use std::time::SystemTime;

    const HOME: &str = "/Users/Tester";

    struct HomeAt;

    impl Platform for HomeAt {
        fn resolve(&self, _: Root) -> Result<PathBuf, PlatformError> {
            Ok(PathBuf::from(HOME))
        }
        fn is_root_user(&self) -> bool {
            false
        }
        fn os(&self) -> Os {
            Os::Macos
        }
    }

    fn md(is_dir: bool, ino: u64) -> Metadata {
        Metadata {
            is_dir,
            is_symlink: false,
            dev: 1,
            ino,
            nlink: if is_dir { 2 } else { 1 },
            blocks: u64::from(!is_dir) * 8,
            len: 0,
            mtime: SystemTime::UNIX_EPOCH,
        }
    }

    /// A fake home that grows by relative paths; every folder on the way is
    /// inserted.
    struct Tree {
        fs: FakeFs,
        ino: u64,
    }

    impl Tree {
        fn new() -> Tree {
            let mut fs = FakeFs::new();
            fs.insert("/Users", md(true, 1)).insert(HOME, md(true, 2));
            Tree { fs, ino: 100 }
        }
        fn parents(&mut self, rel: &str) -> PathBuf {
            let mut cur = PathBuf::from(HOME);
            let parts: Vec<&str> = rel.split('/').collect();
            for part in &parts[..parts.len() - 1] {
                cur.push(part);
                if crate::fs::Fs::symlink_metadata(&self.fs, &cur).is_err() {
                    self.ino += 1;
                    self.fs.insert(&cur, md(true, self.ino));
                }
            }
            cur.push(parts[parts.len() - 1]);
            cur
        }
        fn dir(&mut self, rel: &str) -> &mut Self {
            let p = self.parents(rel);
            self.ino += 1;
            self.fs.insert(p, md(true, self.ino));
            self
        }
        fn file(&mut self, rel: &str) -> &mut Self {
            let p = self.parents(rel);
            self.ino += 1;
            self.fs.insert(p, md(false, self.ino));
            self
        }
        fn link(&mut self, rel: &str, target: &str) -> &mut Self {
            let p = self.parents(rel);
            self.fs.insert_symlink(p, target);
            self
        }
    }

    fn run(fs: &FakeFs, ids: &[&str]) -> ScanReport {
        let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(fs);
        let roots = ResolvedRoots {
            home: PathBuf::from(HOME),
            caches: Path::new(HOME).join("Library/Caches"),
            logs: Path::new(HOME).join("Library/Logs"),
        };
        let ctx = ScanContext {
            fs,
            protect: &protect,
            roots: &roots,
            rule_ctx: RuleContext {
                min_age_days: 0,
                user_paths: Vec::new(),
                now: SystemTime::UNIX_EPOCH,
            },
            tools: &crate::tools::NoTools,
            threads: Some(1),
        };
        let rules = super::super::select(ids).unwrap();
        scan(&rules, &ctx, &AtomicBool::new(false)).unwrap()
    }

    /// Items of `id`, as paths below the home.
    fn listed(report: &ScanReport, id: &str) -> Vec<String> {
        let mut out: Vec<String> = report
            .items
            .iter()
            .filter(|i| i.rule.as_str() == id)
            .filter_map(|i| i.path.strip_prefix(HOME).ok()?.to_str().map(str::to_owned))
            .collect();
        out.sort();
        out
    }

    fn meta(id: &str) -> crate::rule::RuleMeta {
        super::super::select(&[id]).unwrap()[0].meta().clone()
    }

    const ALL: [&str; 5] = [
        "models.huggingface",
        "models.torch-hub",
        "models.whisper",
        "models.lmstudio",
        "models.gpt4all",
    ];

    // FR-005: each model repository is one item.
    #[test]
    fn hf_lists_each_models_dir() {
        let hub = ".cache/huggingface/hub";
        let mut t = Tree::new();
        for repo in [
            "models--julien-c--EsperBERTo-small",
            "datasets--glue",
            "spaces--dalle-mini--dalle-mini",
        ] {
            t.dir(&format!("{hub}/{repo}/blobs"))
                .file(&format!("{hub}/{repo}/blobs/abc"))
                .dir(&format!("{hub}/{repo}/snapshots"))
                .dir(&format!("{hub}/{repo}/refs"));
        }
        // Not repositories: left alone.
        t.dir(&format!("{hub}/.locks"))
            .file(&format!("{hub}/version.txt"))
            .file(&format!("{hub}/models--a--b-file"))
            .dir(&format!("{hub}/other"))
            .dir(&format!("{hub}/Models--x--y"))
            .dir(&format!("{hub}/models-x"))
            .dir(&format!("{hub}/models--"))
            .dir(".cache/huggingface/xet")
            .file(".cache/huggingface/token");
        let r = run(&t.fs, &["models.huggingface"]);
        assert_eq!(
            listed(&r, "models.huggingface"),
            [
                format!("{hub}/datasets--glue"),
                format!("{hub}/models--julien-c--EsperBERTo-small"),
                format!("{hub}/spaces--dalle-mini--dalle-mini"),
            ]
        );
    }

    // FR-014: a model is a download of gigabytes and the user may have no way
    // to get it again: high and never selected.
    #[test]
    fn models_are_high_not_default() {
        for id in ALL {
            let m = meta(id);
            assert_eq!(m.risk, Risk::High, "{id}");
            assert!(!m.default_selected, "{id}");
            assert_eq!(m.category, crate::model::Category::AiModels, "{id}");
            assert_eq!(m.requires_app_closed, None, "{id}");
            assert_eq!(m.os, &[Os::Macos], "{id}");
        }
    }

    #[test]
    fn torch_hub_lists_only_downloaded_checkpoints() {
        let hub = ".cache/torch/hub";
        let mut t = Tree::new();
        t.file(&format!("{hub}/checkpoints/resnet18-f37072fd.pth"))
            .file(&format!("{hub}/checkpoints/vgg16.pth"))
            .dir(&format!("{hub}/checkpoints/nested"))
            .file(&format!("{hub}/checkpoints/nested/x.pth"))
            .dir(&format!("{hub}/pytorch_vision_main"))
            .file(&format!("{hub}/trusted_list"))
            .file(".cache/torch/other.pth");
        let r = run(&t.fs, &["models.torch-hub"]);
        assert_eq!(
            listed(&r, "models.torch-hub"),
            [
                format!("{hub}/checkpoints/resnet18-f37072fd.pth"),
                format!("{hub}/checkpoints/vgg16.pth"),
            ]
        );
    }

    #[test]
    fn whisper_lists_only_the_model_files() {
        let dir = ".cache/whisper";
        let mut t = Tree::new();
        t.file(&format!("{dir}/tiny.pt"))
            .file(&format!("{dir}/large-v3-turbo.pt"))
            .file(&format!("{dir}/notes.txt"))
            .file(&format!("{dir}/tiny.PT"))
            .file(&format!("{dir}/.pt"))
            .file(&format!("{dir}/tiny.pt.part"))
            .dir(&format!("{dir}/base.pt"))
            .file(&format!("{dir}/sub/small.pt"));
        let r = run(&t.fs, &["models.whisper"]);
        assert_eq!(
            listed(&r, "models.whisper"),
            [format!("{dir}/large-v3-turbo.pt"), format!("{dir}/tiny.pt")]
        );
    }

    // FR-005: `<publisher>/<model>` is one item.
    #[test]
    fn lmstudio_lists_publisher_model() {
        let root = ".lmstudio/models";
        let mut t = Tree::new();
        t.file(&format!(
            "{root}/infra-ai/ocelot-v1/ocelot-v1-instruct-q4_0.gguf"
        ))
        .file(&format!("{root}/infra-ai/ocelot-v1/README.md"))
        .file(&format!(
            "{root}/lmstudio-community/gemma-3/gemma-3-q4.gguf"
        ))
        // A loose file at the publisher level, or a model one level
        // deeper than the layout, is not a `<publisher>/<model>`.
        .file(&format!("{root}/stray.gguf"))
        .file(&format!("{root}/infra-ai/loose.gguf"));
        let r = run(&t.fs, &["models.lmstudio"]);
        assert_eq!(
            listed(&r, "models.lmstudio"),
            [
                format!("{root}/infra-ai/ocelot-v1"),
                format!("{root}/lmstudio-community/gemma-3"),
            ]
        );
    }

    #[test]
    fn old_lmstudio_root_also_found() {
        let mut t = Tree::new();
        t.file(".lmstudio/models/new-pub/model-a/a.gguf")
            .file(".cache/lm-studio/models/old-pub/model-b/b.gguf");
        let r = run(&t.fs, &["models.lmstudio"]);
        assert_eq!(
            listed(&r, "models.lmstudio"),
            [
                ".cache/lm-studio/models/old-pub/model-b".to_owned(),
                ".lmstudio/models/new-pub/model-a".to_owned(),
            ]
        );
    }

    // FR-004: the app keeps its chats and documents next to the models.
    #[test]
    fn gpt4all_lists_only_gguf_models() {
        let dir = "Library/Application Support/nomic.ai/GPT4All";
        let mut t = Tree::new();
        t.file(&format!("{dir}/Meta-Llama-3-8B-Instruct.Q4_0.gguf"))
            .file(&format!("{dir}/mistral.gguf"))
            .file(&format!("{dir}/chats.sqlite"))
            .file(&format!("{dir}/localdocs_v3.db"))
            .dir(&format!("{dir}/chats"))
            .file(&format!("{dir}/model.GGUF"))
            .file(&format!("{dir}/.gguf"))
            .file(&format!("{dir}/model.gguf.tmp"))
            .dir(&format!("{dir}/folder.gguf"));
        let r = run(&t.fs, &["models.gpt4all"]);
        assert_eq!(
            listed(&r, "models.gpt4all"),
            [
                format!("{dir}/Meta-Llama-3-8B-Instruct.Q4_0.gguf"),
                format!("{dir}/mistral.gguf"),
            ]
        );
    }

    // FR-005: a link is not a model.
    #[test]
    fn symlinked_models_are_not_items() {
        let mut t = Tree::new();
        t.dir("Elsewhere")
            .link(
                ".cache/huggingface/hub/models--a--b",
                "/Users/Tester/Elsewhere",
            )
            .link(".cache/whisper/tiny.pt", "/Users/Tester/Elsewhere")
            .link(".lmstudio/models/pub/model", "/Users/Tester/Elsewhere")
            .dir(".lmstudio/models/pub/real");
        let r = run(&t.fs, &ALL);
        assert!(listed(&r, "models.huggingface").is_empty());
        assert!(listed(&r, "models.whisper").is_empty());
        assert_eq!(listed(&r, "models.lmstudio"), [".lmstudio/models/pub/real"]);
    }

    // Each rule has its own folders: one tool's files never show up in
    // another's list.
    #[test]
    fn each_rule_keeps_to_its_own_folder() {
        let mut t = Tree::new();
        t.file(".cache/whisper/tiny.pt")
            .file(".cache/torch/hub/checkpoints/m.pth")
            .dir(".cache/huggingface/hub/models--a--b")
            .file(".lmstudio/models/p/m/x.gguf")
            .file("Library/Application Support/nomic.ai/GPT4All/g.gguf");
        let r = run(&t.fs, &ALL);
        for id in ALL {
            assert_eq!(listed(&r, id).len(), 1, "{id}");
        }
        assert_eq!(r.items.len(), 5);
    }
}
