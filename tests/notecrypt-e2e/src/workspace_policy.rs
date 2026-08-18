use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use toml::Value;

const PRODUCT_PACKAGES: &[&str] = &[
    "notecrypt-core",
    "notecrypt-format",
    "notecrypt-crypto",
    "notecrypt-store",
    "notecrypt-backend",
    "notecrypt-replication",
    "notecrypt-service",
    "notecrypt-backend-git",
    "notecrypt-device-unlock",
    "notecrypt-editor-workspace",
    "notecrypt-tui",
    "notecrypt-cli",
];

#[derive(Debug)]
struct PolicyError(String);

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

#[derive(Debug)]
struct PackagePolicy {
    name: String,
    manifest_path: PathBuf,
    publish: Option<bool>,
    dependencies: BTreeSet<String>,
}

#[derive(Debug)]
struct WorkspacePolicy {
    resolver: Option<String>,
    packages: Vec<PackagePolicy>,
}

impl WorkspacePolicy {
    fn load(manifest_dir: &str) -> Result<Self, PolicyError> {
        let workspace_root = Path::new(manifest_dir).ancestors().nth(2).ok_or_else(|| {
            PolicyError("integration test is not below the workspace root".into())
        })?;
        let root_manifest_path = workspace_root.join("Cargo.toml");
        let root_manifest = parse_manifest(&root_manifest_path)?;
        let workspace = root_manifest
            .get("workspace")
            .and_then(Value::as_table)
            .ok_or_else(|| PolicyError("root manifest has no [workspace] table".into()))?;
        let resolver = workspace
            .get("resolver")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let workspace_publish = workspace
            .get("package")
            .and_then(Value::as_table)
            .and_then(|package| package.get("publish"))
            .and_then(Value::as_bool);
        let members = workspace
            .get("members")
            .and_then(Value::as_array)
            .ok_or_else(|| PolicyError("workspace has no members array".into()))?;

        let mut packages = Vec::with_capacity(members.len());
        for member in members {
            let relative_path = member
                .as_str()
                .ok_or_else(|| PolicyError("workspace member is not a string".into()))?;
            let manifest_path = workspace_root.join(relative_path).join("Cargo.toml");
            let manifest = parse_manifest(&manifest_path)?;
            let package = manifest
                .get("package")
                .and_then(Value::as_table)
                .ok_or_else(|| {
                    PolicyError(format!(
                        "{} has no [package] table",
                        manifest_path.display()
                    ))
                })?;
            let name = package
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    PolicyError(format!("{} has no package name", manifest_path.display()))
                })?
                .to_owned();
            let publish = inherited_bool(package.get("publish"), workspace_publish);

            packages.push(PackagePolicy {
                name,
                manifest_path,
                publish,
                dependencies: dependency_names(&manifest),
            });
        }

        Ok(Self { resolver, packages })
    }

    fn assert_resolver(&self, expected: &str) -> Result<(), PolicyError> {
        if self.resolver.as_deref() == Some(expected) {
            return Ok(());
        }

        Err(PolicyError(format!(
            "workspace resolver is {:?}, expected {expected}",
            self.resolver
        )))
    }

    fn assert_all_private(&self) -> Result<(), PolicyError> {
        for package in &self.packages {
            if package.publish != Some(false) {
                return Err(PolicyError(format!(
                    "{} must set publish = false",
                    package.manifest_path.display()
                )));
            }
        }

        Ok(())
    }

    fn assert_dependency_rules(&self) -> Result<(), PolicyError> {
        let workspace_packages: BTreeSet<&str> = self
            .packages
            .iter()
            .map(|package| package.name.as_str())
            .collect();

        for package in &self.packages {
            let allowed = allowed_internal_dependencies(&package.name);
            for dependency in &package.dependencies {
                if workspace_packages.contains(dependency.as_str())
                    && !allowed.contains(dependency.as_str())
                {
                    return Err(PolicyError(format!(
                        "forbidden dependency edge: {} -> {}",
                        package.name, dependency
                    )));
                }
            }
        }

        Ok(())
    }
}

fn parse_manifest(path: &Path) -> Result<Value, PolicyError> {
    let contents = fs::read_to_string(path)
        .map_err(|error| PolicyError(format!("failed to read {}: {error}", path.display())))?;
    toml::from_str(&contents)
        .map_err(|error| PolicyError(format!("failed to parse {}: {error}", path.display())))
}

fn inherited_bool(value: Option<&Value>, workspace_value: Option<bool>) -> Option<bool> {
    match value {
        Some(Value::Boolean(value)) => Some(*value),
        Some(Value::Table(table))
            if table.get("workspace").and_then(Value::as_bool) == Some(true) =>
        {
            workspace_value
        }
        _ => None,
    }
}

fn dependency_names(manifest: &Value) -> BTreeSet<String> {
    let mut dependencies = BTreeSet::new();
    collect_dependency_tables(manifest, &mut dependencies);

    if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
        for target in targets.values() {
            collect_dependency_tables(target, &mut dependencies);
        }
    }

    dependencies
}

fn collect_dependency_tables(value: &Value, dependencies: &mut BTreeSet<String>) {
    for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(table) = value.get(table_name).and_then(Value::as_table) else {
            continue;
        };

        for (dependency_name, specification) in table {
            let package_name = specification
                .get("package")
                .and_then(Value::as_str)
                .unwrap_or(dependency_name);
            dependencies.insert(package_name.to_owned());
        }
    }
}

fn allowed_internal_dependencies(package: &str) -> BTreeSet<&'static str> {
    let rules: BTreeMap<&str, &[&str]> = BTreeMap::from([
        ("notecrypt-core", &[][..]),
        ("notecrypt-format", &[][..]),
        (
            "notecrypt-crypto-format-tests",
            &["notecrypt-format", "notecrypt-crypto"][..],
        ),
        ("notecrypt-crypto", &[][..]),
        (
            "notecrypt-store",
            &["notecrypt-core", "notecrypt-format", "notecrypt-crypto"][..],
        ),
        ("notecrypt-backend", &[][..]),
        (
            "notecrypt-replication",
            &["notecrypt-core", "notecrypt-store", "notecrypt-backend"][..],
        ),
        (
            "notecrypt-service",
            &[
                "notecrypt-store",
                "notecrypt-replication",
                "notecrypt-crypto",
            ][..],
        ),
        ("notecrypt-backend-git", &["notecrypt-backend"][..]),
        ("notecrypt-device-unlock", &["notecrypt-service"][..]),
        ("notecrypt-editor-workspace", &["notecrypt-service"][..]),
        ("notecrypt-tui", &["notecrypt-service"][..]),
        (
            "notecrypt-cli",
            &[
                "notecrypt-tui",
                "notecrypt-service",
                "notecrypt-backend-git",
                "notecrypt-device-unlock",
                "notecrypt-editor-workspace",
            ][..],
        ),
        ("notecrypt-e2e", PRODUCT_PACKAGES),
        ("notecrypt-benches", PRODUCT_PACKAGES),
    ]);

    rules
        .get(package)
        .copied()
        .unwrap_or_default()
        .iter()
        .copied()
        .collect()
}

#[test]
fn workspace_packages_are_private_and_dependencies_point_inward() {
    let workspace = WorkspacePolicy::load(env!("CARGO_MANIFEST_DIR")).unwrap();
    workspace.assert_resolver("3").unwrap();
    workspace.assert_all_private().unwrap();
    workspace.assert_dependency_rules().unwrap();
}
