use notecrypt_store::WorkspaceAbsenceProof;

fn requires_display<T: std::fmt::Display>() {}

fn main() {
    requires_display::<WorkspaceAbsenceProof>();
}
