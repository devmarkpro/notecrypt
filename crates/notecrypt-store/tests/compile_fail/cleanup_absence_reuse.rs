use notecrypt_store::WorkspaceAbsenceProof;

fn consume(_: WorkspaceAbsenceProof) {}

fn reuse(value: WorkspaceAbsenceProof) {
    consume(value);
    consume(value);
}

fn main() {}
