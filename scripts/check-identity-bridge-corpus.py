#!/usr/bin/env python3
import hashlib, json, pathlib, shutil, sys, tempfile

def verify(root):
    manifest = json.loads((root / "identity-bridge-manifest-v1.json").read_text())
    digests = []
    for item in manifest["files"]:
        actual = hashlib.sha256((root / item["path"]).read_bytes()).hexdigest()
        if actual != item["sha256"]:
            raise ValueError(f"identity corpus drift: {item['path']}: {actual}")
        digests.append(actual)
    corpus = hashlib.sha256("".join(digests).encode()).hexdigest()
    if corpus != manifest["corpus_digest"]:
        raise ValueError(f"identity corpus aggregate drift: {corpus}")
    rows = (root / "identity-bridge-conformance-v1.tsv").read_text().splitlines()
    positive = sum(row.split("\t")[1] == "accept" for row in rows[1:])
    negative = sum(row.split("\t")[1] == "reject" for row in rows[1:])
    if (positive, negative) != (manifest["expected_positive_vectors"], manifest["expected_negative_vectors"]):
        raise ValueError(f"identity corpus count mismatch: {(positive, negative)}")
    if any(canary in (root/item["path"]).read_text() for item in manifest["files"] for canary in ("Erika","Mustermann")):
        raise ValueError("identity corpus contains personal-data canary")
    return corpus, positive, negative

root = pathlib.Path(__file__).resolve().parents[1] / "testing" / "vectors"
try:
    corpus, positive, negative = verify(root)
    if "--self-test" in sys.argv:
        with tempfile.TemporaryDirectory() as directory:
            copy = pathlib.Path(directory)
            for source in root.iterdir():
                if source.name.startswith(("identity-bridge", "eudi-schema", "external-")):
                    shutil.copy2(source, copy/source.name)
            target = copy/"eudi-schema-mapping-v1.tsv"
            target.write_bytes(target.read_bytes()+b"drift")
            try: verify(copy)
            except ValueError: pass
            else: raise ValueError("drift self-test failed to detect mutation")
except ValueError as error:
    sys.exit(str(error))
print(f"identity bridge corpus verified: {corpus}, {positive} positive, {negative} negative")
