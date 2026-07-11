#!/usr/bin/env python3
"""
Known-answer behavioral oracle for pyfaidx.

Indexes a fixed FASTA file through the SAME public entry point the fuzz harness drives
(pyfaidx.Fasta) and asserts the decoded record names, sequence content, lengths, coordinate
semantics (1-based get_seq vs 0-based slicing) and error behavior (a missing key raises). These
are real output assertions on pyfaidx's parser/indexer — a no-op / exit(0) / value-altering patch
CANNOT pass — so the suite is not reward-hackable.

Emits one `PASS <name>` / `FAIL <name>` line per check; exits 0 iff every check passed.
mayhem/test.sh tallies the lines into a CTRF summary.
"""
import os
import sys
import tempfile

import pyfaidx

# A small, valid multi-record FASTA with KNOWN sequences.
#   seq1 = ACGTACGTAC + GGGGCCCCAA            (20 bp, wrapped at 10 cols)
#   seq2 = TTTTAAAACC                          (10 bp)
FASTA_CONTENT = (
    ">seq1 first record\n"
    "ACGTACGTAC\n"
    "GGGGCCCCAA\n"
    ">seq2 second record\n"
    "TTTTAAAACC\n"
)

SEQ1 = "ACGTACGTACGGGGCCCCAA"
SEQ2 = "TTTTAAAACC"

results = []


def check(name, cond):
    results.append((name, bool(cond)))


def raises(fn):
    try:
        fn()
    except Exception:
        return True
    return False


def main():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "kat.fasta")
    with open(path, "w") as f:
        f.write(FASTA_CONTENT)
    try:
        fasta = pyfaidx.Fasta(path)

        check("record names indexed", sorted(fasta.keys()) == ["seq1", "seq2"])
        check("contains seq1", "seq1" in fasta)
        check("does not contain missing", "nope" not in fasta)

        check("seq1 full sequence", fasta["seq1"][:].seq == SEQ1)
        check("seq2 full sequence", fasta["seq2"][:].seq == SEQ2)
        check("seq1 length is 20", len(fasta["seq1"]) == 20)
        check("seq2 length is 10", len(fasta["seq2"]) == 10)

        # 0-based, end-exclusive slicing on the record.
        check("seq1 slice [0:4]", fasta["seq1"][0:4].seq == "ACGT")
        check("seq1 slice [10:14]", fasta["seq1"][10:14].seq == "GGGG")
        check("seq1 negative slice [-2:]", fasta["seq1"][-2:].seq == "AA")

        # 1-based, closed interval get_seq.
        check("get_seq 1-based [1,4]", fasta.get_seq("seq1", 1, 4).seq == "ACGT")
        check("get_seq spans wrap [9,12]", fasta.get_seq("seq1", 9, 12).seq == "ACGG")

        # Error semantics: a missing record name must raise, not silently "succeed".
        check("missing key raises", raises(lambda: fasta["does_not_exist"]))

        fasta.close()
    finally:
        for ext in ("", ".fai"):
            try:
                os.unlink(path + ext)
            except OSError:
                pass
        try:
            os.rmdir(d)
        except OSError:
            pass

    ok = True
    for name, passed in results:
        sys.stdout.write(("PASS " if passed else "FAIL ") + name + "\n")
        ok = ok and passed
    sys.stdout.flush()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
