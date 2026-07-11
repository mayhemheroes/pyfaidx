#! /usr/bin/env python3
import atheris
import sys
import fuzz_helpers

with atheris.instrument_imports(include=["pyfaidx"]):
    import pyfaidx

fasta_error_tup = (pyfaidx.FastaIndexingError, pyfaidx.KeyFunctionError, pyfaidx.IndexNotFoundError, pyfaidx.VcfIndexNotFoundError,
                   pyfaidx.FastaNotFoundError, pyfaidx.FetchError, pyfaidx.BedError,
                   pyfaidx.RegionError, pyfaidx.UnsupportedCompressionFormat)

def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        with fdp.ConsumeTemporaryFile('.fasta', all_data=True, as_bytes=True) as fasta_file_path:
            with pyfaidx.Fasta(fasta_file_path) as fasta:
                print(fasta)
    except fasta_error_tup:
        return -1
    except UnicodeDecodeError:
        return -1
    except ValueError as e:
        if 'Duplicate key' in str(e):
            return -1
        raise e


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
