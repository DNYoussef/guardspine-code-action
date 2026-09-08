"""Check verifier pins against an explicit Git tree, never Windows file bytes."""
import ast
import hashlib
import re
import subprocess
import sys


VERIFIER = 'docs/operations/fatal-result-20260908/verify_linux.py'


def verify(expected, read_blob):
    if not isinstance(expected, dict) or len(expected) != 14:
        raise ValueError('Expected exactly 14 reviewed pins')
    for path, digest in expected.items():
        if not isinstance(path, str) or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('Invalid pin entry')
        if hashlib.sha256(read_blob(path)).hexdigest() != digest:
            raise ValueError(f'Git blob pin mismatch: {path}')


def main():
    # No argument means the staged candidate. Reject unstaged tracked edits so
    # a local working-file test cannot be confused with this staged-tree check.
    if len(sys.argv) == 1:
        subprocess.run(['git', 'diff', '--exit-code', '--quiet'], check=True)
        revision = subprocess.check_output(['git', 'write-tree']).decode().strip()
    else:
        revision = subprocess.check_output(['git', 'rev-parse', '--verify',
                                            '--end-of-options', sys.argv[1]]).decode().strip()
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('Expected an immutable Git object ID')

    def blob(path):
        return subprocess.check_output(['git', 'cat-file', 'blob', f'{revision}:{path}'])

    assignments = [ast.literal_eval(node.value) for node in ast.parse(blob(VERIFIER)).body
                   if isinstance(node, ast.Assign) and any(
                       isinstance(target, ast.Name) and target.id == 'EXPECTED'
                       for target in node.targets)]
    expected, = assignments
    verify(expected, blob)
    print('GIT_BLOB_PINS_VERIFIED', len(expected), revision)


if __name__ == '__main__':
    main()
