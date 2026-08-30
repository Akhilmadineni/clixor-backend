#!/bin/sh
set -eu

repository=$(git rev-parse --show-toplevel)
temporary=$(mktemp -d)
trap 'rm -rf "${temporary}"' EXIT HUP INT TERM
checkout=${temporary}/checkout

# file:// is required for --depth to be honored for a local reproduction.
git clone --quiet --depth=1 "file://${repository}" "${checkout}"
if git -C "${checkout}" cat-file -e d2f5a69c9f14d504ad64176dcc62c5ffa7bb032c^{commit} 2>/dev/null; then
  echo 'shallow reproduction unexpectedly contained the pinned legacy object' >&2
  exit 1
fi
git -C "${checkout}" fetch --quiet --unshallow origin
test "$(git -C "${checkout}" rev-parse d2f5a69c9f14d504ad64176dcc62c5ffa7bb032c^{commit})" = \
  d2f5a69c9f14d504ad64176dcc62c5ffa7bb032c
CLIXOR_TEST_REPOSITORY="${checkout}" \
  python3 "${repository}/deploy/oci/test_runtime_reconciler.py" \
  LegacyBaselineTests.test_9e41_staging_transition_is_exact_idempotent_and_preserves_database
