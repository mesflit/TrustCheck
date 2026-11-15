#!/usr/bin/env bash
# TrustCheck — SPDX-License-Identifier: GPL-3.0-only
# Fails if any tracked file violates the source-only repository policy (README → "Distribution").
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

forbidden_ext='\.(apk|aab|apks|ap_|dex|class|jar|aar|so|jks|keystore|p12|pem|key|db|db-shm|db-wal|hprof|zip)$'
forbidden_path='(^|/)(build|\.gradle|\.kotlin|captures|out|release-assets)/|(^|/)(local\.properties|keystore\.properties|signing\.properties|google-services\.json|\.env)$'

status=0
violations=$(git ls-files | grep -Ei "$forbidden_ext" || true)
if [[ -n "$violations" ]]; then
  echo "::error::Binary or secret files are tracked (not allowed):"; echo "$violations"; status=1
fi
violations=$(git ls-files | grep -Ei "$forbidden_path" || true)
if [[ -n "$violations" ]]; then
  echo "::error::Build outputs or local config are tracked (not allowed):"; echo "$violations"; status=1
fi
# Any tracked file git considers binary (other than none expected) is suspicious.
binaries=$(git ls-files -z | xargs -0 -I{} sh -c 'git diff --no-index --numstat /dev/null "{}" 2>/dev/null | grep -q "^-" && echo "{}"' || true)
if [[ -n "$binaries" ]]; then
  echo "::error::Binary files are tracked:"; echo "$binaries"; status=1
fi
# Obvious secrets.
if git grep -nE 'ca-app-pub-[0-9]{16}[~/][0-9]{10}' -- ':!*.md' | grep -v '3940256099942544' ; then
  echo "::error::A non-test AdMob ID is committed. Inject production IDs via CI secrets."; status=1
fi
if git grep -nE 'AIza[0-9A-Za-z_-]{35}|-----BEGIN (RSA |EC )?PRIVATE KEY-----' ; then
  echo "::error::A credential appears to be committed."; status=1
fi
[[ $status -eq 0 ]] && echo "Source-only policy: OK ($(git ls-files | wc -l) tracked files)"
exit $status
