#!/usr/bin/env bash
# One-time setup: Python deps, scanners, Juice Shop clone, resolved lockfile.
set -euo pipefail
cd "$(dirname "$0")"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')          # linux | darwin
ARCH=$(uname -m); [[ "$ARCH" == "x86_64" ]] && ARCH=amd64; [[ "$ARCH" == "aarch64" ]] && ARCH=arm64

echo "==> Python dependencies"
python3 -m pip install -r requirements.txt

echo "==> Scanners into ./tools"
mkdir -p tools
[[ -x tools/syft ]] || curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b tools
[[ -x tools/osv-scanner ]] || {
  curl -sSfL -o tools/osv-scanner \
    "https://github.com/google/osv-scanner/releases/download/v2.2.4/osv-scanner_${OS}_${ARCH}"
  chmod +x tools/osv-scanner
}

echo "==> Juice Shop (official repo)"
mkdir -p target reports
[[ -d target/juice-shop ]] || git clone --depth 200 https://github.com/juice-shop/juice-shop.git target/juice-shop

echo "==> Resolve dependency tree (no install scripts are run)"
(cd target/juice-shop && npm install --package-lock-only --ignore-scripts --package-lock=true --no-audit --no-fund)


if [[ "${WITH_BENCHMARK_TOOLS:-0}" == "1" ]]; then
  echo "==> Grype and Trivy for the benchmark"
  [[ -x tools/grype ]] || curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b tools
  [[ -x tools/trivy ]] || curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b tools
fi

echo "Done. Next: python3 -m guardian.cli && python3 -m guardian.day2 plan && streamlit run app.py"
