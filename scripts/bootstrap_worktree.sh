#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python_bin="${PYTHON:-python3}"
venv_dir="${VENV_DIR:-.venv}"
main_dir="${MAIN_WORKTREE_DIR:-}"

if [[ -z "$main_dir" ]]; then
  common_git_dir="$(git rev-parse --git-common-dir 2>/dev/null || true)"
  if [[ -n "$common_git_dir" ]]; then
    main_dir="$(cd "${common_git_dir}/.." && pwd)"
  fi
fi

copy_first_existing() {
  local target="$1"
  shift

  for source in "$@"; do
    if [[ -n "$source" && -f "$source" ]]; then
      cp "$source" "$target"
      echo "Created ${target} from ${source}"
      return 0
    fi
  done

  return 1
}

if [[ ! -f docker-compose.yaml ]]; then
  if ! copy_first_existing \
    docker-compose.yaml \
    "${main_dir}/docker-compose.yaml" \
    "${main_dir}/docker-compose.yml" \
    docker-compose.example.yml; then
    echo "Could not find a compose file to copy" >&2
    exit 1
  fi
else
  echo "docker-compose.yaml already exists"
fi

if [[ ! -f .env ]]; then
  if [[ -n "$main_dir" && -f "${main_dir}/.env" ]]; then
    cp "${main_dir}/.env" .env
    echo "Created .env from ${main_dir}/.env"
  else
    cat > .env <<'ENV'
CROWDSEC_LAPI_KEY=replace-with-your-lapi-key
ENV
    echo "Created .env with placeholder values"
  fi
else
  echo ".env already exists"
fi

created_venv=false
if [[ ! -x "${venv_dir}/bin/python" ]]; then
  "$python_bin" -m venv "$venv_dir"
  created_venv=true
  echo "Created ${venv_dir}"
else
  echo "${venv_dir} already exists"
fi

if [[ "$created_venv" == true || "${BOOTSTRAP_UPGRADE_PIP:-0}" == "1" ]]; then
  "${venv_dir}/bin/python" -m pip install --upgrade pip
fi

if "${venv_dir}/bin/python" -c "import editables, hatchling" >/dev/null 2>&1; then
  "${venv_dir}/bin/python" -m pip install --no-build-isolation -e ".[dev]"
else
  "${venv_dir}/bin/python" -m pip install -e ".[dev]"
fi

echo "Worktree bootstrap complete"
