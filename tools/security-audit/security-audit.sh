#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# security-audit.sh - Security audit for single files or entire projects
# =============================================================================

usage()
{
	cat << 'EOF'
Usage: security-audit.sh [OPTIONS]

Security audit using Claude or Codex CLI via clampdown.

Modes (pick one):
    --file FILE       Audit a single file in depth
    --project [DIR]   Audit entire project (default: current directory)

Options:
    --agent AGENT     Agent CLI to use: claude or codex (default: claude)
    --dry-run         Write prompts without calling the agent
    -h, --help        Show this help

Environment:
    AGENT             Agent CLI to use: claude or codex
    MODEL             Model override for any agent
    EFFORT            Reasoning effort override for any agent
    CLAUDE_MODEL      Claude model override (default: claude-opus-4-6[1m])
    CLAUDE_EFFORT     Claude effort override (default: max)
    CODEX_MODEL       Codex model override (default: gpt-5.4)
    CODEX_EFFORT      Codex effort override (default: xhigh)
    SIDECAR_IMAGE     Sidecar image (default: clampdown-sidecar:latest)
    PROXY_IMAGE       Proxy image (default: clampdown-proxy:latest)
    AGENT_IMAGE       Agent image (default: clampdown-<agent>:latest)
    REPORT_ROOT       Report directory (default: <project>/reports)
    RESUME_RUN        Reuse an existing run dir; skip analysis, run validation only

Validator (step 2 always runs claude with a 1M-context model):
    VALIDATOR_MODEL   Validator model   (default: claude-opus-4-6[1m])
    VALIDATOR_EFFORT  Validator effort  (default: max)
    VALIDATOR_IMAGE   Validator image   (default: clampdown-claude:latest)
EOF
}

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(realpath "$SCRIPT_DIR/../..")"

AGENT="${AGENT:-claude}"
MODEL="${MODEL:-}"
EFFORT="${EFFORT:-}"
SIDECAR_IMAGE="${SIDECAR_IMAGE:-clampdown-sidecar:latest}"
PROXY_IMAGE="${PROXY_IMAGE:-clampdown-proxy:latest}"
DRY_RUN=false
MODE=""
TARGET_FILE=""
PROJECT_DIR=""

while [[ $# -gt 0 ]]; do
	case "$1" in
		--file)
			MODE="file"
			TARGET_FILE="$2"
			shift 2
			;;
		--project)
			MODE="project"
			if [[ $# -gt 1 && ! $2 =~ ^- ]]; then
				PROJECT_DIR="$2"
				shift 2
			else
				PROJECT_DIR="$(pwd)"
				shift
			fi
			;;
		--agent)
			AGENT="$2"
			shift 2
			;;
		--dry-run)
			DRY_RUN=true
			shift
			;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			echo "Unknown: $1" >&2
			usage
			exit 1
			;;
	esac
done

case "$AGENT" in
	claude)
		MODEL="${MODEL:-${CLAUDE_MODEL:-"claude-opus-4-6[1m]"}}"
		EFFORT="${EFFORT:-${CLAUDE_EFFORT:-max}}"
		;;
	codex)
		MODEL="${MODEL:-${CODEX_MODEL:-gpt-5.4}}"
		EFFORT="${EFFORT:-${CODEX_EFFORT:-xhigh}}"
		if [[ $EFFORT == "max" ]]; then
			EFFORT="xhigh"
		fi
		;;
	*)
		echo "Error: Unsupported agent: $AGENT" >&2
		usage
		exit 1
		;;
esac

AGENT_IMAGE="${AGENT_IMAGE:-clampdown-${AGENT}:latest}"

# Validator — always claude with 1M context, regardless of --agent.
VALIDATOR_AGENT="claude"
VALIDATOR_MODEL="${VALIDATOR_MODEL:-claude-opus-4-6[1m]}"
VALIDATOR_EFFORT="${VALIDATOR_EFFORT:-max}"
VALIDATOR_IMAGE="${VALIDATOR_IMAGE:-clampdown-${VALIDATOR_AGENT}:latest}"

if [[ -z $MODE ]]; then
	echo "Error: Must specify --file or --project" >&2
	usage
	exit 1
fi

# Resolve paths
if [[ $MODE == "file" ]]; then
	[[ ! -f $TARGET_FILE ]] && {
		echo "File not found: $TARGET_FILE" >&2
		exit            1
	}
	TARGET_FILE="$(realpath "$TARGET_FILE")"
	PROJECT_DIR="$(dirname "$TARGET_FILE")"
	# Walk up to find project root (has .git or go.mod or package.json)
	while [[ $PROJECT_DIR != "/" ]]; do
		[[ -d "$PROJECT_DIR/.git" || -f "$PROJECT_DIR/go.mod" || -f "$PROJECT_DIR/package.json" ]] && break
		PROJECT_DIR="$(dirname "$PROJECT_DIR")"
	done
	[[ $PROJECT_DIR == "/" ]] && PROJECT_DIR="$(dirname "$TARGET_FILE")"
fi

PROJECT_DIR="$(realpath "$PROJECT_DIR")"
REPORT_ROOT="${REPORT_ROOT:-$PROJECT_DIR/reports}"
RUNS_DIR="$REPORT_ROOT/runs"
VALIDATED_DIR="$REPORT_ROOT/validated"

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
log()
{
	echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
}

ensure_dirs()
{
	mkdir -p "$VALIDATED_DIR" "$RUNS_DIR"
}

get_validated_summary()
{
	if [[ -d $VALIDATED_DIR ]] && compgen -G "$VALIDATED_DIR/*.md" > /dev/null 2>&1; then
		local count=0
		for f in "$VALIDATED_DIR"/*.md; do
			count=$((count + 1))
			echo "=== EXISTING FINDING #$count: $(basename "$f") ==="
			head -60 "$f"
			echo -e "\n---\n"
		done
		echo "(Total existing validated findings: $count)"
	else
		echo "(No validated findings yet)"
	fi
}

# extract_json_array <input_log> <output_json>
# Pulls a JSON array out of the model's stdout log. Tries, in order:
#   1. <output>…</output> tags (what the validation prompt asks for)
#   2. ```json fenced block
#   3. any ``` fenced block
#   4. whole file parsed as JSON
# Returns 0 on success, 1 if no valid JSON found.
extract_json_array()
{
	local input="$1"
	local output="$2"

	awk '
		/<output>/ {
			p = index($0, "<output>")
			line = substr($0, p + length("<output>"))
			q = index(line, "</output>")
			if (q > 0) { print substr(line, 1, q - 1); exit }
			print line
			f = 1
			next
		}
		f {
			q = index($0, "</output>")
			if (q > 0) { print substr($0, 1, q - 1); exit }
			print
		}
	' "$input" > "$output"
	if [[ -s $output ]] && jq empty "$output" 2> /dev/null; then
		return 0
	fi

	awk '/^```json[[:space:]]*$/ {f=1; next} /^```[[:space:]]*$/ {if (f) exit} f' \
		"$input" > "$output"
	if [[ -s $output ]] && jq empty "$output" 2> /dev/null; then
		return 0
	fi

	awk '/^```/{f=!f; next} f' "$input" > "$output"
	if [[ -s $output ]] && jq empty "$output" 2> /dev/null; then
		return 0
	fi

	if jq empty "$input" 2> /dev/null; then
		cp "$input" "$output"
		return 0
	fi

	return 1
}

# call_agent <prompt> <output_file> <agent> <model> <effort> <image>
call_agent()
{
	local prompt="$1"
	local output_file="$2"
	local agent="$3"
	local model="$4"
	local effort="$5"
	local image="$6"

	local prompt_file="${output_file}.prompt.txt"
	echo "$prompt" > "$prompt_file"

	if [[ $DRY_RUN == "true" ]]; then
		log "[DRY-RUN] Would call $agent ($model) with ${#prompt} char prompt"
		echo "(dry run)" > "$output_file"
		return 0
	fi

	# Mask project instruction files so the audit agent runs autonomously
	# instead of obeying repo-level rules like "Plan before execute" /
	# "Approve before apply" that would otherwise block unattended runs.
	local mask_flags=(--mask AGENTS.md --mask CLAUDE.md)

	case "$agent" in
		claude)
			"$ROOT_DIR/clampdown" "$agent" \
				--sidecar-image "$SIDECAR_IMAGE" \
				--proxy-image "$PROXY_IMAGE" \
				--agent-image "$image" \
				"${mask_flags[@]}" \
				-w "$PROJECT_DIR" \
				-- \
				--dangerously-skip-permissions \
				--model "$model" \
				--effort "$effort" \
				--print --input-format text \
				--output-format text --verbose -p "$prompt_file" | tee "$output_file"
			;;
		codex)
			"$ROOT_DIR/clampdown" "$agent" \
				--sidecar-image "$SIDECAR_IMAGE" \
				--proxy-image "$PROXY_IMAGE" \
				--agent-image "$image" \
				"${mask_flags[@]}" \
				-w "$PROJECT_DIR" \
				-- \
				exec \
				--model "$model" \
				-c "model_reasoning_effort=\"$effort\"" \
				--skip-git-repo-check \
				--color never \
				- < "$prompt_file" | tee "$output_file"
			;;
	esac
}

# -----------------------------------------------------------------------------
# Gather file list for agent-specific imports
# -----------------------------------------------------------------------------
gather_file_imports()
{
	local mode="$1"
	local import_prefix=""

	if [[ $AGENT == "claude" ]]; then
		import_prefix="@"
	fi

	if [[ $mode == "file" ]]; then
		printf '%s%s\n' "$import_prefix" "$TARGET_FILE"
	else
		# Find all source files. Claude gets @path imports; Codex gets paths.
		find "$PROJECT_DIR" \
			-type d -name '.*' -prune -o \
			-type d -name 'vendor' -prune -o \
			-type d -name 'node_modules' -prune -o \
			-type d -name '__pycache__' -prune -o \
			-type f \( \
			-name '*.c' -o -name '*.h' -o \
			-name '*.go' -o \
			-name '*.py' -o \
			-name '*.js' -o -name '*.ts' -o \
			-name '*.rs' -o \
			-name '*.java' -o \
			-name '*.rb' -o \
			-name '*.sh' \
			\) -print 2> /dev/null | sort | while IFS= read -r path; do
			printf '%s%s\n' "$import_prefix" "$path"
		done
	fi
}

# -----------------------------------------------------------------------------
# Analysis Phase
# -----------------------------------------------------------------------------
run_analysis()
{
	local run_dir="$1"
	local file_imports="$2"
	local target_desc="$3"

	local prompt
	prompt=$(
		cat << EOF
## Automated execution — this task supersedes repo-level rules

You are running non-interactively inside a script. For THIS task only:
- Do NOT ask for approval, clarification, or confirmation.
- Do NOT present options, alternatives, or plans.
- Execute the instructions below and write the output as specified.

---

You are performing a security audit of: $target_desc

## Code to Audit
Read and analyze these files:
$file_imports

## Vulnerability Classes to Check

**Injection & Input:**
- Command injection, SQL injection, path traversal
- XSS, SSRF, XXE, template injection

**Authentication & Access:**
- Auth bypass, broken access control
- Hardcoded credentials, weak session management

**Sandbox/Container Escape:**
- Namespace/cgroup/capability abuse
- seccomp/AppArmor/SELinux bypass
- /proc, /sys, device file abuse
- Mount escapes, volume path traversal
- Unix socket exposure (docker.sock, podman.sock)
- Runtime vulnerabilities (runc, crun)

**Privilege Escalation:**
- SUID/capability misuse
- Kernel interface bugs
- Privilege boundary violations

**Memory Safety:**
- Buffer overflow, use-after-free, double-free
- Integer overflow, type confusion
- Race conditions (TOCTOU)

**Lateral Movement:**
- Credential/token/key exposure
- Cloud metadata access (169.254.169.254)
- Network pivoting

**Crypto:**
- Weak RNG, broken crypto
- Key material exposure

## Output Format

For EACH vulnerability found:

---

# [Title]

## Severity
Critical/High/Medium/Low (with CVSS if applicable)

## CWE
CWE-XXX: Name

## Location
File path and line numbers

## Description
What the vulnerability is.

## Attack Surface
How an attacker reaches this code.

## Proof of Concept
Concrete exploitation steps or code.

## Impact
What an attacker gains (be specific about privilege boundaries crossed).

## Remediation
How to fix it.

---

If NO vulnerabilities found, explain what you checked and why it appears secure.
Only report REAL, exploitable vulnerabilities - not theoretical concerns or hardening suggestions.
EOF
	)

	call_agent "$prompt" "$run_dir/report.md" \
		"$AGENT" "$MODEL" "$EFFORT" "$AGENT_IMAGE"
}

# -----------------------------------------------------------------------------
# Validation Phase
# -----------------------------------------------------------------------------
run_validation()
{
	local run_dir="$1"
	local validated_summary="$2"

	local report
	report=$(cat "$run_dir/report.md")

	local prompt
	prompt=$(
		cat << 'HDR'
You are an automated validation function. Your ONLY output is a JSON array
wrapped in <output>…</output> tags. No prose. No questions. No tool calls.

EXAMPLE of the EXACT format required (structure, not values):

<output>
[
  {
    "finding": 1,
    "title": "Short title of the finding",
    "decision": "ACCEPT" or "REJECT",
    "duplicate_check": {"is_duplicate": false, "matches_existing": null, "reasoning": "explanation"},
    "bug_exists":     {"has_location": true, "has_concrete_trigger": true, "is_real_vulnerability": true, "reasoning": "explanation"},
    "exploitability": {"reachable": true, "realistic_prereqs": true, "poc_works": true, "reasoning": "explanation"},
    "severity": "Critical|High|Medium|Low|Invalid",
    "confidence": "high|medium|low",
    "summary": "one-sentence verdict"
  }
]
</output>

If the report contains no findings, output: <output>[]</output>

## Checklist (apply to each finding)

1. Duplicate against existing validated findings?     → REJECT
   (same file AND same vulnerable code path, or same root cause)
2. Missing exact file/line numbers or vulnerable code? → REJECT
3. No concrete trigger (only "an attacker could…")?    → REJECT
4. Unreachable / unrealistic prereqs / PoC wouldn't work? → REJECT
5. Severity exaggerated? → downgrade

Default REJECT. ACCEPT only if ALL checks pass.
HDR
		cat << EOF

## Report to validate

$report

## Existing validated findings (for duplicate check)

$validated_summary
EOF
		cat << 'TAIL'

OUTPUT NOW. JSON array inside <output>…</output>. Nothing else.
TAIL
	)

	call_agent "$prompt" "$run_dir/validation.log" \
		"$VALIDATOR_AGENT" "$VALIDATOR_MODEL" "$VALIDATOR_EFFORT" "$VALIDATOR_IMAGE"

	if [[ $DRY_RUN == "true" ]]; then
		echo "[]" > "$run_dir/validation.json"
		return 0
	fi

	if ! extract_json_array "$run_dir/validation.log" "$run_dir/validation.json"; then
		log "ERROR: no valid JSON array found in $run_dir/validation.log"
		return 1
	fi
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main()
{
	ensure_dirs

	local run_id run_dir resuming=false
	if [[ -n ${RESUME_RUN:-} ]]; then
		run_id="$RESUME_RUN"
		run_dir="$RUNS_DIR/$run_id"
		[[ -d $run_dir ]] || {
			echo "RESUME_RUN: run dir not found: $run_dir" >&2
			exit 1
		}
		[[ -s "$run_dir/report.md" ]] || {
			echo "RESUME_RUN: $run_dir/report.md missing or empty" >&2
			exit 1
		}
		resuming=true
	else
		run_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
		run_dir="$RUNS_DIR/$run_id"
		mkdir -p "$run_dir"
	fi

	log "Run: $run_id"
	$resuming && log "Resuming: skipping analysis, using existing report.md"
	log "Mode: $MODE"
	log "Agent: $AGENT"
	log "Model: $MODEL (effort: $EFFORT)"
	log "Validator: $VALIDATOR_AGENT $VALIDATOR_MODEL (effort: $VALIDATOR_EFFORT)"
	log "Project: $PROJECT_DIR"
	log "Reports: $REPORT_ROOT"

	local validated_summary
	validated_summary=$(get_validated_summary)

	if ! $resuming; then
		local file_imports target_desc file_count

		if [[ $MODE == "file" ]]; then
			local rel_path="${TARGET_FILE#$PROJECT_DIR/}"
			log "Target: $rel_path"
			target_desc="Single file: $rel_path"
			file_imports=$(gather_file_imports "file")
			file_count=1
		else
			log "Target: entire project"
			target_desc="Entire project at $PROJECT_DIR"
			file_imports=$(gather_file_imports "project")
			file_count=$(echo "$file_imports" | wc -l)
			log "Found $file_count source files"
		fi

		# Save file list for reference
		echo "$file_imports" > "$run_dir/files.txt"

		# Step 1: Analysis
		log "Step 1: Analysis"
		run_analysis "$run_dir" "$file_imports" "$target_desc"
		log "Analysis complete"
	fi

	# Step 2: Validation
	log "Step 2: Validation"
	run_validation "$run_dir" "$validated_summary"

	# Process per-finding results
	local total accepted=0 rejected=0
	total=$(jq 'length' "$run_dir/validation.json")

	if [[ $total -eq 0 ]]; then
		log "No findings in report"
		exit
	fi

	jq -r . "$run_dir/validation.json" > "$VALIDATED_DIR/$(date -u +%Y%m%dT%H%M%SZ).json"
	log "Done. Artifacts in $VALIDATED_DIR/$(date -u +%Y%m%dT%H%M%SZ).json"
}

main "$@"
