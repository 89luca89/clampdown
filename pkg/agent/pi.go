// SPDX-License-Identifier: GPL-3.0-only

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Pi implements Agent for the pi coding agent (earendil-works/pi).
type Pi struct{}

func (p *Pi) Name() string  { return "pi" }
func (p *Pi) Image() string { return "ghcr.io/89luca89/clampdown-pi:latest" }

// EgressDomains returns every provider API pi can be pointed at, plus pi's own
// host and the npm registry its package manager installs extensions from. The
// proxy reaches these upstreams from the same network namespace the agent is
// in, so a domain missing here fails the session at the first request.
func (p *Pi) EgressDomains() []string {
	return []string{
		"registry.npmjs.org",
		// pi's own host. It serves the model catalogue pi refreshes at startup,
		// which is what makes models newer than the bundled list selectable.
		// The version check and install telemetry live there too; Env turns
		// both off.
		"pi.dev",
		// Provider APIs, in ProxyRoutes order.
		"api.anthropic.com",
		"api.openai.com",
		"generativelanguage.googleapis.com",
		"api.groq.com",
		"api.deepseek.com",
		"api.mistral.ai",
		"api.x.ai",
		"openrouter.ai",
		"api.ant-ling.com",
		"inference.baseten.co",
		"api.cerebras.ai",
		"api.cloudflare.com",
		"api.fireworks.ai",
		"api.individual.githubcopilot.com",
		"router.huggingface.co",
		"api.kimi.com",
		"api.minimax.io",
		"api.minimaxi.com",
		"api.moonshot.ai",
		"api.moonshot.cn",
		"integrate.api.nvidia.com",
		"opencode.ai",
		"token-plan.ap-southeast-1.maas.aliyuncs.com",
		"token-plan.cn-beijing.maas.aliyuncs.com",
		"api.together.ai",
		"ai-gateway.vercel.sh",
		"api.xiaomimimo.com",
		"token-plan-ams.xiaomimimo.com",
		"token-plan-cn.xiaomimimo.com",
		"token-plan-sgp.xiaomimimo.com",
		"api.z.ai",
		"open.bigmodel.cn",
	}
}

func (p *Pi) Mounts() []Mount { return nil }

// ConfigOverlays forwards the host's pi settings, prompt templates, skills,
// extensions and agent definitions read-only. Extensions run as code inside
// pi's process, so they get the same trust as the agent itself. auth.json is
// deliberately not forwarded: it outranks the environment in pi's credential
// resolution, so seeding it would put the real key inside the agent container.
// models.json is generated per session by PreparePiHome.
func (p *Pi) ConfigOverlays() []Mount {
	agentDir := filepath.Join(Home, ".pi", "agent")
	return []Mount{
		{Src: filepath.Join(agentDir, "settings.json"), Dst: filepath.Join(agentDir, "settings.json")},
		{Src: filepath.Join(agentDir, "prompts"), Dst: filepath.Join(agentDir, "prompts")},
		{Src: filepath.Join(agentDir, "skills"), Dst: filepath.Join(agentDir, "skills")},
		{Src: filepath.Join(agentDir, "extensions"), Dst: filepath.Join(agentDir, "extensions")},
		{Src: filepath.Join(agentDir, "agents"), Dst: filepath.Join(agentDir, "agents")},
	}
}

// Env keeps pi's model catalogue reachable and switches off the rest of its
// startup traffic. The refresh is what puts models newer than the ones bundled
// in the image into the picker; the version check and install telemetry have
// nothing to contribute inside the sandbox.
func (p *Pi) Env() map[string]string {
	return map[string]string{
		"PI_SKIP_VERSION_CHECK": "1",
		"PI_TELEMETRY":          "0",
	}
}

func (p *Pi) Args(passthrough []string) []string { return passthrough }

// PromptFile returns ~/.pi/agent/APPEND_SYSTEM.md, which pi appends to its
// system prompt when present. The project-level copy of that file only loads
// for trusted projects; the global one always loads.
func (p *Pi) PromptFile() string {
	return filepath.Join(Home, ".pi", "agent", "APPEND_SYSTEM.md")
}

// ProxyRoutes returns upstream API routes for every pi provider that
// authenticates with a key and a usable endpoint. pi reads no base-URL
// environment variable, so BaseURLEnv exists only to let .clampdownrc repoint
// the proxy upstream; the URL pi itself is pointed at is written into
// models.json by PreparePiHome.
//
// Each upstream is the provider's registered baseUrl, version path included,
// because the proxy joins the upstream path with the path pi appends to it.
// The header is the one pi's API implementation uses for that provider:
// x-api-key for the Anthropic-style APIs, x-goog-api-key for the GenAI SDK,
// Bearer for the OpenAI SDK and Mistral.
//
// Providers pi registers that cannot be proxied this way, and why:
//   - amazon-bedrock: its AWS SDK builds and signs its own requests, ignoring
//     the provider baseUrl, so a repointed endpoint never sees the traffic
//   - google-vertex: authenticates through application default credentials,
//     which need an hourly-refreshed OAuth token, not a static key
//   - openai-codex: OAuth only, the token lives in auth.json
//   - cloudflare-ai-gateway: needs a gateway token in cf-aig-authorization
//     plus the upstream provider's key, two credentials on one route
//   - radius: shipped as a gateway configuration, not a built-in provider
//
// Providers sharing a key with an earlier route (opencode, moonshotai-cn,
// qwen-token-plan-individual) are listed after it: the first match picks the
// session's upstream, but the sibling still gets repointed in models.json and
// its host stays allowlisted. Point CLAMPDOWN_UPSTREAM at the sibling's host to
// use it instead of the one picked by the key.
func (p *Pi) ProxyRoutes() []ProxyRoute {
	return []ProxyRoute{
		// Common providers first: the first route with a key set wins.
		{Port: ProxyPort, Upstream: "https://api.anthropic.com",
			KeyEnv: "ANTHROPIC_API_KEY", HeaderName: "x-api-key",
			BaseURLEnv: "ANTHROPIC_BASE_URL", ProviderID: "anthropic"},
		{Port: ProxyPort, Upstream: "https://api.openai.com/v1",
			KeyEnv: "OPENAI_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			BaseURLEnv: "OPENAI_BASE_URL", ProviderID: "openai"},
		{Port: ProxyPort, Upstream: "https://generativelanguage.googleapis.com/v1beta",
			KeyEnv: "GEMINI_API_KEY", KeyEnvFallback: "GOOGLE_GENERATIVE_AI_API_KEY",
			HeaderName: "x-goog-api-key", ProviderID: "google"},
		{Port: ProxyPort, Upstream: "https://api.groq.com/openai/v1",
			KeyEnv: "GROQ_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			BaseURLEnv: "GROQ_BASE_URL", ProviderID: "groq"},
		{Port: ProxyPort, Upstream: "https://api.deepseek.com",
			KeyEnv: "DEEPSEEK_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			BaseURLEnv: "DEEPSEEK_BASE_URL", ProviderID: "deepseek"},
		{Port: ProxyPort, Upstream: "https://api.mistral.ai",
			KeyEnv: "MISTRAL_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			BaseURLEnv: "MISTRAL_BASE_URL", ProviderID: "mistral"},
		{Port: ProxyPort, Upstream: "https://api.x.ai/v1",
			KeyEnv: "XAI_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			BaseURLEnv: "XAI_BASE_URL", ProviderID: "xai"},
		{Port: ProxyPort, Upstream: "https://openrouter.ai/api/v1",
			KeyEnv: "OPENROUTER_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			BaseURLEnv: "OPENROUTER_BASE_URL", ProviderID: "openrouter"},
		{Port: ProxyPort, Upstream: "https://api.ant-ling.com/v1",
			KeyEnv: "ANT_LING_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "ant-ling"},
		// Azure endpoints are per-resource and carry the deployment in the
		// path, which pi only builds when it can see the endpoint: the value
		// must be the full base URL, deployment included.
		{Port: ProxyPort, KeyEnv: "AZURE_OPENAI_API_KEY", HeaderName: "api-key",
			UpstreamEnv: "AZURE_OPENAI_BASE_URL", ProviderID: "azure-openai-responses"},
		{Port: ProxyPort, Upstream: "https://inference.baseten.co/v1",
			KeyEnv: "BASETEN_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "baseten"},
		{Port: ProxyPort, Upstream: "https://api.cerebras.ai/v1",
			KeyEnv: "CEREBRAS_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "cerebras"},
		// The account is part of the path, so it comes from the environment
		// rather than the route; pi reads the same variable for its own
		// credential check (see EnvAllowlist).
		{
			Port:             ProxyPort,
			KeyEnv:           "CLOUDFLARE_API_KEY",
			UpstreamEnv:      "CLOUDFLARE_ACCOUNT_ID",
			UpstreamTemplate: "https://api.cloudflare.com/client/v4/accounts/%s/ai/v1",
			HeaderName:       "Authorization",
			HeaderPrefix:     "Bearer ",
			ProviderID:       "cloudflare-workers-ai",
		},
		{Port: ProxyPort, Upstream: "https://api.fireworks.ai/inference",
			KeyEnv: "FIREWORKS_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "fireworks"},
		// The documented env token is used as an API key, with no token
		// exchange on that path.
		{Port: ProxyPort, Upstream: "https://api.individual.githubcopilot.com",
			KeyEnv: "COPILOT_GITHUB_TOKEN", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "github-copilot"},
		{Port: ProxyPort, Upstream: "https://router.huggingface.co/v1",
			KeyEnv: "HF_TOKEN", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "huggingface"},
		{Port: ProxyPort, Upstream: "https://api.kimi.com/coding",
			KeyEnv: "KIMI_API_KEY", HeaderName: "x-api-key",
			ProviderID: "kimi-coding"},
		{Port: ProxyPort, Upstream: "https://api.minimax.io/anthropic",
			KeyEnv: "MINIMAX_API_KEY", HeaderName: "x-api-key",
			ProviderID: "minimax"},
		{Port: ProxyPort, Upstream: "https://api.minimaxi.com/anthropic",
			KeyEnv: "MINIMAX_CN_API_KEY", HeaderName: "x-api-key",
			ProviderID: "minimax-cn"},
		{Port: ProxyPort, Upstream: "https://api.moonshot.ai/v1",
			KeyEnv: "MOONSHOT_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "moonshotai"},
		{Port: ProxyPort, Upstream: "https://api.moonshot.cn/v1",
			KeyEnv: "MOONSHOT_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "moonshotai-cn"},
		{Port: ProxyPort, Upstream: "https://integrate.api.nvidia.com/v1",
			KeyEnv: "NVIDIA_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "nvidia"},
		{Port: ProxyPort, Upstream: "https://opencode.ai/zen/go/v1",
			KeyEnv: "OPENCODE_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "opencode-go"},
		{Port: ProxyPort, Upstream: "https://opencode.ai/zen/v1",
			KeyEnv: "OPENCODE_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "opencode"},
		{Port: ProxyPort, Upstream: "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1",
			KeyEnv: "QWEN_TOKEN_PLAN_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "qwen-token-plan"},
		{Port: ProxyPort, Upstream: "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1",
			KeyEnv: "QWEN_TOKEN_PLAN_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "qwen-token-plan-individual"},
		{Port: ProxyPort, Upstream: "https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
			KeyEnv: "QWEN_TOKEN_PLAN_CN_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "qwen-token-plan-cn"},
		{Port: ProxyPort, Upstream: "https://api.together.ai/v1",
			KeyEnv: "TOGETHER_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "together"},
		{Port: ProxyPort, Upstream: "https://ai-gateway.vercel.sh",
			KeyEnv: "AI_GATEWAY_API_KEY", HeaderName: "x-api-key",
			ProviderID: "vercel-ai-gateway"},
		{Port: ProxyPort, Upstream: "https://api.xiaomimimo.com/v1",
			KeyEnv: "XIAOMI_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "xiaomi"},
		{Port: ProxyPort, Upstream: "https://token-plan-ams.xiaomimimo.com/v1",
			KeyEnv: "XIAOMI_TOKEN_PLAN_AMS_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "xiaomi-token-plan-ams"},
		{Port: ProxyPort, Upstream: "https://token-plan-cn.xiaomimimo.com/v1",
			KeyEnv: "XIAOMI_TOKEN_PLAN_CN_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "xiaomi-token-plan-cn"},
		{Port: ProxyPort, Upstream: "https://token-plan-sgp.xiaomimimo.com/v1",
			KeyEnv: "XIAOMI_TOKEN_PLAN_SGP_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "xiaomi-token-plan-sgp"},
		{Port: ProxyPort, Upstream: "https://api.z.ai/api/coding/paas/v4",
			KeyEnv: "ZAI_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "zai"},
		{Port: ProxyPort, Upstream: "https://open.bigmodel.cn/api/coding/paas/v4",
			KeyEnv: "ZAI_CODING_CN_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "zai-coding-cn"},
	}
}

func (p *Pi) ProxyEnvOverride(_ []ProxyRoute) map[string]string { return nil }

// EnvAllowlist admits terminal rendering and prompt-cache knobs, plus the two
// provider vars pi resolves for itself: the azure API version it appends to the
// request path, and the cloudflare account id, which its credential check wants
// present even though the proxy carries the endpoint. Neither is a secret. A
// PI_ prefix would admit PI_CODING_AGENT_DIR, which repoints pi at another
// config directory -- a models.json there runs its "!command" values as shell
// commands -- and PI_PACKAGE_DIR, which repoints package loading. The
// egress-control vars (PI_SKIP_VERSION_CHECK, PI_TELEMETRY) are set by the
// sandbox and stay with it. Provider endpoints and keys never reach the agent:
// the proxy holds them and models.json points pi at the proxy.
func (p *Pi) EnvAllowlist() EnvAllow {
	return EnvAllow{Names: []string{
		"AZURE_OPENAI_API_VERSION", "CLOUDFLARE_ACCOUNT_ID",
		"PI_CACHE_RETENTION", "PI_CLEAR_ON_SHRINK", "PI_HARDWARE_CURSOR",
		"PI_HYPERLINKS", "PI_IMAGE_PROTOCOL", "PI_TRUE_COLOR",
		"PI_TUI_ESC_TIMEOUT",
	}}
}

// PreparePiHome writes the models.json that routes pi's providers through the
// auth proxy, inside the agent's persistent HOME directory. Provider-level
// baseUrl overrides keep pi's built-in models and its environment-key auth.
// Every provider sharing the active route's key is repointed, so switching
// provider inside pi cannot send the dummy key to the real endpoint.
func PreparePiHome(homeDir string, routes []ProxyRoute, active *ProxyRoute) error {
	agentDir := filepath.Join(homeDir, ".pi", "agent")
	err := os.MkdirAll(agentDir, 0o700)
	if err != nil {
		return fmt.Errorf("create pi agent dir: %w", err)
	}

	return writePiModels(filepath.Join(agentDir, "models.json"), routes, active)
}

func writePiModels(path string, routes []ProxyRoute, active *ProxyRoute) error {
	providers := make(map[string]any)
	for _, r := range routes {
		if active == nil || r.ProviderID == "" {
			continue
		}
		if !sharesKeyEnv(r, *active) {
			continue
		}
		// 127.0.0.1, not localhost: node resolves localhost to ::1 first, the
		// refused connect trips the network helper's firewall guidance, and the
		// fallback to IPv4 succeeds -- one false guidance block per API request.
		providers[r.ProviderID] = map[string]any{
			"baseUrl": fmt.Sprintf("http://127.0.0.1:%d", r.Port),
		}
	}

	// No active route means nothing to repoint. Drop a file left by an earlier
	// session so a run without a key doesn't send traffic to a proxy that
	// isn't there.
	if len(providers) == 0 {
		err := os.Remove(path)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove pi models config: %w", err)
		}
		return nil
	}

	cfg := map[string]any{"providers": providers}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal pi models config: %w", err)
	}
	data = append(data, '\n')

	existing, err := os.ReadFile(path)
	if err == nil && string(existing) == string(data) {
		return nil
	}

	err = os.WriteFile(path, data, 0o600)
	if err != nil {
		return fmt.Errorf("write pi models config: %w", err)
	}
	return nil
}

// sharesKeyEnv reports whether two routes read the same credential variable.
func sharesKeyEnv(a, b ProxyRoute) bool {
	for _, name := range []string{a.KeyEnv, a.KeyEnvFallback} {
		if name != "" && (name == b.KeyEnv || name == b.KeyEnvFallback) {
			return true
		}
	}
	return false
}
