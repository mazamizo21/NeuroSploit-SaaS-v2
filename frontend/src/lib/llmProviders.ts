export type LlmModelGroup = {
  label: string;
  models: string[];
};

export type LlmProviderDef = {
  id: string;
  label: string;
  apiStyle: "openai" | "anthropic";
  defaultBase: string;
  defaultModel: string;
  models: string[];
  /** Optional optgroup definitions for rendering a grouped model dropdown. */
  modelGroups?: LlmModelGroup[];
  /** Optional map of model id -> human-friendly label for dropdowns. */
  modelLabels?: Record<string, string>;
  authOptions: { id: string; label: string }[];
};

const MOONSHOT_MODELS = [
  "moonshot/kimi-k2.5",
  "moonshot/kimi-k2-0905-preview",
  "moonshot/kimi-k2-turbo-preview",
  "moonshot/kimi-k2-thinking",
  "moonshot/kimi-k2-thinking-turbo",
];

const SYNTHETIC_MODELS = [
  "synthetic/hf:MiniMaxAI/MiniMax-M2.1",
  "synthetic/hf:moonshotai/Kimi-K2-Thinking",
  "synthetic/hf:zai-org/GLM-4.7",
  "synthetic/hf:deepseek-ai/DeepSeek-R1-0528",
  "synthetic/hf:deepseek-ai/DeepSeek-V3-0324",
  "synthetic/hf:deepseek-ai/DeepSeek-V3.1",
  "synthetic/hf:deepseek-ai/DeepSeek-V3.1-Terminus",
  "synthetic/hf:deepseek-ai/DeepSeek-V3.2",
  "synthetic/hf:meta-llama/Llama-3.3-70B-Instruct",
  "synthetic/hf:meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8",
  "synthetic/hf:moonshotai/Kimi-K2-Instruct-0905",
  "synthetic/hf:openai/gpt-oss-120b",
  "synthetic/hf:Qwen/Qwen3-235B-A22B-Instruct-2507",
  "synthetic/hf:Qwen/Qwen3-Coder-480B-A35B-Instruct",
  "synthetic/hf:Qwen/Qwen3-VL-235B-A22B-Instruct",
  "synthetic/hf:zai-org/GLM-4.5",
  "synthetic/hf:zai-org/GLM-4.6",
  "synthetic/hf:deepseek-ai/DeepSeek-V3",
  "synthetic/hf:Qwen/Qwen3-235B-A22B-Thinking-2507",
];

const VENICE_MODELS = [
  "venice/llama-3.3-70b",
  "venice/llama-3.2-3b",
  "venice/hermes-3-llama-3.1-405b",
  "venice/qwen3-235b-a22b-thinking-2507",
  "venice/qwen3-235b-a22b-instruct-2507",
  "venice/qwen3-coder-480b-a35b-instruct",
  "venice/qwen3-next-80b",
  "venice/qwen3-vl-235b-a22b",
  "venice/qwen3-4b",
  "venice/deepseek-v3.2",
  "venice/venice-uncensored",
  "venice/mistral-31-24b",
  "venice/google-gemma-3-27b-it",
  "venice/openai-gpt-oss-120b",
  "venice/zai-org-glm-4.7",
  "venice/claude-opus-45",
  "venice/claude-sonnet-45",
  "venice/openai-gpt-52",
  "venice/openai-gpt-52-codex",
  "venice/gemini-3-pro-preview",
  "venice/gemini-3-flash-preview",
  "venice/grok-41-fast",
  "venice/grok-code-fast-1",
  "venice/kimi-k2-thinking",
  "venice/minimax-m21",
];

// Mirror the model dropdown structure from Redamon (optgroups + descriptive labels).
const OPENAI_MODELS = [
  "openai/gpt-5.2",
  "openai/gpt-5.2-pro",
  "openai/gpt-5",
  "openai/gpt-5-mini",
  "openai/gpt-5-nano",
  "openai/gpt-4.1",
  "openai/gpt-4.1-mini",
  "openai/gpt-4.1-nano",
];

const OPENAI_MODEL_GROUPS: LlmModelGroup[] = [
  { label: "GPT-5.2", models: ["openai/gpt-5.2", "openai/gpt-5.2-pro"] },
  { label: "GPT-5", models: ["openai/gpt-5", "openai/gpt-5-mini", "openai/gpt-5-nano"] },
  { label: "GPT-4.1", models: ["openai/gpt-4.1", "openai/gpt-4.1-mini", "openai/gpt-4.1-nano"] },
];

const OPENAI_MODEL_LABELS: Record<string, string> = {
  "openai/gpt-5.2": "gpt-5.2 - Flagship reasoning model",
  "openai/gpt-5.2-pro": "gpt-5.2-pro - Smarter, more precise (Responses API)",
  "openai/gpt-5": "gpt-5 - Previous reasoning model",
  "openai/gpt-5-mini": "gpt-5-mini - Faster, cost-efficient GPT-5",
  "openai/gpt-5-nano": "gpt-5-nano - Fastest, cheapest GPT-5",
  "openai/gpt-4.1": "gpt-4.1 - Smartest non-reasoning model",
  "openai/gpt-4.1-mini": "gpt-4.1-mini - Fast, cost-efficient",
  "openai/gpt-4.1-nano": "gpt-4.1-nano - Fastest, cheapest",
};

const CODEX_MODELS = ["openai-codex/gpt-5.2", "openai-codex/gpt-5.2-pro"];

const CODEX_MODEL_GROUPS: LlmModelGroup[] = [
  { label: "GPT-5.2", models: CODEX_MODELS },
];

const CODEX_MODEL_LABELS: Record<string, string> = {
  "openai-codex/gpt-5.2": "gpt-5.2 - Flagship reasoning model",
  "openai-codex/gpt-5.2-pro": "gpt-5.2-pro - Smarter, more precise (Responses API)",
};

const ANTHROPIC_MODELS = [
  "anthropic/claude-opus-4-6",
  "anthropic/claude-sonnet-4-5-20250929",
  "anthropic/claude-haiku-4-5-20251001",
];

const ANTHROPIC_MODEL_GROUPS: LlmModelGroup[] = [
  { label: "Anthropic Claude", models: ANTHROPIC_MODELS },
];

const ANTHROPIC_MODEL_LABELS: Record<string, string> = {
  "anthropic/claude-opus-4-6": "Claude Opus 4.6 - Most capable model",
  "anthropic/claude-sonnet-4-5-20250929": "Claude Sonnet 4.5 - Balanced performance",
  "anthropic/claude-haiku-4-5-20251001": "Claude Haiku 4.5 - Fast and efficient",
};

export const OWNER_LLM_PROVIDERS: LlmProviderDef[] = [
  {
    id: "openai",
    label: "OpenAI",
    apiStyle: "openai",
    defaultBase: "https://api.openai.com/v1",
    defaultModel: "openai/gpt-5.2",
    models: OPENAI_MODELS,
    modelGroups: OPENAI_MODEL_GROUPS,
    modelLabels: OPENAI_MODEL_LABELS,
    authOptions: [{ id: "api_key", label: "API key (Option A)" }],
  },
  {
    id: "openai-codex",
    label: "OpenAI Codex",
    apiStyle: "openai",
    defaultBase: "https://api.openai.com/v1",
    defaultModel: "openai-codex/gpt-5.2",
    models: CODEX_MODELS,
    modelGroups: CODEX_MODEL_GROUPS,
    modelLabels: CODEX_MODEL_LABELS,
    authOptions: [
      { id: "oauth_token", label: "OAuth token (Option B)" },
      { id: "api_key", label: "API key (Option A)" },
    ],
  },
  {
    id: "anthropic",
    label: "Anthropic (Claude)",
    apiStyle: "anthropic",
    defaultBase: "https://api.anthropic.com/v1/messages",
    defaultModel: "anthropic/claude-opus-4-6",
    models: ANTHROPIC_MODELS,
    modelGroups: ANTHROPIC_MODEL_GROUPS,
    modelLabels: ANTHROPIC_MODEL_LABELS,
    authOptions: [
      { id: "api_key", label: "API key (Option A)" },
      { id: "setup_token", label: "Setup token (Option B)" },
    ],
  },
  {
    id: "openrouter",
    label: "OpenRouter",
    apiStyle: "openai",
    defaultBase: "https://openrouter.ai/api/v1",
    defaultModel: "openrouter/anthropic/claude-sonnet-4-5",
    models: ["openrouter/anthropic/claude-sonnet-4-5"],
    authOptions: [{ id: "api_key", label: "API key" }],
  },
  {
    id: "vercel-ai-gateway",
    label: "Vercel AI Gateway",
    apiStyle: "anthropic",
    defaultBase: "",
    defaultModel: "vercel-ai-gateway/anthropic/claude-opus-4.5",
    models: ["vercel-ai-gateway/anthropic/claude-opus-4.5"],
    authOptions: [{ id: "api_key", label: "API key" }],
  },
  {
    id: "moonshot",
    label: "Moonshot AI",
    apiStyle: "openai",
    defaultBase: "https://api.moonshot.ai/v1",
    defaultModel: MOONSHOT_MODELS[0],
    models: MOONSHOT_MODELS,
    authOptions: [{ id: "api_key", label: "API key" }],
  },
  {
    id: "kimi-coding",
    label: "Kimi Coding",
    apiStyle: "anthropic",
    defaultBase: "",
    defaultModel: "kimi-coding/k2p5",
    models: ["kimi-coding/k2p5"],
    authOptions: [{ id: "api_key", label: "API key" }],
  },
  {
    id: "synthetic",
    label: "Synthetic",
    apiStyle: "anthropic",
    defaultBase: "https://api.synthetic.new/anthropic",
    defaultModel: SYNTHETIC_MODELS[0],
    models: SYNTHETIC_MODELS,
    authOptions: [{ id: "api_key", label: "API key" }],
  },
  {
    id: "opencode",
    label: "OpenCode Zen",
    apiStyle: "openai",
    defaultBase: "",
    defaultModel: "opencode/claude-opus-4-5",
    models: ["opencode/claude-opus-4-5"],
    authOptions: [{ id: "api_key", label: "API key" }],
  },
  {
    id: "zai",
    label: "Z.AI (GLM)",
    apiStyle: "openai",
    defaultBase: "https://api.z.ai/api/coding/paas/v4",
    defaultModel: "zai/glm-4.7",
    models: ["zai/glm-4.7"],
    authOptions: [{ id: "api_key", label: "API key" }],
  },
  {
    id: "glm",
    label: "GLM Models (Legacy)",
    apiStyle: "openai",
    defaultBase: "https://api.z.ai/api/coding/paas/v4",
    defaultModel: "glm-4.7",
    models: ["glm-4.7"],
    authOptions: [{ id: "api_key", label: "API key" }],
  },
  {
    id: "venice",
    label: "Venice AI",
    apiStyle: "openai",
    defaultBase: "https://api.venice.ai/api/v1",
    defaultModel: "venice/llama-3.3-70b",
    models: VENICE_MODELS,
    authOptions: [{ id: "api_key", label: "API key" }],
  },
  {
    id: "minimax",
    label: "MiniMax",
    apiStyle: "anthropic",
    defaultBase: "https://api.minimax.io/anthropic",
    defaultModel: "minimax/MiniMax-M2.1",
    models: ["minimax/MiniMax-M2.1", "minimax/MiniMax-M2.1-lightning"],
    authOptions: [{ id: "api_key", label: "API key" }],
  },
  {
    id: "google",
    label: "Google Gemini",
    apiStyle: "openai",
    defaultBase: "",
    defaultModel: "google/gemini-3-pro-preview",
    models: ["google/gemini-3-pro-preview", "google/gemini-3-flash-preview"],
    authOptions: [{ id: "api_key", label: "API key" }],
  },
  {
    id: "google-vertex",
    label: "Google Vertex",
    apiStyle: "openai",
    defaultBase: "",
    defaultModel: "",
    models: [],
    authOptions: [{ id: "oauth_token", label: "OAuth token" }],
  },
  {
    id: "google-antigravity",
    label: "Google Antigravity",
    apiStyle: "openai",
    defaultBase: "",
    defaultModel: "",
    models: [],
    authOptions: [{ id: "oauth_token", label: "OAuth token" }],
  },
  {
    id: "google-gemini-cli",
    label: "Google Gemini CLI",
    apiStyle: "openai",
    defaultBase: "",
    defaultModel: "",
    models: [],
    authOptions: [{ id: "oauth_token", label: "OAuth token" }],
  },
  {
    id: "qwen-portal",
    label: "Qwen (Portal)",
    apiStyle: "openai",
    defaultBase: "https://portal.qwen.ai/v1",
    defaultModel: "qwen-portal/coder-model",
    models: ["qwen-portal/coder-model", "qwen-portal/vision-model"],
    authOptions: [{ id: "oauth_token", label: "OAuth token" }],
  },
  {
    id: "xai",
    label: "xAI",
    apiStyle: "openai",
    defaultBase: "",
    defaultModel: "",
    models: [],
    authOptions: [{ id: "api_key", label: "API key" }],
  },
  {
    id: "groq",
    label: "Groq",
    apiStyle: "openai",
    defaultBase: "",
    defaultModel: "",
    models: [],
    authOptions: [{ id: "api_key", label: "API key" }],
  },
  {
    id: "cerebras",
    label: "Cerebras",
    apiStyle: "openai",
    defaultBase: "https://api.cerebras.ai/v1",
    defaultModel: "cerebras/zai-glm-4.7",
    models: ["cerebras/zai-glm-4.7", "cerebras/zai-glm-4.6"],
    authOptions: [{ id: "api_key", label: "API key" }],
  },
  {
    id: "mistral",
    label: "Mistral",
    apiStyle: "openai",
    defaultBase: "",
    defaultModel: "",
    models: [],
    authOptions: [{ id: "api_key", label: "API key" }],
  },
  {
    id: "github-copilot",
    label: "GitHub Copilot",
    apiStyle: "openai",
    defaultBase: "",
    defaultModel: "",
    models: [],
    authOptions: [{ id: "oauth_token", label: "OAuth token" }],
  },
  {
    id: "ollama",
    label: "Ollama",
    apiStyle: "openai",
    defaultBase: "http://127.0.0.1:11434/v1",
    defaultModel: "ollama/llama3.3",
    models: ["ollama/llama3.3", "ollama/qwen2.5-coder:32b", "ollama/deepseek-r1:32b"],
    authOptions: [{ id: "api_key", label: "API key (not required)" }],
  },
  {
    id: "lmstudio",
    label: "LM Studio (Local)",
    apiStyle: "openai",
    defaultBase: "http://host.docker.internal:1234/v1",
    defaultModel: "lmstudio/qwen3-coder-next",
    models: ["lmstudio/qwen3-coder-next", "lmstudio/local-model"],
    authOptions: [{ id: "api_key", label: "API key (not required)" }],
  },
  {
    id: "xiaomi",
    label: "Xiaomi",
    apiStyle: "anthropic",
    defaultBase: "https://api.xiaomimimo.com/anthropic",
    defaultModel: "xiaomi/mimo-v2-flash",
    models: ["xiaomi/mimo-v2-flash"],
    authOptions: [{ id: "api_key", label: "API key" }],
  },
  {
    id: "amazon-bedrock",
    label: "Amazon Bedrock",
    apiStyle: "openai",
    defaultBase: "",
    defaultModel: "amazon-bedrock/anthropic.claude-opus-4-5-20251101-v1:0",
    models: ["amazon-bedrock/anthropic.claude-opus-4-5-20251101-v1:0"],
    authOptions: [{ id: "bearer_token", label: "Bearer token (optional)" }],
  },
];

export const getProviderLabel = (id: string) => {
  const match = OWNER_LLM_PROVIDERS.find((p) => p.id === id);
  return match ? match.label : id;
};
