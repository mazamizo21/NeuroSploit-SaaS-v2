export interface ChatEnvelope<TPayload = unknown> {
  type: string;
  payload: TPayload;
  timestamp?: string;
  job_id?: string;
}

export interface OutputPayload {
  line: string;
  timestamp?: string;
}

export interface GuidanceAckPayload {
  message: string;
  queue_position?: number;
}

export interface ThinkingPayload {
  iteration: number;
  phase: string;
  thought: string;
  reasoning?: string;
}

export interface ThinkingChunkPayload {
  chunk: string;
}

export interface ToolStartPayload {
  tool_name: string;
  command: string;
  args?: Record<string, unknown>;
}

export interface ToolOutputChunkPayload {
  tool_name: string;
  chunk: string;
  is_final?: boolean;
}

export interface ToolCompletePayload {
  tool_name: string;
  success: boolean;
  output_summary: string;
  findings?: string[];
  next_steps?: string[];
}

export interface PhaseUpdatePayload {
  phase: string;
  iteration: number;
  attack_type?: string;
}

export interface ApprovalRequestPayload {
  from_phase: string;
  to_phase: string;
  reason: string;
  planned_actions: string[];
  risks: string[];
}

export interface QuestionRequestPayload {
  question_id: string;
  question: string;
  context?: string;
  format?: string;
  options?: string[];
}

export interface ResponsePayload {
  answer: string;
  iteration: number;
  phase: string;
  complete?: boolean;
}

export interface TodoItem {
  id: string;
  type?: string;
  target?: string;
  details?: string;
  severity?: string;
  exploited?: boolean;
  exploit_attempts?: number;
  not_exploitable_reason?: string;
}

export interface TodoUpdatePayload {
  items: TodoItem[];
}

export interface TaskCompletePayload {
  message: string;
  final_phase: string;
  total_iterations: number;
}

export interface ErrorPayload {
  message: string;
  recoverable?: boolean;
}

export interface ToolRun {
  id: string;
  tool_name: string;
  command: string;
  args?: Record<string, unknown>;
  started_at: string;
  output: string[];
  completed: boolean;
  success?: boolean;
  output_summary?: string;
  findings?: string[];
  next_steps?: string[];
}
