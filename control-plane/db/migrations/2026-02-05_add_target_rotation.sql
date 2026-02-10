-- Add job-level target rotation controls and missing max_iterations column

ALTER TABLE jobs
    ADD COLUMN IF NOT EXISTS max_iterations INTEGER DEFAULT 30,
    ADD COLUMN IF NOT EXISTS enable_target_rotation BOOLEAN DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS target_focus_window INTEGER DEFAULT 6,
    ADD COLUMN IF NOT EXISTS target_focus_limit INTEGER DEFAULT 30,
    ADD COLUMN IF NOT EXISTS target_min_commands INTEGER DEFAULT 8;

-- Backfill explicit defaults where NULL (defense-in-depth)
UPDATE jobs
SET max_iterations = COALESCE(max_iterations, 30),
    enable_target_rotation = COALESCE(enable_target_rotation, TRUE),
    target_focus_window = COALESCE(target_focus_window, 6),
    target_focus_limit = COALESCE(target_focus_limit, 30),
    target_min_commands = COALESCE(target_min_commands, 8);
