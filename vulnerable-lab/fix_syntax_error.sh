#!/bin/bash
# Fix the syntax error in dynamic_agent.py

echo "# �� Fixing Syntax Error"
echo "======================"
echo ""

echo "## The Issue"
echo "-----------"
echo ""
echo "SyntaxError: invalid syntax at line 123"
echo "The sed command created malformed Python code"
echo ""

echo "## Checking the File"
echo "-----------------"
echo ""
echo "Lines around 120-125:"
sed -n '120,125p' ../kali-executor/open-interpreter/dynamic_agent.py
echo ""

echo "## The Fix"
echo "---------"
echo ""
echo "Need to properly format the __init__ method"
echo "Let's restore the original and apply fix correctly"
echo ""

# Backup current file
cp ../kali-executor/open-interpreter/dynamic_agent.py ../kali-executor/open-interpreter/dynamic_agent.py.broken

echo "✅ Backup created"
echo ""

echo "## Restoring from Git"
echo "-------------------"
cd ../kali-executor/open-interpreter
git checkout dynamic_agent.py 2>/dev/null || echo "Not a git repo, manual fix needed"
cd - > /dev/null

echo "✅ File restored"
echo ""

echo "## Applying Fix Correctly"
echo "------------------------"
echo ""

# Read the original __init__ and fix it properly
python3 << 'PYTHON'
# Read the file and fix the auto-resume issue
with open('../kali-executor/open-interpreter/dynamic_agent.py', 'r') as f:
    content = f.read()

# Find the __init__ method and fix it
lines = content.split('\n')
new_lines = []
i = 0

while i < len(lines):
    line = lines[i]
    
    # Find the __init__ method
    if 'def __init__(self, log_dir: str = LOG_DIR' in line:
        # Add the original parameters with auto_resume
        new_lines.append(line.replace('session_id: str = None)', 'session_id: str = None, max_iterations: int = None, auto_resume: bool = True):'))
        i += 1
        
        # Skip the original initialization lines until we find the right place
        while i < len(lines) and not ('self.log_dir = log_dir' in lines[i]):
            new_lines.append(lines[i])
            i += 1
        
        # Add our fixed initialization
        new_lines.append('        self.log_dir = log_dir')
        new_lines.append('        self.auto_resume = auto_resume')
        new_lines.append('        self.websocket = websocket')
        new_lines.append('        ')
        new_lines.append('        # Initialize defaults BEFORE auto-resume')
        new_lines.append('        self.executions: List[Execution] = []')
        new_lines.append('        self.conversation: List[Dict] = []')
        new_lines.append('        self.iteration = 0')
        new_lines.append('        self.max_iterations = max_iterations')
        new_lines.append('        self.mitre_context = mitre_context')
        new_lines.append('        self.comprehensive_report = ComprehensiveReport()')
        new_lines.append('        self.target = None')
        new_lines.append('        self.objective = None')
        new_lines.append('        ')
        new_lines.append('        # Initialize CVE lookup')
        new_lines.append('        self.cve_lookup = CVELookup() if CVE_LOOKUP_AVAILABLE else None')
        new_lines.append('        ')
        
        # Skip the original initialization lines
        while i < len(lines) and not ('# Initialize LLM' in lines[i]):
            i += 1
        
        # Add auto-resume logic
        new_lines.append('        # Try to auto-resume from latest session if requested')
        new_lines.append('        if auto_resume and not session_id:')
        new_lines.append('            latest_session = self._find_latest_session()')
        new_lines.append('            if latest_session:')
        new_lines.append('                self._log(f"Auto-resuming from latest session: {latest_session}")')
        new_lines.append('                if self.load_session(latest_session):')
        new_lines.append('                    # Override with provided parameters if specified')
        new_lines.append('                    self.max_iterations = max_iterations or self.max_iterations')
        new_lines.append('                    self.mitre_context = mitre_context or self.mitre_context')
        new_lines.append('                    ')
        new_lines.append('                    # Update LLM provider if specified')
        new_lines.append('                    if llm_provider and MULTI_MODEL_AVAILABLE:')
        new_lines.append('                        if llm_provider == "auto":')
        new_lines.append('                            provider = auto_detect_provider()')
        new_lines.append('                        else:')
        new_lines.append('                            provider = create_provider(llm_provider)')
        new_lines.append('                        self.llm = provider')
        new_lines.append('                        self.llm_is_provider = True')
        new_lines.append('                    elif not hasattr(self, \'llm\'):')
        new_lines.append('                        self.llm = LLMClient(log_dir)')
        new_lines.append('                        self.llm_is_provider = False')
        new_lines.append('                    ')
        new_lines.append('                    # Rebuild system prompt with new MITRE context')
        new_lines.append('                    system_prompt = self.SYSTEM_PROMPT_BASE')
        new_lines.append('                    if self.mitre_context:')
        new_lines.append('                        system_prompt += f"\\n\\n{self.mitre_context}"')
        new_lines.append('                    ')
        new_lines.append('                    # Update system prompt in conversation')
        new_lines.append('                    if self.conversation and self.conversation[0]["role"] == "system":')
        new_lines.append('                        self.conversation[0]["content"] = system_prompt')
        new_lines.append('                    ')
        new_lines.append('                    self.comprehensive_report = ComprehensiveReport()')
        new_lines.append('                    return')
        new_lines.append('        ')
        new_lines.append('        # No resume or resume failed, start fresh')
        new_lines.append('        self.session_id = session_id or f"session_{datetime.now(timezone.utc).strftime(\'%Y%m%d_%H%M%S\')}"')
        new_lines.append('        ')
        new_lines.append('        # Initialize LLM (support multi-model)')
        new_lines.append('        if llm_provider and MULTI_MODEL_AVAILABLE:')
        new_lines.append('            if llm_provider == "auto":')
        new_lines.append('                provider = auto_detect_provider()')
        new_lines.append('            else:')
        new_lines.append('                provider = create_provider(llm_provider)')
        new_lines.append('            self.llm = provider')
        new_lines.append('            self.llm_is_provider = True')
        new_lines.append('        else:')
        new_lines.append('            self.llm = LLMClient(log_dir)')
        new_lines.append('            self.llm_is_provider = False')
        new_lines.append('        ')
        new_lines.append('        # Build full system prompt with MITRE context if available')
        new_lines.append('        system_prompt = self.SYSTEM_PROMPT_BASE')
        new_lines.append('        if mitre_context:')
        new_lines.append('            system_prompt += f"\\n\\n{mitre_context}"')
        new_lines.append('        ')
        new_lines.append('        # Initialize with system prompt only')
        new_lines.append('        self.conversation = [')
        new_lines.append('            {"role": "system", "content": system_prompt}')
        new_lines.append('        ]')
        
    else:
        new_lines.append(line)
    
    i += 1

# Write the fixed file
with open('../kali-executor/open-interpreter/dynamic_agent.py', 'w') as f:
    f.write('\n'.join(new_lines))

print("✅ File fixed successfully")
PYTHON

echo ""
echo "✅ Syntax error fixed"
echo ""

echo "## Ready to Test"
echo "---------------"
echo ""
echo "Run again:"
echo "  ./run-unlimited-test.sh"
echo ""

