# Fix for auto-resume AttributeError
# In __init__, initialize defaults before auto-resume

def __init__(self, log_dir: str = LOG_DIR, mitre_context: str = None, 
             llm_provider: str = None, websocket = None, session_id: str = None, max_iterations: int = None, 
             auto_resume: bool = True):
    self.log_dir = log_dir
    self.auto_resume = auto_resume
    self.websocket = websocket
    
    # Initialize defaults BEFORE auto-resume
    self.executions: List[Execution] = []
    self.conversation: List[Dict] = []
    self.iteration = 0
    self.max_iterations = max_iterations
    self.mitre_context = mitre_context  # Initialize here!
    self.comprehensive_report = ComprehensiveReport()
    self.target = None
    self.objective = None
    
    # Initialize CVE lookup
    self.cve_lookup = CVELookup() if CVE_LOOKUP_AVAILABLE else None
    
    # Try to auto-resume from latest session if requested
    if auto_resume and not session_id:
        latest_session = self._find_latest_session()
        if latest_session:
            self._log(f"Auto-resuming from latest session: {latest_session}")
            if self.load_session(latest_session):
                # Override with provided parameters if specified
                self.max_iterations = max_iterations or self.max_iterations
                self.mitre_context = mitre_context or self.mitre_context
                
                # Update LLM provider if specified
                if llm_provider and MULTI_MODEL_AVAILABLE:
                    if llm_provider == "auto":
                        provider = auto_detect_provider()
                    else:
                        provider = create_provider(llm_provider)
                    self.llm = provider
                    self.llm_is_provider = True
                elif not hasattr(self, 'llm'):
                    self.llm = LLMClient(log_dir)
                    self.llm_is_provider = False
                
                # Rebuild system prompt with new MITRE context
                system_prompt = self.SYSTEM_PROMPT_BASE
                if self.mitre_context:
                    system_prompt += f"\n\n{self.mitre_context}"
                
                # Update system prompt in conversation
                if self.conversation and self.conversation[0]["role"] == "system":
                    self.conversation[0]["content"] = system_prompt
                
                return
    
    # No resume or resume failed, start fresh
    self.session_id = session_id or f"session_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    
    # Initialize LLM (support multi-model)
    if llm_provider and MULTI_MODEL_AVAILABLE:
        if llm_provider == "auto":
            provider = auto_detect_provider()
        else:
            provider = create_provider(llm_provider)
        self.llm = provider
        self.llm_is_provider = True
    else:
        self.llm = LLMClient(log_dir)
        self.llm_is_provider = False
    
    # Build full system prompt with MITRE context if available
    system_prompt = self.SYSTEM_PROMPT_BASE
    if mitre_context:
        system_prompt += f"\n\n{mitre_context}"
    
    # Initialize with system prompt only
    self.conversation = [
        {"role": "system", "content": system_prompt}
    ]
