"""
NeuroSploit SaaS v2 - Load Testing with Locust
Tests API performance under load
"""

from locust import HttpUser, task, between
import random

class NeuroSploitUser(HttpUser):
    """Simulates a user interacting with NeuroSploit API"""
    
    wait_time = between(1, 3)  # Wait 1-3 seconds between tasks
    
    def on_start(self):
        """Called when a simulated user starts"""
        # In production, would login and get real token
        # For now, simulate with mock data
        self.job_ids = [
            "550e8400-e29b-41d4-a716-446655440000",
            "550e8400-e29b-41d4-a716-446655440001",
            "550e8400-e29b-41d4-a716-446655440002"
        ]
        self.headers = {
            "Authorization": "Bearer mock_token_for_load_testing"
        }
    
    @task(5)
    def get_health(self):
        """Health check (most common)"""
        self.client.get("/health")
    
    @task(3)
    def list_mitre_techniques(self):
        """List MITRE techniques (cached, fast)"""
        limit = random.choice([10, 25, 50, 100])
        self.client.get(f"/api/v1/mitre/techniques?limit={limit}")
    
    @task(2)
    def get_mitre_technique(self):
        """Get specific MITRE technique"""
        technique_id = random.choice(["T1046", "T1190", "T1059", "T1003", "T1078"])
        self.client.get(f"/api/v1/mitre/techniques/{technique_id}")
    
    @task(2)
    def get_mitre_tactics(self):
        """Get MITRE tactics"""
        self.client.get("/api/v1/mitre/tactics")
    
    @task(1)
    def get_tool_techniques(self):
        """Get tool-to-technique mapping"""
        tool = random.choice(["nmap", "metasploit", "sqlmap", "hydra"])
        self.client.get(f"/api/v1/mitre/tools/{tool}/techniques")
    
    @task(1)
    def get_mitre_coverage(self):
        """Get MITRE coverage statistics"""
        self.client.get("/api/v1/mitre/coverage")
    
    @task(1)
    def get_cron_patterns(self):
        """Get scheduled job patterns"""
        self.client.get("/api/v1/scheduled-jobs/patterns")
    
    # Note: The following tasks would require authentication
    # Uncomment when auth is properly set up
    
    # @task(2)
    # def list_jobs(self):
    #     """List jobs (requires auth)"""
    #     self.client.get("/api/v1/jobs", headers=self.headers)
    
    # @task(1)
    # def get_attack_graph(self):
    #     """Get attack graph (expensive operation)"""
    #     job_id = random.choice(self.job_ids)
    #     self.client.get(
    #         f"/api/v1/attack-graphs/jobs/{job_id}",
    #         headers=self.headers
    #     )
    
    # @task(1)
    # def get_critical_paths(self):
    #     """Get critical attack paths"""
    #     job_id = random.choice(self.job_ids)
    #     self.client.get(
    #         f"/api/v1/attack-graphs/jobs/{job_id}/paths/critical",
    #         headers=self.headers
    #     )

class HeavyUser(HttpUser):
    """Simulates users performing expensive operations"""
    
    wait_time = between(5, 10)
    
    def on_start(self):
        self.job_ids = [
            "550e8400-e29b-41d4-a716-446655440000",
            "550e8400-e29b-41d4-a716-446655440001"
        ]
        self.headers = {
            "Authorization": "Bearer mock_token_for_load_testing"
        }
    
    # @task(1)
    # def build_attack_graph(self):
    #     """Build attack graph (very expensive)"""
    #     job_id = random.choice(self.job_ids)
    #     self.client.post(
    #         f"/api/v1/attack-graphs/jobs/{job_id}/build",
    #         headers=self.headers
    #     )
    
    # @task(1)
    # def export_graph(self):
    #     """Export attack graph"""
    #     job_id = random.choice(self.job_ids)
    #     format_type = random.choice(["json", "graphml", "cytoscape"])
    #     self.client.get(
    #         f"/api/v1/attack-graphs/jobs/{job_id}/export?format={format_type}",
    #         headers=self.headers
    #     )
    
    @task(2)
    def get_mitre_context(self):
        """Get AI context (generates text)"""
        tool = random.choice(["nmap", "metasploit", "sqlmap"])
        self.client.get(f"/api/v1/mitre/context?tool_name={tool}")
