#!/usr/bin/env python3
"""
TazoSploit CLI - Tazos
Professional penetration testing command-line interface with scheduling support
"""

import sys
import argparse
import json
import asyncio
from datetime import datetime
from typing import Optional, List

# Add parent directory to path for imports
sys.path.insert(0, '/Users/tazjack/Documents/PenTest/TazoSploit')

from schedulers import (
    CronScheduler,
    JobType,
    JobStatus,
    JobParser,
    ScanJob,
    ReconJob,
    ExploitJob,
    ReportJob,
    MonitorJob,
    CleanupJob,
    SkillsManager,
    SkillMetadata
)


class TazosCLI:
    """TazoSploit CLI Application"""
    
    def __init__(self):
        self.scheduler = None
        self.parser = JobParser()
        self.skills_manager = None
    
    def get_scheduler(self) -> CronScheduler:
        """Get scheduler instance"""
        if self.scheduler is None:
            self.scheduler = CronScheduler(jobs_dir="memory/jobs")
            self.scheduler.start()
        return self.scheduler
    
    def get_skills_manager(self) -> SkillsManager:
        """Get skills manager instance"""
        if self.skills_manager is None:
            self.skills_manager = SkillsManager(
                skills_dir="skills",
                marketplace_file="skills/SKILL_CATALOG.json"
            )
        return self.skills_manager
    
    def cmd_schedule(self, args):
        """
        Schedule a pentest task
        
        Usage: tazos schedule "scan target.com" "daily at 3am"
        """
        try:
            scheduler = self.get_scheduler()
            
            # Parse job type from description
            params = self.parser.extract_job_params(args.description)
            job_type_str = params.get('job_type', 'scan')
            
            # Determine job type
            job_type = JobType(job_type_str) if job_type_str in [jt.value for jt in JobType] else JobType.SCAN
            
            # Create job config based on type
            job_config = self._create_job_config(job_type, args.description, params)
            
            # Schedule the job
            job = scheduler.schedule(
                description=args.description,
                natural_time=args.time,
                job_config=job_config
            )
            
            print(f"✅ Job scheduled successfully!")
            print(f"   Job ID: {job.id}")
            print(f"   Description: {job.config.name}")
            print(f"   Type: {job.config.job_type.value}")
            print(f"   Scheduled: {job.scheduled_at}")
            print(f"   Status: {job.status.value}")
            
            if args.json:
                print(json.dumps(job.to_dict(), indent=2, default=str))
            
        except Exception as e:
            print(f"❌ Failed to schedule job: {e}", file=sys.stderr)
            sys.exit(1)
    
    def _create_job_config(self, job_type: JobType, description: str, params: dict):
        """Create job config based on type"""
        
        if job_type == JobType.SCAN:
            return ScanJob(
                name=description,
                description=description,
                target=params.get('targets', [''])[0] if params.get('targets') else params.get('domains', [''])[0] if params.get('domains') else '',
                scan_type=params.get('scan_type', 'full'),
                tools=params.get('tools', ['nmap', 'nuclei']),
                priority=params.get('priority', 'normal')
            )
        
        elif job_type == JobType.RECON:
            return ReconJob(
                name=description,
                description=description,
                target=params.get('targets', [''])[0] if params.get('targets') else params.get('domains', [''])[0] if params.get('domains') else '',
                recon_type=params.get('recon_type', 'subdomain'),
                tools=params.get('tools', ['subfinder', 'amass']),
                passive_only=params.get('passive_only', True)
            )
        
        elif job_type == JobType.EXPLOIT:
            return ExploitJob(
                name=description,
                description=description,
                target=params.get('targets', [''])[0] if params.get('targets') else params.get('domains', [''])[0] if params.get('domains') else '',
                exploit_type=params.get('exploit_type', 'automatic'),
                safe_mode=True,
                max_harm='minimal'
            )
        
        elif job_type == JobType.MONITOR:
            return MonitorJob(
                name=description,
                description=description,
                target=params.get('targets', [''])[0] if params.get('targets') else params.get('domains', [''])[0] if params.get('domains') else '',
                monitor_type=params.get('monitor_type', 'availability'),
                check_interval=params.get('check_interval', 300)
            )
        
        elif job_type == JobType.REPORT:
            return ReportJob(
                name=description,
                description=description,
                report_type=params.get('report_type', 'full'),
                output_format=params.get('output_format', 'pdf')
            )
        
        elif job_type == JobType.CLEANUP:
            return CleanupJob(
                name=description,
                description=description,
                cleanup_type=params.get('cleanup_type', 'logs'),
                older_than_days=params.get('older_than_days', 30)
            )
        
        else:
            return ScanJob(name=description, description=description)
    
    def cmd_jobs_list(self, args):
        """
        List all jobs
        
        Usage: tazos jobs list [--status STATUS] [--type TYPE]
        """
        try:
            scheduler = self.get_scheduler()
            
            # Parse filters
            status_filter = None
            if args.status:
                try:
                    status_filter = JobStatus(args.status)
                except ValueError:
                    print(f"❌ Invalid status: {args.status}", file=sys.stderr)
                    print(f"   Valid statuses: {[s.value for s in JobStatus]}", file=sys.stderr)
                    sys.exit(1)
            
            type_filter = None
            if args.type:
                try:
                    type_filter = JobType(args.type)
                except ValueError:
                    print(f"❌ Invalid job type: {args.type}", file=sys.stderr)
                    print(f"   Valid types: {[jt.value for jt in JobType]}", file=sys.stderr)
                    sys.exit(1)
            
            # Get jobs
            jobs = scheduler.list_jobs(status=status_filter, job_type=type_filter)
            
            if not jobs:
                print("No jobs found.")
                return
            
            # Display jobs
            if args.json:
                print(json.dumps([job.to_dict() for job in jobs], indent=2, default=str))
            else:
                self._print_job_table(jobs)
        
        except Exception as e:
            print(f"❌ Failed to list jobs: {e}", file=sys.stderr)
            sys.exit(1)
    
    def _print_job_table(self, jobs: List):
        """Print jobs in a formatted table"""
        print("\n" + "="*100)
        print(f"{'ID':<8} {'Type':<12} {'Status':<12} {'Name':<30} {'Scheduled':<20}")
        print("="*100)
        
        for job in jobs:
            print(f"{job.id[:8]:<8} {job.config.job_type.value:<12} {job.status.value:<12} {job.config.name[:30]:<30} {job.scheduled_at.strftime('%Y-%m-%d %H:%M:%S') if job.scheduled_at else 'N/A':<20}")
        
        print("="*100)
        print(f"Total: {len(jobs)} jobs\n")
    
    def cmd_jobs_show(self, args):
        """
        Show job details
        
        Usage: tazos jobs show <job-id>
        """
        try:
            scheduler = self.get_scheduler()
            job = scheduler.get_job(args.job_id)
            
            if not job:
                print(f"❌ Job not found: {args.job_id}", file=sys.stderr)
                sys.exit(1)
            
            if args.json:
                print(json.dumps(job.to_dict(), indent=2, default=str))
            else:
                self._print_job_details(job)
        
        except Exception as e:
            print(f"❌ Failed to show job: {e}", file=sys.stderr)
            sys.exit(1)
    
    def _print_job_details(self, job):
        """Print detailed job information"""
        print("\n" + "="*80)
        print(f"Job Details: {job.config.name}")
        print("="*80)
        
        print(f"\nID:              {job.id}")
        print(f"Type:            {job.config.job_type.value}")
        print(f"Status:          {job.status.value}")
        print(f"Priority:        {job.config.priority.value}")
        print(f"Description:     {job.config.description or 'N/A'}")
        
        print(f"\nSchedule:")
        print(f"  Created At:     {job.created_at}")
        print(f"  Scheduled At:   {job.scheduled_at}")
        print(f"  Started At:     {job.started_at}")
        print(f"  Completed At:   {job.completed_at}")
        
        if job.get_duration():
            print(f"  Duration:       {job.get_duration():.2f} seconds")
        
        print(f"\nRetry Information:")
        print(f"  Retry Count:    {job.retry_count}")
        print(f"  Max Retries:    {job.config.max_retries}")
        
        if job.error_message:
            print(f"\nError:")
            print(f"  {job.error_message}")
        
        if job.logs:
            print(f"\nRecent Logs:")
            for log in job.logs[-5:]:
                print(f"  {log}")
        
        if job.result:
            print(f"\nResult:")
            print(f"  {json.dumps(job.result, indent=4, default=str)}")
        
        print("\n" + "="*80 + "\n")
    
    def cmd_jobs_cancel(self, args):
        """
        Cancel a job
        
        Usage: tazos jobs cancel <job-id>
        """
        try:
            scheduler = self.get_scheduler()
            
            if scheduler.cancel_job(args.job_id):
                print(f"✅ Job cancelled: {args.job_id}")
            else:
                print(f"❌ Failed to cancel job: {args.job_id}", file=sys.stderr)
                sys.exit(1)
        
        except Exception as e:
            print(f"❌ Failed to cancel job: {e}", file=sys.stderr)
            sys.exit(1)
    
    def cmd_jobs_history(self, args):
        """
        Show job history
        
        Usage: tazos jobs history [--limit N]
        """
        try:
            scheduler = self.get_scheduler()
            history = scheduler.get_job_history(limit=args.limit or 100)
            
            if not history:
                print("No job history found.")
                return
            
            if args.json:
                print(json.dumps(history, indent=2, default=str))
            else:
                print(f"\nJob History (last {len(history)} entries):")
                print("="*100)
                
                for entry in history:
                    status = entry.get('status', 'unknown')
                    name = entry.get('config', {}).get('name', 'Unknown')
                    job_type = entry.get('job_type', 'unknown')
                    completed_at = entry.get('completed_at', 'N/A')
                    
                    status_emoji = {
                        'completed': '✅',
                        'failed': '❌',
                        'cancelled': '⏹️'
                    }.get(status, '⏳')
                    
                    print(f"{status_emoji} [{job_type}] {name}")
                    print(f"   Status: {status}")
                    print(f"   Completed: {completed_at}")
                    print()
        
        except Exception as e:
            print(f"❌ Failed to show history: {e}", file=sys.stderr)
            sys.exit(1)
    
    def cmd_jobs_stats(self, args):
        """
        Show scheduler statistics
        
        Usage: tazos jobs stats
        """
        try:
            scheduler = self.get_scheduler()
            stats = scheduler.get_stats()
            
            if args.json:
                print(json.dumps(stats, indent=2, default=str))
            else:
                print("\nScheduler Statistics")
                print("="*60)
                print(f"Scheduler Running:  {'✅ Yes' if stats['scheduler_running'] else '❌ No'}")
                print(f"Total Jobs:         {stats['total_jobs']}")
                print(f"Running Jobs:       {stats['running_jobs']}")
                print(f"Scheduled Jobs:     {stats['scheduled_jobs']}")
                
                print(f"\nJobs by Status:")
                for status, count in stats['jobs_by_status'].items():
                    emoji = {
                        'scheduled': '📅',
                        'pending': '⏳',
                        'running': '🔄',
                        'completed': '✅',
                        'failed': '❌',
                        'cancelled': '⏹️'
                    }.get(status, '❓')
                    print(f"  {emoji} {status}: {count}")
                
                print(f"\nJobs by Type:")
                for job_type, count in stats['jobs_by_type'].items():
                    print(f"  • {job_type}: {count}")
                
                if stats.get('next_fire_time'):
                    print(f"\nNext Scheduled Run: {stats['next_fire_time']}")
                
                print("="*60 + "\n")
        
        except Exception as e:
            print(f"❌ Failed to show stats: {e}", file=sys.stderr)
            sys.exit(1)
    
    def cmd_skills_list(self, args):
        """
        List available skills
        
        Usage: tazos skills list [--category CATEGORY] [--installed-only]
        """
        try:
            manager = self.get_skills_manager()
            
            skills = manager.list_skills(
                category=args.category,
                installed_only=args.installed_only
            )
            
            if not skills:
                print("No skills found.")
                return
            
            if args.json:
                print(json.dumps([skill.to_dict() for skill in skills], indent=2, default=str))
            else:
                self._print_skills_table(skills)
        
        except Exception as e:
            print(f"❌ Failed to list skills: {e}", file=sys.stderr)
            sys.exit(1)
    
    def _print_skills_table(self, skills: List):
        """Print skills in a formatted table"""
        print("\n" + "="*100)
        print(f"{'ID':<20} {'Name':<25} {'Category':<18} {'Installed':<10} {'Rating':<8}")
        print("="*100)
        
        for skill in skills:
            installed = "✅" if skill.installed else "❌"
            rating = f"⭐ {skill.rating:.1f}"
            print(f"{skill.id:<20} {skill.name:<25} {skill.category:<18} {installed:<10} {rating:<8}")
        
        print("="*100)
        print(f"Total: {len(skills)} skills\n")
    
    def cmd_skills_install(self, args):
        """
        Install a skill from marketplace
        
        Usage: tazos skills install <skill_name>
        """
        try:
            manager = self.get_skills_manager()
            
            # Try exact match first
            skill_id = args.skill_name
            
            # If not exact match, try fuzzy search
            if skill_id not in manager.marketplace:
                results = manager.search_skills(skill_id)
                if results:
                    skill_id = results[0].id
                    print(f"Found skill: {results[0].name}")
                else:
                    print(f"❌ Skill not found: {args.skill_name}", file=sys.stderr)
                    print("   Use 'tazos skills list' to see available skills", file=sys.stderr)
                    sys.exit(1)
            
            result = manager.install_skill(skill_id)
            
            if result.success:
                print(f"✅ {result.message}")
                if result.installed_tools:
                    print(f"\nInstalled tools: {', '.join(result.installed_tools)}")
                if result.warnings:
                    print(f"\n⚠️  Warnings:")
                    for warning in result.warnings:
                        print(f"   - {warning}")
            else:
                print(f"❌ {result.message}", file=sys.stderr)
                sys.exit(1)
        
        except Exception as e:
            print(f"❌ Failed to install skill: {e}", file=sys.stderr)
            sys.exit(1)
    
    def cmd_skills_remove(self, args):
        """
        Remove an installed skill
        
        Usage: tazos skills remove <skill_name>
        """
        try:
            manager = self.get_skills_manager()
            
            # Find skill ID
            skill_id = args.skill_name
            
            # Try exact match first
            if skill_id not in manager.installed_skills:
                # Try marketplace
                if skill_id in manager.marketplace:
                    skill_id = skill_id
                else:
                    # Try fuzzy search
                    results = manager.search_skills(skill_id)
                    if results:
                        skill_id = results[0].id
                    else:
                        print(f"❌ Skill not found: {args.skill_name}", file=sys.stderr)
                        sys.exit(1)
            
            if manager.remove_skill(skill_id):
                print(f"✅ Skill removed: {skill_id}")
            else:
                print(f"❌ Failed to remove skill: {args.skill_name}", file=sys.stderr)
                sys.exit(1)
        
        except Exception as e:
            print(f"❌ Failed to remove skill: {e}", file=sys.stderr)
            sys.exit(1)
    
    def cmd_skills_info(self, args):
        """
        Get detailed information about a skill
        
        Usage: tazos skills info <skill_name>
        """
        try:
            manager = self.get_skills_manager()
            
            # Find skill
            skill_id = args.skill_name
            
            # Try exact match
            skill = manager.get_skill_info(skill_id)
            
            # If not found, try fuzzy search
            if not skill:
                results = manager.search_skills(skill_id)
                if results:
                    skill = results[0]
                else:
                    print(f"❌ Skill not found: {args.skill_name}", file=sys.stderr)
                    sys.exit(1)
            
            if args.json:
                print(json.dumps(skill.to_dict(), indent=2, default=str))
            else:
                self._print_skill_info(skill)
        
        except Exception as e:
            print(f"❌ Failed to show skill info: {e}", file=sys.stderr)
            sys.exit(1)
    
    def _print_skill_info(self, skill: SkillMetadata):
        """Print detailed skill information"""
        print("\n" + "="*80)
        print(f"Skill: {skill.name}")
        print("="*80)
        
        print(f"\nID:              {skill.id}")
        print(f"Description:     {skill.description}")
        print(f"Category:        {skill.category}")
        print(f"Version:         {skill.version}")
        print(f"Author:          {skill.author}")
        print(f"Installed:       {'✅ Yes' if skill.installed else '❌ No'}")
        print(f"Enabled:         {'✅ Yes' if skill.enabled else '❌ No'}")
        
        print(f"\nRating:")
        rating_stars = "⭐" * int(skill.rating)
        print(f"  {rating_stars} ({skill.rating:.1f}/5.0)")
        print(f"  {skill.downloads} downloads")
        
        if skill.tags:
            print(f"\nTags:")
            print(f"  {', '.join(skill.tags)}")
        
        if skill.tools:
            print(f"\nTools:")
            for tool in skill.tools:
                print(f"  • {tool}")
        
        if skill.requirements:
            print(f"\nRequirements:")
            for req in skill.requirements:
                print(f"  • {req}")
        
        if skill.mitre_techniques:
            print(f"\nMITRE ATT&CK:")
            print(f"  {', '.join(skill.mitre_techniques)}")
        
        print("\n" + "="*80 + "\n")
    
    def cmd_skills_search(self, args):
        """
        Search skills by name, description, or tags
        
        Usage: tazos skills search <query>
        """
        try:
            manager = self.get_skills_manager()
            results = manager.search_skills(args.query)
            
            if not results:
                print(f"No skills found matching: {args.query}")
                return
            
            print(f"\nFound {len(results)} skills matching '{args.query}':")
            self._print_skills_table(results)
        
        except Exception as e:
            print(f"❌ Failed to search skills: {e}", file=sys.stderr)
            sys.exit(1)
    
    def cmd_skills_create(self, args):
        """
        Create a custom skill
        
        Usage: tazos skills create <name> --description "..." --category <category>
        """
        try:
            manager = self.get_skills_manager()
            
            # Validate category
            if args.category not in manager.CATEGORIES:
                print(f"❌ Invalid category: {args.category}", file=sys.stderr)
                print(f"   Valid categories: {', '.join(manager.CATEGORIES)}", file=sys.stderr)
                sys.exit(1)
            
            # Create skill
            skill = manager.create_skill(
                name=args.name,
                description=args.description,
                category=args.category,
                author=args.author or "Custom"
            )
            
            print(f"✅ Skill created successfully!")
            print(f"   ID:          {skill.id}")
            print(f"   Name:        {skill.name}")
            print(f"   Category:    {skill.category}")
            print(f"   Description: {skill.description}")
            print(f"\nSkill installed at: skills/{skill.id}/")
            print(f"Edit the skill files to customize implementation.")
            
        except Exception as e:
            print(f"❌ Failed to create skill: {e}", file=sys.stderr)
            sys.exit(1)
    
    def cmd_skills_categories(self, args):
        """
        List all available skill categories
        
        Usage: tazos skills categories
        """
        try:
            manager = self.get_skills_manager()
            categories = manager.get_categories()
            
            print("\nAvailable Categories:")
            print("="*40)
            
            for category in categories:
                # Count skills in this category
                skills = manager.list_skills(category=category)
                print(f"  • {category:<20} ({len(skills)} skills)")
            
            print("="*40 + "\n")
        
        except Exception as e:
            print(f"❌ Failed to list categories: {e}", file=sys.stderr)
            sys.exit(1)
    
    def cmd_skills_stats(self, args):
        """
        Show skills marketplace statistics
        
        Usage: tazos skills stats
        """
        try:
            manager = self.get_skills_manager()
            stats = manager.get_stats()
            
            if args.json:
                print(json.dumps(stats, indent=2, default=str))
            else:
                print("\nSkills Marketplace Statistics")
                print("="*60)
                print(f"Total Skills:       {stats['total_skills']}")
                print(f"Installed Skills:   {stats['installed_skills']}")
                print(f"Categories:         {stats['categories']}")
                print(f"Total Downloads:    {stats['downloads']}")
                print(f"Average Rating:     ⭐ {stats['average_rating']:.2f}/5.0")
                
                # Show top skills
                top_skills = sorted(
                    manager.marketplace.values(),
                    key=lambda x: x.downloads,
                    reverse=True
                )[:5]
                
                print(f"\nTop 5 Most Downloaded:")
                for i, skill in enumerate(top_skills, 1):
                    print(f"  {i}. {skill.name} ({skill.downloads} downloads)")
                
                print("="*60 + "\n")
        
        except Exception as e:
            print(f"❌ Failed to show stats: {e}", file=sys.stderr)
            sys.exit(1)


def main():
    """Main CLI entry point"""
    cli = TazosCLI()
    
    parser = argparse.ArgumentParser(
        prog='tazos',
        description='TazoSploit CLI - Professional penetration testing with scheduling',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tazos schedule "scan example.com" "daily at 3am"
  tazos schedule "check for new CVEs" "every 6 hours"
  tazos schedule "discover subdomains" "every 30 minutes"
  tazos jobs list
  tazos jobs show <job-id>
  tazos jobs cancel <job-id>
  tazos jobs history --limit 20
  tazos jobs stats
        """
    )
    
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Schedule command
    schedule_parser = subparsers.add_parser('schedule', help='Schedule a pentest task')
    schedule_parser.add_argument('description', help='Job description')
    schedule_parser.add_argument('time', help='Natural language time (e.g., "daily at 3am")')
    schedule_parser.set_defaults(func=cli.cmd_schedule)
    
    # Jobs subcommands
    jobs_parser = subparsers.add_parser('jobs', help='Manage jobs')
    jobs_subparsers = jobs_parser.add_subparsers(dest='jobs_command', help='Job commands')
    
    # Skills subcommands
    skills_parser = subparsers.add_parser('skills', help='Manage skills')
    skills_subparsers = skills_parser.add_subparsers(dest='skills_command', help='Skills commands')
    
    # jobs list
    list_parser = jobs_subparsers.add_parser('list', help='List all jobs')
    list_parser.add_argument('--status', help='Filter by status')
    list_parser.add_argument('--type', help='Filter by job type')
    list_parser.set_defaults(func=cli.cmd_jobs_list)
    
    # jobs show
    show_parser = jobs_subparsers.add_parser('show', help='Show job details')
    show_parser.add_argument('job_id', help='Job ID')
    show_parser.set_defaults(func=cli.cmd_jobs_show)
    
    # jobs cancel
    cancel_parser = jobs_subparsers.add_parser('cancel', help='Cancel a job')
    cancel_parser.add_argument('job_id', help='Job ID')
    cancel_parser.set_defaults(func=cli.cmd_jobs_cancel)
    
    # jobs history
    history_parser = jobs_subparsers.add_parser('history', help='Show job history')
    history_parser.add_argument('--limit', type=int, help='Number of entries to show')
    history_parser.set_defaults(func=cli.cmd_jobs_history)
    
    # jobs stats
    stats_parser = jobs_subparsers.add_parser('stats', help='Show scheduler statistics')
    stats_parser.set_defaults(func=cli.cmd_jobs_stats)
    
    # skills list
    skills_list_parser = skills_subparsers.add_parser('list', help='List available skills')
    skills_list_parser.add_argument('--category', help='Filter by category')
    skills_list_parser.add_argument('--installed-only', action='store_true', help='Show only installed skills')
    skills_list_parser.set_defaults(func=cli.cmd_skills_list)
    
    # skills install
    skills_install_parser = skills_subparsers.add_parser('install', help='Install a skill')
    skills_install_parser.add_argument('skill_name', help='Skill name or ID to install')
    skills_install_parser.set_defaults(func=cli.cmd_skills_install)
    
    # skills remove
    skills_remove_parser = skills_subparsers.add_parser('remove', help='Remove a skill')
    skills_remove_parser.add_argument('skill_name', help='Skill name or ID to remove')
    skills_remove_parser.set_defaults(func=cli.cmd_skills_remove)
    
    # skills info
    skills_info_parser = skills_subparsers.add_parser('info', help='Get skill information')
    skills_info_parser.add_argument('skill_name', help='Skill name or ID')
    skills_info_parser.set_defaults(func=cli.cmd_skills_info)
    
    # skills search
    skills_search_parser = skills_subparsers.add_parser('search', help='Search skills')
    skills_search_parser.add_argument('query', help='Search query')
    skills_search_parser.set_defaults(func=cli.cmd_skills_search)
    
    # skills create
    skills_create_parser = skills_subparsers.add_parser('create', help='Create a custom skill')
    skills_create_parser.add_argument('name', help='Skill name')
    skills_create_parser.add_argument('--description', required=True, help='Skill description')
    skills_create_parser.add_argument('--category', required=True, help='Skill category')
    skills_create_parser.add_argument('--author', help='Skill author')
    skills_create_parser.set_defaults(func=cli.cmd_skills_create)
    
    # skills categories
    skills_categories_parser = skills_subparsers.add_parser('categories', help='List skill categories')
    skills_categories_parser.set_defaults(func=cli.cmd_skills_categories)
    
    # skills stats
    skills_stats_parser = skills_subparsers.add_parser('stats', help='Show marketplace statistics')
    skills_stats_parser.set_defaults(func=cli.cmd_skills_stats)
    
    # Parse arguments
    args = parser.parse_args()
    
    # Execute command
    if args.command == 'schedule':
        cli.cmd_schedule(args)
    elif args.command == 'jobs' and args.jobs_command:
        if args.func:
            args.func(args)
    elif args.command == 'skills' and args.skills_command:
        if args.func:
            args.func(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
