"""
TazoSploit SaaS v2 - Workspaces Router
API endpoints for team collaboration
"""

import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_

from ..database import get_db
from ..models import Workspace, WorkspaceMember, FindingComment, ActivityLog, Finding, User
from ..auth import get_current_user

router = APIRouter()

# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class WorkspaceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    is_default: bool = False

class WorkspaceUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    settings: Optional[dict] = None

class WorkspaceMemberAdd(BaseModel):
    user_id: str
    role: str = Field(default="member", pattern="^(admin|member|viewer)$")
    can_create_jobs: bool = True
    can_edit_findings: bool = True
    can_delete: bool = False

class WorkspaceMemberResponse(BaseModel):
    user_id: str
    user_email: str
    user_name: Optional[str]
    role: str
    can_create_jobs: bool
    can_edit_findings: bool
    can_delete: bool
    joined_at: datetime

class WorkspaceResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    is_default: bool
    member_count: int
    created_by: Optional[str]
    created_at: datetime
    updated_at: datetime

class CommentCreate(BaseModel):
    comment: str = Field(..., min_length=1)

class CommentResponse(BaseModel):
    id: str
    finding_id: str
    user_id: Optional[str]
    user_email: Optional[str]
    user_name: Optional[str]
    comment: str
    edited: bool
    created_at: datetime
    updated_at: datetime

class ActivityResponse(BaseModel):
    id: str
    activity_type: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    title: Optional[str]
    description: Optional[str]
    user_id: Optional[str]
    user_email: Optional[str]
    user_name: Optional[str]
    metadata: dict
    created_at: datetime

# =============================================================================
# WORKSPACE ENDPOINTS
# =============================================================================

@router.post("", response_model=WorkspaceResponse)
async def create_workspace(
    workspace_data: WorkspaceCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create a new workspace"""
    
    tenant_id = current_user.tenant_id
    
    # Create workspace
    workspace = Workspace(
        tenant_id=tenant_id,
        created_by=current_user.id,
        name=workspace_data.name,
        description=workspace_data.description,
        is_default=workspace_data.is_default
    )
    
    db.add(workspace)
    await db.flush()
    
    # Add creator as admin
    member = WorkspaceMember(
        workspace_id=workspace.id,
        user_id=current_user.id,
        role="admin",
        can_create_jobs=True,
        can_edit_findings=True,
        can_delete=True
    )
    
    db.add(member)
    
    # Log activity
    activity = ActivityLog(
        workspace_id=workspace.id,
        user_id=current_user.id,
        activity_type="workspace.created",
        resource_type="workspace",
        resource_id=workspace.id,
        title=f"Created workspace: {workspace.name}",
        description=f"{current_user.email} created a new workspace"
    )
    
    db.add(activity)
    await db.commit()
    await db.refresh(workspace)
    
    return _build_workspace_response(workspace, 1)

@router.get("", response_model=List[WorkspaceResponse])
async def list_workspaces(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List all workspaces user has access to"""
    
    tenant_id = current_user.tenant_id
    
    # Get workspaces where user is a member
    query = select(Workspace).join(WorkspaceMember).where(
        and_(
            Workspace.tenant_id == tenant_id,
            WorkspaceMember.user_id == current_user.id
        )
    )
    
    result = await db.execute(query)
    workspaces = result.scalars().all()
    
    responses = []
    for workspace in workspaces:
        member_count = len(workspace.members)
        responses.append(_build_workspace_response(workspace, member_count))
    
    return responses

@router.get("/{workspace_id}", response_model=WorkspaceResponse)
async def get_workspace(
    workspace_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get workspace details"""
    
    workspace = await _get_workspace_with_access(db, workspace_id, current_user)
    member_count = len(workspace.members)
    
    return _build_workspace_response(workspace, member_count)

@router.put("/{workspace_id}", response_model=WorkspaceResponse)
async def update_workspace(
    workspace_id: str,
    workspace_data: WorkspaceUpdate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Update workspace"""
    
    workspace = await _get_workspace_with_access(db, workspace_id, current_user, require_admin=True)
    
    if workspace_data.name is not None:
        workspace.name = workspace_data.name
    if workspace_data.description is not None:
        workspace.description = workspace_data.description
    if workspace_data.settings is not None:
        workspace.settings = workspace_data.settings
    
    workspace.updated_at = datetime.utcnow()
    
    # Log activity
    activity = ActivityLog(
        workspace_id=workspace.id,
        user_id=current_user.id,
        activity_type="workspace.updated",
        resource_type="workspace",
        resource_id=workspace.id,
        title=f"Updated workspace: {workspace.name}",
        description=f"{current_user.email} updated workspace settings"
    )
    
    db.add(activity)
    await db.commit()
    await db.refresh(workspace)
    
    member_count = len(workspace.members)
    return _build_workspace_response(workspace, member_count)

@router.delete("/{workspace_id}")
async def delete_workspace(
    workspace_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Delete workspace"""
    
    workspace = await _get_workspace_with_access(db, workspace_id, current_user, require_admin=True)
    
    await db.delete(workspace)
    await db.commit()
    
    return {"message": "Workspace deleted"}

# =============================================================================
# MEMBER ENDPOINTS
# =============================================================================

@router.get("/{workspace_id}/members", response_model=List[WorkspaceMemberResponse])
async def list_members(
    workspace_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List workspace members"""
    
    workspace = await _get_workspace_with_access(db, workspace_id, current_user)
    
    responses = []
    for member in workspace.members:
        user = await db.get(User, member.user_id)
        if user:
            responses.append(WorkspaceMemberResponse(
                user_id=str(member.user_id),
                user_email=user.email,
                user_name=user.full_name,
                role=member.role,
                can_create_jobs=member.can_create_jobs,
                can_edit_findings=member.can_edit_findings,
                can_delete=member.can_delete,
                joined_at=member.joined_at
            ))
    
    return responses

@router.post("/{workspace_id}/members")
async def add_member(
    workspace_id: str,
    member_data: WorkspaceMemberAdd,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Add member to workspace"""
    
    workspace = await _get_workspace_with_access(db, workspace_id, current_user, require_admin=True)
    
    # Check if user exists and belongs to same tenant
    user = await db.get(User, uuid.UUID(member_data.user_id))
    if not user or user.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if already a member
    existing = await db.execute(
        select(WorkspaceMember).where(
            and_(
                WorkspaceMember.workspace_id == uuid.UUID(workspace_id),
                WorkspaceMember.user_id == uuid.UUID(member_data.user_id)
            )
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="User is already a member")
    
    # Add member
    member = WorkspaceMember(
        workspace_id=uuid.UUID(workspace_id),
        user_id=uuid.UUID(member_data.user_id),
        role=member_data.role,
        can_create_jobs=member_data.can_create_jobs,
        can_edit_findings=member_data.can_edit_findings,
        can_delete=member_data.can_delete,
        invited_by=current_user.id
    )
    
    db.add(member)
    
    # Log activity
    activity = ActivityLog(
        workspace_id=workspace.id,
        user_id=current_user.id,
        activity_type="member.added",
        resource_type="workspace",
        resource_id=workspace.id,
        title=f"Added member: {user.email}",
        description=f"{current_user.email} added {user.email} as {member_data.role}"
    )
    
    db.add(activity)
    await db.commit()
    
    return {"message": "Member added"}

@router.delete("/{workspace_id}/members/{user_id}")
async def remove_member(
    workspace_id: str,
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Remove member from workspace"""
    
    workspace = await _get_workspace_with_access(db, workspace_id, current_user, require_admin=True)
    
    member = await db.execute(
        select(WorkspaceMember).where(
            and_(
                WorkspaceMember.workspace_id == uuid.UUID(workspace_id),
                WorkspaceMember.user_id == uuid.UUID(user_id)
            )
        )
    )
    member = member.scalar_one_or_none()
    
    if not member:
        raise HTTPException(status_code=404, detail="Member not found")
    
    # Don't allow removing the last admin
    if member.role == "admin":
        admin_count = sum(1 for m in workspace.members if m.role == "admin")
        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot remove the last admin")
    
    user = await db.get(User, uuid.UUID(user_id))
    
    await db.delete(member)
    
    # Log activity
    activity = ActivityLog(
        workspace_id=workspace.id,
        user_id=current_user.id,
        activity_type="member.removed",
        resource_type="workspace",
        resource_id=workspace.id,
        title=f"Removed member: {user.email if user else user_id}",
        description=f"{current_user.email} removed a member"
    )
    
    db.add(activity)
    await db.commit()
    
    return {"message": "Member removed"}

# =============================================================================
# COMMENT ENDPOINTS
# =============================================================================

@router.post("/findings/{finding_id}/comments", response_model=CommentResponse)
async def add_comment(
    finding_id: str,
    comment_data: CommentCreate,
    workspace_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Add comment to finding"""
    
    # Verify workspace access
    await _get_workspace_with_access(db, workspace_id, current_user)
    
    # Verify finding exists and belongs to tenant
    finding = await db.get(Finding, uuid.UUID(finding_id))
    if not finding or finding.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Create comment
    comment = FindingComment(
        finding_id=uuid.UUID(finding_id),
        user_id=current_user.id,
        workspace_id=uuid.UUID(workspace_id),
        comment=comment_data.comment
    )
    
    db.add(comment)
    
    # Log activity
    activity = ActivityLog(
        workspace_id=uuid.UUID(workspace_id),
        user_id=current_user.id,
        activity_type="finding.commented",
        resource_type="finding",
        resource_id=uuid.UUID(finding_id),
        title=f"Commented on finding: {finding.title}",
        description=comment_data.comment[:100]
    )
    
    db.add(activity)
    await db.commit()
    await db.refresh(comment)
    
    return CommentResponse(
        id=str(comment.id),
        finding_id=str(comment.finding_id),
        user_id=str(comment.user_id),
        user_email=current_user.email,
        user_name=current_user.full_name,
        comment=comment.comment,
        edited=comment.edited,
        created_at=comment.created_at,
        updated_at=comment.updated_at
    )

@router.get("/findings/{finding_id}/comments", response_model=List[CommentResponse])
async def list_comments(
    finding_id: str,
    workspace_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List comments on finding"""
    
    # Verify workspace access
    await _get_workspace_with_access(db, workspace_id, current_user)
    
    query = select(FindingComment).where(
        and_(
            FindingComment.finding_id == uuid.UUID(finding_id),
            FindingComment.workspace_id == uuid.UUID(workspace_id)
        )
    ).order_by(FindingComment.created_at)
    
    result = await db.execute(query)
    comments = result.scalars().all()
    
    responses = []
    for comment in comments:
        user = await db.get(User, comment.user_id) if comment.user_id else None
        responses.append(CommentResponse(
            id=str(comment.id),
            finding_id=str(comment.finding_id),
            user_id=str(comment.user_id) if comment.user_id else None,
            user_email=user.email if user else None,
            user_name=user.full_name if user else None,
            comment=comment.comment,
            edited=comment.edited,
            created_at=comment.created_at,
            updated_at=comment.updated_at
        ))
    
    return responses

# =============================================================================
# ACTIVITY FEED ENDPOINTS
# =============================================================================

@router.get("/{workspace_id}/activity", response_model=List[ActivityResponse])
async def get_activity_feed(
    workspace_id: str,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get workspace activity feed"""
    
    await _get_workspace_with_access(db, workspace_id, current_user)
    
    query = select(ActivityLog).where(
        ActivityLog.workspace_id == uuid.UUID(workspace_id)
    ).order_by(ActivityLog.created_at.desc()).limit(limit)
    
    result = await db.execute(query)
    activities = result.scalars().all()
    
    responses = []
    for activity in activities:
        user = await db.get(User, activity.user_id) if activity.user_id else None
        responses.append(ActivityResponse(
            id=str(activity.id),
            activity_type=activity.activity_type,
            resource_type=activity.resource_type,
            resource_id=str(activity.resource_id) if activity.resource_id else None,
            title=activity.title,
            description=activity.description,
            user_id=str(activity.user_id) if activity.user_id else None,
            user_email=user.email if user else None,
            user_name=user.full_name if user else None,
            metadata=activity.metadata,
            created_at=activity.created_at
        ))
    
    return responses

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

async def _get_workspace_with_access(
    db: AsyncSession,
    workspace_id: str,
    current_user,
    require_admin: bool = False
) -> Workspace:
    """Get workspace and verify user has access"""
    
    workspace = await db.get(Workspace, uuid.UUID(workspace_id))
    
    if not workspace or workspace.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Workspace not found")
    
    # Check membership
    member = await db.execute(
        select(WorkspaceMember).where(
            and_(
                WorkspaceMember.workspace_id == uuid.UUID(workspace_id),
                WorkspaceMember.user_id == current_user.id
            )
        )
    )
    member = member.scalar_one_or_none()
    
    if not member:
        raise HTTPException(status_code=403, detail="Access denied")
    
    if require_admin and member.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return workspace

def _build_workspace_response(workspace: Workspace, member_count: int) -> dict:
    """Build workspace response"""
    return {
        "id": str(workspace.id),
        "name": workspace.name,
        "description": workspace.description,
        "is_default": workspace.is_default,
        "member_count": member_count,
        "created_by": str(workspace.created_by) if workspace.created_by else None,
        "created_at": workspace.created_at,
        "updated_at": workspace.updated_at
    }
