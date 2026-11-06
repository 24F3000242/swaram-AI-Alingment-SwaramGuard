"""Executable tool system for simulated agents.

Every tool:
1. Passes through the PolicyGateway BEFORE execution.
2. If denied by policy, the environment operation NEVER executes.
3. Emits an auditable RawEvent.
4. Returns an actual ToolResult to the agent.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

from app.schemas import Agent, RawEvent

if TYPE_CHECKING:
    from app.modules.simulator.engine import AgentRunner
    from app.modules.simulator.environment import SharedEnvironment


@dataclass(frozen=True)
class ToolResult:
    tool_name: str
    success: bool
    data: Any = None
    error: str | None = None
    gateway_decision: str = "not_checked"
    event_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "gateway_decision": self.gateway_decision,
            "event_id": self.event_id,
        }


class ToolRegistry:
    """Manages available tools and executes them against the shared environment."""

    def __init__(self, runner: AgentRunner, env: SharedEnvironment) -> None:
        self.runner = runner
        self.env = env

    def read_file(self, agent: Agent, path: str, *, malicious: bool = False) -> ToolResult:
        norm_path = self.env.fs.normalize_path(path)
        gw_check = self.env.gateway.check(agent, resource=norm_path)
        status = "denied" if not gw_check.executes else "success"

        event = self.runner.emit(
            agent,
            "resource_access",
            "read",
            status=status,
            resource=norm_path,
            gateway_decision=gw_check.decision,
            payload={"path": norm_path},
            malicious=malicious,
        )

        if not gw_check.executes:
            return ToolResult(
                tool_name="read_file",
                success=False,
                error=f"Policy violation: {gw_check.reason}",
                gateway_decision=gw_check.decision,
                event_id=event.event_id,
            )

        try:
            content = self.env.fs.read_file(norm_path, reader_id=agent.agent_id)
            return ToolResult(
                tool_name="read_file",
                success=True,
                data=content,
                gateway_decision=gw_check.decision,
                event_id=event.event_id,
            )
        except Exception as exc:
            return ToolResult(
                tool_name="read_file",
                success=False,
                error=str(exc),
                gateway_decision=gw_check.decision,
                event_id=event.event_id,
            )

    def write_file(self, agent: Agent, path: str, content: str, *, data_ref: str | None = None, malicious: bool = False) -> ToolResult:
        norm_path = self.env.fs.normalize_path(path)
        gw_check = self.env.gateway.check(agent, resource=norm_path)
        status = "denied" if not gw_check.executes else "success"

        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
        payload: dict[str, Any] = {
            "path": norm_path,
            "bytes": len(content.encode("utf-8")),
            "content_hash": content_hash,
        }
        if data_ref:
            payload["data_ref"] = data_ref

        event = self.runner.emit(
            agent,
            "resource_access",
            "write",
            status=status,
            resource=norm_path,
            gateway_decision=gw_check.decision,
            payload=payload,
            malicious=malicious,
        )

        if not gw_check.executes:
            return ToolResult(
                tool_name="write_file",
                success=False,
                error=f"Policy violation: {gw_check.reason}",
                gateway_decision=gw_check.decision,
                event_id=event.event_id,
            )

        vfile = self.env.fs.write_file(norm_path, content, writer_id=agent.agent_id)
        return ToolResult(
            tool_name="write_file",
            success=True,
            data={"path": vfile.path, "bytes": vfile.size, "content_hash": vfile.content_hash},
            gateway_decision=gw_check.decision,
            event_id=event.event_id,
        )

    def delete_file(self, agent: Agent, path: str, *, malicious: bool = False) -> ToolResult:
        norm_path = self.env.fs.normalize_path(path)
        gw_check = self.env.gateway.check(agent, resource=norm_path)
        status = "denied" if not gw_check.executes else "success"

        event = self.runner.emit(
            agent,
            "resource_access",
            "delete",
            status=status,
            resource=norm_path,
            gateway_decision=gw_check.decision,
            payload={"path": norm_path},
            malicious=malicious,
        )

        if not gw_check.executes:
            return ToolResult(
                tool_name="delete_file",
                success=False,
                error=f"Policy violation: {gw_check.reason}",
                gateway_decision=gw_check.decision,
                event_id=event.event_id,
            )

        deleted = self.env.fs.delete_file(norm_path, deleter_id=agent.agent_id)
        return ToolResult(
            tool_name="delete_file",
            success=deleted,
            data={"deleted": deleted, "path": norm_path},
            gateway_decision=gw_check.decision,
            event_id=event.event_id,
        )

    def list_files(self, agent: Agent, prefix: str | None = None, *, malicious: bool = False) -> ToolResult:
        resource_path = prefix or "repo"
        gw_check = self.env.gateway.check(agent, resource=resource_path)
        status = "denied" if not gw_check.executes else "success"

        event = self.runner.emit(
            agent,
            "resource_access",
            "list",
            status=status,
            resource=resource_path,
            gateway_decision=gw_check.decision,
            payload={"prefix": prefix},
            malicious=malicious,
        )

        if not gw_check.executes:
            return ToolResult(
                tool_name="list_files",
                success=False,
                error=f"Policy violation: {gw_check.reason}",
                gateway_decision=gw_check.decision,
                event_id=event.event_id,
            )

        vfiles = self.env.fs.list_files(prefix)
        file_list = [{"path": f.path, "size": f.size, "owner": f.owner} for f in vfiles]
        return ToolResult(
            tool_name="list_files",
            success=True,
            data=file_list,
            gateway_decision=gw_check.decision,
            event_id=event.event_id,
        )

    def query_database(self, agent: Agent, table: str, *, filter_key: str | None = None, filter_val: Any = None, malicious: bool = False) -> ToolResult:
        table_name = table.strip()
        resource_path = f"data/{table_name}"
        gw_check = self.env.gateway.check(agent, resource=resource_path)
        status = "denied" if not gw_check.executes else "success"

        event = self.runner.emit(
            agent,
            "resource_access",
            "query",
            status=status,
            resource=resource_path,
            gateway_decision=gw_check.decision,
            payload={"table": table_name},
            malicious=malicious,
        )

        if not gw_check.executes:
            return ToolResult(
                tool_name="query_database",
                success=False,
                error=f"Policy violation: {gw_check.reason}",
                gateway_decision=gw_check.decision,
                event_id=event.event_id,
            )

        filter_fn = None
        if filter_key is not None:
            filter_fn = lambda r: r.get(filter_key) == filter_val

        records = self.env.db.query(table_name, filter_fn=filter_fn, actor_id=agent.agent_id)
        return ToolResult(
            tool_name="query_database",
            success=True,
            data=records,
            gateway_decision=gw_check.decision,
            event_id=event.event_id,
        )

    def insert_database(self, agent: Agent, table: str, record: dict[str, Any], *, data_ref: str | None = None, malicious: bool = False) -> ToolResult:
        table_name = table.strip()
        resource_path = f"data/{table_name}"
        gw_check = self.env.gateway.check(agent, resource=resource_path)
        status = "denied" if not gw_check.executes else "success"

        payload: dict[str, Any] = {"table": table_name, "record_keys": list(record.keys())}
        if data_ref:
            payload["data_ref"] = data_ref

        event = self.runner.emit(
            agent,
            "resource_access",
            "insert",
            status=status,
            resource=resource_path,
            gateway_decision=gw_check.decision,
            payload=payload,
            malicious=malicious,
        )

        if not gw_check.executes:
            return ToolResult(
                tool_name="insert_database",
                success=False,
                error=f"Policy violation: {gw_check.reason}",
                gateway_decision=gw_check.decision,
                event_id=event.event_id,
            )

        rec_id = self.env.db.insert(table_name, record, actor_id=agent.agent_id)
        return ToolResult(
            tool_name="insert_database",
            success=True,
            data={"record_id": rec_id, "table": table_name},
            gateway_decision=gw_check.decision,
            event_id=event.event_id,
        )

    def update_database(self, agent: Agent, table: str, record_id: str, updates: dict[str, Any], *, malicious: bool = False) -> ToolResult:
        table_name = table.strip()
        resource_path = f"data/{table_name}"
        gw_check = self.env.gateway.check(agent, resource=resource_path)
        status = "denied" if not gw_check.executes else "success"

        event = self.runner.emit(
            agent,
            "resource_access",
            "update",
            status=status,
            resource=resource_path,
            gateway_decision=gw_check.decision,
            payload={"table": table_name, "record_id": record_id},
            malicious=malicious,
        )

        if not gw_check.executes:
            return ToolResult(
                tool_name="update_database",
                success=False,
                error=f"Policy violation: {gw_check.reason}",
                gateway_decision=gw_check.decision,
                event_id=event.event_id,
            )

        ok = self.env.db.update(table_name, record_id, updates, actor_id=agent.agent_id)
        return ToolResult(
            tool_name="update_database",
            success=ok,
            data={"updated": ok, "record_id": record_id},
            gateway_decision=gw_check.decision,
            event_id=event.event_id,
        )

    def delete_database(self, agent: Agent, table: str, record_id: str, *, malicious: bool = False) -> ToolResult:
        table_name = table.strip()
        resource_path = f"data/{table_name}"
        gw_check = self.env.gateway.check(agent, resource=resource_path)
        status = "denied" if not gw_check.executes else "success"

        event = self.runner.emit(
            agent,
            "resource_access",
            "delete",
            status=status,
            resource=resource_path,
            gateway_decision=gw_check.decision,
            payload={"table": table_name, "record_id": record_id},
            malicious=malicious,
        )

        if not gw_check.executes:
            return ToolResult(
                tool_name="delete_database",
                success=False,
                error=f"Policy violation: {gw_check.reason}",
                gateway_decision=gw_check.decision,
                event_id=event.event_id,
            )

        ok = self.env.db.delete(table_name, record_id, actor_id=agent.agent_id)
        return ToolResult(
            tool_name="delete_database",
            success=ok,
            data={"deleted": ok, "record_id": record_id, "table": table_name},
            gateway_decision=gw_check.decision,
            event_id=event.event_id,
        )

    def send_message(
        self,
        agent: Agent,
        recipient_id: str,
        intent: str,
        topic: str,
        content: str,
        *,
        data_ref: str | None = None,
        malicious: bool = False,
    ) -> ToolResult:
        # Resolve recipient
        recipient = self.runner.get_agent_by_id(recipient_id)
        if recipient is None:
            # Handle unknown recipient via broker safe failure
            recipient_dummy = Agent(
                agent_id=recipient_id,
                run_id=agent.run_id,
                name="Unknown",
                role="unknown",
                permissions=[],
            )
            recipient = recipient_dummy

        event = self.runner.message(
            agent,
            recipient,
            intent,
            topic,
            content_override=content,
            data_ref=data_ref,
            malicious=malicious,
        )
        success = event.status == "success"
        error = event.payload.get("delivery_error")

        return ToolResult(
            tool_name="send_message",
            success=success,
            data={"message_id": event.payload.get("message_id"), "recipient": recipient_id},
            error=error,
            event_id=event.event_id,
        )

    def read_inbox(self, agent: Agent, *, malicious: bool = False) -> ToolResult:
        events = self.runner.receive_messages(agent, malicious=malicious)
        received_msgs = [
            {
                "message_id": e.payload.get("message_id"),
                "sender_id": e.payload.get("sender_id"),
                "intent": e.payload.get("intent"),
                "topic": e.payload.get("topic"),
                "content": e.payload.get("content"),
                "data_ref": e.payload.get("data_ref"),
            }
            for e in events
        ]
        return ToolResult(
            tool_name="read_inbox",
            success=True,
            data=received_msgs,
            event_id=events[-1].event_id if events else None,
        )

    def access_external(
        self,
        agent: Agent,
        target: str,
        resource: str | None = None,
        data: Any = None,
        *,
        action: str = "upload",
        malicious: bool = False,
    ) -> ToolResult:
        gw_check = self.env.gateway.check(agent, resource=resource, target=target)
        status = "denied" if not gw_check.executes else "success"

        payload: dict[str, Any] = {"target": target, "data_summary": str(data)[:100]}
        if resource:
            payload["resource"] = resource

        event = self.runner.emit(
            agent,
            "data_transfer",
            action,
            status=status,
            target=target,
            resource=resource,
            gateway_decision=gw_check.decision,
            payload=payload,
            malicious=malicious,
        )

        if not gw_check.executes:
            return ToolResult(
                tool_name="access_external",
                success=False,
                error=f"Policy violation: {gw_check.reason}",
                gateway_decision=gw_check.decision,
                event_id=event.event_id,
            )

        return ToolResult(
            tool_name="access_external",
            success=True,
            data={"target": target, "transferred": True},
            gateway_decision=gw_check.decision,
            event_id=event.event_id,
        )

    def admin_operation(
        self,
        agent: Agent,
        operation: str,
        target: str | None = None,
        params: dict[str, Any] | None = None,
        *,
        malicious: bool = False,
    ) -> ToolResult:
        resource_target = target or f"system/{operation}"
        gw_check = self.env.gateway.check(agent, resource=resource_target)
        status = "denied" if not gw_check.executes else "success"

        payload = dict(params or {})
        payload["operation"] = operation

        event = self.runner.emit(
            agent,
            "tool_call",
            operation,
            status=status,
            resource=resource_target,
            gateway_decision=gw_check.decision,
            payload=payload,
            malicious=malicious,
        )

        if not gw_check.executes:
            return ToolResult(
                tool_name="admin_operation",
                success=False,
                error=f"Policy violation: {gw_check.reason}",
                gateway_decision=gw_check.decision,
                event_id=event.event_id,
            )

        return ToolResult(
            tool_name="admin_operation",
            success=True,
            data={"operation": operation, "target": target},
            gateway_decision=gw_check.decision,
            event_id=event.event_id,
        )
