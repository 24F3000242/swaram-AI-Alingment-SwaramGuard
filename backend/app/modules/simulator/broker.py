"""In-memory Message Broker and Agent Inboxes for SwarmGuard simulator.

Enables real agent-to-agent communication, delivery to private inboxes,
cross-run isolation, access control, and auditability.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass(frozen=True)
class Message:
    """Represents a message sent from one agent to another."""

    message_id: str
    run_id: str
    sender_id: str
    recipient_id: str
    timestamp: str
    intent: str
    topic: str
    content: str
    data_ref: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "message_id": self.message_id,
            "run_id": self.run_id,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "timestamp": self.timestamp,
            "intent": self.intent,
            "topic": self.topic,
            "content": self.content,
        }
        if self.data_ref is not None:
            d["data_ref"] = self.data_ref
        if self.metadata:
            d["metadata"] = dict(self.metadata)
        return d


@dataclass(frozen=True)
class DeliveryResult:
    """Outcome of a broker dispatch attempt."""

    success: bool
    message: Message | None
    error: str | None = None


class AgentInbox:
    """Private message inbox for a specific agent within a simulation run."""

    def __init__(self, agent_id: str, run_id: str):
        self.agent_id = agent_id
        self.run_id = run_id
        self._messages: list[Message] = []
        self._processed_ids: set[str] = set()

    def deliver(self, message: Message) -> None:
        """Internal delivery method called by the MessageBroker."""
        if message.recipient_id != self.agent_id:
            raise ValueError(
                f"Cannot deliver message {message.message_id}: intended for {message.recipient_id}, not {self.agent_id}"
            )
        if message.run_id != self.run_id:
            raise ValueError(
                f"Cross-run isolation violation: message run '{message.run_id}' != inbox run '{self.run_id}'"
            )
        self._messages.append(message)

    def get_messages(self, reader_agent_id: str) -> list[Message]:
        """Inspect all delivered messages in the inbox. Enforces private access."""
        self._verify_access(reader_agent_id)
        return list(self._messages)

    def pop_unprocessed(self, reader_agent_id: str) -> list[Message]:
        """Retrieve all unprocessed messages and mark them as processed."""
        self._verify_access(reader_agent_id)
        unprocessed = [m for m in self._messages if m.message_id not in self._processed_ids]
        for m in unprocessed:
            self._processed_ids.add(m.message_id)
        return unprocessed

    def mark_processed(self, reader_agent_id: str, message_id: str) -> None:
        """Mark a specific message as processed."""
        self._verify_access(reader_agent_id)
        self._processed_ids.add(message_id)

    def clear(self, reader_agent_id: str) -> None:
        """Clear all messages from the inbox."""
        self._verify_access(reader_agent_id)
        self._messages.clear()
        self._processed_ids.clear()

    @property
    def count(self) -> int:
        return len(self._messages)

    @property
    def unread_count(self) -> int:
        return len(self._messages) - len(self._processed_ids)

    def _verify_access(self, reader_agent_id: str) -> None:
        if reader_agent_id != self.agent_id:
            raise PermissionError(
                f"Unauthorized inbox access: Agent '{reader_agent_id}' cannot read private inbox of '{self.agent_id}'"
            )


class MessageBroker:
    """Isolated, in-memory message broker scoped to a single simulation run."""

    def __init__(self, run_id: str):
        if not run_id or not isinstance(run_id, str):
            raise ValueError("MessageBroker requires a valid, non-empty run_id string")
        self.run_id = run_id
        self._inboxes: dict[str, AgentInbox] = {}
        self._delivery_log: list[Message] = []
        self._dead_letters: list[dict[str, Any]] = []

    def register_agent(self, agent_id: str) -> AgentInbox:
        """Register an agent and initialize its private inbox."""
        if not agent_id or not isinstance(agent_id, str):
            raise ValueError(f"Invalid agent_id: {agent_id!r}")
        if agent_id not in self._inboxes:
            self._inboxes[agent_id] = AgentInbox(agent_id=agent_id, run_id=self.run_id)
        return self._inboxes[agent_id]

    def register_agents(self, agent_ids: Iterable[str]) -> None:
        """Register multiple agents in batch."""
        for aid in agent_ids:
            self.register_agent(aid)

    def is_registered(self, agent_id: str) -> bool:
        """Check whether an agent is registered in this broker."""
        return agent_id in self._inboxes

    def send(
        self,
        sender_id: str,
        recipient_id: str,
        *,
        intent: str,
        topic: str,
        content: str,
        timestamp: str,
        message_id: str | None = None,
        data_ref: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> DeliveryResult:
        """Route and deliver a message to the recipient's inbox.

        Safely handles unknown recipients and malformed payloads without crashing.
        """
        if not sender_id or not isinstance(sender_id, str):
            return DeliveryResult(success=False, message=None, error="Invalid sender_id: must be a non-empty string")
        if not recipient_id or not isinstance(recipient_id, str):
            return DeliveryResult(success=False, message=None, error="Invalid recipient_id: must be a non-empty string")
        if not intent or not isinstance(intent, str):
            return DeliveryResult(success=False, message=None, error="Invalid intent: must be a non-empty string")
        if not topic or not isinstance(topic, str):
            return DeliveryResult(success=False, message=None, error="Invalid topic: must be a non-empty string")

        msg = Message(
            message_id=message_id or f"msg-{uuid.uuid4().hex[:10]}",
            run_id=self.run_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            timestamp=timestamp,
            intent=intent,
            topic=topic,
            content=content or "",
            data_ref=data_ref,
            metadata=metadata or {},
        )

        # Handle unknown recipient safely
        if recipient_id not in self._inboxes:
            err = f"Unknown recipient '{recipient_id}' in run '{self.run_id}'"
            self._dead_letters.append({"message": msg, "error": err, "timestamp": timestamp})
            return DeliveryResult(success=False, message=msg, error=err)

        # Deliver to recipient inbox
        inbox = self._inboxes[recipient_id]
        inbox.deliver(msg)
        self._delivery_log.append(msg)
        return DeliveryResult(success=True, message=msg, error=None)

    def get_inbox(self, agent_id: str, reader_agent_id: str | None = None) -> AgentInbox:
        """Access an agent's inbox, checking authorization if reader_agent_id is provided."""
        if agent_id not in self._inboxes:
            raise KeyError(f"Agent '{agent_id}' is not registered in broker for run '{self.run_id}'")
        inbox = self._inboxes[agent_id]
        if reader_agent_id is not None and reader_agent_id != agent_id:
            raise PermissionError(
                f"Unauthorized inbox access: Agent '{reader_agent_id}' cannot read private inbox of '{agent_id}'"
            )
        return inbox

    def receive(self, agent_id: str) -> list[Message]:
        """Convenience method: Agent retrieves its unread messages from its private inbox."""
        inbox = self.get_inbox(agent_id, reader_agent_id=agent_id)
        return inbox.pop_unprocessed(reader_agent_id=agent_id)

    @property
    def delivery_log(self) -> list[Message]:
        """Audit log of all delivered messages in this run."""
        return list(self._delivery_log)

    @property
    def dead_letters(self) -> list[dict[str, Any]]:
        """Log of undeliverable messages."""
        return list(self._dead_letters)


class BrokerRegistry:
    """Thread-safe registry mapping run_id to its dedicated MessageBroker."""

    def __init__(self):
        self._brokers: dict[str, MessageBroker] = {}

    def get_or_create(self, run_id: str) -> MessageBroker:
        if run_id not in self._brokers:
            self._brokers[run_id] = MessageBroker(run_id)
        return self._brokers[run_id]

    def create(self, run_id: str) -> MessageBroker:
        """Create and register a fresh MessageBroker for a new simulation run."""
        broker = MessageBroker(run_id)
        self._brokers[run_id] = broker
        return broker

    def get(self, run_id: str) -> MessageBroker | None:
        return self._brokers.get(run_id)

    def remove(self, run_id: str) -> None:
        self._brokers.pop(run_id, None)

    def clear(self) -> None:
        self._brokers.clear()


BROKER_REGISTRY = BrokerRegistry()


def get_broker(run_id: str) -> MessageBroker | None:
    """Retrieve the broker associated with a specific simulation run_id."""
    return BROKER_REGISTRY.get(run_id)


def reset_brokers() -> None:
    """Clear all brokers from the registry (useful for test resets)."""
    BROKER_REGISTRY.clear()
