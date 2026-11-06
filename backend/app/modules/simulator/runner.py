"""Agent runtime: executes agent actions through the pre-execution gateway and the optional live guard."""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Sequence
from app.adapters.base import AgentAdapter
from app.modules.simulator.agent import ROLE_OBJECTIVES, SimulatedAgent
from app.modules.simulator.broker import BROKER_REGISTRY, MessageBroker
from app.modules.simulator.environment import SharedEnvironment, get_environment
from app.modules.simulator.gateway import PolicyGateway
from app.modules.simulator.tools import ToolRegistry
from app.modules.simulator.world import ROLE_ORDER, ROLE_PERMISSIONS
from app.schemas import Agent, RawEvent
from app.timeutil import iso


class AgentRunner:
    """Executes agent actions, routing protected ones through the gateway first."""

    def __init__(
        self,
        run_id: str,
        run_hex: str,
        base_time: datetime,
        rng: random.Random,
        gateway: PolicyGateway,
        adapter: AgentAdapter,
        broker: MessageBroker | None = None,
        env: SharedEnvironment | None = None,
        live=None,  # optional live guard: gate(agent_id, event_type, target) before, observe(event) after
    ):
        self.run_id = run_id
        self.run_hex = run_hex
        self.clock = base_time
        self.rng = rng
        self.gateway = gateway
        self.adapter = adapter
        self.broker = broker or BROKER_REGISTRY.get_or_create(run_id)
        self.env = env or get_environment(run_id)
        self.env.gateway = self.gateway
        self.env.broker = self.broker
        self.tools = ToolRegistry(self, self.env)
        self.events: list[RawEvent] = []
        self._sequence_counter: int = 0
        self.malicious_event_ids: list[str] = []
        self.live = live
        self._agent_registry: dict[str, Agent] = {}
        self.sim_agents: list[SimulatedAgent] = []
        self.sim_agents_by_id: dict[str, SimulatedAgent] = {}
        self.ai_trace: dict | None = None  # set by autonomous.py while a model decision is being executed

    def register_agents(self, agents: Sequence[Agent]) -> None:
        """Register agent identities and initialize SimulatedAgent instances."""
        for a in agents:
            self._agent_registry[a.agent_id] = a
            if a.agent_id not in self.sim_agents_by_id:
                sim_agent = SimulatedAgent(
                    agent=a,
                    tools=self.tools,
                    adapter=self.adapter,
                    objective=ROLE_OBJECTIVES.get(a.role),
                )
                self.sim_agents.append(sim_agent)
                self.sim_agents_by_id[a.agent_id] = sim_agent

    def get_agent_by_id(self, agent_id: str) -> Agent | None:
        """Retrieve an agent by its ID or by role name fallback."""
        if agent_id in self._agent_registry:
            return self._agent_registry[agent_id]
        for a in self._agent_registry.values():
            if a.role == agent_id:
                return a
        return None

    def get_sim_agent(self, agent_id: str) -> SimulatedAgent | None:
        """Retrieve a SimulatedAgent instance by agent ID."""
        return self.sim_agents_by_id.get(agent_id)

    def emit(
        self,
        agent: Agent,
        event_type: str,
        action: str,
        *,
        status: str = "success",
        target: str | None = None,
        resource: str | None = None,
        gateway_decision: str | None = None,
        payload: dict | None = None,
        malicious: bool = False,
        pregated: tuple[str | None] | None = None,  # (reason,) when the caller already asked the live guard
    ) -> RawEvent:
        self.clock += timedelta(milliseconds=self.rng.randint(400, 2500))
        self._sequence_counter += 1
        seq = self._sequence_counter
        # Resource-side observations are telemetry, not actions: never gated.
        paused = pregated[0] if pregated is not None else (self.live.gate(agent.agent_id, event_type, target, action=action, resource=resource, payload=payload,
                                 sequence=seq, timestamp=iso(self.clock))
                  if self.live and event_type != "observation" else None)
        if paused:  # denied before execution: a real gateway block, not a post-hoc label
            status, gateway_decision = "denied", "blocked"
            payload = {**(payload or {}), "quarantined": True, "gateway_reason": paused}
        if self.ai_trace is not None and event_type != "observation":
            payload = {**(payload or {}), "ai_trace": self.ai_trace}
        event = RawEvent(
            run_id=self.run_id,
            event_id=f"evt-{self.run_hex}-{seq:04d}",
            agent_id=agent.agent_id,
            timestamp=iso(self.clock),
            event_type=event_type,
            action=action,
            status=status,
            target=target,
            resource=resource,
            sequence=seq,
            gateway_decision=gateway_decision,
            payload=payload or {},
        )
        self.events.append(event)
        if malicious:
            self.malicious_event_ids.append(event.event_id)
        if self.live:
            self.live.observe(event)
        return event

    def protected(
        self,
        agent: Agent,
        event_type: str,
        action: str,
        *,
        resource: str | None = None,
        target: str | None = None,
        payload: dict | None = None,
        malicious: bool = False,
    ) -> bool:
        """Check policy BEFORE executing. Returns True if the tool actually ran."""
        check = self.gateway.check(agent, resource=resource, target=target)
        payload = dict(payload or {})
        if check.decision != "not_checked":
            payload["gateway_reason"] = check.reason
        event = self.emit(
            agent,
            event_type,
            action,
            status="denied" if not check.executes else "success",
            target=target,
            resource=resource,
            gateway_decision=check.decision,
            payload=payload,
            malicious=malicious,
        )
        return event.status != "denied"  # also False when the live guard paused this agent

    def access(self, agent: Agent, resource: str, action: str = "read", malicious: bool = False) -> bool:
        return self.protected(agent, "resource_access", action, resource=resource, malicious=malicious)

    def message(
        self,
        sender: Agent,
        recipient: Agent,
        intent: str,
        topic: str,
        *,
        content_override: str | None = None,
        data_ref: str | None = None,
        claims: dict | None = None,
        extra_payload: dict | None = None,
        malicious: bool = False,
    ) -> RawEvent:
        """Deliver a message through the MessageBroker and record a 'send' event."""
        content = content_override or self.adapter.compose_message(sender.role, recipient.role, intent, topic)
        msg_id = f"msg-{self.run_hex}-{self._sequence_counter + 1:04d}"
        payload: dict = {"intent": intent, "topic": topic, "content": content, "message_id": msg_id}
        if data_ref:
            payload["data_ref"] = data_ref
        if claims:
            payload["claims"] = claims
        if extra_payload:
            payload.update(extra_payload)
        # Ensure participants are registered in the broker
        if not self.broker.is_registered(sender.agent_id):
            self.broker.register_agent(sender.agent_id)
        if not self.broker.is_registered(recipient.agent_id):
            self.broker.register_agent(recipient.agent_id)
        # Ask the live guard BEFORE delivery: a contained hand-off must never reach the recipient's inbox.
        denied = (self.live.gate(sender.agent_id, "message", recipient.agent_id, action="send", payload=payload,
                                 sequence=self._sequence_counter + 1, timestamp=iso(self.clock)) if self.live else None)
        if denied:
            return self.emit(sender, "message", "send", target=recipient.agent_id, payload=payload, malicious=malicious,
                             pregated=(denied,))
        delivery = self.broker.send(
            sender.agent_id,
            recipient.agent_id,
            intent=intent,
            topic=topic,
            content=content,
            timestamp=iso(self.clock),
            message_id=msg_id,
            data_ref=data_ref,
        )
        status = "success" if delivery.success else "failed"
        if not delivery.success and delivery.error:
            payload["delivery_error"] = delivery.error
        return self.emit(
            sender,
            "message",
            "send",
            status=status,
            target=recipient.agent_id,
            payload=payload,
            malicious=malicious,
            pregated=(None,),
        )

    def receive_messages(self, agent: Agent, *, malicious: bool = False) -> list[RawEvent]:
        """Agent checks and processes unread messages from its private inbox, emitting 'receive' events."""
        if not self.broker.is_registered(agent.agent_id):
            self.broker.register_agent(agent.agent_id)
        messages = self.broker.receive(agent.agent_id)
        events = []
        for msg in messages:
            self.clock += timedelta(milliseconds=250)
            self._sequence_counter += 1
            seq = self._sequence_counter
            payload = {
                "message_id": msg.message_id,
                "intent": msg.intent,
                "topic": msg.topic,
                "content": msg.content,
                "sender_id": msg.sender_id,
            }
            if msg.data_ref:
                payload["data_ref"] = msg.data_ref
            event = RawEvent(
                run_id=self.run_id,
                event_id=f"evt-{self.run_hex}-{seq:04d}",
                agent_id=agent.agent_id,
                timestamp=iso(self.clock),
                event_type="message",
                action="receive",
                status="success",
                target=msg.sender_id,
                resource=None,
                sequence=seq,
                gateway_decision=None,
                payload=payload,
            )
            self.events.append(event)
            if malicious:
                self.malicious_event_ids.append(event.event_id)
            events.append(event)
            if self.live:
                self.live.observe(event)
        return events


def _make_agents(run_id: str, run_hex: str, count: int) -> list[Agent]:
    agents = []
    for i in range(count):
        role = ROLE_ORDER[i % len(ROLE_ORDER)]
        agents.append(Agent(
            agent_id=f"agt-{run_hex}-{i + 1:02d}",
            run_id=run_id,
            name=f"{role.title()} {i // len(ROLE_ORDER) + 1}",
            role=role,
            permissions=list(ROLE_PERMISSIONS[role]),
        ))
    return agents


def _first(agents: list[Agent], role: str) -> Agent | None:
    return next((a for a in agents if a.role == role), None)
