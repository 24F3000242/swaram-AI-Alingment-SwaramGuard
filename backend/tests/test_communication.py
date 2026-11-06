"""Tests for Member 1: Agent Communication & Message Broker System.

Verifies:
1. Message delivery to intended recipient inboxes.
2. Unprocessed message popping and processing state.
3. Simulation-run isolation (cross-run message separation).
4. Unknown recipient and malformed message error handling.
5. Private inbox access control (preventing snooping across agents).
6. Generation of valid RawEvent records for send and receive actions.
7. Compatibility with deterministic replay and existing simulator contracts.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.adapters.base import DeterministicAdapter
from app.modules.simulator.broker import (
    BROKER_REGISTRY,
    AgentInbox,
    DeliveryResult,
    Message,
    MessageBroker,
    get_broker,
    reset_brokers,
)
from app.modules.simulator.engine import AgentRunner, run_simulation
from app.modules.simulator.gateway import PolicyGateway
from app.schemas import Agent, RawEvent, ScenarioConfig


@pytest.fixture(autouse=True)
def clean_broker_registry():
    """Ensure every test has a clean registry."""
    reset_brokers()
    yield
    reset_brokers()


def test_message_delivery_to_recipient_inbox():
    """Test 1: A message sent to an agent actually reaches its inbox with correct data."""
    broker = MessageBroker("run-test-01")
    broker.register_agents(["agt-01", "agt-02"])

    res = broker.send(
        sender_id="agt-01",
        recipient_id="agt-02",
        intent="assign_task",
        topic="SG-101",
        content="Please analyze the telemetry log.",
        timestamp="2026-01-15T09:00:01.000Z",
        data_ref="data/public",
    )

    assert res.success is True
    assert res.message is not None
    assert res.message.sender_id == "agt-01"
    assert res.message.recipient_id == "agt-02"
    assert res.message.data_ref == "data/public"

    # Check recipient inbox
    inbox = broker.get_inbox("agt-02", reader_agent_id="agt-02")
    assert inbox.count == 1
    assert inbox.unread_count == 1
    msgs = inbox.get_messages(reader_agent_id="agt-02")
    assert len(msgs) == 1
    assert msgs[0].content == "Please analyze the telemetry log."

    # Verify sender inbox did NOT receive it
    sender_inbox = broker.get_inbox("agt-01", reader_agent_id="agt-01")
    assert sender_inbox.count == 0


def test_recipient_retrieval_and_processing():
    """Test 2: Recipient can pop unprocessed messages and mark them as processed."""
    broker = MessageBroker("run-test-02")
    broker.register_agents(["agt-sender", "agt-receiver"])

    # Send 2 messages
    broker.send(
        "agt-sender", "agt-receiver", intent="task_1", topic="T1", content="First task", timestamp="2026-01-15T09:00:01.000Z"
    )
    broker.send(
        "agt-sender", "agt-receiver", intent="task_2", topic="T2", content="Second task", timestamp="2026-01-15T09:00:02.000Z"
    )

    inbox = broker.get_inbox("agt-receiver", reader_agent_id="agt-receiver")
    assert inbox.count == 2
    assert inbox.unread_count == 2

    # First read pops 2 unread messages
    first_batch = inbox.pop_unprocessed(reader_agent_id="agt-receiver")
    assert len(first_batch) == 2
    assert inbox.unread_count == 0

    # Subsequent read returns empty list because all are processed
    second_batch = inbox.pop_unprocessed(reader_agent_id="agt-receiver")
    assert len(second_batch) == 0

    # Total message history remains intact
    assert len(inbox.get_messages(reader_agent_id="agt-receiver")) == 2


def test_cross_run_isolation():
    """Test 3: Messages in run A are strictly isolated from run B."""
    broker_a = BROKER_REGISTRY.get_or_create("run-alpha")
    broker_b = BROKER_REGISTRY.get_or_create("run-beta")

    broker_a.register_agent("agt-common")
    broker_b.register_agent("agt-common")

    broker_a.send(
        "agt-sender-a", "agt-common", intent="notice", topic="A", content="Message in Run Alpha", timestamp="2026-01-15T09:00:00.000Z"
    )

    inbox_a = broker_a.get_inbox("agt-common", reader_agent_id="agt-common")
    inbox_b = broker_b.get_inbox("agt-common", reader_agent_id="agt-common")

    assert inbox_a.count == 1
    assert inbox_b.count == 0

    # Direct delivery rejection when run IDs mismatch
    foreign_msg = Message(
        message_id="msg-x",
        run_id="run-alpha",
        sender_id="agt-01",
        recipient_id="agt-common",
        timestamp="2026-01-15T09:00:00.000Z",
        intent="test",
        topic="T",
        content="Foreign message",
    )
    with pytest.raises(ValueError, match="Cross-run isolation violation"):
        inbox_b.deliver(foreign_msg)


def test_unknown_recipient_handled_safely():
    """Test 4: Broker safely records dead letters without raising unhandled exceptions."""
    broker = MessageBroker("run-test-04")
    broker.register_agent("agt-01")

    res = broker.send(
        sender_id="agt-01",
        recipient_id="agt-ghost",  # Not registered
        intent="ping",
        topic="health",
        content="Are you there?",
        timestamp="2026-01-15T09:00:00.000Z",
    )

    assert res.success is False
    assert "Unknown recipient" in (res.error or "")
    assert len(broker.dead_letters) == 1
    assert broker.dead_letters[0]["message"].recipient_id == "agt-ghost"


def test_invalid_messages_rejected_safely():
    """Test 5: Malformed parameters fail gracefully with clear errors."""
    broker = MessageBroker("run-test-05")
    broker.register_agent("agt-01")

    # Missing recipient
    r1 = broker.send("", "agt-01", intent="i", topic="t", content="c", timestamp="2026-01-15T09:00:00.000Z")
    assert r1.success is False

    # Missing sender
    r2 = broker.send("agt-01", "", intent="i", topic="t", content="c", timestamp="2026-01-15T09:00:00.000Z")
    assert r2.success is False

    # Empty intent
    r3 = broker.send("agt-01", "agt-01", intent="", topic="t", content="c", timestamp="2026-01-15T09:00:00.000Z")
    assert r3.success is False


def test_private_inbox_access_control():
    """Test 6: Agents cannot snoop on other agents' private inboxes."""
    broker = MessageBroker("run-test-06")
    broker.register_agents(["agt-alice", "agt-eve"])

    broker.send(
        "agt-bob", "agt-alice", intent="secret", topic="keys", content="super-secret-payload", timestamp="2026-01-15T09:00:00.000Z"
    )

    inbox_alice = broker.get_inbox("agt-alice")

    # Eve tries to read Alice's inbox
    with pytest.raises(PermissionError, match="Unauthorized inbox access"):
        inbox_alice.get_messages(reader_agent_id="agt-eve")

    with pytest.raises(PermissionError, match="Unauthorized inbox access"):
        inbox_alice.pop_unprocessed(reader_agent_id="agt-eve")

    with pytest.raises(PermissionError, match="Unauthorized inbox access"):
        broker.get_inbox("agt-alice", reader_agent_id="agt-eve")

    # Alice can read her own inbox
    assert len(inbox_alice.get_messages(reader_agent_id="agt-alice")) == 1


def test_send_and_receive_raw_events_generation():
    """Test 7: AgentRunner generates compliant send and receive RawEvent records."""
    run_id = "run-comm01"
    base_time = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
    broker = MessageBroker(run_id)
    agents = [
        Agent(agent_id="agt-01", run_id=run_id, name="Planner", role="planner", permissions=[]),
        Agent(agent_id="agt-02", run_id=run_id, name="Coder", role="coder", permissions=[]),
    ]
    broker.register_agents(a.agent_id for a in agents)

    import random
    rng = random.Random(42)
    runner = AgentRunner(
        run_id, "comm01", base_time, rng, PolicyGateway("monitor"), DeterministicAdapter(), broker=broker
    )

    # 1. Send message
    send_event = runner.message(agents[0], agents[1], "assign_task", "SG-101")
    assert send_event.event_type == "message"
    assert send_event.action == "send"
    assert send_event.agent_id == "agt-01"
    assert send_event.target == "agt-02"
    assert send_event.status == "success"
    assert "message_id" in send_event.payload
    assert send_event.payload["intent"] == "assign_task"

    # Verify message is in recipient inbox
    inbox = broker.get_inbox("agt-02", reader_agent_id="agt-02")
    assert inbox.count == 1
    assert inbox.unread_count == 1

    # 2. Receive message
    recv_events = runner.receive_messages(agents[1])
    assert len(recv_events) == 1
    recv_ev = recv_events[0]
    assert recv_ev.event_type == "message"
    assert recv_ev.action == "receive"
    assert recv_ev.agent_id == "agt-02"
    assert recv_ev.target == "agt-01"
    assert recv_ev.status == "success"
    assert recv_ev.payload["message_id"] == send_event.payload["message_id"]
    assert recv_ev.payload["intent"] == "assign_task"
    assert recv_ev.sequence == send_event.sequence + 1

    # All unread messages are now processed
    assert inbox.unread_count == 0


def test_simulation_integration_and_delivery():
    """Test 8: Full simulation execution delivers messages through broker to all recipient inboxes."""
    sim = run_simulation(ScenarioConfig(scenario_id="normal_collaboration", agent_count=5, seed=123))
    broker = get_broker(sim.run.run_id)
    assert broker is not None

    # Every agent in the simulation should have a registered inbox
    for agent in sim.agents:
        assert broker.is_registered(agent.agent_id)
        inbox = broker.get_inbox(agent.agent_id, reader_agent_id=agent.agent_id)
        assert isinstance(inbox, AgentInbox)

    # Verify message events correspond to actual messages in delivery log
    message_send_events = [e for e in sim.events if e.event_type == "message" and e.action == "send"]
    message_recv_events = [e for e in sim.events if e.event_type == "message" and e.action == "receive"]
    assert len(message_send_events) == len(broker.delivery_log)
    assert len(message_send_events) > 0
    assert len(message_recv_events) == len(message_send_events)

    # Check recipient content matches event content
    for event, msg in zip(message_send_events, broker.delivery_log):
        assert event.agent_id == msg.sender_id
        assert event.target == msg.recipient_id
        assert event.payload["content"] == msg.content
        assert event.payload["intent"] == msg.intent

    # Verify that all delivered messages have been read and consumed from inboxes
    for agent in sim.agents:
        inbox = broker.get_inbox(agent.agent_id, reader_agent_id=agent.agent_id)
        assert inbox.unread_count == 0


def test_simulation_produces_send_and_receive_events_with_matching_correlation():
    """Test 9: Every received event corresponds 1:1 to an actual sent message with matching metadata."""
    for scenario_id in ("normal_collaboration", "coordinated_leakage"):
        sim = run_simulation(ScenarioConfig(scenario_id=scenario_id, agent_count=5, seed=42))
        sends = [e for e in sim.events if e.event_type == "message" and e.action == "send"]
        recvs = [e for e in sim.events if e.event_type == "message" and e.action == "receive"]

        assert len(sends) > 0, f"Scenario {scenario_id} must emit send events"
        assert len(recvs) == len(sends), f"Scenario {scenario_id} must have equal send and receive events"

        # Index sends by message_id
        sends_by_id = {s.payload["message_id"]: s for s in sends}
        assert len(sends_by_id) == len(sends), "All message IDs must be unique"

        for recv in recvs:
            msg_id = recv.payload.get("message_id")
            assert msg_id is not None, "Receive event must contain message_id"
            assert msg_id in sends_by_id, f"Receive event references unknown message_id: {msg_id}"

            send = sends_by_id[msg_id]
            # 1. Matching recipient
            assert recv.agent_id == send.target, f"Recipient mismatch for {msg_id}"
            # 2. Matching sender
            assert recv.target == send.agent_id, f"Sender target mismatch for {msg_id}"
            assert recv.payload.get("sender_id") == send.agent_id, f"Sender payload mismatch for {msg_id}"
            # 3. Matching content, intent, and topic
            assert recv.payload["content"] == send.payload["content"], f"Content mismatch for {msg_id}"
            assert recv.payload["intent"] == send.payload["intent"], f"Intent mismatch for {msg_id}"
            assert recv.payload["topic"] == send.payload["topic"], f"Topic mismatch for {msg_id}"
            if "data_ref" in send.payload:
                assert recv.payload.get("data_ref") == send.payload["data_ref"]

            # 4. Monotonic sequence ordering: receive must happen after send
            assert recv.sequence > send.sequence, "Receive sequence must follow send sequence"
            assert recv.timestamp >= send.timestamp, "Receive timestamp must be >= send timestamp"


def test_multi_agent_broadcast_consumption():
    """Test 10: Messages sent to multiple agents are consumed by their respective intended recipients."""
    run_id = "run-broadcast"
    base_time = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
    broker = MessageBroker(run_id)
    agents = [
        Agent(agent_id="agt-mgr", run_id=run_id, name="Manager", role="planner", permissions=[]),
        Agent(agent_id="agt-worker-1", run_id=run_id, name="Worker 1", role="coder", permissions=[]),
        Agent(agent_id="agt-worker-2", run_id=run_id, name="Worker 2", role="analyst", permissions=[]),
        Agent(agent_id="agt-worker-3", run_id=run_id, name="Worker 3", role="researcher", permissions=[]),
    ]
    broker.register_agents(a.agent_id for a in agents)

    import random
    runner = AgentRunner(
        run_id, "bcast", base_time, random.Random(101), PolicyGateway("monitor"), DeterministicAdapter(), broker=broker
    )

    # Manager sends distinct assignments to each worker
    worker_agents = agents[1:]
    sent_msgs = []
    for w in worker_agents:
        ev = runner.message(agents[0], w, "assign_task", f"Task-for-{w.agent_id}")
        sent_msgs.append(ev)

    # Check that each worker's inbox has exactly 1 unread message
    for w in worker_agents:
        inbox = broker.get_inbox(w.agent_id, reader_agent_id=w.agent_id)
        assert inbox.unread_count == 1
        assert inbox.count == 1

    # Worker 1 retrieves its messages
    w1_recvs = runner.receive_messages(worker_agents[0])
    assert len(w1_recvs) == 1
    assert w1_recvs[0].agent_id == worker_agents[0].agent_id
    assert w1_recvs[0].payload["topic"] == f"Task-for-{worker_agents[0].agent_id}"

    # Worker 1 inbox is now empty, others still have 1 unread
    assert broker.get_inbox(worker_agents[0].agent_id, reader_agent_id=worker_agents[0].agent_id).unread_count == 0
    assert broker.get_inbox(worker_agents[1].agent_id, reader_agent_id=worker_agents[1].agent_id).unread_count == 1
    assert broker.get_inbox(worker_agents[2].agent_id, reader_agent_id=worker_agents[2].agent_id).unread_count == 1

    # Remaining workers consume their messages
    w2_recvs = runner.receive_messages(worker_agents[1])
    w3_recvs = runner.receive_messages(worker_agents[2])
    assert len(w2_recvs) == 1
    assert len(w3_recvs) == 1
    assert w2_recvs[0].agent_id == worker_agents[1].agent_id
    assert w3_recvs[0].agent_id == worker_agents[2].agent_id

    # Second call to receive produces no duplicate events
    assert runner.receive_messages(worker_agents[0]) == []
    assert runner.receive_messages(worker_agents[1]) == []
    assert runner.receive_messages(worker_agents[2]) == []

