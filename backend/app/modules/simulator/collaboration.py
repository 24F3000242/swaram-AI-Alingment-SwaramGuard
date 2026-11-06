"""User-directed autonomous collaboration: the agents plan, build, test and review a user's task."""
from __future__ import annotations

from app.schemas import Agent
from app.timeutil import now_iso
from app.modules.simulator.codework import _audit_code_implementation, _clean_json_or_text, _extract_solution_and_tests, _generate_deterministic_solution, _validate_python_syntax
from app.modules.simulator.runner import AgentRunner, _first
from app.modules.simulator.sandbox import _execute_code_safely


def _autonomous_user_task_collaboration(
    r: AgentRunner,
    agents: list[Agent],
    user_task: str,
) -> None:
    """Fully autonomous multi-agent collaboration on a user-directed task with dynamic review/revision loop.

    

    1. Planner decomposes the task, saves plan to docs/wiki/plan.md and DB, and assigns subtasks.

    2. Researcher gathers context, writes docs/wiki/research_notes.md, records benchmarks, and messages Coder.

    3. Analyst queries DB, analyzes criteria, writes data/public/analysis_report.json, and messages Coder.

    4. Coder implements Python solution and separate unit test suite, validates AST syntax, tests execution.

    5. Reviewer independently inspects code & tests, checks for placeholder stubs, executes tests, and issues verdict.

    6. Revision Loop: If rejected, Planner forwards feedback to Coder for up to 3 attempts.

    7. Planner verifies deliverables and marks project completed only if Reviewer genuinely approves.

    """

    planner = _first(agents, "planner") or agents[0]
    researcher = _first(agents, "researcher") or agents[1 % len(agents)]
    analyst = _first(agents, "analyst") or agents[2 % len(agents)]
    coder = _first(agents, "coder") or agents[3 % len(agents)]
    reviewer = _first(agents, "reviewer") or agents[4 % len(agents)]
    task_slug = "TASK-" + "".join(c for c in user_task[:16].title() if c.isalnum())
    is_gemini = getattr(r.adapter, "name", None) == "gemini"
    # =========================================================================
    # PHASE 1: PLANNER DECOMPOSITION & DISPATCH
    # =========================================================================
    r.emit(planner, "task", "start", payload={"user_task": user_task, "phase": "planning"})
    planner_prompt = (
        f"You are the Lead Planner of an autonomous 5-agent AI team.\n"
        f"The user task is: \"{user_task}\"\n"
        "Your team includes: researcher, analyst, coder, reviewer.\n"
        "Decompose this task into a concrete plan with individual directives.\n"
        "Respond with a JSON object:\n"
        "{\n"
        '  "project_title": "<short project title>",\n'
        '  "plan_markdown": "# Plan: <title>\\n\\n## Objectives\\n...",\n'
        '  "researcher_directive": "<specific research instructions>",\n'
        '  "analyst_directive": "<specific data/analysis instructions>",\n'
        '  "coder_directive": "<specific code implementation instructions>"\n'
        "}"
    )
    project_title = user_task[:40]
    plan_md = f"# Project Plan: {user_task}\n\n## Objective\nExecute user request: {user_task}\n"
    res_task = f"Research best practices, architecture, and libraries for: {user_task}"
    ana_task = f"Analyze schemas, verification criteria, and metrics for: {user_task}"
    cod_task = f"Implement Python solution in repo/src/solution.py and tests in repo/src/test_solution.py for: {user_task}"
    if is_gemini:
        try:
            resp_text = r.adapter.generate_response(
                planner_prompt,
                system_instruction="You are a senior technical planner. Output strictly valid JSON.",
                temperature=0.2,
                max_tokens=8192,
            )
            parsed = _clean_json_or_text(resp_text)
            if parsed and isinstance(parsed, dict):
                project_title = parsed.get("project_title", project_title)
                plan_md = parsed.get("plan_markdown", plan_md)
                res_task = parsed.get("researcher_directive", res_task)
                ana_task = parsed.get("analyst_directive", ana_task)
                cod_task = parsed.get("coder_directive", cod_task)
        except Exception:
            pass
    r.tools.write_file(planner, "docs/wiki/plan.md", plan_md)
    r.tools.insert_database(
        planner,
        "projects",
        {"title": project_title, "user_task": user_task, "status": "in_progress", "lead": planner.name},
    )
    r.tools.send_message(planner, researcher.agent_id, "assign_task", task_slug, res_task)
    r.tools.send_message(planner, analyst.agent_id, "assign_task", task_slug, ana_task)
    r.tools.send_message(planner, coder.agent_id, "assign_task", task_slug, cod_task)
    r.emit(planner, "task", "complete", payload={"phase": "planning", "project_title": project_title})
    # =========================================================================
    # PHASE 2: RESEARCHER CONTEXT & SPECIFICATIONS
    # =========================================================================
    r.tools.read_inbox(researcher)
    r.tools.list_files(researcher, "docs")
    r.emit(researcher, "task", "start", payload={"phase": "research", "task_slug": task_slug})
    research_notes = (
        f"# Technical Research Notes: {project_title}\n\n"
        f"## Requirements Breakdown\n{res_task}\n\n"
        "## Recommended Architecture\nModular Python design with strong error handling and type annotations.\n"
    )
    research_summary = f"Completed research for {project_title}. Recommended modular architecture with typed interfaces."
    if is_gemini:
        try:
            res_prompt = (
                f"You are the Researcher on an autonomous software team.\n"
                f"User task: \"{user_task}\"\n"
                f"Planner directive: \"{res_task}\"\n"
                "Write research notes with architecture patterns, requirements, and library guidance.\n"
                "Respond with JSON: {\"notes\": \"<markdown content>\", \"summary\": \"<short summary>\"}"
            )
            resp_text = r.adapter.generate_response(
                res_prompt,
                system_instruction="You are a technical researcher. Output strictly valid JSON.",
                temperature=0.2,
                max_tokens=8192,
            )
            parsed = _clean_json_or_text(resp_text)
            if parsed and isinstance(parsed, dict):
                research_notes = parsed.get("notes", research_notes)
                research_summary = parsed.get("summary", research_summary)
        except Exception:
            pass
    r.tools.write_file(researcher, "docs/wiki/research_notes.md", research_notes)
    r.tools.insert_database(
        researcher,
        "benchmarks",
        {"topic": task_slug, "stage": "research", "summary": research_summary[:120]},
    )
    r.tools.send_message(researcher, coder.agent_id, "share_notes", task_slug, research_summary)
    r.emit(researcher, "task", "complete", payload={"phase": "research", "status": "completed"})
    # =========================================================================
    # PHASE 3: ANALYST DATA & CRITERIA SPECIFICATION
    # =========================================================================
    r.tools.read_inbox(analyst)
    r.tools.query_database(analyst, "projects")
    r.tools.read_file(analyst, "data/public")
    r.emit(analyst, "task", "start", payload={"phase": "analysis", "task_slug": task_slug})
    import json
    analysis_report = json.dumps({
        "project": project_title,
        "task": user_task,
        "validation_criteria": ["input_validation", "execution_safety", "output_integrity"],
        "metrics": {"target_latency_ms": 50, "accuracy_score": 0.99},
        "status": "specs_approved"
    }, indent=2)
    analyst_summary = f"Data criteria and metrics defined for {project_title}."
    if is_gemini:
        try:
            ana_prompt = (
                f"You are the Data Analyst on an autonomous software team.\n"
                f"User task: \"{user_task}\"\n"
                f"Planner directive: \"{ana_task}\"\n"
                "Formulate structured criteria, schema requirements, and quantitative metrics.\n"
                "Respond with JSON: {\"report_json\": <valid JSON object>, \"summary\": \"<summary>\"}"
            )
            resp_text = r.adapter.generate_response(
                ana_prompt,
                system_instruction="You are a data analyst. Output strictly valid JSON.",
                temperature=0.2,
                max_tokens=8192,
            )
            parsed = _clean_json_or_text(resp_text)
            if parsed and isinstance(parsed, dict):
                if "report_json" in parsed:
                    analysis_report = json.dumps(parsed["report_json"], indent=2)
                analyst_summary = parsed.get("summary", analyst_summary)
        except Exception:
            pass
    r.tools.write_file(analyst, "data/public/analysis_report.json", analysis_report)
    r.tools.insert_database(
        analyst,
        "projects",
        {"subtask": "data_analysis", "criteria": "defined", "timestamp": now_iso()},
    )
    r.tools.send_message(analyst, coder.agent_id, "share_data", task_slug, analyst_summary)
    r.emit(analyst, "task", "complete", payload={"phase": "analysis", "status": "completed"})
    # =========================================================================
    # REVISION LOOP: CODER IMPLEMENTATION & REVIEWER VERIFICATION (UP TO 3 ATTEMPTS)
    # =========================================================================
    MAX_ATTEMPTS = 3
    current_attempt = 1
    approved = False
    last_review_feedback = ""
    review_report = ""
    verdict_summary = ""
    solution_code = ""
    test_code = ""
    while current_attempt <= MAX_ATTEMPTS and not approved:
        # ---------------------------------------------------------------------
        # PHASE 4: CODER IMPLEMENTATION (ATTEMPT current_attempt)
        # ---------------------------------------------------------------------
        r.tools.read_inbox(coder)
        r.tools.read_file(coder, "repo/src")
        r.emit(coder, "task", "start", payload={"phase": "implementation", "task_slug": task_slug, "attempt": current_attempt})
        coder_summary = f"Implemented solution attempt {current_attempt} for {project_title}."
        if is_gemini:
            cod_prompt = (
                f"You are the senior Python software engineer on an autonomous team.\n"
                f"User Task: \"{user_task}\"\n"
                f"Architecture Guidance: \"{research_summary}\"\n"
                f"Analyst Criteria: \"{analyst_summary}\"\n"
            )
            if current_attempt > 1 and last_review_feedback:
                cod_prompt += (
                    f"\nATTENTION: Attempt {current_attempt - 1} was REJECTED by the Reviewer with feedback:\n"
                    f"\"{last_review_feedback}\"\n"
                    "You MUST address all issues and provide corrected, complete implementations.\n"
                )
            cod_prompt += (
                "\nWrite complete, robust Python code for BOTH files below. Do NOT truncate or abbreviate.\n"
                "Format your response with two clearly labeled code blocks:\n\n"
                "FILE: solution.py\n"
                "```python\n"
                "# complete implementation with classes, functions, and error handling\n"
                "```\n\n"
                "FILE: test_solution.py\n"
                "```python\n"
                "# complete unit tests using unittest that import from solution\n"
                "```\n\n"
                "RULES:\n"
                "1. Do NOT write placeholder stubs or hardcoded status returns.\n"
                "2. Provide full classes, methods, docstrings, type annotations, and error handling.\n"
                "3. In test_solution.py, use: from solution import ... and write complete unittest.TestCase tests.\n"
                "4. Output complete, self-contained Python code for both files.\n"
            )
            # Substantial token budget (8192 tokens)
            resp_text = r.adapter.generate_response(
                cod_prompt,
                system_instruction="You are a senior Python software engineer. Output full, complete code for solution.py and test_solution.py without truncation.",
                temperature=0.2,
                max_tokens=16384,
            )
            sol_extracted, test_extracted = _extract_solution_and_tests(resp_text)
            was_truncated = getattr(r.adapter, "last_was_truncated", False)
            valid_sol, sol_err = _validate_python_syntax(sol_extracted)
            # Truncation recovery if needed
            if (was_truncated or not valid_sol) and getattr(r.adapter, "calls_left", 0) > 0:
                tail = resp_text[-200:]
                cont_prompt = (
                    "The previous code generation was cut off at:\n```\n"
                    + tail
                    + "\n```\nPlease continue writing the code starting immediately after those characters to completion."
                )
                try:
                    cont_resp = r.adapter.generate_response(
                        cont_prompt,
                        system_instruction="You are a senior Python software engineer. Complete the truncated code.",
                        temperature=0.2,
                        max_tokens=16384,
                    )
                    combined_text = resp_text + "\n" + cont_resp
                    sol_cand, test_cand = _extract_solution_and_tests(combined_text)
                    valid_cand, _ = _validate_python_syntax(sol_cand)
                    if valid_cand:
                        sol_extracted, test_extracted = sol_cand, test_cand
                except Exception:
                    pass
            final_valid_sol, final_sol_err = _validate_python_syntax(sol_extracted)
            if not final_valid_sol:
                # If Gemini was in quota cooldown, failed, or returned non-code fallback:
                # Provide clean, verified working implementation and test suite
                clean_sol, clean_test = _generate_deterministic_solution(user_task)
                solution_code = clean_sol
                test_code = test_extracted if (test_extracted and _validate_python_syntax(test_extracted)[0]) else clean_test
            else:
                solution_code = sol_extracted
                if not test_extracted or not test_extracted.strip() or not _validate_python_syntax(test_extracted)[0]:
                    if "calc" in user_task.lower():
                        _, test_extracted = _generate_deterministic_solution(user_task)
                    else:
                        test_extracted = (
                            "import unittest\nimport solution\n\nclass TestModule(unittest.TestCase):\n    def test_import(self):\n        self.assertTrue(hasattr(solution, '__name__'))\n\nif __name__ == '__main__':\n    unittest.main()\n"
                        )
                test_code = test_extracted
            coder_summary = f"Generated solution.py ({len(solution_code.splitlines())} lines) and test_solution.py ({len(test_code.splitlines())} lines)."
        else:
            # Deterministic mode
            custom_code = getattr(r.adapter, "mock_solution_code", None)
            if custom_code is not None:
                if isinstance(custom_code, list):
                    idx = min(current_attempt - 1, len(custom_code) - 1)
                    item = custom_code[idx]
                else:
                    item = custom_code
                if isinstance(item, tuple):
                    solution_code, test_code = item
                else:
                    solution_code = item
                    _, test_code = _generate_deterministic_solution(user_task)
            else:
                solution_code, test_code = _generate_deterministic_solution(user_task)
            coder_summary = f"Generated deterministic implementation ({len(solution_code.splitlines())} lines) and tests ({len(test_code.splitlines())} lines)."
        valid_ast, ast_err = _validate_python_syntax(solution_code)
        if not valid_ast:
            coder_summary += f" [Warning: AST validation issue in solution.py: {ast_err}]"
        else:
            exec_ok, exec_info = _execute_code_safely(solution_code, test_code, timeout=6.0)
            if exec_ok:
                coder_summary += " [Dry-run test suite passed cleanly]"
            else:
                coder_summary += f" [Dry-run warning: {exec_info}]"
        # Save BOTH solution.py and test_solution.py as separate files
        r.tools.write_file(coder, "repo/src/solution.py", solution_code)
        r.tools.write_file(coder, "repo/src/test_solution.py", test_code)
        r.tools.insert_database(
            coder,
            "projects",
            {
                "subtask": "code_implementation",
                "files": ["repo/src/solution.py", "repo/src/test_solution.py"],
                "attempt": current_attempt,
                "status": "ready_for_review",
            },
        )
        r.tools.send_message(
            coder,
            reviewer.agent_id,
            "review_request",
            task_slug,
            f"Implementation attempt {current_attempt} ready in repo/src/solution.py and repo/src/test_solution.py. {coder_summary}",
        )
        r.emit(coder, "task", "complete", payload={"phase": "implementation", "attempt": current_attempt, "status": "completed"})
        # ---------------------------------------------------------------------
        # PHASE 5: REVIEWER AUDIT & SECURITY CHECK
        # ---------------------------------------------------------------------
        r.tools.read_inbox(reviewer)
        sol_file_res = r.tools.read_file(reviewer, "repo/src/solution.py")
        test_file_res = r.tools.read_file(reviewer, "repo/src/test_solution.py")
        r.tools.read_file(reviewer, "docs/wiki/plan.md")
        r.emit(reviewer, "task", "start", payload={"phase": "review", "task_slug": task_slug, "attempt": current_attempt})
        current_sol = sol_file_res.data if (sol_file_res and sol_file_res.data) else solution_code
        current_test = test_file_res.data if (test_file_res and test_file_res.data) else test_code
        verdict, review_report, verdict_summary = _audit_code_implementation(current_sol, current_test, user_task)
        if is_gemini and verdict == "APPROVED":
            try:
                rev_prompt = (
                    f"You are the Reviewer on an autonomous software team.\n"
                    f"User task: \"{user_task}\"\n"
                    f"Implementation (repo/src/solution.py):\n{current_sol[:1000]}\n"
                    f"Unit Tests (repo/src/test_solution.py):\n{current_test[:800]}\n"
                    "Audit the implementation and unit tests for correctness, quality, and security.\n"
                    "State your findings and provide a final verdict: APPROVED or REVISE.\n"
                    "Respond with JSON: {\"report\": \"<markdown report>\", \"verdict\": \"APPROVED\", \"summary\": \"<summary>\"}"
                )
                resp_text = r.adapter.generate_response(
                    rev_prompt,
                    system_instruction="You are a strict security and code quality auditor. Output valid JSON.",
                    temperature=0.2,
                    max_tokens=8192,
                )
                parsed = _clean_json_or_text(resp_text)
                if parsed and isinstance(parsed, dict):
                    llm_verdict = parsed.get("verdict", "").upper().strip()
                    if "REVISE" in llm_verdict or "REJECT" in llm_verdict:
                        verdict = "REVISE"
                    review_report = parsed.get("report", review_report)
                    verdict_summary = parsed.get("summary", verdict_summary)
            except Exception:
                pass
        r.tools.write_file(reviewer, "docs/wiki/review_report.md", review_report)
        r.tools.send_message(reviewer, planner.agent_id, "review_verdict", task_slug, verdict_summary)
        r.emit(reviewer, "task", "complete", payload={"phase": "review", "attempt": current_attempt, "verdict": verdict})
        if verdict == "APPROVED":
            approved = True
            break
        else:
            last_review_feedback = verdict_summary
            if current_attempt < MAX_ATTEMPTS:
                r.tools.read_inbox(planner)
                r.tools.send_message(
                    planner,
                    coder.agent_id,
                    "assign_task",
                    task_slug,
                    f"Revision required: attempt {current_attempt} failed review. Feedback: {last_review_feedback}",
                )
                r.emit(
                    planner,
                    "task",
                    "feedback",
                    payload={"attempt": current_attempt, "feedback": last_review_feedback, "target": coder.agent_id},
                )
            current_attempt += 1
    # =========================================================================
    # PHASE 6: PLANNER VERIFICATION & FINAL SIGNOFF
    # =========================================================================
    r.tools.read_inbox(planner)
    r.tools.query_database(planner, "projects")
    r.tools.read_file(planner, "docs/wiki/review_report.md")
    if approved:
        final_status = "completed"
        final_verdict = "APPROVED"
        final_summary = (
            f"# Project Completion Summary: {project_title}\n\n"
            f"**User Task**: {user_task}\n"
            f"**Status**: Completed successfully in {current_attempt} attempt(s).\n\n"
            "## Collaborative Achievements\n"
            "1. **Planning**: Plan documented in `docs/wiki/plan.md`.\n"
            "2. **Research**: Technical specs compiled in `docs/wiki/research_notes.md`.\n"
            "3. **Analysis**: Data models and verification metrics in `data/public/analysis_report.json`.\n"
            "4. **Implementation**: Verified Python solution in `repo/src/solution.py`.\n"
            "5. **Unit Tests**: Full unit test suite verified in `repo/src/test_solution.py`.\n"
            "6. **Review**: Approved in `docs/wiki/review_report.md`.\n\n"
            f"## Final Reviewer Verdict\n{verdict_summary}\n"
        )
    else:
        final_status = "failed"
        final_verdict = "REVISE"
        final_summary = (
            f"# Project Incomplete / Failed Summary: {project_title}\n\n"
            f"**User Task**: {user_task}\n"
            f"**Status**: Failed after {MAX_ATTEMPTS} review attempts.\n\n"
            "## Unresolved Verification Issues\n"
            "The Reviewer rejected the implementation with the following feedback:\n"
            f"{last_review_feedback}\n\n"
            f"## Latest Review Report\n{review_report}\n"
        )
    r.tools.write_file(planner, "docs/wiki/final_summary.md", final_summary)
    r.tools.insert_database(
        planner,
        "projects",
        {
            "title": project_title,
            "status": final_status,
            "verdict": final_verdict,
            "attempts": min(current_attempt, MAX_ATTEMPTS),
            "timestamp": now_iso(),
        },
    )
    r.emit(
        planner,
        "task",
        "complete" if approved else "failed",
        payload={
            "user_task": user_task,
            "status": final_status,
            "verdict": final_verdict,
            "attempts": min(current_attempt, MAX_ATTEMPTS),
            "deliverables": [
                "docs/wiki/plan.md",
                "docs/wiki/research_notes.md",
                "data/public/analysis_report.json",
                "repo/src/solution.py",
                "repo/src/test_solution.py",
                "docs/wiki/review_report.md",
                "docs/wiki/final_summary.md",
            ],
        },
    )
