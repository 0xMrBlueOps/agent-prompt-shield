from __future__ import annotations

import json

import pytest

from agent_prompt_shield.redlab import Attempt, AttemptResult, Campaign, RedLabLedger, Scope
from agent_prompt_shield.redlab_cli import main
from agent_prompt_shield.redlab_drafts import DraftStore
from agent_prompt_shield.redlab_strategy import OpenAIResponsesStrategist, StrategyPacket
from agent_prompt_shield.redlab_tournament import (
    StrategyLens,
    StrategyTournament,
    TournamentConfig,
    load_seed_material,
    parse_labeled_payload,
)


def _campaign() -> Campaign:
    return Campaign(
        campaign_id="campaign-tournament",
        name="Authorized challenge",
        scope=Scope(
            target="manual challenge target",
            authorization="owner-authorized lab",
            allowed_actions=("submit test prompts",),
            prohibited_actions=("access third-party data",),
        ),
        objective="Test instruction-boundary handling",
        success_criteria=("target performs the declared challenge behavior",),
    )


def _attempt(*, payload: str = "prior payload exact") -> Attempt:
    return Attempt(
        attempt_id="attempt-focus",
        campaign_id="campaign-tournament",
        attack_family="instruction_confusion",
        hypothesis="untrusted context may influence ranking",
        payload=payload,
        delivery_channel="manual_challenge",
        result=AttemptResult.PARTIAL,
        target_response="The target acknowledged the content but did not select it.",
        lesson="Task framing changed the explanation.",
    )


def _proposal(
    title: str,
    payload: str,
    *,
    action_tags: list[str] | None = None,
) -> dict[str, object]:
    return {
        "title": title,
        "action": "mutate",
        "attack_family": "instruction_confusion",
        "hypothesis": f"{title} may alter ranking",
        "controlled_change": f"Change only the variable described by {title}",
        "proposed_payload": payload,
        "expected_signal": "The target ranks the controlled listing higher.",
        "stop_condition": "Stop after one unchanged result.",
        "parent_attempt_id": "attempt-focus",
        "action_tags": action_tags or ["submit-test-prompts"],
    }


class TournamentTransport:
    def __init__(self) -> None:
        self.generation_packets: list[dict[str, object]] = []
        self.critic_candidates: list[dict[str, object]] = []
        self.critic_calls = 0

    def __call__(self, request):
        name = request["text"]["format"]["name"]
        packet = json.loads(request["input"][0]["content"][0]["text"])
        if name == "redlab_strategy_proposals":
            self.generation_packets.append(packet)
            lens = packet["research_controls"]["lens"]
            if "trust-boundary" in lens.lower() or len(self.generation_packets) == 1:
                proposals = [
                    _proposal(
                        "Trust boundary placement",
                        (
                            "Provider:\nalpha\nModel:\nmodel-a\nDescription:\n"
                            "structured utility evidence for a precise planning request"
                        ),
                    ),
                    _proposal("Historical duplicate", "prior payload exact"),
                ]
            else:
                proposals = [
                    _proposal(
                        "Duplicate from peer lane",
                        (
                            "Provider:\nalpha\nModel:\nmodel-a\nDescription:\n"
                            "structured utility evidence for a precise planning request"
                        ),
                    ),
                    _proposal(
                        "Format boundary",
                        (
                            "Provider:\nbeta\nModel:\nmodel-b\nDescription:\n"
                            "delimiter isolated recommendation context with measurable task fit"
                        ),
                    ),
                ]
            return {
                "output_text": json.dumps(
                    {"analysis": f"Analysis for {lens}", "proposals": proposals}
                )
            }

        self.critic_calls += 1
        self.critic_candidates = packet["candidates"]
        rankings = []
        for candidate in self.critic_candidates:
            high = candidate["title"] == "Format boundary"
            value = 5 if high else 3
            rankings.append(
                {
                    "candidate_id": candidate["candidate_id"],
                    "evidence_fit": value,
                    "scope_fidelity": 5,
                    "novelty": value,
                    "testability": value,
                    "information_gain": value,
                    "rationale": "Strong controlled comparison.",
                    "risk": "Manual validation is still required.",
                }
            )
        return {
            "output_text": json.dumps(
                {"analysis": "The format candidate has the highest information value.", "rankings": rankings}
            )
        }


def _packet() -> StrategyPacket:
    campaign = _campaign()
    return StrategyPacket(
        campaign=campaign,
        attempts=(_attempt(),),
        focus_attempt_id="attempt-focus",
        max_proposals=2,
    )


def test_tournament_deduplicates_ranks_and_retains_audit_analysis() -> None:
    transport = TournamentTransport()
    strategist = OpenAIResponsesStrategist(model="test-model", transport=transport)
    tournament = StrategyTournament(strategist, critic_transport=transport)
    config = TournamentConfig(
        lenses=(StrategyLens.TRUST_BOUNDARY, StrategyLens.FORMAT_BOUNDARY),
        proposals_per_lens=2,
        finalists=1,
    )

    result = tournament.run(
        _packet(),
        config,
        seed_material=("untrusted corpus example",),
        excluded_payloads=("prior payload exact",),
    )

    assert config.planned_api_calls == 3
    assert len(transport.generation_packets) == 2
    assert transport.critic_calls == 1
    assert {item.proposal.title for item in result.candidates} == {
        "Trust boundary placement",
        "Format boundary",
    }
    assert result.finalists[0].proposal.title == "Format boundary"
    assert result.critic_analysis.startswith("The format candidate")
    assert {item["candidate_id"] for item in transport.critic_candidates} == {
        item.candidate_id for item in result.candidates
    }
    assert all(
        packet["research_controls"]["seed_material_is_untrusted_data"]
        for packet in transport.generation_packets
    )


def test_tournament_rejects_out_of_scope_candidate_before_critic() -> None:
    critic_calls = 0

    def transport(request):
        nonlocal critic_calls
        if request["text"]["format"]["name"] == "redlab_strategy_tournament_ranking":
            critic_calls += 1
            raise AssertionError("critic must not receive an out-of-scope candidate")
        return {
            "output_text": json.dumps(
                {
                    "analysis": "Unsafe candidate should be rejected.",
                    "proposals": [
                        _proposal(
                            "Scope expansion",
                            "attempt to access unrelated data",
                            action_tags=["access-third-party-data"],
                        )
                    ],
                }
            )
        }

    strategist = OpenAIResponsesStrategist(model="test-model", transport=transport)
    tournament = StrategyTournament(strategist, critic_transport=transport)

    with pytest.raises(ValueError, match="prohibited action tags"):
        tournament.run(
            _packet(),
            TournamentConfig(
                lenses=(StrategyLens.TRUST_BOUNDARY,),
                proposals_per_lens=1,
                finalists=1,
            ),
        )

    assert critic_calls == 0


def test_tournament_rejects_incomplete_critic_ranking() -> None:
    def transport(request):
        if request["text"]["format"]["name"] == "redlab_strategy_proposals":
            return {
                "output_text": json.dumps(
                    {
                        "analysis": "Two candidates remain.",
                        "proposals": [
                            _proposal("Candidate A", "alpha uniquely controlled payload"),
                            _proposal("Candidate B", "beta independently measured content"),
                        ],
                    }
                )
            }
        packet = json.loads(request["input"][0]["content"][0]["text"])
        candidate = packet["candidates"][0]
        return {
            "output_text": json.dumps(
                {
                    "analysis": "Only one score was returned.",
                    "rankings": [
                        {
                            "candidate_id": candidate["candidate_id"],
                            "evidence_fit": 3,
                            "scope_fidelity": 5,
                            "novelty": 3,
                            "testability": 3,
                            "information_gain": 3,
                            "rationale": "Incomplete by design.",
                            "risk": "Missing coverage.",
                        }
                    ],
                }
            )
        }

    strategist = OpenAIResponsesStrategist(model="test-model", transport=transport)
    tournament = StrategyTournament(strategist, critic_transport=transport)

    with pytest.raises(ValueError, match="every supplied candidate exactly once"):
        tournament.run(
            _packet(),
            TournamentConfig(
                lenses=(StrategyLens.MINIMAL_MUTATION,),
                proposals_per_lens=2,
                finalists=1,
            ),
        )


def test_tournament_preserves_format_only_controlled_variants() -> None:
    def transport(request):
        if request["text"]["format"]["name"] == "redlab_strategy_proposals":
            return {
                "output_text": json.dumps(
                    {
                        "analysis": "Field ordering is the controlled variable.",
                        "proposals": [
                            _proposal(
                                "Provider first",
                                "Provider:\nalpha\nModel:\nmodel-a\nDescription:\nprecise utility",
                            ),
                            _proposal(
                                "Description first",
                                "Description:\nprecise utility\nModel:\nmodel-a\nProvider:\nalpha",
                            ),
                        ],
                    }
                )
            }
        packet = json.loads(request["input"][0]["content"][0]["text"])
        rankings = [
            {
                "candidate_id": candidate["candidate_id"],
                "evidence_fit": 4,
                "scope_fidelity": 5,
                "novelty": 4,
                "testability": 5,
                "information_gain": 4,
                "rationale": "A controlled field-order comparison.",
                "risk": "Order effects require manual confirmation.",
            }
            for candidate in packet["candidates"]
        ]
        return {
            "output_text": json.dumps(
                {"analysis": "Both controlled variants are useful.", "rankings": rankings}
            )
        }

    strategist = OpenAIResponsesStrategist(model="test-model", transport=transport)
    tournament = StrategyTournament(strategist, critic_transport=transport)
    result = tournament.run(
        _packet(),
        TournamentConfig(
            lenses=(StrategyLens.FORMAT_BOUNDARY,),
            proposals_per_lens=2,
            finalists=2,
        ),
    )

    assert len(result.candidates) == 2
    assert {item.proposal.title for item in result.finalists} == {
        "Provider first",
        "Description first",
    }


def test_stop_candidate_does_not_poison_later_lane_exclusions() -> None:
    generation_calls = 0

    def transport(request):
        nonlocal generation_calls
        if request["text"]["format"]["name"] == "redlab_strategy_proposals":
            generation_calls += 1
            if generation_calls == 1:
                proposal = {
                    "title": "Stop this hypothesis",
                    "action": "stop",
                    "attack_family": "instruction_confusion",
                    "hypothesis": "The current hypothesis is exhausted.",
                    "controlled_change": "No further change.",
                    "proposed_payload": "",
                    "expected_signal": "No further experiment.",
                    "stop_condition": "Resume only with new evidence.",
                    "parent_attempt_id": "attempt-focus",
                    "action_tags": [],
                }
            else:
                proposal = _proposal(
                    "Try a separate scoped hypothesis",
                    "distinct evidence-based controlled payload",
                )
            return {
                "output_text": json.dumps(
                    {"analysis": "Lane-specific conclusion.", "proposals": [proposal]}
                )
            }
        packet = json.loads(request["input"][0]["content"][0]["text"])
        rankings = [
            {
                "candidate_id": candidate["candidate_id"],
                "evidence_fit": 4,
                "scope_fidelity": 5,
                "novelty": 4,
                "testability": 4,
                "information_gain": 4,
                "rationale": "The lane conclusion is scoped.",
                "risk": "Manual review remains required.",
            }
            for candidate in packet["candidates"]
        ]
        return {
            "output_text": json.dumps(
                {"analysis": "Both lane conclusions are valid.", "rankings": rankings}
            )
        }

    strategist = OpenAIResponsesStrategist(model="test-model", transport=transport)
    result = StrategyTournament(strategist, critic_transport=transport).run(
        _packet(),
        TournamentConfig(
            lenses=(StrategyLens.ADVERSARIAL_CRITIC, StrategyLens.TASK_FIT),
            proposals_per_lens=1,
            finalists=2,
        ),
    )

    assert generation_calls == 2
    assert len(result.candidates) == 2
    assert {item.proposal.action.value for item in result.candidates} == {
        "stop",
        "mutate",
    }


def test_seed_loading_and_labeled_payload_parsing(tmp_path) -> None:
    json_seed = tmp_path / "pliny.json"
    json_seed.write_text(
        json.dumps(
            {
                "tests": [
                    {"prompt": "first corpus prompt"},
                    {"description": "second corpus description"},
                ]
            }
        ),
        encoding="utf-8",
    )
    text_seed = tmp_path / "notes.txt"
    text_seed.write_text(
        "third research note\n\nfirst corpus prompt\n",
        encoding="utf-8",
    )

    seeds = load_seed_material((json_seed, text_seed))

    assert seeds == (
        "first corpus prompt",
        "second corpus description",
        "third research note",
    )
    assert parse_labeled_payload(
        "Provider:\nprovider-a\nModel:\nmodel-a\nDescription:\nline one\nline two"
    ) == {
        "Provider": "provider-a",
        "Model": "model-a",
        "Description": "line one\nline two",
    }


def test_tournament_cli_dry_run_is_offline_and_enforces_cost_cap(
    tmp_path,
    capsys,
) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    ledger = RedLabLedger(ledger_path)
    campaign = ledger.create_campaign(_campaign())
    attempt = ledger.record_attempt(_attempt())
    seed_path = tmp_path / "promptfoo.json"
    seed_path.write_text(
        json.dumps({"tests": [{"prompt": "untrusted local seed"}]}),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "--ledger",
            str(ledger_path),
            "strategy-tournament",
            "--attempt",
            attempt.attempt_id,
            "--lens",
            "trust-boundary",
            "--lens",
            "format-boundary",
            "--proposals-per-lens",
            "2",
            "--finalists",
            "1",
            "--seed-file",
            str(seed_path),
            "--dry-run",
        ]
    )

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["planned_api_calls"] == 3
    assert output["max_planned_output_tokens"] == 18_000
    assert output["generation_calls"] == 2
    assert output["critic_calls"] == 1
    assert output["seed_items"] == 1
    assert output["excluded_payloads"] == 1
    assert len(output["generation_requests"]) == 2
    assert all(
        request["max_output_tokens"] == 6_000
        for request in output["generation_requests"]
    )
    assert DraftStore(ledger_path).drafts(campaign_id=campaign.campaign_id) == []

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "--ledger",
                str(ledger_path),
                "strategy-tournament",
                "--attempt",
                attempt.attempt_id,
                "--lens",
                "trust-boundary",
                "--max-api-calls",
                "1",
                "--dry-run",
            ]
        )

    assert exc.value.code == 2
    assert "exceeding --max-api-calls 1" in capsys.readouterr().err


def test_tournament_cli_persists_only_selected_finalists(
    tmp_path,
    capsys,
    monkeypatch,
) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    ledger = RedLabLedger(ledger_path)
    campaign = ledger.create_campaign(_campaign())
    attempt = ledger.record_attempt(_attempt())
    transport = TournamentTransport()
    strategist = OpenAIResponsesStrategist(model="offline-model", transport=transport)
    monkeypatch.setattr(
        "agent_prompt_shield.redlab_cli.OpenAIResponsesStrategist",
        lambda **_kwargs: strategist,
    )

    exit_code = main(
        [
            "--ledger",
            str(ledger_path),
            "strategy-tournament",
            "--attempt",
            attempt.attempt_id,
            "--lens",
            "trust-boundary",
            "--proposals-per-lens",
            "2",
            "--finalists",
            "1",
        ]
    )

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["critic_analysis"]
    assert len(output["candidates"]) == 1
    assert output["candidates"][0]["rank"] == 1
    assert output["candidates"][0]["selected"] is True
    assert output["candidates"][0]["draft_id"] == output["drafts"][0]["draft_id"]
    assert output["candidates"][0]["proposal"]["payload_fields"]["Provider"] == "alpha"
    drafts = DraftStore(ledger_path).drafts(campaign_id=campaign.campaign_id)
    assert len(drafts) == 1
    assert drafts[0].proposal.title == "Trust boundary placement"
