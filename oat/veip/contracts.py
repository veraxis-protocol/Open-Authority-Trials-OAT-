"""Witness admission contracts mechanically derived from the frozen register."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator


class AdmissionError(ValueError):
    """Candidate bytes are malformed or do not satisfy the frozen contract."""


def _schema_for(description: Any) -> dict[str, Any]:
    if isinstance(description, list):
        return {"type": "string", "enum": description}
    text = str(description).lower()
    if "int>=2" in text:
        return {"type": "integer", "minimum": 2}
    if "list" in text or "sequence" in text or "paths" in text:
        return {"type": "array"}
    if "object" in text or "dict" in text or "envelope" in text or "proposal" in text:
        return {"type": "object"}
    if "bool" in text or "flag" in text:
        return {"type": "boolean"}
    return {"type": "string"}


@dataclass(frozen=True)
class WitnessContract:
    falsifier_id: str
    property_id: str
    falsifier_version: str
    input_schema: dict[str, Any]
    candidate_witness_schema: dict[str, Any]
    required_observables: tuple[str, ...]
    canonicalization_rule: str
    missing_field_behavior: str
    unknown_field_behavior: str
    type_validation: str
    unevaluable_conditions: tuple[str, ...]
    negative_condition: str
    counterexample_condition: str
    claim_ceiling: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "falsifier_id": self.falsifier_id,
            "property_id": self.property_id,
            "falsifier_version": self.falsifier_version,
            "input_schema": self.input_schema,
            "candidate_witness_schema": self.candidate_witness_schema,
            "required_observables": list(self.required_observables),
            "canonicalization_rule": self.canonicalization_rule,
            "missing_field_behavior": self.missing_field_behavior,
            "unknown_field_behavior": self.unknown_field_behavior,
            "type_validation": self.type_validation,
            "unevaluable_conditions": list(self.unevaluable_conditions),
            "negative_non_counterexample_condition": self.negative_condition,
            "counterexample_condition": self.counterexample_condition,
            "claim_ceiling": self.claim_ceiling,
        }


def derive_contract(entry: dict[str, Any]) -> WitnessContract:
    """Derive, without semantic additions, the candidate input envelope."""
    inputs = dict(entry["input_schema"])
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["inputs"],
        "additionalProperties": False,
        "properties": {
            "inputs": {
                "type": "object",
                "required": list(inputs),
                "additionalProperties": False,
                "properties": {name: _schema_for(desc) for name, desc in inputs.items()},
            }
        },
    }
    return WitnessContract(
        falsifier_id=str(entry["falsifier_id"]),
        property_id=str(entry["property_id"]),
        falsifier_version=str(entry["falsifier_version"]),
        input_schema=inputs,
        candidate_witness_schema=schema,
        required_observables=tuple(str(x) for x in entry["required_observables"]),
        canonicalization_rule=(
            "RFC 8785-like OAT canonical JSON: UTF-8, sorted keys, compact separators"
        ),
        missing_field_behavior="UNEVALUABLE",
        unknown_field_behavior="UNEVALUABLE",
        type_validation="JSON Schema Draft 2020-12 before subject invocation",
        unevaluable_conditions=(
            "candidate_witness is null or not an object",
            "required input is absent",
            "unknown input is present",
            "input type is invalid",
            "required observable is absent after subject invocation",
            "subject invocation cannot be reconstructed",
        ),
        negative_condition="admitted and evaluated, with the frozen counterexample predicate false",
        counterexample_condition=str(entry["counterexample_condition"]),
        claim_ceiling=str(entry["claim_ceiling"]),
    )


def derive_ready_contracts(register: dict[str, Any]) -> dict[str, WitnessContract]:
    return {
        str(entry["falsifier_id"]): derive_contract(entry)
        for entry in register["falsifiers"]
        if entry["status"] == "READY"
    }


def admit(contract: WitnessContract, candidate: Any) -> dict[str, Any]:
    errors = sorted(
        Draft202012Validator(contract.candidate_witness_schema).iter_errors(candidate),
        key=lambda error: list(error.path),
    )
    if errors:
        raise AdmissionError("; ".join(error.message for error in errors))
    assert isinstance(candidate, dict)
    return {"inputs": dict(candidate["inputs"])}
