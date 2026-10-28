"""Base común de los agentes: un solo loop de tool use con los controles en código (ADR-004, ADR-012).

Cada agente es un `AgentSpec` (system prompt + herramientas propias). `BaseAgent.run` aplica:
- lista blanca POR AGENTE: un nombre fuera de `spec.tools` se rechaza, se audita y no ejecuta;
- validación Pydantic de cada input antes de ejecutar;
- `max_steps` por agente y un `Budget` de llamadas compartido por toda la corrida;
- `stop_reason` (`refusal`, `max_tokens`) y errores de la API como estados de corte;
- herramienta de salida opcional: cuando el modelo la llama, se valida y el agente termina.
Cada llamada a una herramienta queda en la auditoría con el nombre del agente.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import anthropic
from pydantic import BaseModel, ValidationError

from guardian.audit import AuditLog
from guardian.config import MAX_AGENT_STEPS, MAX_API_CALLS_PER_RUN


class ToolError(Exception):
    """Error que vuelve al modelo como tool_result con is_error. `outcome` va a la auditoría."""

    def __init__(self, message: str, outcome: str = "error") -> None:
        super().__init__(message)
        self.outcome = outcome


class ApiBudgetExceeded(Exception):
    """Se alcanzó el tope de llamadas de la corrida. Corta todo, incluidos los subagentes."""


@dataclass
class Budget:
    """Tope global de llamadas a la API, compartido por todos los agentes de una corrida."""

    max_calls: int = MAX_API_CALLS_PER_RUN
    calls: int = 0

    def take(self) -> None:
        if self.calls >= self.max_calls:
            raise ApiBudgetExceeded()
        self.calls += 1


@dataclass(frozen=True)
class Tool:
    """Herramienta de un agente. `handler=None` indica una herramienta de salida (sin efectos)."""

    definition: dict[str, Any]
    input_model: type[BaseModel]
    handler: Callable[[Any, Any], dict[str, Any]] | None = None

    @property
    def name(self) -> str:
        return self.definition["name"]


def make_tool(name: str, description: str, properties: dict[str, Any], input_model: type[BaseModel],
              handler: Callable[[Any, Any], dict[str, Any]] | None = None) -> Tool:
    schema = {"type": "object", "properties": properties, "required": list(properties),
              "additionalProperties": False}
    return Tool({"name": name, "description": description, "strict": True, "input_schema": schema},
                input_model, handler)


@dataclass(frozen=True)
class AgentSpec:
    name: str
    system_prompt: str
    tools: dict[str, Tool]
    max_steps: int = MAX_AGENT_STEPS
    max_tokens: int = 4096
    effort: str = "low"
    output_tool: str | None = None  # si está, el agente termina cuando el modelo la llama

    def __post_init__(self) -> None:
        if any(nombre != t.name for nombre, t in self.tools.items()):
            raise ValueError("cada herramienta tiene que estar registrada con su propio nombre")
        if self.output_tool is not None:
            salida = self.tools.get(self.output_tool)
            if salida is None or salida.handler is not None:
                raise ValueError("la herramienta de salida tiene que existir y no tener handler")


@dataclass(frozen=True)
class ToolCallRecord:
    agent: str
    step: int
    tool: str
    outcome: str


@dataclass
class AgentResult:
    # completed | output | no_output | invalid_output | max_steps | api_budget | refusal | max_tokens | api_error
    status: str
    agent: str
    steps: int = 0
    final_text: str = ""
    output: BaseModel | None = None
    error: str | None = None
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0


def execute_tool(tools: dict[str, Tool], context: Any, name: str, raw_input: Any) -> tuple[dict[str, Any], bool, str]:
    """Ejecuta una herramienta de la lista blanca. Devuelve (resultado, is_error, outcome).

    `ApiBudgetExceeded` no se atrapa acá: corta la corrida en el loop del agente.
    """
    tool = tools.get(name)
    if tool is None or tool.handler is None:
        return {"error": "herramienta no permitida"}, True, "rejected"
    try:
        args = tool.input_model.model_validate(raw_input)
    except ValidationError as exc:
        # Solo campo y motivo: nunca se repite el valor que mandó el modelo.
        detalle = "; ".join(f"{'.'.join(map(str, e['loc'])) or 'input'}: {e['msg']}" for e in exc.errors())
        return {"error": f"input inválido para {name}: {detalle}"}, True, "rejected"
    try:
        return tool.handler(context, args), False, "ok"
    except ToolError as exc:
        return {"error": str(exc)}, True, exc.outcome


def _texto(content: list[Any]) -> str:
    return "\n".join(b.text for b in content if getattr(b, "type", None) == "text").strip()


class BaseAgent:
    def __init__(self, spec: AgentSpec, client: Any, *, model: str, budget: Budget | None = None,
                 audit: AuditLog | None = None) -> None:
        self.spec = spec
        self.client = client
        self.model = model
        self.budget = budget or Budget()
        self.audit = audit  # None: sin auditoría (p. ej. clasificaciones de la evaluación)

    def request_params(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        """Parámetros de `messages.create`. Sin temperature ni tool_choice forzado."""
        return {
            "model": self.model,
            "max_tokens": self.spec.max_tokens,
            "system": self.spec.system_prompt,
            "tools": [t.definition for t in self.spec.tools.values()],
            "tool_choice": {"type": "auto"},
            "output_config": {"effort": self.spec.effort},
            "messages": list(messages),
        }

    def _record(self, step: int, name: str, tool_input: Any, outcome: str, inicio: float) -> None:
        if self.audit is not None:
            self.audit.record(agent=self.spec.name, step=step, tool=name, tool_input=tool_input,
                              allowed=name in self.spec.tools, outcome=outcome,
                              duration_ms=(time.perf_counter() - inicio) * 1000)

    def run(self, user_content: str, context: Any = None) -> AgentResult:
        spec = self.spec
        resultado = AgentResult(status="max_steps", agent=spec.name)
        messages: list[dict[str, Any]] = [{"role": "user", "content": user_content}]

        for paso in range(1, spec.max_steps + 1):
            try:
                self.budget.take()
            except ApiBudgetExceeded:
                resultado.status = "api_budget"
                break
            resultado.steps = paso
            try:
                respuesta = self.client.messages.create(**self.request_params(messages))
            except anthropic.APIError as exc:
                resultado.status, resultado.error = "api_error", type(exc).__name__
                break

            uso = getattr(respuesta, "usage", None)
            resultado.input_tokens += getattr(uso, "input_tokens", 0) or 0
            resultado.output_tokens += getattr(uso, "output_tokens", 0) or 0

            if respuesta.stop_reason in ("refusal", "max_tokens"):
                resultado.status = respuesta.stop_reason
                break
            bloques = [b for b in respuesta.content if getattr(b, "type", None) == "tool_use"]
            if not bloques:
                resultado.final_text = _texto(respuesta.content)
                resultado.status = "no_output" if spec.output_tool else "completed"
                break

            # Se reenvía el contenido completo (incluidos los bloques de thinking), como pide la API.
            messages.append({"role": "assistant", "content": respuesta.content})
            tool_results: list[dict[str, Any]] = []
            cortar = False
            for bloque in bloques:
                inicio = time.perf_counter()
                if spec.output_tool is not None and bloque.name == spec.output_tool:
                    try:
                        resultado.output = spec.tools[bloque.name].input_model.model_validate(bloque.input)
                        resultado.status, outcome = "output", "ok"
                    except ValidationError:
                        resultado.status, outcome = "invalid_output", "rejected"
                    self._record(paso, bloque.name, bloque.input, outcome, inicio)
                    resultado.tool_calls.append(ToolCallRecord(spec.name, paso, bloque.name, outcome))
                    cortar = True
                    break
                try:
                    payload, es_error, outcome = execute_tool(spec.tools, context, bloque.name, bloque.input)
                except ApiBudgetExceeded:
                    payload, es_error, outcome = {"error": "se alcanzó el tope de llamadas a la API"}, True, "rejected"
                    resultado.status, cortar = "api_budget", True
                self._record(paso, bloque.name, bloque.input, outcome, inicio)
                resultado.tool_calls.append(ToolCallRecord(spec.name, paso, bloque.name, outcome))
                tool_results.append({"type": "tool_result", "tool_use_id": bloque.id,
                                     "content": json.dumps(payload, ensure_ascii=False), "is_error": es_error})
                if cortar:
                    break
            if cortar:
                break
            messages.append({"role": "user", "content": tool_results})

        return resultado
