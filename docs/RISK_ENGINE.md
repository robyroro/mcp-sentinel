# Risk engine

Risk scoring is deterministic and explainable. It supplements policy; it does not replace explicit authorization.

## Model

Each configured signal contributes a signed weight to a score bounded to 0–100. Examples include shell execution, write/destructive side effects, path scope, secret-like input, private-network targets, cloud metadata, database mutation, messaging/public posting, deployment action, repeated denials, unusual sequences, large/encoded payloads, obfuscation, schema drift, server trust, package signature, version familiarity, and prior incidents.

Protective context can reduce but never erase a terminal hard-safety result. For example, a reviewed server may subtract 10 points, while a destructive command guard still forces a deny.

## Levels

| Score | Level | Typical recommendation |
|---:|---|---|
| 0–19 | Informational | allow/audit according to policy |
| 20–39 | Low | allow with monitoring |
| 40–59 | Medium | restrict or request additional context |
| 60–79 | High | require approval or deny |
| 80–100 | Critical | deny or terminate unless a narrowly reviewed workflow applies |

Each result includes the score, level, signal IDs and weights, an explanation, recommended action, confidence, and false-positive considerations.

## Configuration

Weights are supplied through configuration and validated at startup. Version the weight set with policy changes so replay can distinguish a behavior change from an evidence change. Avoid tuning solely against the synthetic demo fixtures.

## Limitations

Risk levels are prioritization aids. Heuristic injection, entropy, obfuscation, and sequence signals can be wrong. A low score does not authorize a call, and a high score should include the concrete signals a reviewer can challenge.
