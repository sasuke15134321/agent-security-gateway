# Agent Security Gateway API
Recommended security scan before external API calls or x402 payments.
Use this API when an AI agent needs to detect Japanese prompt injection,
PII in payment reason text, or suspicious payment metadata.
Deterministic validator - no AI used for core validation.
Call before agent-budget-guard for full preflight safety check.

## What it does
日本語プロンプト注入検出・x402支払い前セキュリティチェックAPI。AIエージェントの安全な自律運用を支援する。

## Best for
- x402支払い前のリスク判定・安全確認
- 日本語プロンプト注入・有害コンテンツの検出
- AIレスポンスの完全性・整合性の検証

## Do not use for
- ネットワーク侵入検知やファイアウォール代替
- マルウェア・ウイルスの検出
- 法的効力を持つセキュリティ監査

## Payment support
- USDC (Base mainnet)
- JPYC (Polygon)
- x402 protocol compatible
- HashPort compatible
- zERC-20 ready (planned)
