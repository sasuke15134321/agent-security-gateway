#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Database operations for Agent Security Gateway
Handles PostgreSQL database for scan logs and threat statistics
"""

import os
import json
import asyncpg
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import hashlib


class SecurityDatabase:
    def __init__(self):
        # Use DATABASE_URL environment variable for PostgreSQL connection
        self.database_url = os.getenv("DATABASE_URL")
        if not self.database_url:
            # Fallback to individual components if DATABASE_URL not set
            host = os.getenv("POSTGRES_HOST", "localhost")
            port = os.getenv("POSTGRES_PORT", "5432")
            database = os.getenv("POSTGRES_DB", "security_gateway")
            user = os.getenv("POSTGRES_USER", "postgres")
            password = os.getenv("POSTGRES_PASSWORD", "")

            if password:
                self.database_url = f"postgresql://{user}:{password}@{host}:{port}/{database}"
            else:
                self.database_url = f"postgresql://{user}@{host}:{port}/{database}"

        print(f"[INFO] PostgreSQL database configured: {self.database_url.split('@')[1] if '@' in self.database_url else self.database_url}")

    async def get_connection(self):
        """Get database connection"""
        return await asyncpg.connect(self.database_url)

    async def initialize(self):
        """Initialize database and create tables if they don't exist"""
        conn = await self.get_connection()
        try:
            # Create scan_logs table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id SERIAL PRIMARY KEY,
                    content_hash VARCHAR(255) NOT NULL,
                    content_type VARCHAR(50) NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level VARCHAR(20) NOT NULL,
                    threats_detected JSONB DEFAULT '[]',
                    sensitivity VARCHAR(20) DEFAULT 'medium',
                    scan_timestamp TIMESTAMP DEFAULT NOW(),
                    scan_duration_ms INTEGER DEFAULT 0,
                    client_ip VARCHAR(45),
                    metadata JSONB DEFAULT '{}'
                )
            """)

            # Create threat_stats table for aggregated statistics
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_stats (
                    id SERIAL PRIMARY KEY,
                    threat_type VARCHAR(50) NOT NULL,
                    detection_count INTEGER DEFAULT 1,
                    first_detected TIMESTAMP DEFAULT NOW(),
                    last_detected TIMESTAMP DEFAULT NOW(),
                    average_risk_score FLOAT DEFAULT 0.0,
                    total_risk_score INTEGER DEFAULT 0
                )
            """)

            # Create daily_summary table for daily statistics
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS daily_summary (
                    id SERIAL PRIMARY KEY,
                    summary_date DATE UNIQUE NOT NULL,
                    total_scans INTEGER DEFAULT 0,
                    high_risk_scans INTEGER DEFAULT 0,
                    threats_detected INTEGER DEFAULT 0,
                    top_threat_type VARCHAR(50),
                    average_risk_score FLOAT DEFAULT 0.0,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """)

            # Create indexes for better performance
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_logs_timestamp ON scan_logs(scan_timestamp)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_logs_content_hash ON scan_logs(content_hash)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_logs_risk_score ON scan_logs(risk_score)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_logs_threats_gin ON scan_logs USING GIN (threats_detected)")

            await conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_stats_type ON threat_stats(threat_type)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_stats_last_detected ON threat_stats(last_detected)")

            await conn.execute("CREATE INDEX IF NOT EXISTS idx_daily_summary_date ON daily_summary(summary_date)")

            # Create validation_logs table for deterministic validation
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS validation_logs (
                    id SERIAL PRIMARY KEY,
                    content_hash VARCHAR(255) NOT NULL,
                    rules_applied TEXT NOT NULL,
                    passed BOOLEAN NOT NULL,
                    violation_count INTEGER DEFAULT 0,
                    critical_violations INTEGER DEFAULT 0,
                    strict_mode BOOLEAN DEFAULT TRUE,
                    violations JSONB DEFAULT '[]',
                    validation_timestamp TIMESTAMP DEFAULT NOW(),
                    client_ip VARCHAR(45),
                    metadata JSONB DEFAULT '{}'
                )
            """)

            # Create indexes for validation_logs
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_validation_logs_timestamp ON validation_logs(validation_timestamp)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_validation_logs_content_hash ON validation_logs(content_hash)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_validation_logs_passed ON validation_logs(passed)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_validation_logs_violations_gin ON validation_logs USING GIN (violations)")

            # Create payment_check_logs table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS payment_check_logs (
                    id SERIAL PRIMARY KEY,
                    agent_id VARCHAR(255) NOT NULL,
                    api_url TEXT NOT NULL,
                    api_domain VARCHAR(255) NOT NULL,
                    amount_usdc FLOAT NOT NULL,
                    safe_to_pay BOOLEAN NOT NULL,
                    risk_score INTEGER NOT NULL,
                    recommended_action VARCHAR(20) NOT NULL,
                    warnings JSONB DEFAULT '[]',
                    checked_at TIMESTAMP DEFAULT NOW()
                )
            """)

            await conn.execute("CREATE INDEX IF NOT EXISTS idx_payment_check_agent_id ON payment_check_logs(agent_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_payment_check_api_domain ON payment_check_logs(api_domain)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_payment_check_checked_at ON payment_check_logs(checked_at)")

            print("[OK] PostgreSQL database initialized with all tables and indexes")

        finally:
            await conn.close()

    async def log_scan_result(self, content_hash: str, content_type: str, risk_score: int,
                            threats_detected: List[str], sensitivity: str = "medium",
                            scan_duration_ms: int = 0, client_ip: str = None) -> int:
        """
        Log security scan result

        Args:
            content_hash: Hash of scanned content
            content_type: Type of content
            risk_score: Risk score (0-100)
            threats_detected: List of detected threats
            sensitivity: Sensitivity level
            scan_duration_ms: Scan duration in milliseconds
            client_ip: Client IP address

        Returns:
            Log ID
        """
        conn = await self.get_connection()
        try:
            # Determine risk level
            risk_level = self._get_risk_level(risk_score)

            # Insert scan log
            log_id = await conn.fetchval("""
                INSERT INTO scan_logs (content_hash, content_type, risk_score, risk_level,
                                     threats_detected, sensitivity, scan_duration_ms, client_ip)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id
            """, content_hash, content_type, risk_score, risk_level,
                json.dumps(threats_detected), sensitivity, scan_duration_ms, client_ip)

            # Update threat statistics
            await self._update_threat_stats(conn, threats_detected, risk_score)

            # Update daily summary
            await self._update_daily_summary(conn, risk_score, threats_detected)

            return log_id

        finally:
            await conn.close()

    async def log_validation_result(self, content_hash: str, rules_applied: List[str],
                                  passed: bool, violation_count: int,
                                  strict_mode: bool = True, violations: List[Dict] = None,
                                  critical_violations: int = 0, client_ip: str = None) -> int:
        """
        Log deterministic validation result

        Args:
            content_hash: Hash of validated content
            rules_applied: List of applied validation rules
            passed: Whether validation passed
            violation_count: Total number of violations
            strict_mode: Whether strict mode was used
            violations: List of violation details
            critical_violations: Number of critical violations
            client_ip: Client IP address

        Returns:
            Log ID
        """
        conn = await self.get_connection()
        try:
            # Insert validation log
            log_id = await conn.fetchval("""
                INSERT INTO validation_logs (content_hash, rules_applied, passed, violation_count,
                                           critical_violations, strict_mode, violations, client_ip)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id
            """, content_hash, json.dumps(rules_applied), passed, violation_count,
                critical_violations, strict_mode, json.dumps(violations or []), client_ip)

            return log_id

        finally:
            await conn.close()

    async def _update_threat_stats(self, conn: asyncpg.Connection, threats_detected: List[str], risk_score: int):
        """Update threat statistics"""
        for threat_type in threats_detected:
            # Check if threat type exists
            existing = await conn.fetchrow("""
                SELECT id, detection_count, total_risk_score FROM threat_stats WHERE threat_type = $1
            """, threat_type)

            if existing:
                # Update existing record
                new_count = existing['detection_count'] + 1
                new_total_risk = existing['total_risk_score'] + risk_score
                new_avg_risk = new_total_risk / new_count

                await conn.execute("""
                    UPDATE threat_stats
                    SET detection_count = $1, last_detected = NOW(),
                        average_risk_score = $2, total_risk_score = $3
                    WHERE threat_type = $4
                """, new_count, new_avg_risk, new_total_risk, threat_type)
            else:
                # Insert new record
                await conn.execute("""
                    INSERT INTO threat_stats (threat_type, detection_count, average_risk_score, total_risk_score)
                    VALUES ($1, $2, $3, $4)
                """, threat_type, 1, float(risk_score), risk_score)

    async def _update_daily_summary(self, conn: asyncpg.Connection, risk_score: int, threats_detected: List[str]):
        """Update daily summary statistics"""
        today = datetime.now().date()

        # Check if today's summary exists
        existing = await conn.fetchrow("""
            SELECT id, total_scans, high_risk_scans, threats_detected, average_risk_score
            FROM daily_summary WHERE summary_date = $1
        """, today)

        is_high_risk = risk_score >= 60
        threat_count = len(threats_detected)

        if existing:
            # Update existing summary
            new_total_scans = existing['total_scans'] + 1
            new_high_risk = existing['high_risk_scans'] + (1 if is_high_risk else 0)
            new_threats = existing['threats_detected'] + threat_count
            new_avg_risk = ((existing['average_risk_score'] * existing['total_scans']) + risk_score) / new_total_scans

            await conn.execute("""
                UPDATE daily_summary
                SET total_scans = $1, high_risk_scans = $2, threats_detected = $3, average_risk_score = $4
                WHERE summary_date = $5
            """, new_total_scans, new_high_risk, new_threats, new_avg_risk, today)
        else:
            # Insert new summary
            await conn.execute("""
                INSERT INTO daily_summary (summary_date, total_scans, high_risk_scans,
                                         threats_detected, average_risk_score)
                VALUES ($1, $2, $3, $4, $5)
            """, today, 1, 1 if is_high_risk else 0, threat_count, float(risk_score))

    def _get_risk_level(self, risk_score: int) -> str:
        """Get risk level from score"""
        if risk_score >= 80:
            return "critical"
        elif risk_score >= 60:
            return "high"
        elif risk_score >= 30:
            return "medium"
        else:
            return "low"

    async def log_payment_check(
        self,
        agent_id: str,
        api_url: str,
        api_domain: str,
        amount_usdc: float,
        safe_to_pay: bool,
        risk_score: int,
        recommended_action: str,
        warnings: List[str],
    ) -> int:
        """Log a pre-payment check result for repeat-call detection."""
        conn = await self.get_connection()
        try:
            log_id = await conn.fetchval("""
                INSERT INTO payment_check_logs
                    (agent_id, api_url, api_domain, amount_usdc,
                     safe_to_pay, risk_score, recommended_action, warnings)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id
            """, agent_id, api_url, api_domain, amount_usdc,
                safe_to_pay, risk_score, recommended_action, json.dumps(warnings))
            return log_id
        finally:
            await conn.close()

    async def get_recent_payment_checks(
        self, agent_id: str, hours: int = 1
    ) -> List[Dict[str, Any]]:
        """Return payment checks for an agent within the last N hours."""
        conn = await self.get_connection()
        try:
            cutoff = datetime.now() - timedelta(hours=hours)
            rows = await conn.fetch("""
                SELECT api_url, api_domain, amount_usdc, safe_to_pay,
                       risk_score, recommended_action, checked_at
                FROM payment_check_logs
                WHERE agent_id = $1 AND checked_at >= $2
                ORDER BY checked_at DESC
            """, agent_id, cutoff)
            return [
                {
                    "api_url": row["api_url"],
                    "api_domain": row["api_domain"],
                    "amount_usdc": row["amount_usdc"],
                    "safe_to_pay": row["safe_to_pay"],
                    "risk_score": row["risk_score"],
                    "recommended_action": row["recommended_action"],
                    "checked_at": row["checked_at"].isoformat(),
                }
                for row in rows
            ]
        finally:
            await conn.close()

    async def get_threat_statistics(self) -> Dict[str, Any]:
        """Get threat detection statistics"""
        conn = await self.get_connection()
        try:
            stats = {}

            # Total scans
            total_scans = await conn.fetchval("SELECT COUNT(*) FROM scan_logs")
            stats['total_scans'] = total_scans

            # Threats by type
            threat_counts = await conn.fetch("""
                SELECT threat_type, detection_count
                FROM threat_stats
                ORDER BY detection_count DESC
            """)
            stats['threats_by_type'] = {row['threat_type']: row['detection_count'] for row in threat_counts}

            # Risk distribution
            risk_distribution = await conn.fetch("""
                SELECT risk_level, COUNT(*) as count
                FROM scan_logs
                GROUP BY risk_level
                ORDER BY
                    CASE risk_level
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                    END
            """)
            stats['risk_distribution'] = {row['risk_level']: row['count'] for row in risk_distribution}

            # Top threats (recent 30 days)
            top_threats = await conn.fetch("""
                SELECT threat_type, detection_count, average_risk_score, last_detected
                FROM threat_stats
                WHERE last_detected >= NOW() - INTERVAL '30 days'
                ORDER BY detection_count DESC, average_risk_score DESC
                LIMIT 10
            """)
            stats['top_threats'] = [
                {
                    'threat_type': row['threat_type'],
                    'detection_count': row['detection_count'],
                    'average_risk_score': round(row['average_risk_score'], 2),
                    'last_detected': row['last_detected'].isoformat() if row['last_detected'] else None
                }
                for row in top_threats
            ]

            # Recent activity (last 7 days)
            recent_activity = await conn.fetch("""
                SELECT DATE(scan_timestamp) as scan_date, COUNT(*) as scans,
                       AVG(risk_score) as avg_risk, COUNT(CASE WHEN risk_score >= 60 THEN 1 END) as high_risk_count
                FROM scan_logs
                WHERE scan_timestamp >= NOW() - INTERVAL '7 days'
                GROUP BY DATE(scan_timestamp)
                ORDER BY scan_date DESC
            """)
            stats['recent_activity'] = [
                {
                    'date': row['scan_date'].isoformat(),
                    'scans': row['scans'],
                    'average_risk': round(row['avg_risk'], 2),
                    'high_risk_count': row['high_risk_count']
                }
                for row in recent_activity
            ]

            # Overall statistics
            overall_stats = await conn.fetchrow("""
                SELECT
                    AVG(risk_score) as avg_risk,
                    COUNT(CASE WHEN risk_score >= 80 THEN 1 END) as critical_count,
                    COUNT(CASE WHEN risk_score >= 60 THEN 1 END) as high_risk_count,
                    COUNT(CASE WHEN risk_score < 30 THEN 1 END) as safe_count
                FROM scan_logs
            """)

            stats['overall'] = {
                'average_risk_score': round(overall_stats['avg_risk'] or 0, 2),
                'critical_scans': overall_stats['critical_count'] or 0,
                'high_risk_scans': overall_stats['high_risk_count'] or 0,
                'safe_scans': overall_stats['safe_count'] or 0
            }

            return stats

        finally:
            await conn.close()

    async def get_scan_history(self, limit: int = 100, risk_level: str = None) -> List[Dict[str, Any]]:
        """
        Get scan history

        Args:
            limit: Maximum number of records to return
            risk_level: Filter by risk level

        Returns:
            List of scan records
        """
        conn = await self.get_connection()
        try:
            query = """
                SELECT content_hash, content_type, risk_score, risk_level,
                       threats_detected, scan_timestamp, scan_duration_ms
                FROM scan_logs
            """
            params = []

            if risk_level:
                query += " WHERE risk_level = $1"
                params.append(risk_level)

            query += " ORDER BY scan_timestamp DESC LIMIT $" + str(len(params) + 1)
            params.append(limit)

            rows = await conn.fetch(query, *params)

            history = []
            for row in rows:
                history.append({
                    'content_hash': row['content_hash'],
                    'content_type': row['content_type'],
                    'risk_score': row['risk_score'],
                    'risk_level': row['risk_level'],
                    'threats_detected': json.loads(row['threats_detected']) if row['threats_detected'] else [],
                    'scan_timestamp': row['scan_timestamp'].isoformat(),
                    'scan_duration_ms': row['scan_duration_ms']
                })

            return history

        finally:
            await conn.close()

    async def cleanup_old_data(self, days_to_keep: int = 90):
        """Clean up old scan logs to prevent database growth"""
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)

        conn = await self.get_connection()
        try:
            # Delete old scan logs
            deleted_logs = await conn.fetchval("""
                WITH deleted_logs AS (
                    DELETE FROM scan_logs WHERE scan_timestamp < $1
                    RETURNING id
                )
                SELECT COUNT(*) FROM deleted_logs
            """, cutoff_date)

            # Delete old daily summaries
            deleted_summaries = await conn.fetchval("""
                WITH deleted_summaries AS (
                    DELETE FROM daily_summary WHERE summary_date < $1
                    RETURNING id
                )
                SELECT COUNT(*) FROM deleted_summaries
            """, cutoff_date.date())

            if deleted_logs > 0 or deleted_summaries > 0:
                print(f"[INFO] Cleaned up {deleted_logs} old scan logs and {deleted_summaries} old summaries")

        finally:
            await conn.close()

    async def test_connection(self) -> bool:
        """Test database connection"""
        try:
            conn = await self.get_connection()
            await conn.fetchval("SELECT 1")
            await conn.close()
            return True
        except Exception as e:
            print(f"[ERROR] Database connection test failed: {e}")
            return False


# Global database instance
security_db = SecurityDatabase()