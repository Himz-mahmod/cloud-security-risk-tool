"""
benchmark_indexes.py

Measures what the indexes in database.py actually do, on generated data.

Run:  python benchmark_indexes.py

It builds an in-memory database with 50,000 generated assessments, times
two queries with the indexes in place, drops the indexes, and times them
again. Timings depend on the machine, so treat the ratios as the result,
not the milliseconds. This is a quick local measurement, not a rigorous
benchmark.
"""

import random
import time

from database import get_connection

N = 50_000
REPS = 200
CATEGORIES = ["Access Control", "Data Protection", "Governance",
              "Network Security", "Patch Management"]


def build(conn) -> None:
    random.seed(1)
    conn.execute("INSERT INTO users (username, password_hash) VALUES ('bench', 'x')")
    conn.executemany(
        "INSERT INTO controls (name, category) VALUES (?, ?)",
        [(f"Control {i}", random.choice(CATEGORIES)) for i in range(N)],
    )
    rows = []
    for control_id in range(1, N + 1):
        likelihood, impact, effort = (random.randint(1, 5), random.randint(1, 5),
                                      random.randint(1, 3))
        risk = likelihood * impact
        level = ("Critical" if risk >= 20 else "High" if risk >= 12
                 else "Medium" if risk >= 6 else "Low")
        rows.append((control_id, 1, likelihood, impact, effort, "Non-compliant", risk,
                     risk / effort, risk / effort * random.uniform(0.7, 1.3), level))
    conn.executemany(
        """INSERT INTO assessments
           (control_id, assessed_by, likelihood, impact, effort, status,
            risk_score, priority_score, weighted_priority_score, priority_level)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )
    conn.commit()


def average_ms(conn, sql, params=()) -> float:
    start = time.perf_counter()
    for _ in range(REPS):
        conn.execute(sql, params).fetchall()
    return (time.perf_counter() - start) / REPS * 1000


def main() -> None:
    conn = get_connection(":memory:")
    build(conn)

    by_level = "SELECT id FROM assessments WHERE priority_level = ?"
    top_five = "SELECT id FROM assessments ORDER BY weighted_priority_score DESC LIMIT 5"

    indexed = (average_ms(conn, by_level, ("Critical",)), average_ms(conn, top_five))
    conn.execute("DROP INDEX idx_assessments_priority_level")
    conn.execute("DROP INDEX idx_assessments_weighted_score")
    plain = (average_ms(conn, by_level, ("Critical",)), average_ms(conn, top_five))

    print(f"rows: {N:,}")
    print(f"filter by priority level : {indexed[0]:8.3f} ms with index | "
          f"{plain[0]:8.3f} ms without | {plain[0] / indexed[0]:.1f}x")
    print(f"top 5 by weighted score  : {indexed[1]:8.3f} ms with index | "
          f"{plain[1]:8.3f} ms without | {plain[1] / indexed[1]:.0f}x")


if __name__ == "__main__":
    main()
