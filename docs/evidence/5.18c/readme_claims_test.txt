============================= test session starts =============================
platform win32 -- Python 3.14.4, pytest-9.1.1, pluggy-1.6.0 -- C:\Users\BIT PATNA\AppData\Local\Programs\Python\Python314\python.exe
cachedir: .pytest_cache
hypothesis profile 'dev' -> deadline=None, max_examples=50, suppress_health_check=(HealthCheck.too_slow,)
rootdir: C:\Users\BIT PATNA\ai-agent-firewall
configfile: pyproject.toml
plugins: anyio-4.15.1, hypothesis-6.168.5, platformdirs-4.13.0, asyncio-1.4.0, cov-7.1.0, timeout-2.4.0
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
timeout: 30.0s
timeout method: thread
timeout func_only: False
collecting ... collected 1 item

tests/test_readme_claims.py::test_readme_approvals_per_task_and_scope_match_generated_report PASSED [100%]

============================== 1 passed in 0.63s ==============================
