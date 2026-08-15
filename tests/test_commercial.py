import pytest
from app.billing import get_plan_limits, price_to_plan

def test_plan_limits():
    starter = get_plan_limits("starter")
    pro = get_plan_limits("pro")
    premium = get_plan_limits("premium")
    assert starter["monthly_scans"] == 100
    assert pro["monthly_scans"] == 1000
    assert premium["monthly_scans"] == 10000
    assert get_plan_limits("invalid")["monthly_scans"] == 0

def test_price_to_plan():
    assert price_to_plan("unrecognized") == "unknown"
