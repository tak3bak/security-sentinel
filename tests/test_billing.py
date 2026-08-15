from app.billing import price_to_plan

def test_unknown_price_is_unknown():
    assert price_to_plan("not-a-price") == "unknown"
