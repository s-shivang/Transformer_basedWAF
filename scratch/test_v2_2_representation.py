import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.pipeline.feature_builder import (
    is_safe_param_key,
    normalize_json_keys,
    build_representation_d_v2_2,
    build_features,
)

def test_param_normalization():
    from src.pipeline.parser import parse_raw_http
    print("Testing is_safe_param_key...")
    assert is_safe_param_key("ciudad") == True
    assert is_safe_param_key("precio") == True
    assert is_safe_param_key("B1") == True
    assert is_safe_param_key("id") == True
    assert is_safe_param_key("param_123") == True

    # Injection / sensitive keys should NOT be considered safe (must be preserved verbatim)
    assert is_safe_param_key("$ne") == False
    assert is_safe_param_key("$gt") == False
    assert is_safe_param_key("admin' OR 1=1") == False
    assert is_safe_param_key("<script>") == False
    assert is_safe_param_key("user;DROP") == False
    print("✓ is_safe_param_key tests passed")

    print("\nTesting Query Param Normalization in build_representation_d_v2_2...")
    raw1 = "GET /tienda1/miembros/identificate.jsp?ciudad=Madrid&precio=45&B1=Enviar HTTP/1.1\r\nHost: example.com\r\n\r\n"
    req1 = parse_raw_http(raw1)
    rep1 = build_representation_d_v2_2(req1)
    print("Input query: ciudad=Madrid&precio=45&B1=Enviar")
    print("Output rep:", rep1)
    assert "P1=Madrid" in rep1
    assert "P2=45" in rep1
    assert "P3=Enviar" in rep1
    assert "ciudad=" not in rep1
    assert "precio=" not in rep1
    print("✓ Query param normalization passed")

    print("\nTesting Injection Query Param Preservation...")
    raw2 = "GET /search?id=1'%20OR%201=1--&safe_tag=electronics HTTP/1.1\r\nHost: example.com\r\n\r\n"
    req2 = parse_raw_http(raw2)
    rep2 = build_representation_d_v2_2(req2)
    print("Input raw:", raw2.strip())
    print("Output rep:", rep2)
    assert "P1=1' OR 1=1--" in rep2 or "id=1' OR 1=1--" in rep2 or "1' OR 1=1--" in rep2
    assert "electronics" in rep2
    print("✓ Safe param with injection value passed")

    raw3 = 'POST /api/filter HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{"user": {"$ne": null}, "password": {"$gt": ""}}'
    req3 = parse_raw_http(raw3)
    rep3 = build_representation_d_v2_2(req3)
    print("\nInput JSON body:", raw3.split("\r\n\r\n")[1])
    print("Output rep:", rep3)
    assert "$ne" in rep3
    assert "$gt" in rep3
    # user and password should be normalized to P1, P2
    assert "P1" in rep3
    print("✓ JSON injection key preservation passed")

    print("\nTesting build_features integration...")
    feats = [build_features(r, "structured_v2_2") for r in [req1, req2, req3]]
    assert len(feats) == 3
    print("✓ build_features(req, 'structured_v2_2') passed")
    print("\nAll representation v2.2 tests PASSED!")

if __name__ == "__main__":
    test_param_normalization()
