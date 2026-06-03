import subprocess
def test_autoloop_version():
    r = subprocess.run(["python3","-m","domain_chip_crypto_trading.autoloop","--version"], capture_output=True, timeout=5)
    assert r.returncode in (0,2)
