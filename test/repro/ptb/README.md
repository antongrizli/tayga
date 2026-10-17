# Historical PTB reproduction corpus

The retained Python scripts and packet image were moved without regenerating packet bytes from `test/_ptb_*` at source commit `e804964533083fbc1e467d1a07334636822701c8`. Packet paths now resolve beside the scripts. The scripts require Linux, root, Scapy and the prepared CLAT environment; they are historical diagnostic tools, not portable test-suite modules. The runner uses disposable namespaces named `client`, `router`, `clatns`, and `server`; reserve the workflow lock and use an isolated VM.

The maintained PMTUD checks are [test_pmtud.py](../../system/test_pmtud.py) and [test_pmtud_b.py](../../system/test_pmtud_b.py). CI must preserve logs and failures; this corpus alone establishes no current correctness or performance claim.
