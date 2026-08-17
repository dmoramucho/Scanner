"""The demo seeder: a small estate, planted by running the real pipeline.

Why this is not a pile of `insert` statements. The API's own tests plant rows directly
(`tests/integration/estate.py`) and are right to — they test the API, so the pipeline is
noise. A *demo* estate has the opposite requirement: the whole point is to look at the UI and
believe what it shows. Rows written by hand can show a confidence value no collector could
have produced, a priority no rule would have derived, or an insight citing evidence that was
never assembled. The UI would look perfect and prove nothing.

So the estate here is grown, not written: the scope gate authorizes each target, the sink
records observations, entity resolution builds the assets, the correlator derives every match
and every priority band, and the triage pipeline assembles and redacts the dossier before any
proposal is attached. Provenance in the demo data is real provenance.

**What is stubbed, and why that is the honest line.** Three things are external to this
system: NVD, CISA's KEV catalog and EPSS, and the language model. Those are replaced with
offline stand-ins (`sources.py`) so the seeder is deterministic and needs no network. Nothing
*we* wrote is stubbed — including the KEV floor and the grounding check, which run for real
against the stand-ins' output and would refuse it if it broke a rule.
"""

from __future__ import annotations

from collections.abc import Sequence

__all__: Sequence[str] = []
