import json
from tainttrace import Tracker,tracked,taint_source
@tracked
def transform(value): return str(value).upper()
@tracked(side_effect=True)
def simulated_write(value): return "stored: "+str(value)
with Tracker() as tracker:
 untrusted=taint_source("external fixture text",source_id="fixture:input",reason="explicitly labeled example")
 simulated_write(transform(untrusted))
 transform("local trusted example")
print(json.dumps(tracker.blast_radius().to_dict(),indent=2))
