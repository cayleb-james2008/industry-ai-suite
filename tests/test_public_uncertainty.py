import pytest
from scripts.export_public_lab import _receipt

@pytest.mark.parametrize('uncertainty', [None, '', '   ', []])
def test_public_uncertainty_missing_has_explicit_limitation(uncertainty):
    source={'app_slug':'searchlift','status':'UNVERIFIED','workflow_status':'UNVERIFIED','uncertainty':uncertainty,'workflow_reason':'No traffic or ranking measurements were supplied.'}
    receipt=_receipt('searchlift',source,'2026-10-04T00:00:00Z')
    assert receipt['uncertainty']=='No traffic or ranking measurements were supplied.'

@pytest.mark.parametrize('uncertainty', ['Bounded sample only.', ['No internal records.', 'No organization authority.']])
def test_public_uncertainty_preserves_recorded_detail(uncertainty):
    source={'app_slug':'handoffhub','status':'UNVERIFIED','uncertainty':uncertainty}
    assert _receipt('handoffhub',source,'2026-10-04T00:00:00Z')['uncertainty']==uncertainty

def test_public_uncertainty_no_recorded_reason_remains_explicitly_unverified():
    receipt=_receipt('sentineldesk',{'app_slug':'sentineldesk','status':'UNVERIFIED'},'2026-10-04T00:00:00Z')
    assert isinstance(receipt['uncertainty'],str)
    assert 'UNVERIFIED' in receipt['uncertainty']
