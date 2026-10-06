"""Import source-bound timestamp records without inventing physical endpoints.

Collector metadata binds source/build/schema/instrument/connection/profile identity.
It is not a claim that a P4 digest contains those fields or that the collector ran
on hardware. Current internal digests cannot establish wire departure, queue drain
or outstation SELECT/OPERATE acceptance. Intervals remain derived observations,
not guaranteed future maxima or automatic authorization inputs.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

IDENTITY_FIELDS = ('source_sha256', 'instrument_sha256', 'schema_sha256',
                   'build_id', 'connection_id', 'operation_profile_sha256')
INTERNAL_EVENTS = frozenset(('request_ingress', 'ack_ingress', 'response_complete_ingress',
    'ack_deadline', 'response_deadline', 'ack_commit', 'response_commit',
    'readiness_expiry_service', 'blocker_termination', 'reset_abort', 'quarantine_complete'))
EXTERNAL_ENDPOINTS = {
    'ack_wire_departure': frozenset(('switch_wire', 'wire_master')),
    'response_wire_departure': frozenset(('switch_wire', 'wire_master')),
    'queue_drained': frozenset(('traffic_manager',)),
    'select_accept': frozenset(('outstation_application',)),
    'operate_accept': frozenset(('outstation_application',)),
}


def _integer(value, name, low=0, high=None):
    if isinstance(value, bool) or not isinstance(value, int) or value < low or (high is not None and value >= high):
        raise ValueError(name + ' must be an integer in its declared range')


class ObservationRecord:
    def __init__(self, record, source, digest):
        self.identity = record['identity']
        self.observed_at = record['observed_at']
        self.samples = record['samples']
        self.source, self.sha256 = str(source), digest
        self._events = {(s['transaction_id'], s['event']): s for s in self.samples}
        self._pairs = {pair['pair_id']:pair for pair in record.get('sbo_pairs', [])}

    def interval(self, transaction_id, start_event, end_event, *, max_interval_ns=40_000_000):
        """Decode a same-clock, same-association interval within an explicit horizon.

        Full owner and application identity must match; no generation-wrap or
        phase association is inferred. Missing events and ambiguous ordering stay
        unavailable. Long SBO intervals require suitable wider endpoint clocks.
        """
        _integer(max_interval_ns, 'max_interval_ns', low=1)
        a = self._events.get((str(transaction_id), start_event))
        b = self._events.get((str(transaction_id), end_event))
        return self._interval(a,b,start_event,end_event,max_interval_ns)

    def _interval(self,a,b,start_event,end_event,max_interval_ns,*,same_phase=True):
        result = dict(value_ns=None, evidence_kind='unavailable', quantity='internal interval',
                      endpoints=[start_event, end_event], reason='', source=self.source,
                      source_sha256=self.sha256)
        if not a or not b:
            result['reason'] = 'required endpoint is unavailable'
            return result
        if a['evidence_kind'] != 'observed' or b['evidence_kind'] != 'observed':
            result['reason'] = 'configured/estimated timestamps are not observed endpoint events'
            return result
        fields=('clock_domain','clock_width_bits','marker_mask')
        if same_phase:
            fields+=('owner_cookie','app_seq','operation')
        for field in fields:
            if a[field] != b[field]:
                result['reason'] = field + ' differs; no aligned same-association interval'
                return result
        if a['connection_cookie'] != b['connection_cookie']:
            result['reason'] = 'connection cookie differs'
            return result
        if any(not sample[name] for sample in (a,b) for name in ('src_ipv4','dst_ipv4','sport','dport')):
            result['reason'] = 'full socket tuple is unavailable; pulse identity alone is insufficient'
            return result
        def flow(sample):
            return sorted(((sample['src_ipv4'],sample['sport']), (sample['dst_ipv4'],sample['dport'])))
        if flow(a) != flow(b):
            result['reason'] = 'full socket tuple differs'
            return result
        modulus = 1 << a['clock_width_bits']
        if max_interval_ns >= modulus // 2:
            result['reason'] = 'interval horizon exceeds the clock half-range'
            return result
        mask = a['marker_mask']
        if mask + 1 > max_interval_ns:
            result['reason'] = 'timestamp quantisation exceeds the declared interval horizon'
            return result
        delta = ((b['timestamp_ns'] & ~mask) - (a['timestamp_ns'] & ~mask)) % modulus
        if delta > max_interval_ns:
            result['reason'] = 'backward/ambiguous timestamp or interval outside declared horizon'
            return result
        result.update(value_ns=delta, evidence_kind='derived', reason='',
            clock_domain=a['clock_domain'], quantisation_ns=mask + 1,
            quantity=('external endpoint interval' if start_event in EXTERNAL_ENDPOINTS or
                      end_event in EXTERNAL_ENDPOINTS else 'internal interval'))
        return result

    def sbo_cycle(self,pair_id,*,max_interval_ns=40_000_000):
        """Only an explicit current-profile/object-set relation may cross phases.

        App sequence and owner legitimately differ between SELECT and OPERATE.
        No pair is inferred from event adjacency, timestamps or a common tuple.
        This observed cycle is not automatically a native-cycle upper bound.
        """
        _integer(max_interval_ns,'max_interval_ns',low=1)
        pair=self._pairs.get(str(pair_id))
        a=b=None
        reason='explicit SELECT/OPERATE pair relation is unavailable'
        if pair:
            if (pair['operation_profile_sha256'] != self.identity['operation_profile_sha256'] or
                    pair['select_object_set_sha256'] != pair['operate_object_set_sha256']):
                reason='SBO profile or exact real/decoy object set differs'
            else:
                a=self._events.get((pair['select_transaction_id'],'select_accept'))
                b=self._events.get((pair['operate_transaction_id'],'operate_accept'))
                if a and b and (a['operation'] != 'SELECT' or b['operation'] != 'OPERATE'):
                    a=b=None
                    reason='SBO relation does not reference SELECT and OPERATE acceptance events'
        result=self._interval(a,b,'select_accept','operate_accept',max_interval_ns,same_phase=False)
        result.update(pair_id=str(pair_id),quantity='outstation SELECT-to-OPERATE acceptance interval')
        if a is None or b is None:
            result['reason']=reason
        return result

    def summary(self):
        return dict(identity=self.identity, observed_at=self.observed_at, source=self.source,
            sha256=self.sha256, sample_count=len(self.samples),
            events=sorted({s['event'] for s in self.samples}),
            sbo_pair_count=len(self._pairs),
            not_established=['physical endpoints not present remain unavailable',
                'clock alignment between capture and switch domains',
                'observed maxima bound future traffic', 'hardware authorization'])


def load_observations(path, expected_identity):
    """Read JSON or header-first JSONL; refuse stale/unbound collector metadata."""
    path = Path(path)
    raw = path.read_bytes()
    try:
        record = json.loads(raw)
    except json.JSONDecodeError:
        rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
        if not rows:
            raise ValueError('empty observation record')
        record = dict(rows[0], samples=rows[1:])
    if not isinstance(record, dict) or type(record.get('version')) is not int or record.get('version') != 1:
        raise ValueError('unsupported observation record version')
    identity = record.get('identity', {})
    if not isinstance(identity, dict) or not isinstance(expected_identity, dict):
        raise ValueError('observation identity must be an explicit object')
    for name in IDENTITY_FIELDS:
        expected = expected_identity.get(name)
        if not isinstance(expected, str) or not expected or identity.get(name) != expected:
            raise ValueError('observation identity differs or is unavailable: ' + name)
        if name.endswith('sha256') and (len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected)):
            raise ValueError('invalid SHA256 identity: ' + name)
    try:
        stamp = datetime.fromisoformat(record['observed_at'].replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            raise ValueError('observation time has no timezone')
    except (KeyError, AttributeError, TypeError, ValueError) as exc:
        raise ValueError('invalid observation time') from exc
    samples = record.get('samples')
    if not isinstance(samples, list):
        raise ValueError('observation samples must be a list')
    seen = set()
    for s in samples:
        if not isinstance(s, dict):
            raise ValueError('invalid observation sample')
        required = ('transaction_id', 'owner_cookie', 'operation', 'app_seq', 'event', 'timestamp_ns',
                    'clock_domain', 'clock_width_bits', 'marker_mask', 'endpoint', 'evidence_kind',
                    'connection_cookie', 'src_ipv4', 'dst_ipv4', 'sport', 'dport')
        if any(name not in s for name in required):
            raise ValueError('sample lacks an explicit endpoint/clock/association field')
        if not isinstance(s['transaction_id'], str) or not s['transaction_id']:
            raise ValueError('transaction_id must be a nonempty string')
        if s['operation'] not in ('READ', 'SELECT', 'OPERATE', 'SBO'):
            raise ValueError('unsupported observation operation')
        _integer(s['owner_cookie'], 'owner_cookie', high=1 << 32)
        _integer(s['connection_cookie'], 'connection_cookie', high=1 << 32)
        for name in ('src_ipv4', 'dst_ipv4'):
            _integer(s[name], name, high=1 << 32)
        for name in ('sport', 'dport'):
            _integer(s[name], name, high=1 << 16)
        _integer(s['app_seq'], 'app_seq', high=16)
        _integer(s['clock_width_bits'], 'clock_width_bits', low=1, high=65)
        _integer(s['timestamp_ns'], 'timestamp_ns', high=1 << s['clock_width_bits'])
        _integer(s['marker_mask'], 'marker_mask', high=1 << s['clock_width_bits'])
        if s['marker_mask'] & (s['marker_mask'] + 1):
            raise ValueError('marker mask must cover contiguous low bits')
        if s['marker_mask'] + 1 >= (1 << s['clock_width_bits']) // 2:
            raise ValueError('marker mask erases the usable elapsed clock half-range')
        if not isinstance(s['clock_domain'], str) or not s['clock_domain']:
            raise ValueError('clock domain is unavailable')
        if s['evidence_kind'] not in ('observed', 'configured', 'estimated', 'unavailable'):
            raise ValueError('unsupported observation evidence kind')
        event = s['event']
        if event in INTERNAL_EVENTS:
            if s['endpoint'] != 'ingress':
                raise ValueError('internal event must retain its ingress endpoint')
        elif event in EXTERNAL_ENDPOINTS:
            if s['endpoint'] not in EXTERNAL_ENDPOINTS[event]:
                raise ValueError('external endpoint cannot be inferred from an ingress event')
        else:
            raise ValueError('unsupported observation event: ' + str(event))
        key = (s['transaction_id'], event)
        if key in seen:
            raise ValueError('duplicate event for one transaction')
        seen.add(key)
    pairs=record.get('sbo_pairs',[])
    if not isinstance(pairs,list):
        raise ValueError('SBO pair relations must be a list')
    pair_ids=set()
    for pair in pairs:
        if not isinstance(pair,dict) or any(not isinstance(pair.get(name),str) or not pair[name] for name in (
                'pair_id','select_transaction_id','operate_transaction_id','operation_profile_sha256',
                'select_object_set_sha256','operate_object_set_sha256')):
            raise ValueError('incomplete explicit SBO pair relation')
        if pair['pair_id'] in pair_ids or pair['select_transaction_id']==pair['operate_transaction_id']:
            raise ValueError('duplicate pair or identical SELECT/OPERATE transaction relation')
        for name in ('operation_profile_sha256','select_object_set_sha256','operate_object_set_sha256'):
            if len(pair[name]) != 64 or any(c not in '0123456789abcdef' for c in pair[name]):
                raise ValueError('invalid SBO relation hash')
        pair_ids.add(pair['pair_id'])
    return ObservationRecord(record, path, hashlib.sha256(raw).hexdigest())
