"""Separate WAN run completion, offered rate and strict media delivery gates."""
import math

def assess(result, seconds, pps, transport="quic", acceptance="strict"):
    if transport not in ("quic", "wt", "sctp") or acceptance not in ("strict", "transport"):
        raise ValueError("unknown transport or acceptance policy")
    required = ('sent', 'recv', 'errs', 'duration_s', 'peak_in_flight',
                'missing_echoes', 'echo_timeouts', 'late_echoes', 'pending_at_end')
    valid = (result.get('schema_version') == 2
             and all(isinstance(result.get(k), (int, float))
                     and not isinstance(result[k], bool) and math.isfinite(result[k])
                     and result[k] >= 0 for k in required))
    if valid:
        valid = (result['recv'] <= result['sent']
                 and result['missing_echoes'] == result['sent'] - result['recv']
                 and result['late_echoes'] <= result['echo_timeouts']
                 and result['late_echoes'] <= result['recv'])
    delivery = bool(valid and result['sent'] > 0 and result['missing_echoes'] == 0 and result['echo_timeouts'] == 0
                    and result['pending_at_end'] == 0)
    stability = bool(valid and result.get('completed') is True and result['errs'] == 0
                     and result['duration_s'] >= seconds * .99 and result['pending_at_end'] == 0
                     and (result.get('exit_code') == 0 or
                          (result.get('exit_code') == 1 and not delivery)))
    rate = bool(valid and result['sent'] >= seconds * pps * .99
                and result['peak_in_flight'] >= 1)
    # This gate checks session operation, NOT network delivery quality or support readiness.
    operation = bool(stability and rate and result['recv'] > 0)
    strict = bool(operation and delivery and result.get('exit_code') == 0)
    selected = strict if acceptance == 'strict' or transport == 'sctp' else operation
    reasons = []
    if not valid:
        reasons.append('missing/inconsistent v2 diagnostics; inspect session stderr and exit_code')
    else:
        if not stability:
            reasons.append('session incomplete or operational/protocol error')
        if not rate:
            reasons.append('incomplete send volume')
        if result['sent'] == 0:
            reasons.append('no media sent; delivery not established')
        elif not delivery:
            reasons.append(f"media: {result['missing_echoes']} missing, {result['echo_timeouts']} deadlines exceeded")
    return dict(stability_pass=stability, rate_pass=rate, delivery_pass=delivery,
                transport_pass=operation, strict_pass=strict, acceptance=acceptance,
                transport=transport, **{'pass': selected},
                failure_reasons=reasons)
