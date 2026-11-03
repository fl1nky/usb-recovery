"""Explicit v1 product expectations, separate from immutable text-slot oracles.

The old corpora correctly record zero text slots for three empty messages.
Keeping those meaningful document references does not add any text bytes.
"""
POLICY = 'retained_media_records_v1'


def retained_parts_v1(case, historical_text_parts):
    parts = list(historical_text_parts)
    if not parts and case.get('document_id') is not None:
        parts.append(dict(text='', text_field='message', supplemental=False))
    return parts


def expected_record_count_v1(case):
    return max(case['expected_text_slots'], int(case.get('document_id') is not None))
