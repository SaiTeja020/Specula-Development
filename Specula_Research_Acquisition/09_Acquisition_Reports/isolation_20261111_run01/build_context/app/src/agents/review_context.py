"""Model-facing evidence copies and a bounded fixture-origin reasoning check."""
import json
import re


ORIGIN_POLICY = (
    'Assess recorded behavior and outcomes within the case. Data-generation and '
    'fixture labels, including synthetic/test/simulation markers, are provenance '
    'only. Their presence or absence cannot establish benignness, maliciousness, '
    'authorization, execution success or absence of compromise. Use behavioral '
    'evidence and corroborating controls; preserve uncertainty.'
)
ORIGIN_KEYS = frozenset({'synthetic', 'is_synthetic', 'fixture_id'})


def review_data(value):
    """Copy structured evidence without fixture labels; never edit source data."""
    if isinstance(value, dict):
        return {key: review_data(item) for key, item in value.items()
                if str(key).casefold() not in ORIGIN_KEYS}
    if isinstance(value, (list, tuple)):
        return [review_data(item) for item in value]
    return value


def review_json(value, **kwargs):
    return json.dumps(review_data(value), **kwargs)


def origin_errors(value):
    """Reject explicit provenance-to-verdict shortcuts, not neutral descriptions.

    This lexical constraint supplements review; it does not prove entailment.
    """
    if isinstance(value, dict):
        return sorted({error for item in value.values() for error in origin_errors(item)})
    if isinstance(value, (list, tuple)):
        return sorted({error for item in value for error in origin_errors(item)})
    if not isinstance(value, str):
        return []
    for sentence in re.split(r'[.!?;]\s+|\n', value.lower()):
        if not re.search(
            r'\b(synthetic (?:flag|marker|nature|data|events?|records?|logs?|origin|provenance|therefore|thus|means|implies)'
            r'|fixture(?:[_ -](?:id|flag|marker|origin|provenance))?'
            r'|simulated (?:data|events?|records?|logs?)|test[ -]data'
            r'|(?:is|are|was|were|being|because|since) synthetic'
            r'|(?:is|are|was|were|being) (?:only |just )?a simulation)\b', sentence):
            continue
        bounded = re.sub(r'\b(?:not (?:a |an )?|no )(?:verified|confirmed) (?:malicious (?:campaign|activity)|attack|compromise)\b', '', sentence)
        if not re.search(r'\b(benign(?:ness)?|harmless|safe(?:ty)?|legitimate|malicious(?:ness)?|threat|attack|compromis(?:e|ed)|authori[sz](?:ed|ation)|executed|successful)\b', bounded):
            continue
        # Denying an inference is allowed; a later positive inference must still
        # be checked, so a negation cannot exempt the entire sentence.
        assertion = re.sub(
            r'\b(?:(?:(?:does|do|did|would|could|should|must) not|cannot|never|'
            r'(?:doesn|don|didn|wouldn|couldn|shouldn|mustn|can)[\x27\u2019]t) '
            r'(?:(?:alone|by itself|itself) )?(?:be used to )?'
            r'|limits? (?:the )?ability to )'
            r'(?:prove|indicate|suggest|support|confirm|establish|mean|imply|show|ensure|demonstrate)(?:s|ed)?\b',
            '', sentence)
        if re.search(r'\b(indicat\w*|suggest\w*|support\w*|confirm\w*|prov(?:e[sd]?|ing)|establish\w*|mean\w*|impl(?:y|ies)|show\w*|ensur\w*|demonstrat\w*|therefore|thus|hence|because|since|due to|so|represent\w*)\b', assertion):
            return ['Fixture provenance cannot establish a behavioral verdict']
    return []
