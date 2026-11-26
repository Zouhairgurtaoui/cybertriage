from cybertriage.domain.triage import RetrievedReference


def format_reference(reference: RetrievedReference, number: int) -> str:
    if reference.provenance_json is not None and (not isinstance(reference.provenance_json, str) or len(reference.provenance_json.encode("utf-8")) > 4096):
        raise ValueError("Reference provenance exceeds its formatting budget.")
    provenance = ("Reference freshness (application metadata; not incident observations):\n"
                  f"{reference.provenance_json}\n") if reference.provenance_json else ""
    return (f"[R{number}]\nTitle: {reference.title}\nSource: {reference.source_url}\n"
            f"{provenance}Excerpt:\n{reference.text}")
